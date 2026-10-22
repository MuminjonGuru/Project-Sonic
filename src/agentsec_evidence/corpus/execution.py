"""Sequential fixed-core collection with sealed attempts and offline native replay."""

from __future__ import annotations

import argparse
import json
import time
import uuid
from pathlib import Path
from typing import Any, cast

from pydantic import JsonValue

from agentsec_evidence.adapters.agent_audit import normalize_agent_audit, parse_agent_audit_json
from agentsec_evidence.agents.execution import AgentAuditToolConfig, build_agent_argv
from agentsec_evidence.agents.semantics import native_projection
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.core.io import atomic_write_bytes
from agentsec_evidence.corpus.contracts import (
    CorpusCoreAdmission,
    CorpusCorePlan,
    current_implementation,
    load_preparation,
    prepare_core,
    schedule,
    semgrep_scope,
    verify_admission,
    verify_frozen,
    verify_parent,
)
from agentsec_evidence.custom_rules.baseline_execution import (
    LIMITS,
    check_image,
    cleanup_ok,
    invoke,
    verify_invocation,
)
from agentsec_evidence.custom_rules.repository_contracts import current_native
from agentsec_evidence.custom_rules.repository_execution import argv_for
from agentsec_evidence.custom_rules.shared_execution import (
    _read_capture,
    capture_ok,
    run_capture,
)
from agentsec_evidence.execution.config import load_toml_config
from agentsec_evidence.execution.process import ProcessCapture
from agentsec_evidence.orchestration.shared import minimal_environment, resolve_docker
from agentsec_evidence.pilot.runner import evidence_records, save
from agentsec_evidence.reporting.custom_contracts import FAMILIES, IMAGE
from agentsec_evidence.research.execution import assess_research_execution, build_research_argv
from agentsec_evidence.research.models import SemgrepPassEvidence, load_research_profile
from agentsec_evidence.research.retained import (
    RetainedManifest,
    bounded_file,
    plain_path,
    read_retained_research,
)
from agentsec_evidence.research.semgrep import build_dual_view, reconcile_semgrep_pass


def stage_argv(
    root: Path, plan: CorpusCorePlan, row: dict[str, Any], docker: Path, name: str
) -> list[str]:
    tool = load_toml_config(root / "metadata/tool.toml", AgentAuditToolConfig).value
    producer = row["producer"]
    family = next((f for f in FAMILIES if f.key == producer), None)
    if family is not None:
        return argv_for(docker, tool, root, row["batch"], name, family)
    if producer == "agent-audit-python":
        return build_agent_argv(
            docker=docker, tool=tool, profile=LIMITS, name=name, target=root / "baseline/agent"
        )
    scope = semgrep_scope(plan)
    if scope is None:
        raise ValueError("No eligible whole Semgrep selection")
    return build_research_argv(
        docker=docker,
        name=name,
        profile_bytes=bounded_file(root / "metadata/profile.json", 1024**2),
        scope=scope,
        role="research" if producer == "semgrep-research" else "repository-policy",
        rules=root / "rules",
        target=root / "baseline/semgrep",
        output=root / row["key"],
    )


def observe(
    root: Path, plan: CorpusCorePlan, row: dict[str, Any], capture: ProcessCapture
) -> dict[str, Any]:
    family = next((f for f in FAMILIES if f.key == row["producer"]), None)
    if family is not None:
        if not capture_ok(capture, {0, 1, 2}):
            raise ValueError("Custom process exceeded bounds or failed")
        native = current_native(
            capture.stdout,
            bounded_file(root / f"batches/{row['batch']:03d}/request.json", 256 * 1024),
            family,
            capture.exit_code,
        )
        return {
            "kind": "custom",
            "finding_records": sum(len(f.findings or []) for f in native.files),
            "native": native.model_dump(mode="json"),
            "semantic": [f.model_dump(mode="json") for f in native.files],
            "native_sha256": sha256_bytes(capture.stdout),
        }
    if row["producer"] == "agent-audit-python":
        if not capture_ok(capture, {0, 1}):
            raise ValueError("Agent Audit process failed or exceeded bounds")
        parsed = parse_agent_audit_json(capture.stdout)
        mapped = normalize_agent_audit(
            parsed,
            inputs=[c.checked_input() for c in plan.assessment.checks],
            run_id="corpus-core",
            execution_id=row["key"],
            target_snapshot_id=plan.validation.preview.source_content_sha256,
        )
        # The shared adapter issues opaque IDs. This replayable derivative binds identity
        # to the native blob, its array position and the exact execution instead.
        findings = []
        for index, finding in enumerate(mapped.findings):
            value = finding.model_dump(mode="json")
            value["record_id"] = "finding_corpus_" + semantic_hash(
                {
                    "version": "corpus-core-record-v1",
                    "execution_id": row["key"],
                    "native_sha256": sha256_bytes(capture.stdout),
                    "native_index": index,
                }
            )
            findings.append(value)
        return {
            "kind": "agent-audit",
            "finding_records": len(mapped.findings),
            "findings": findings,
            "native_scanned_files": parsed.document.scanned_files,
            "selected_files": len(plan.validation.preview.selection),
            "analysis_completeness": "not-established",
            "per_file_completion": "not-observable",
            "unknown_native_fields": list(parsed.unknown_field_paths),
            "semantic": native_projection(capture.stdout),
            "native_sha256": sha256_bytes(capture.stdout),
            "stderr_present": bool(capture.stderr),
        }
    scope = semgrep_scope(plan)
    if scope is None:
        raise ValueError("Cannot interpret Semgrep without whole input scope")
    evidence = reconcile_semgrep_pass(
        profile_bytes=bounded_file(root / "metadata/profile.json", 1024**2),
        scope=scope,
        execution_id=row["key"],
        role="research" if row["producer"] == "semgrep-research" else "repository-policy",
        native_json=bounded_file(root / row["key"] / "native.json", 4 * 1024**2),
        native_sarif=bounded_file(root / row["key"] / "native.sarif", 4 * 1024**2),
        allow_policy_directory_skips=True,
    )
    assessment = assess_research_execution(capture, cleanup_succeeded=True, evidence=evidence)
    if assessment.analysis_state == "failed":
        raise ValueError("Semgrep process/native reconciliation failed")
    return {
        "kind": "semgrep",
        "finding_records": len(evidence.findings),
        "evidence": evidence.model_dump(mode="json"),
        "assessment": assessment.model_dump(mode="json"),
        "semantic": evidence.model_dump(
            mode="json", exclude={"execution_id", "native_json_sha256", "native_sarif_sha256"}
        ),
    }


def images(root: Path, plan: CorpusCorePlan) -> list[str]:
    producers = {r["producer"] for r in schedule(plan) if r["state"] == "not-run"}
    required = []
    if producers & {f.key for f in FAMILIES}:
        required.append(IMAGE)
    if "agent-audit-python" in producers:
        required.append(
            load_toml_config(root / "metadata/tool.toml", AgentAuditToolConfig).value.image
        )
    if "semgrep-research" in producers:
        required.append(
            load_research_profile(bounded_file(root / "metadata/profile.json", 1024**2)).image
        )
    return required


def _custom_invoke(argv: list[str], directory: Path, environment: dict[str, str]) -> ProcessCapture:
    name = argv[argv.index("--name") + 1]
    try:
        return run_capture(argv, directory, environment)
    finally:
        cleanup = run_capture(
            [argv[0], "rm", "--force", name], directory / "cleanup", environment, timeout=15
        )
        if not cleanup_ok(cleanup):
            raise ValueError("Custom container cleanup not confirmed")


def _check_budget(root: Path) -> None:
    records = evidence_records(root)
    # Reserve the largest bounded process/native pair plus failure metadata before launch.
    if len(records) > 4000 or sum(r["bytes"] for r in records) > 108 * 1024**2:
        raise ValueError("Retained attempt budget exhausted; no further launch")


def run_core(
    project: Path,
    preparation: Path,
    admission_path: Path,
    output: Path,
    *,
    docker: Path | None = None,
) -> dict[str, Any]:
    project = plain_path(project, directory=True)
    preparation = plain_path(preparation, directory=True)
    plan = load_preparation(project, preparation)
    current_implementation(project, plan)
    admission_raw = bounded_file(admission_path, 64 * 1024)
    admission = CorpusCoreAdmission.model_validate_json(admission_raw)
    plan_raw = bounded_file(preparation / "plan.json", 4 * 1024**2)
    verify_admission(plan, plan_raw, admission)
    output = output.absolute()
    plain_path(output.parent, directory=True)
    if (
        output.exists()
        or output == project / "workspace"
        or not output.is_relative_to(project / "workspace")
    ):
        raise ValueError("Use a fresh ignored attempt; no overwrite, retry or implicit resume")
    executable = resolve_docker(docker)
    if executable is None:
        raise ValueError("Docker required; no host or network fallback")
    output.mkdir()
    start = time.perf_counter_ns()
    result: dict[str, Any] = {
        "contract": "corpus-core-execution-v1",
        "finished": False,
        "error": None,
        "execution_root": str(output),
        "rows": schedule(plan),
        "duration_ns": None,
        "target_execution": False,
        "optional_stages": "not-admitted-in-core",
    }
    atomic_write_bytes(output / "plan.json", plan_raw)
    atomic_write_bytes(output / "admission.json", admission_raw)
    try:
        for path in plan.frozen_pins:
            atomic_write_bytes(output / path, bounded_file(preparation / path, 4 * 1024**2))
        verify_frozen(output, plan)
        environment = minimal_environment(output / "runtime")
        for i, image in enumerate(images(output, plan)):
            check_image(
                run_capture(
                    [str(executable), "image", "inspect", image],
                    output / f"preflight/i{i}",
                    environment,
                    timeout=30,
                ),
                image,
            )
        paired: dict[int, list[SemgrepPassEvidence]] = {}
        for row in result["rows"]:
            if row["state"] != "not-run":
                continue
            row["state"] = "failed"
            save(output / "result.json", result)
            _check_budget(output)
            directory = output / row["key"]
            directory.mkdir(parents=True)
            argv = stage_argv(output, plan, row, executable, "corpus-core-" + uuid.uuid4().hex)
            if row["batch"] is not None:
                capture = _custom_invoke(argv, directory / "process", environment)
            else:
                capture = invoke(
                    argv,
                    directory / "process",
                    environment,
                    native_pair=row["producer"].startswith("semgrep-"),
                )
            observation = observe(output, plan, row, capture)
            if observation["kind"] == "semgrep":
                evidence = SemgrepPassEvidence.model_validate(observation["evidence"])
                paired.setdefault(row["repetition"], []).append(evidence)
                if len(paired[row["repetition"]]) == 2:
                    build_dual_view(*paired[row["repetition"]])
            save(directory / "observation.json", observation)
            row.update(
                state="observed",
                finding_records=observation["finding_records"],
                duration_ns=capture.duration_ns,
                semantic_sha256=semantic_hash(cast(JsonValue, observation["semantic"])),
            )
            save(output / "result.json", result)
            print(f"{plan.assessment.candidate_id} {row['key']}: observed", flush=True)
        verify_frozen(output, plan)
        verify_parent(project, plan)
        result["finished"] = True
    except BaseException as exc:
        result["error"] = {"type": type(exc).__name__, "message": str(exc)}
        for failed in result["rows"]:
            if failed["state"] == "failed":
                save(output / failed["key"] / "failure.json", result["error"])
        raise
    finally:
        result["duration_ns"] = time.perf_counter_ns() - start
        save(output / "result.json", result)
        save(
            output / "evidence-manifest.json",
            RetainedManifest.model_validate({"files": evidence_records(output)}).model_dump(
                mode="json"
            ),
        )
    return result


def verify_core(project: Path, root: Path) -> dict[str, Any]:
    retained = read_retained_research(root)
    plan = CorpusCorePlan.model_validate_json(retained.read("plan.json"))
    verify_frozen(root, plan)
    verify_parent(project, plan)
    verify_admission(
        plan,
        retained.read("plan.json"),
        CorpusCoreAdmission.model_validate_json(retained.read("admission.json")),
    )
    result = json.loads(retained.read("result.json"))
    if (
        result.get("contract") != "corpus-core-execution-v1"
        or result.get("target_execution") is not False
        or result.get("optional_stages") != plan.optional_stages
    ):
        raise ValueError("Core result contract differs")
    if type(result.get("finished")) is not bool or (
        result["finished"] != (result.get("error") is None)
    ):
        raise ValueError("Completion and error states disagree")
    if type(result.get("duration_ns")) is not int or result["duration_ns"] < 0:
        raise ValueError("Missing attempt timing")
    rows, expected = result["rows"], schedule(plan)
    if len(rows) != len(expected):
        raise ValueError("Core schedule count differs")
    allowed = {*plan.frozen_pins, "plan.json", "admission.json", "result.json"}
    process_files = ("command.json", "process.json", "stdout.bin", "stderr.bin", "failure.json")
    for i in range(len(images(root, plan))):
        allowed.update(f"preflight/i{i}/{name}" for name in process_files)
    for initial in expected:
        key = initial["key"]
        if initial["state"] != "not-run":
            continue
        allowed.update({key + "/observation.json", key + "/failure.json"})
        for prefix in ("process", "process/cleanup"):
            allowed.update(f"{key}/{prefix}/{name}" for name in process_files)
        if initial["producer"].startswith("semgrep-"):
            allowed.update({key + "/native.json", key + "/native.sarif"})
    if set(retained.files) - allowed:
        raise ValueError("Unscheduled evidence member")
    has_observations = any(r["state"] == "observed" for r in rows)
    for i, image in enumerate(images(root, plan)):
        key = f"preflight/i{i}"
        if (
            not result["finished"]
            and not has_observations
            and key + "/process.json" not in retained.files
        ):
            continue
        capture = _read_capture(retained.files, key)
        if list(capture.argv[1:]) != ["image", "inspect", image]:
            raise ValueError("Image preflight command differs")
        if result["finished"] or has_observations:
            check_image(capture, image)
    observations = {}
    pair: dict[int, list[SemgrepPassEvidence]] = {}
    failed_seen = False
    for row, initial in zip(rows, expected, strict=True):
        if any(row[k] != initial[k] for k in ("key", "repetition", "producer", "batch", "reasons")):
            raise ValueError("Core schedule identity changed")
        key = row["key"]
        if initial["state"] != "not-run" or row["state"] == "not-run":
            if row != initial or any(p.startswith(key + "/") for p in retained.files):
                raise ValueError("Unrun/unsupported stage contains results")
            if initial["state"] == "not-run" and result["finished"]:
                raise ValueError("Finished attempt has unrun cells")
            failed_seen = failed_seen or initial["state"] == "not-run"
            continue
        if row["state"] == "failed":
            if (
                result["finished"]
                or failed_seen
                or any(
                    row[k] is not None
                    for k in ("finding_records", "duration_ns", "semantic_sha256")
                )
            ):
                raise ValueError("Failed stage cannot carry successful observations")
            failed_seen = True
            # A failed receipt is retained, not promoted to verified native analysis.
            if key + "/process/command.json" in retained.files:
                command = json.loads(retained.read(key + "/process/command.json"))["argv"]
                from agentsec_evidence.custom_rules.baseline_execution import portable

                name = command[command.index("--name") + 1]
                argv = stage_argv(root, plan, row, root / "plan.json", name)
                if portable(command, result["execution_root"]) != portable(
                    argv, str(root.absolute())
                ):
                    raise ValueError("Failed-stage command differs")
            continue
        if row["state"] != "observed" or failed_seen:
            raise ValueError("Invalid execution order or state")
        capture = _read_capture(retained.files, key + "/process")
        name = capture.argv[capture.argv.index("--name") + 1]
        argv = stage_argv(root, plan, row, root / "plan.json", name)
        verify_invocation(
            retained.files, key + "/process", capture, argv, result["execution_root"], root
        )
        observation = observe(root, plan, row, capture)
        if observation != json.loads(retained.read(key + "/observation.json")):
            raise ValueError("Observation differs from native evidence")
        initial.update(
            state="observed",
            finding_records=observation["finding_records"],
            duration_ns=capture.duration_ns,
            semantic_sha256=semantic_hash(cast(JsonValue, observation["semantic"])),
        )
        if row != initial:
            raise ValueError("Row counters or semantic projection differ")
        if observation["kind"] == "semgrep":
            pair.setdefault(row["repetition"], []).append(
                SemgrepPassEvidence.model_validate(observation["evidence"])
            )
        observations[key] = observation
    for evidence in pair.values():
        if len(evidence) == 2:
            build_dual_view(*evidence)
        elif result["finished"]:
            raise ValueError("Missing Semgrep policy view")
    return {
        "contract": "corpus-core-verification-v1",
        "integrity_replayed": True,
        "execution_finished": result["finished"],
        "error": result["error"],
        "manifest_sha256": retained.manifest_sha256,
        "plan": plan.model_dump(mode="json"),
        "rows": rows,
        "observations": observations,
        "duration_ns": result["duration_ns"],
        "scanner_invocations_during_replay": 0,
        "unique_vulnerabilities": None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "verify-preparation", "run", "verify"))
    parser.add_argument("--project", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--validation", type=Path)
    parser.add_argument("--rules", type=Path)
    parser.add_argument("--preparation", type=Path)
    parser.add_argument("--admission", type=Path)
    args = parser.parse_args()
    if args.mode == "prepare":
        if args.validation is None or args.rules is None:
            parser.error("prepare requires --validation and --rules")
        prepare_core(args.project, args.validation, args.rules, args.output)
    if args.mode in {"prepare", "verify-preparation"}:
        plan = load_preparation(args.project, args.output)
        print(
            json.dumps(
                {"candidate_id": plan.assessment.candidate_id, "prepared": True, "detectors_run": 0}
            )
        )
        return
    if args.mode == "run":
        if args.preparation is None or args.admission is None:
            parser.error("run requires --preparation and --admission")
        run_core(args.project, args.preparation, args.admission, args.output)
    replay = verify_core(args.project, args.output)
    print(
        json.dumps({k: v for k, v in replay.items() if k not in {"observations", "plan"}}, indent=2)
    )


if __name__ == "__main__":
    main()
