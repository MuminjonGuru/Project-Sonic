"""Pinned baseline observations on approved, finite authored groups; never target execution."""

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
from agentsec_evidence.agents.records import AgentInputReport, AgentInputRequest
from agentsec_evidence.agents.semantics import native_projection
from agentsec_evidence.agents.validation import canonical_artifact_path, load_agent_json
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.core.io import atomic_write_bytes
from agentsec_evidence.custom_rules.baseline_inputs import (
    PROFILE_PATH,
    PROFILE_SHA,
    BaselineSelection,
    Role,
    authored_snapshot_id,
    group_requests,
    planned_rows,
    repeatability,
    select_baseline,
)
from agentsec_evidence.custom_rules.shared_execution import (
    _read_capture,
    capture_ok,
    check_native,
    run_capture,
    save_capture,
    verify_shared,
)
from agentsec_evidence.custom_rules.shared_inputs import prepare_shared, read_registry
from agentsec_evidence.execution.config import ExecutionProfile, load_toml_config
from agentsec_evidence.execution.process import ProcessCapture, run_bounded_process
from agentsec_evidence.models.contracts import ContractModel
from agentsec_evidence.orchestration.shared import minimal_environment, resolve_docker
from agentsec_evidence.pilot.runner import evidence_records, save
from agentsec_evidence.reporting.custom_contracts import FAMILIES
from agentsec_evidence.research.execution import assess_research_execution, build_research_argv
from agentsec_evidence.research.models import (
    SemgrepPassEvidence,
    load_research_profile,
    verify_rule_bytes,
)
from agentsec_evidence.research.retained import bounded_file, plain_path, read_retained_research
from agentsec_evidence.research.semgrep import build_dual_view, reconcile_semgrep_pass

LIMITS = ExecutionProfile.model_validate(
    {
        "profile_id": "authored-baseline-groups-v1",
        "profile_kind": "development",
        "network": "denied",
        "target_mount": "read-only",
        "max_workers": 1,
        "limits": {
            "timeout_seconds": 120,
            "cpu_count": 2,
            "memory_mb": 2048,
            "pids": 256,
            "tmpfs_mb": 256,
            "max_stdout_bytes": 2 * 1024**2,
            "max_stderr_bytes": 1024**2,
            "max_native_bytes": 2 * 1024**2,
        },
    }
)


def custom_reference(root: Path, inputs: dict[str, bytes]) -> dict[str, Any]:
    """Reuse verified custom evidence without claiming it was rerun in this treatment."""
    verified = verify_shared(root)
    if (
        verified["origin_assertions_passed"] is not True
        or verified["repeatability_passed"] is not True
    ):
        raise ValueError("Custom source rehearsal did not pass")
    retained = read_retained_research(root)
    plan = json.loads(retained.read("plan.json"))
    if {e["path"]: e["sha256"] for e in plan["inventory"]} != {
        path: sha256_bytes(raw) for path, raw in inputs.items()
    }:
        raise ValueError("Custom and baseline source bytes differ")
    observations: dict[str, dict[str, Any]] = {path: {} for path in sorted(inputs)}
    result = json.loads(retained.read("result.json"))
    for row in result["rows"]:
        if row["repetition"] != 1:
            continue
        family = next(f for f in FAMILIES if f.key == row["family"])
        capture = _read_capture(retained.files, row["key"])
        native = check_native(
            capture.stdout,
            retained.read(f"batches/{row['batch']:03d}/request.json"),
            family,
            capture.exit_code,
        )
        for file in native.files:
            observations[file.path][family.key] = {
                "state": file.state,
                "findings": [
                    cast(ContractModel, f).model_dump(mode="json") for f in file.findings or []
                ]
                if file.findings is not None
                else None,
                "native_path": row["key"] + "/stdout.bin",
                "native_sha256": sha256_bytes(capture.stdout),
            }
    return {
        "contract": "verified-custom-source-reference-v1",
        "original_manifest_sha256": retained.manifest_sha256,
        "snapshot_id": verified["snapshot_id"],
        "source_pins": plan["source_pins"],
        "catalog_pins": plan["catalog_pins"],
        "observations": observations,
        "provenance": (
            "Derived from verified first repetition; original native bundle retained separately"
        ),
        "not_rerun": True,
    }


def frozen_hashes(files: dict[str, bytes]) -> dict[str, str]:
    return {path: sha256_bytes(raw) for path, raw in sorted(files.items())}


def verify_frozen(root: Path, pins: dict[str, str]) -> None:
    for path, digest in pins.items():
        canonical_artifact_path(path)
        if sha256_bytes(bounded_file(root / path, 4 * 1024**2)) != digest:
            raise ValueError("Frozen treatment bytes changed: " + path)
    for prefix in ("implementation", "rules", "registries", "groups"):
        expected = {p for p in pins if p.startswith(prefix + "/")}
        actual = {p.relative_to(root).as_posix() for p in (root / prefix).rglob("*") if p.is_file()}
        if actual != expected:
            raise ValueError("Frozen treatment membership changed: " + prefix)


def invoke(
    argv: list[str], directory: Path, environment: dict[str, str], *, native_pair: bool = False
) -> ProcessCapture:
    directory.mkdir(parents=True, exist_ok=False)
    save(directory / "command.json", {"argv": argv})
    name = argv[argv.index("--name") + 1]
    try:
        capture = run_bounded_process(
            argv,
            cwd=directory,
            environment=environment,
            timeout_seconds=120,
            max_stdout_bytes=4 * 1024**2 if native_pair else 2 * 1024**2,
            max_stderr_bytes=4 * 1024**2 if native_pair else 1024**2,
            monitored_files=(directory.parent / "native.json", directory.parent / "native.sarif")
            if native_pair
            else (),
            max_generated_bytes=8 * 1024**2 if native_pair else None,
        )
        save_capture(directory, capture)
    except BaseException as exc:
        save(directory / "failure.json", {"type": type(exc).__name__})
        raise
    finally:
        cleanup = run_capture(
            [argv[0], "rm", "--force", name], directory / "cleanup", environment, timeout=15
        )
        if not cleanup_ok(cleanup):
            raise ValueError("Container cleanup not confirmed")
    return capture


def cleanup_ok(capture: ProcessCapture) -> bool:
    return capture_ok(capture, {0}) or (
        capture_ok(capture, {1}) and b"no such container" in capture.stderr.lower()
    )


def stage_argv(
    root: Path,
    docker: Path,
    name: str,
    group: str,
    role: Role,
    key: str,
    selection: BaselineSelection,
) -> list[str]:
    if selection.scope is None:
        raise ValueError("No eligible source group")
    target = root / f"groups/{group}/selected"
    if role == "agent-audit":
        if selection.agent_blockers:
            raise ValueError("Agent Audit group refused by input policy")
        tool = load_toml_config(root / "tool.toml", AgentAuditToolConfig).value
        return build_agent_argv(docker=docker, tool=tool, profile=LIMITS, name=name, target=target)
    return build_research_argv(
        docker=docker,
        name=name,
        profile_bytes=bounded_file(root / "profile.json", 1024**2),
        scope=selection.scope,
        role=role,
        rules=root / "rules",
        target=target,
        output=root / key,
    )


def native_observation(
    root: Path, row: dict[str, Any], selection: BaselineSelection, capture: ProcessCapture
) -> tuple[dict[str, Any], SemgrepPassEvidence | None]:
    directory = root / row["key"]
    if selection.scope is None:
        raise ValueError("Cannot interpret native evidence without an eligible selection")
    if row["role"] == "agent-audit":
        if selection.agent_blockers or not capture_ok(capture, {0, 1}):
            raise ValueError("Agent Audit policy or process failed")
        parsed = parse_agent_audit_json(capture.stdout)
        normalized = normalize_agent_audit(
            parsed,
            inputs=[c.checked_input() for c in selection.checks],
            run_id="authored-baseline",
            execution_id=row["key"],
            target_snapshot_id=selection.scope.target_snapshot_id,
        )
        files: dict[str, Any] = {}
        for check in selection.checks:
            path = check.artifact.source.path
            findings = [
                {
                    "rule_id": f.rule.native_id,
                    "message": f.message.model_dump(mode="json"),
                    "location": f.locations[0].model_dump(mode="json"),
                }
                for f in normalized.findings
                if f.locations[0].artifact_path == path
            ]
            files[path] = {
                "state": "native-per-file-completion-not-observable",
                "findings": findings,
            }
        return {
            "files": files,
            "finding_records": len(normalized.findings),
            "native_scanned_files": parsed.document.scanned_files,
            "selected_files": len(selection.checks),
            "native": native_projection(capture.stdout),
            "native_stderr_present": bool(capture.stderr),
            "analysis_completeness": "not-established",
            "unknown_native_fields": list(parsed.unknown_field_paths),
        }, None
    evidence = reconcile_semgrep_pass(
        profile_bytes=bounded_file(root / "profile.json", 1024**2),
        scope=selection.scope,
        execution_id=row["key"],
        role=row["role"],
        native_json=bounded_file(directory / "native.json", 4 * 1024**2),
        native_sarif=bounded_file(directory / "native.sarif", 4 * 1024**2),
        allow_policy_directory_skips=True,
    )
    assessment = assess_research_execution(capture, cleanup_succeeded=True, evidence=evidence)
    if assessment.analysis_state == "failed":
        raise ValueError("Semgrep execution failed; retain native evidence, do not score")
    projection = evidence.model_dump(
        mode="json", exclude={"execution_id", "native_json_sha256", "native_sarif_sha256"}
    )
    return {
        "evidence": projection,
        "files": {
            f.path: {
                "state": f.state,
                "native_reason": f.native_reason,
                "findings": [
                    h.model_dump(mode="json") for h in evidence.findings if h.anchor.path == f.path
                ],
            }
            for f in evidence.files
        },
        "finding_records": len(evidence.findings),
        "assessment": assessment.model_dump(mode="json"),
    }, evidence


def run_baselines(
    project: Path,
    output: Path,
    *,
    custom_run: Path,
    rule_source: Path,
    repetitions: int = 2,
    docker: Path | None = None,
) -> dict[str, Any]:
    project = plain_path(project, directory=True)
    output = output.absolute()
    if output == project / "workspace" or not output.is_relative_to(project / "workspace"):
        raise ValueError("Attempt must be a new ignored workspace child")
    plain_path(output.parent, directory=True)
    if output.exists():
        raise ValueError("Attempt exists; never overwrite or silently resume")
    rows = planned_rows(repetitions)
    prepared = prepare_shared(project)
    requests = group_requests(prepared)
    profile_raw = bounded_file(project / PROFILE_PATH, 1024**2)
    if sha256_bytes(profile_raw) != PROFILE_SHA:
        raise ValueError("Candidate rules profile changed")
    profile = load_research_profile(profile_raw)
    rules = {
        r.source_path: bounded_file(rule_source / r.source_path, 256 * 1024) for r in profile.rules
    }
    license_raw = bounded_file(rule_source / "LICENSE", 256 * 1024)
    verify_rule_bytes(profile, rules, license_bytes=license_raw)
    reference = custom_reference(custom_run, prepared.inputs)
    executable = resolve_docker(docker)
    if executable is None:
        raise ValueError("Docker required; no host fallback")
    tool = load_toml_config(project / "configs/tools/agent-audit.toml", AgentAuditToolConfig)
    frozen = {
        **{"implementation/" + p: raw for p, raw in prepared.sources.items()},
        **{"registries/" + p: raw for p, raw in prepared.registries.items()},
        **{"rules/" + p: raw for p, raw in rules.items()},
        "rules/LICENSE": license_raw,
        "profile.json": profile_raw,
        "tool.toml": tool.raw,
    }
    for group, request in requests.items():
        frozen[f"groups/{group}/request.json"] = request.model_dump_json().encode()
        for path in request.selected:
            frozen[f"groups/{group}/full/{path}"] = prepared.inputs[path]
    output.mkdir()
    result: dict[str, Any] = {
        "contract": "authored-baseline-execution-v1",
        "split": "development-only",
        "repetitions": repetitions,
        "rows": rows,
        "finished": False,
        "error": None,
        "execution_root": str(output),
        "limits": LIMITS.model_dump(mode="json"),
        "target_execution": False,
        "unique_vulnerabilities": None,
        "approval": "Student-approved controlled-group treatment, 2026-10-22",
    }
    started = time.perf_counter_ns()
    pins: dict[str, str] = {}
    try:
        for path, raw in frozen.items():
            atomic_write_bytes(output / path, raw)
        save(output / "custom-reference.json", reference)
        frozen["custom-reference.json"] = (output / "custom-reference.json").read_bytes()
        pins = frozen_hashes(frozen)
        save(output / "freeze.json", pins)
        save(output / "result.json", result)
        environment = minimal_environment(output / "runtime")
        for index, image in enumerate(
            (tool.value.validator_image, tool.value.image, profile.image)
        ):
            capture = run_capture(
                [str(executable), "image", "inspect", image],
                output / f"preflight/{index}",
                environment,
                timeout=30,
            )
            check_image(capture, image)
        selections = {}
        for group, request in requests.items():
            verify_frozen(output, pins)
            base = output / f"groups/{group}"
            argv = build_agent_argv(
                docker=executable,
                tool=tool.value,
                profile=LIMITS,
                name="baseline-syntax-" + uuid.uuid4().hex,
                target=base / "full",
                worker_source=output / "implementation/src",
                request=base / "request.json",
            )
            capture = invoke(argv, output / f"validation/{group}", environment)
            if not capture_ok(capture, {0}) or capture.stderr:
                raise ValueError("Isolated syntax validation failed")
            report = AgentInputReport.model_validate(
                load_agent_json(capture.stdout, max_bytes=2 * 1024**2)
            )
            selection = select_baseline(request, frozen[f"groups/{group}/request.json"], report)
            selections[group] = selection
            save(base / "selection.json", selection.record())
            frozen[f"groups/{group}/selection.json"] = (base / "selection.json").read_bytes()
            for check in selection.checks:
                path = check.artifact.source.path
                key = f"groups/{group}/selected/{path}"
                atomic_write_bytes(output / key, prepared.inputs[path])
                frozen[key] = prepared.inputs[path]
            pins = frozen_hashes(frozen)
            save(output / "freeze.json", pins)
        for row in rows:
            selection = selections[row["group"]]
            blockers = ["no-eligible-inputs"] if selection.scope is None else []
            if row["role"] == "agent-audit":
                blockers.extend(selection.agent_blockers)
            if blockers:
                row.update(state="refused", reasons=sorted(set(blockers)))
                save(output / "result.json", result)
                continue
            verify_frozen(output, pins)
            directory = output / row["key"]
            directory.mkdir(parents=True)
            argv = stage_argv(
                output,
                executable,
                "baseline-" + uuid.uuid4().hex,
                row["group"],
                row["role"],
                row["key"],
                selection,
            )
            row["state"] = "failed"
            capture = invoke(
                argv, directory / "process", environment, native_pair=row["role"] != "agent-audit"
            )
            if row["role"] == "agent-audit":
                atomic_write_bytes(directory / "native.json", capture.stdout)
            projection, evidence = native_observation(output, row, selection, capture)
            save(directory / "observation.json", projection)
            if evidence:
                save(directory / "evidence.json", evidence.model_dump(mode="json"))
            row.update(
                state="observed",
                finding_records=projection["finding_records"],
                duration_ns=capture.duration_ns,
                semantic_sha256=semantic_hash(cast(JsonValue, projection)),
            )
            save(output / "result.json", result)
            print(f"{row['key']}: {row['finding_records']} native reports", flush=True)
        verify_frozen(output, pins)
        result["finished"] = True
    except BaseException as exc:
        result["error"] = {"type": type(exc).__name__, "message": str(exc)[:1000]}
        raise
    finally:
        result["duration_ns"] = time.perf_counter_ns() - started
        result["repeatability"] = repeatability(rows)
        save(output / "result.json", result)
        save(output / "evidence-manifest.json", {"files": evidence_records(output)})
    return verify_baselines(output)


def check_image(capture: ProcessCapture, image: str) -> None:
    if not capture_ok(capture, {0}) or list(capture.argv[1:]) != ["image", "inspect", image]:
        raise ValueError("Pinned image inspect failed")
    images = json.loads(capture.stdout)
    if (
        len(images) != 1
        or images[0].get("Os") != "linux"
        or not (images[0].get("Id") == image or image in images[0].get("RepoDigests", []))
    ):
        raise ValueError("Wrong pinned Linux image; no pull or fallback")


def portable(argv: list[str], root: str) -> list[str]:
    result = list(argv)
    result[0] = "docker"
    for index, part in enumerate(result):
        if part == "--name":
            result[index + 1] = "container-name"
        elif part == "--mount":
            mount = result[index + 1].replace("\\", "/")
            prefix = "type=bind,source=" + root.replace("\\", "/").rstrip("/") + "/"
            if not mount.startswith(prefix):
                raise ValueError("Unexpected external mount in retained invocation")
            result[index + 1] = "type=bind,source=ROOT/" + mount.removeprefix(prefix)
    return result


def verify_baselines(root: Path) -> dict[str, Any]:
    """Replay native parsing and eligibility without Docker or scanner execution."""
    retained = read_retained_research(root)
    result = json.loads(retained.read("result.json"))
    if (
        result.get("contract") != "authored-baseline-execution-v1"
        or result.get("finished") is not True
        or result.get("error") is not None
        or result.get("target_execution") is not False
        or result.get("unique_vulnerabilities") is not None
        or result.get("limits") != LIMITS.model_dump(mode="json")
    ):
        raise ValueError("Incomplete or incompatible baseline attempt")
    pins = json.loads(retained.read("freeze.json"))
    expected_pins = {
        path
        for path in retained.files
        if path.startswith(("implementation/", "rules/", "registries/", "groups/"))
        or path in {"tool.toml", "profile.json", "custom-reference.json"}
    }
    if set(pins) != expected_pins:
        raise ValueError("Frozen pin membership differs from required treatment files")
    verify_frozen(root, pins)
    if sha256_bytes(retained.read("profile.json")) != PROFILE_SHA:
        raise ValueError("Baseline profile pin differs")
    profile = load_research_profile(retained.read("profile.json"))
    verify_rule_bytes(
        profile,
        {r.source_path: retained.read("rules/" + r.source_path) for r in profile.rules},
        license_bytes=retained.read("rules/LICENSE"),
    )
    tool = load_toml_config(root / "tool.toml", AgentAuditToolConfig).value
    for index, image in enumerate((tool.validator_image, tool.image, profile.image)):
        check_image(_read_capture(retained.files, f"preflight/{index}"), image)
    selections = {}
    all_inputs: dict[str, bytes] = {}
    expected_inputs = {
        f"{f.key}/{c.id}.py": c.source.encode()
        for f in FAMILIES
        for c in read_registry(retained.read("registries/" + f.registry), f.key).cases
    }
    snapshot = authored_snapshot_id(expected_inputs)
    for family in FAMILIES:
        base = f"groups/{family.key}"
        raw = retained.read(base + "/request.json")
        request = AgentInputRequest.model_validate(load_agent_json(raw, max_bytes=256 * 1024))
        if (
            request.target_snapshot_id != snapshot
            or set(request.selected)
            != {p for p in expected_inputs if p.startswith(family.key + "/")}
            or set(request.selected) != {e.path for e in request.inventory}
            or set(request.selected.values()) != {"python-source"}
        ):
            raise ValueError("Registry grouping or snapshot identity differs")
        for entry in request.inventory:
            data = retained.read(base + "/full/" + entry.path)
            if sha256_bytes(data) != entry.sha256 or len(data) != entry.byte_length:
                raise ValueError("Group request source mismatch")
            all_inputs[entry.path] = data
        capture = _read_capture(retained.files, "validation/" + family.key)
        if not capture_ok(capture, {0}) or capture.stderr:
            raise ValueError("Invalid syntax validator capture")
        selection = select_baseline(
            request,
            raw,
            AgentInputReport.model_validate(load_agent_json(capture.stdout, max_bytes=2 * 1024**2)),
        )
        if selection.record() != json.loads(retained.read(base + "/selection.json")):
            raise ValueError("Selection differs from isolated validation")
        for check in selection.checks:
            path = check.artifact.source.path
            if retained.read(base + "/selected/" + path) != all_inputs[path]:
                raise ValueError("Selected baseline source differs")
        expected = build_agent_argv(
            docker=root / "result.json",
            tool=tool,
            profile=LIMITS,
            name="verify-syntax",
            target=root / base / "full",
            worker_source=root / "implementation/src",
            request=root / base / "request.json",
        )
        verify_invocation(
            retained.files,
            "validation/" + family.key,
            capture,
            expected,
            result["execution_root"],
            root,
        )
        selections[family.key] = selection
    # Source membership comes from pinned registries, never from scanner findings.
    if all_inputs != expected_inputs:
        raise ValueError("Baseline group union differs from authored cases")
    reference = json.loads(retained.read("custom-reference.json"))
    if (
        reference.get("snapshot_id") != snapshot
        or reference.get("catalog_pins") != {f.key: f.catalog_sha256 for f in FAMILIES}
        or set(reference.get("observations", {})) != set(expected_inputs)
        or any(
            set(record) != {f.key for f in FAMILIES}
            for record in reference["observations"].values()
        )
    ):
        raise ValueError("Custom reference scope or catalogs differ")
    expected_rows = planned_rows(result["repetitions"])
    rows = result["rows"]
    if len(rows) != len(expected_rows):
        raise ValueError("Baseline schedule length differs")
    observations = {}
    pair: dict[tuple[int, str], list[SemgrepPassEvidence]] = {}
    for row, expected_row in zip(rows, expected_rows, strict=True):
        if any(row[k] != expected_row[k] for k in ("key", "group", "role", "repetition")):
            raise ValueError("Baseline schedule differs")
        selection = selections[row["group"]]
        blockers = ["no-eligible-inputs"] if selection.scope is None else []
        if row["role"] == "agent-audit":
            blockers.extend(selection.agent_blockers)
        if blockers:
            expected_row.update(state="refused", reasons=sorted(set(blockers)))
            if row != expected_row or any(p.startswith(row["key"] + "/") for p in retained.files):
                raise ValueError("Refused stage has observations or unexpected native execution")
            continue
        capture = _read_capture(retained.files, row["key"] + "/process")
        expected_argv = stage_argv(
            root,
            root / "result.json",
            "verify-stage",
            row["group"],
            row["role"],
            row["key"],
            selection,
        )
        verify_invocation(
            retained.files,
            row["key"] + "/process",
            capture,
            expected_argv,
            result["execution_root"],
            root,
        )
        projection, evidence = native_observation(root, row, selection, capture)
        if projection != json.loads(retained.read(row["key"] + "/observation.json")):
            raise ValueError("Projection differs from retained native evidence")
        if (
            row["role"] == "agent-audit"
            and retained.read(row["key"] + "/native.json") != capture.stdout
        ):
            raise ValueError("Agent native report differs from captured stdout")
        expected_row.update(
            state="observed",
            finding_records=projection["finding_records"],
            duration_ns=capture.duration_ns,
            semantic_sha256=semantic_hash(cast(JsonValue, projection)),
        )
        if row != expected_row:
            raise ValueError("Baseline summary differs from raw results")
        if evidence:
            pair.setdefault((row["repetition"], row["group"]), []).append(evidence)
        observations[row["key"]] = projection
    for paired_evidence in pair.values():
        if len(paired_evidence) != 2:
            raise ValueError("Missing paired Semgrep views")
        build_dual_view(*paired_evidence)
    if result["repeatability"] != repeatability(rows):
        raise ValueError("Repeatability summary differs")
    return {
        "contract": "authored-baseline-validation-v1",
        "passed": True,
        "manifest_sha256": retained.manifest_sha256,
        "authored_files": len(all_inputs),
        "eligible_files": sum(len(s.checks) for s in selections.values()),
        "excluded": [e for s in selections.values() for e in s.exclusions],
        "rows": rows,
        "repeatability": repeatability(rows),
        "observations": observations,
        "limitations": [
            "Authored grouped development inputs, not independent public evaluation.",
            "Agent Audit sees one registry; repository sharding equivalence is unestablished.",
            "Rule reports are not unique vulnerabilities; no accuracy or superiority score.",
            "Original custom evidence is referenced, not rerun; baseline repetitions are fresh.",
            "Agent Audit per-file completion is unobservable; refusals are not clean results.",
            "Timers are engineering receipts, not a controlled performance comparison.",
        ],
    }


def verify_invocation(
    files: dict[str, bytes],
    key: str,
    capture: ProcessCapture,
    expected: list[str],
    execution_root: str,
    root: Path,
) -> None:
    if portable(list(capture.argv), execution_root) != portable(expected, str(root.absolute())):
        raise ValueError("Retained execution isolation or command differs")
    cleanup = _read_capture(files, key + "/cleanup")
    argv = list(capture.argv)
    name = argv[argv.index("--name") + 1]
    if list(cleanup.argv) != [argv[0], "rm", "--force", name] or not cleanup_ok(cleanup):
        raise ValueError("Cleanup capture is invalid")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("run", "verify"))
    parser.add_argument("--project", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--custom-run", type=Path)
    parser.add_argument("--rule-source", type=Path)
    parser.add_argument("--repetitions", type=int, default=2)
    args = parser.parse_args()
    if args.mode == "run":
        if args.custom_run is None or args.rule_source is None:
            parser.error("run requires --custom-run and --rule-source")
        result = run_baselines(
            args.project,
            args.output,
            custom_run=args.custom_run,
            rule_source=args.rule_source,
            repetitions=args.repetitions,
        )
    else:
        result = verify_baselines(args.output)
    print(json.dumps({k: v for k, v in result.items() if k != "observations"}, indent=2))


if __name__ == "__main__":
    main()
