from __future__ import annotations

import csv
import dataclasses
import io
import json
import os
import platform
import time
from pathlib import Path
from typing import Any, Literal, cast

from jsonschema import Draft7Validator
from pydantic import JsonValue

from agentsec_evidence.adapters.agent_audit import normalize_agent_audit, parse_agent_audit_json
from agentsec_evidence.agents.execution import AgentAuditToolConfig, build_agent_argv
from agentsec_evidence.agents.records import AgentInputReport
from agentsec_evidence.agents.semantics import native_projection
from agentsec_evidence.agents.view_validation import assess_agent_view_report
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes, sha256_file
from agentsec_evidence.core.io import atomic_write_bytes, atomic_write_jsonl, atomic_write_model
from agentsec_evidence.dependencies.analysis import dependency_semantic_hash
from agentsec_evidence.dependencies.pipeline import run_dependency_scan
from agentsec_evidence.execution.config import ExecutionProfile, load_toml_config
from agentsec_evidence.execution.docker import portable_docker_argv
from agentsec_evidence.execution.process import ProcessCapture, run_bounded_process
from agentsec_evidence.exports.sarif import build_sarif
from agentsec_evidence.models.contracts import ExecutionOutcome
from agentsec_evidence.orchestration.shared import (
    cleanup_container,
    make_execution,
    minimal_environment,
    resolve_docker,
)
from agentsec_evidence.pilot.inputs import (
    ADMISSION_PATH,
    LIMITS_PATH,
    PLAN_PATH,
    TOOL_PATH,
    load_plan,
    prepare_pilot_inputs,
)
from agentsec_evidence.pilot.models import PilotRow, PilotStage, planned_rows, repeatability
from agentsec_evidence.reporting.dependency import load_dependency_run, summarize_dependency
from agentsec_evidence.reporting.service import require_new_derivative, write_common_report
from agentsec_evidence.research.execution import assess_research_execution, build_research_argv
from agentsec_evidence.research.inputs import assess_research_syntax
from agentsec_evidence.research.models import load_research_profile, verify_rule_bytes
from agentsec_evidence.research.retained import bounded_file, plain_path
from agentsec_evidence.research.semgrep import (
    build_dual_view,
    directory_skip_context,
    reconcile_semgrep_pass,
)


def save(path: Path, value: Any) -> None:
    atomic_write_bytes(
        path, (json.dumps(value, indent=2, sort_keys=True, default=str) + "\n").encode()
    )


def load(path: Path, limit: int = 4 * 1024 * 1024) -> Any:
    return json.loads(bounded_file(path, limit))


def invoke(
    argv: list[str],
    directory: Path,
    *,
    project: Path,
    docker: Path,
    name: str,
    environment: dict[str, str],
    native_pair: bool = False,
) -> tuple[ProcessCapture, bool]:
    directory.mkdir(exist_ok=False)
    save(directory / "command.json", {"argv": argv, "target_execution": False})
    try:
        capture = run_bounded_process(
            argv,
            cwd=project,
            environment=environment,
            timeout_seconds=120,
            max_stdout_bytes=4 * 1024 * 1024 if native_pair else 2 * 1024 * 1024,
            max_stderr_bytes=4 * 1024 * 1024 if native_pair else 1024 * 1024,
            monitored_files=(directory.parent / "native.json", directory.parent / "native.sarif")
            if native_pair
            else (),
            max_generated_bytes=8 * 1024 * 1024 if native_pair else None,
        )
        atomic_write_bytes(directory / "stdout.bin", capture.stdout)
        atomic_write_bytes(directory / "stderr.bin", capture.stderr)
        record = dataclasses.asdict(capture)
        del record["stdout"], record["stderr"]
        save(directory / "process.json", record)
    except BaseException as exc:
        save(directory / "launch-or-capture-failure.json", {"type": type(exc).__name__})
        raise
    finally:
        try:
            cleaned = cleanup_container(
                docker=docker, container_name=name, cwd=project, environment=environment
            )
        except OSError:
            cleaned = False
        save(directory / "cleanup.json", {"succeeded": cleaned})
    return capture, cleaned


def ready_capture(capture: ProcessCapture, cleaned: bool, exits: set[int]) -> bool:
    return (
        capture.exit_code in exits
        and cleaned
        and not capture.timed_out
        and not capture.output_limited
        and not capture.stdout_truncated
        and not capture.stderr_truncated
    )


def table_bytes(rows: list[PilotRow]) -> bytes:
    columns = list(PilotRow.model_fields)
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        value = row.model_dump(mode="json")
        writer.writerow(
            {
                key: "unknown"
                if item is None
                else json.dumps(item)
                if isinstance(item, list)
                else item
                for key, item in value.items()
            }
        )
    return buffer.getvalue().encode()


def write_table(path: Path, rows: list[PilotRow]) -> None:
    atomic_write_bytes(path, table_bytes(rows))


def evidence_records(root: Path) -> list[dict[str, Any]]:
    records = []
    for directory, dirs, names in os.walk(root):
        if Path(directory) == root:
            dirs[:] = [name for name in dirs if name != "runtime"]
        for name in dirs:
            plain_path(Path(directory) / name, directory=True)
        for name in sorted(names):
            path = Path(directory) / name
            if path == root / "evidence-manifest.json":
                continue
            plain_path(path, directory=False)
            records.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
    return sorted(records, key=lambda r: r["path"])


def seal_attempt(root: Path) -> None:
    save(
        root / "evidence-manifest.json",
        {"contract": "source-pilot-evidence-v1", "files": evidence_records(root)},
    )


def run_source_pilot(
    *,
    project: Path,
    cache: Path,
    rule_source: Path,
    database: Path,
    output: Path,
    docker: Path | None = None,
) -> dict[str, Any]:
    project = plain_path(project, directory=True)
    output = require_new_derivative(output, [cache, rule_source, database.parent])
    if output == project / "workspace" or not output.is_relative_to(project / "workspace"):
        raise ValueError("Pilot output must be a fresh ignored workspace child")
    plain_path(output.parent, directory=True)
    plan = load_plan(project)
    executable = resolve_docker(docker)
    if executable is None:
        raise ValueError("Pinned local Docker required; no fallback or download")
    output.mkdir(exist_ok=False)
    rows = planned_rows()
    result: dict[str, Any] = {
        "contract": "same-repository-pilot-report-v1",
        "plan_sha256": sha256_file(project / PLAN_PATH),
        "repository": plan.repository,
        "revision": plan.revision,
        "content_sha256": plan.content_sha256,
        "split": plan.split,
        "instrument_finished": False,
        "input_unchanged": None,
        "vulnerability_total": None,
        "target_execution": False,
        "repetition_wall_ns": [],
        "manual_recovery_actions_during_attempt": 0,
        "manual_preparation_and_adjudication_time_ns": None,
        "coverage": [
            {
                "surface": "repository inventory",
                "state": "observed",
                "files": 47,
                "evidence": "preparation/artifact-inventory.json",
            },
            {
                "surface": "Python source",
                "state": "bounded-static-treatment",
                "files": 26,
                "per_file_detection_completeness": "unknown",
                "evidence": "semgrep-input-plan.json",
            },
            {
                "surface": "dependency lockfile",
                "state": "supported-inventory-and-matching",
                "eligible_pypi_name_version_identities": 159,
                "local_roots_separate": 1,
                "per_package_matching_completion": "unknown",
            },
            {"surface": "Dockerfile", "state": "observed-unsupported", "execution": "not-run"},
            {
                "surface": "langgraph.json",
                "state": "observed-unsupported",
                "interpretation": "Not treated as MCP configuration",
            },
            {
                "surface": "prompts",
                "state": "no-dedicated-treatment",
                "interpretation": "Python file selection is not prompt-injection coverage",
            },
            {
                "surface": "MCP configurations and skill files",
                "state": "no-filename-candidate-recognized",
                "execution": "not-run",
                "interpretation": "No absence or safety claim",
            },
            {
                "surface": "memory/identity/permissions",
                "state": "unknown",
                "interpretation": "No current inventory recognizer or dedicated treatment",
            },
            {
                "surface": "agent communication",
                "state": "not-assessed",
                "interpretation": "No dedicated treatment or completeness claim",
            },
            {"surface": "runtime exploitability", "state": "outside-static-study-treatment"},
        ],
        "limitations": [
            "One formative pilot; no complete vulnerability oracle or accuracy estimate.",
            "C1 reuses C0 conventional observations and adds Agent Audit. "
            "Paired OSV paths are not additive vulnerabilities.",
            "Agent Audit per-file completion and LangGraph-specific coverage remain unknown.",
            "Both Semgrep views disable implicit Git filtering; policy view is not repository CI.",
            "Prompt, skill, memory, permission and runtime coverage is not inferred "
            "from Python acceptance.",
            "Dockerfile is present but unsupported; KICS is not run on this pilot.",
            "Host cache is uncontrolled. Timings do not establish performance superiority.",
            "The pilot envelope is separate from existing common-report source contracts.",
        ],
    }
    current: tuple[int, str] | None = None
    started = time.monotonic_ns()
    dependency_bundles: list[Path] = []
    try:
        inputs = prepare_pilot_inputs(
            project, output, cache=cache, rule_source=rule_source, database=database
        )
        tool = load_toml_config(project / TOOL_PATH, AgentAuditToolConfig)
        limits = load_toml_config(project / LIMITS_PATH, ExecutionProfile)
        profile_bytes = inputs.semgrep.profile_bytes
        profile = load_research_profile(profile_bytes)
        environment = minimal_environment(output / "runtime")
        code = []
        for path in sorted((project / "src").rglob("*.py")):
            relative = path.relative_to(project).as_posix()
            raw = path.read_bytes()
            atomic_write_bytes(output / "trusted-source" / relative, raw)
            code.append({"path": relative, "sha256": sha256_bytes(raw)})
        save(
            output / "host.json",
            {"platform": platform.platform(), "python": platform.python_version()},
        )
        dependency_tools = load(project / "configs/dependency/tools.json")
        for index, image in enumerate(
            (
                profile.image,
                tool.value.image,
                tool.value.validator_image,
                dependency_tools["syft"]["image"],
                dependency_tools["osv"]["image"],
            )
        ):
            capture = run_bounded_process(
                [str(executable), "image", "inspect", image],
                cwd=project,
                environment=environment,
                timeout_seconds=30,
                max_stdout_bytes=1024 * 1024,
                max_stderr_bytes=1024 * 1024,
            )
            atomic_write_bytes(output / "images" / f"{index}.stdout.bin", capture.stdout)
            atomic_write_bytes(output / "images" / f"{index}.stderr.bin", capture.stderr)
            if not ready_capture(capture, True, {0}):
                raise ValueError("Required pinned image unavailable; never pull automatically")
        freeze = {
            "plan_sha256": result["plan_sha256"],
            "source_content_sha256": plan.content_sha256,
            "code": code,
            "pins": plan.pins,
            "database_sha256": plan.database_sha256,
            "views": {
                "semgrep": semantic_hash(inputs.semgrep_view.model_dump(mode="json")),
                "agent": semantic_hash(inputs.agent_view.model_dump(mode="json")),
            },
            "timing": "Preparation/image checks/freeze outside repetition wall; "
            "repetitions include validation, tools, capture, normalization and replay guards",
            "retry": "No retries/resume. New output root for a separately retained attempt.",
            "input_records": evidence_records(output),
        }
        save(output / "freeze.json", freeze)
        result["freeze_sha256"] = sha256_file(output / "freeze.json")

        def guard() -> None:
            if (
                load_plan(project) != plan
                or sha256_file(project / PLAN_PATH) != result["plan_sha256"]
            ):
                raise ValueError("Pilot plan changed during execution")
            if {p.relative_to(project).as_posix() for p in (project / "src").rglob("*.py")} != {
                entry["path"] for entry in code
            }:
                raise ValueError("Trusted source file set changed")
            for entry in code:
                if (
                    sha256_file(project / entry["path"]) != entry["sha256"]
                    or sha256_file(output / "trusted-source" / entry["path"]) != entry["sha256"]
                ):
                    raise ValueError("Trusted runner or worker source changed")
            for entry in freeze["input_records"]:
                if sha256_file(output / entry["path"]) != entry["sha256"]:
                    raise ValueError("Frozen input or preparation receipt changed")
            verify = load_research_profile(profile_bytes)
            verify_rule_bytes(
                verify,
                {
                    r.source_path: bounded_file(output / "rules" / r.source_path, 256 * 1024)
                    for r in verify.rules
                },
                license_bytes=bounded_file(output / "rules/LICENSE", 256 * 1024),
            )
            inputs.replay()

        def set_row(row: PilotRow) -> None:
            index = next(
                i
                for i, old in enumerate(rows)
                if (old.repetition, old.stage) == (row.repetition, row.stage)
            )
            rows[index] = row
            save(output / "progress.json", [r.model_dump(mode="json") for r in rows])

        for repetition in range(1, 4):
            tick = time.monotonic_ns()
            cell = output / f"repetition-{repetition}"
            cell.mkdir()
            guard()
            name = "pilot-syntax-" + semantic_hash({"cell": str(cell)})[:20]
            argv = build_agent_argv(
                docker=executable,
                tool=tool.value,
                profile=limits.value,
                name=name,
                target=output / "agent-view/target",
                worker_source=output / "trusted-source/src",
                request=output / "request.json",
            )
            worker, cleaned = invoke(
                argv,
                cell / "syntax",
                project=project,
                docker=executable,
                name=name,
                environment=environment,
            )
            if not ready_capture(worker, cleaned, {0}) or worker.stderr:
                raise ValueError("Syntax worker failed; no scanner authorized")
            assessment = assess_agent_view_report(
                inputs.agent, inputs.agent_view, inputs.request, worker.stdout
            )
            atomic_write_model(cell / "input-assessment.json", assessment)
            if not assessment.input_gate_passed or not assess_research_syntax(
                inputs.request, (output / "request.json").read_bytes(), worker.stdout
            ):
                for row in list(rows):
                    if row.repetition == repetition:
                        set_row(
                            PilotRow(
                                **{
                                    **row.model_dump(),
                                    "state": "refused",
                                    "reasons": ("input-gate-refused",),
                                    "evidence": (f"repetition-{repetition}/input-assessment.json",),
                                }
                            )
                        )
                raise ValueError("Input policy/syntax refused; scanners not launched")
            checks = AgentInputReport.model_validate_json(worker.stdout).checks
            pair = []
            for role in ("research", "repository-policy"):
                stage: PilotStage = "semgrep-research" if role == "research" else "semgrep-policy"
                current = repetition, stage
                native = cell / stage
                # Mount output must exist; capture receipts use a separate new directory.
                native.mkdir()
                name = "pilot-semgrep-" + semantic_hash({"path": str(native)})[:20]
                assert inputs.preparation.scope is not None
                argv = build_research_argv(
                    docker=executable,
                    name=name,
                    profile_bytes=profile_bytes,
                    scope=inputs.preparation.scope,
                    role=role,
                    rules=output / "rules",
                    target=output / "semgrep-view/target",
                    output=native,
                )
                guard()
                capture, cleaned = invoke(
                    argv,
                    native / "capture",
                    project=project,
                    docker=executable,
                    name=name,
                    environment=environment,
                    native_pair=True,
                )
                evidence = reconcile_semgrep_pass(
                    profile_bytes=profile_bytes,
                    scope=inputs.preparation.scope,
                    execution_id=name,
                    role=role,
                    native_json=bounded_file(native / "native.json", 4 * 1024 * 1024),
                    native_sarif=bounded_file(native / "native.sarif", 4 * 1024 * 1024),
                    allow_policy_directory_skips=True,
                )
                save(
                    native / "directory-skips.json",
                    directory_skip_context(
                        inputs.preparation.scope, bounded_file(native / "native.json", 4 * 1024**2)
                    ),
                )
                Draft7Validator(
                    load(project / "schemas/vendor/oasis/sarif-schema-2.1.0.json")
                ).validate(load(native / "native.sarif"))
                execution = assess_research_execution(
                    capture, cleanup_succeeded=cleaned, evidence=evidence
                )
                atomic_write_model(native / "evidence.json", evidence)
                atomic_write_model(native / "assessment.json", execution)
                projection: JsonValue = {
                    "directory_skips": load(native / "directory-skips.json"),
                    "evidence": evidence.model_dump(
                        mode="json",
                        exclude={"execution_id", "native_json_sha256", "native_sarif_sha256"},
                    ),
                    "assessment": execution.model_dump(mode="json"),
                    "exit_code": capture.exit_code,
                }
                save(native / "semantic.json", projection)
                set_row(
                    PilotRow(
                        repetition=repetition,
                        stage=stage,
                        state="failed" if execution.analysis_state == "failed" else "partial",
                        finding_records=len(evidence.findings),
                        unit="native-rule-reports",
                        duration_ns=capture.duration_ns,
                        exit_code=capture.exit_code,
                        semantic_sha256=semantic_hash(projection),
                        evidence=(
                            f"repetition-{repetition}/{stage}/evidence.json",
                            f"repetition-{repetition}/{stage}/native.json",
                            f"repetition-{repetition}/{stage}/native.sarif",
                        ),
                        reasons=execution.reasons or ("rule-by-file-completion-not-established",),
                    )
                )
                pair.append(evidence)
                guard()
                if execution.analysis_state == "failed":
                    raise ValueError("Semgrep execution failed; attempt retained, no silent retry")
            atomic_write_model(cell / "dual-view.json", build_dual_view(*pair))
            current = repetition, "agent-audit"
            native = cell / "agent-audit"
            name = "pilot-agent-" + semantic_hash({"path": str(native)})[:20]
            argv = build_agent_argv(
                docker=executable,
                tool=tool.value,
                profile=limits.value,
                name=name,
                target=output / "agent-view/target",
            )
            guard()
            capture, cleaned = invoke(
                argv, native, project=project, docker=executable, name=name, environment=environment
            )
            atomic_write_bytes(native / "native.json", capture.stdout)
            parsed = parse_agent_audit_json(capture.stdout)
            run_id = "pilot-" + semantic_hash({"path": str(cell)})[:24]
            normalized = normalize_agent_audit(
                parsed,
                inputs=[c.checked_input() for c in checks],
                run_id=run_id,
                execution_id=name,
                target_snapshot_id=inputs.agent.inventory.snapshot.snapshot_id,
            )
            reasons = ["native-per-file-completion-not-observable"]
            if capture.stderr:
                reasons.append("native-stderr-retained-for-review")
            if parsed.document.scanned_files != 26:
                reasons.append("native-file-count-differs-from-selection")
            state: Literal["partial", "failed"] = (
                "partial" if ready_capture(capture, cleaned, {0, 1}) else "failed"
            )
            if state == "failed":
                reasons.append("process-or-cleanup-failed")
            atomic_write_jsonl(native / "findings.jsonl", normalized.findings)
            portable = portable_docker_argv(
                argv,
                docker_executable=executable,
                mount_replacements={output / "agent-view/target": "TARGET"},
            )
            execution_record = make_execution(
                execution_id=name,
                run_id=run_id,
                snapshot=inputs.agent.inventory.snapshot,
                tool=tool.value,
                profile=limits.value,
                config_sha256=result["freeze_sha256"],
                ruleset_sha256=semantic_hash(
                    {
                        "image": tool.value.image,
                        "selection": "builtin-rules/severity-info/static-only",
                    }
                ),
                portable_argv=list(portable),
                environment=environment,
                capture=capture,
                outcome=ExecutionOutcome.PARTIAL if state == "partial" else ExecutionOutcome.FAILED,
                native_byte_length=len(capture.stdout),
                cleanup_attempted=True,
                cleanup_succeeded=cleaned,
            )
            atomic_write_model(native / "execution.json", execution_record)
            sarif = build_sarif(normalized.findings, execution=execution_record)
            Draft7Validator(
                load(project / "schemas/vendor/oasis/sarif-schema-2.1.0.json")
            ).validate(sarif)
            save(native / "results.sarif", sarif)
            projection = {
                "native": native_projection(capture.stdout),
                "state": state,
                "reasons": cast(JsonValue, reasons),
                "exit_code": capture.exit_code,
            }
            save(native / "semantic.json", projection)
            set_row(
                PilotRow(
                    repetition=repetition,
                    stage="agent-audit",
                    state=state,
                    finding_records=len(normalized.findings),
                    unit="native-rule-reports",
                    duration_ns=capture.duration_ns,
                    exit_code=capture.exit_code,
                    semantic_sha256=semantic_hash(projection),
                    evidence=(
                        f"repetition-{repetition}/agent-audit/native.json",
                        f"repetition-{repetition}/agent-audit/findings.jsonl",
                        f"repetition-{repetition}/agent-audit/results.sarif",
                    ),
                    reasons=tuple(reasons),
                )
            )
            guard()
            if state == "failed":
                raise ValueError("Agent process failed; attempt retained")
            current = repetition, "osv-direct"
            dep = run_dependency_scan(
                project_root=project,
                workspace_root=cell / "dependencies",
                source=inputs.source,
                label="github:langchain-samples/cicd-pipeline-example",
                revision=plan.revision,
                database=inputs.database,
                database_sha256=plan.database_sha256,
                split="pilot",
                admission_file=project / ADMISSION_PATH,
            )
            bundle = Path(str(dep["bundle_root"]))
            dependency_bundles.append(bundle)
            dependency_run = load_dependency_run(bundle)
            summary = summarize_dependency(dependency_run)
            atomic_write_model(cell / "dependency-summary.json", summary)
            for stage in cast(tuple[PilotStage, ...], ("osv-direct", "syft", "osv-sbom")):
                observation = next(item for item in summary.stages if item.stage == stage)
                process = cast(dict[str, Any], dep["stages"]).get(stage, {})
                set_row(
                    PilotRow(
                        repetition=repetition,
                        stage=stage,
                        state=observation.state
                        if observation.state in {"complete", "partial", "failed"}
                        else "failed",
                        finding_records=observation.reported_match_occurrences
                        if stage != "syft"
                        else None,
                        package_identities=observation.identified_unique_packages,
                        unit="package-identities"
                        if stage == "syft"
                        else "package-advisory-occurrences",
                        duration_ns=process.get("duration_ns"),
                        exit_code=process.get("exit_code"),
                        semantic_sha256=dependency_semantic_hash(
                            [dependency_run.stages[stage]], dependency_run.scope
                        )
                        if dependency_run.scope and stage in dependency_run.stages
                        else None,
                        evidence=(
                            bundle.relative_to(output).as_posix() + "/manifest.json",
                            f"repetition-{repetition}/dependency-summary.json",
                        ),
                        reasons=("identity-projection-limits-retained",)
                        if stage == "syft"
                        else ("per-package-matching-not-observable",),
                    )
                )
            guard()
            result["repetition_wall_ns"].append(time.monotonic_ns() - tick)
            current = None
            print(
                f"Repetition {repetition}/3 retained; dependency pipeline {dep['state']}",
                flush=True,
            )
            if dep["state"] == "failed":
                raise ValueError("Dependency pipeline failed; no silent retry")
        write_common_report(
            project_root=project,
            bundles=dependency_bundles,
            output=output / "dependency-common-report",
        )
        guard()
        result["input_unchanged"] = True
        result["instrument_finished"] = True
    except BaseException as exc:
        result["failure"] = {
            "type": type(exc).__name__,
            "message": str(exc)[:1000],
            "cell": current,
        }
        if current:
            rows = [
                PilotRow(
                    **{
                        **row.model_dump(),
                        "state": "failed",
                        "reasons": (*row.reasons, "attempt-interrupted-see-receipts"),
                    }
                )
                if (row.repetition, row.stage) == current
                else row
                for row in rows
            ]
        raise
    finally:
        result["attempt_wall_ns"] = time.monotonic_ns() - started
        result["repeatability"] = repeatability(rows)
        result["rows"] = [row.model_dump(mode="json") for row in rows]
        save(output / "pilot-report.json", result)
        write_table(output / "comparison.csv", rows)
        seal_attempt(output)
    return result
