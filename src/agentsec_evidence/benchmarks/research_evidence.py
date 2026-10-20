"""Reopen controlled-case evidence before allowing a ledger cell to be reused."""

import tomllib
from pathlib import Path
from typing import Any, cast

from agentsec_evidence.agents.execution import AgentAuditToolConfig, build_agent_argv
from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.benchmarks.attempt_models import ResearchEvidence, ResearchPassRow
from agentsec_evidence.benchmarks.models import ResearchBenchmarkPlan, ResearchCell
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.execution.config import ExecutionProfile
from agentsec_evidence.reporting.research import load_research_source, read_research_capture
from agentsec_evidence.research.controlled import (
    EXECUTION_PATH,
    PROFILE_PATH,
    REGISTRY_PATH,
    VALIDATOR_PATH,
)
from agentsec_evidence.research.execution import build_research_argv
from agentsec_evidence.research.models import MAX_REPORT_BYTES
from agentsec_evidence.research.retained import bounded_file, plain_path, read_retained_research

RETAINED_PINS = {
    PROFILE_PATH: "profile.json",
    REGISTRY_PATH: "cases.json",
    EXECUTION_PATH: "execution-profile.toml",
    VALIDATOR_PATH: "validator-tool.toml",
}


def verify_research_attempt(
    project: Path, execution: Path, run_id: str, plan: ResearchBenchmarkPlan, cell: ResearchCell
) -> ResearchEvidence:
    """Verify original paths and frozen bytes; no scanner or target code is executed."""
    plain_path(project, directory=True)
    execution = plain_path(execution, directory=True)
    if {p.name for p in execution.iterdir()} != {"environment", "case"}:
        raise ValueError("Unexpected controlled execution entries")
    environment = plain_path(execution / "environment", directory=True)
    if {p.name for p in environment.iterdir()} != {"pyproject.toml", "uv.lock"}:
        raise ValueError("Unexpected controlled environment pins")
    retained = read_retained_research(execution / "case")
    frozen = {}
    for pin in plan.pins:
        if pin.path in RETAINED_PINS:
            path = RETAINED_PINS[pin.path]
            raw = retained.read(path)
            frozen[path] = {"path": path, "bytes": pin.bytes, "sha256": pin.sha256}
        else:
            raw = bounded_file(environment / pin.path, MAX_REPORT_BYTES)
        if len(raw) != pin.bytes or sha256_bytes(raw) != pin.sha256:
            raise ValueError("Controlled treatment or environment bytes differ from plan")
    for prefix, pins in (("rules/", plan.rule_files), ("worker-source/", plan.implementation)):
        expected_files = {}
        for pin in pins:
            path = prefix + (
                pin.path.removeprefix("src/") if prefix == "worker-source/" else pin.path
            )
            raw = retained.read(path)
            if len(raw) != pin.bytes or sha256_bytes(raw) != pin.sha256:
                raise ValueError("Controlled rule or worker bytes differ from plan")
            expected_files[path] = {"path": path, "bytes": pin.bytes, "sha256": pin.sha256}
        if {p for p in retained.files if p.startswith(prefix)} != set(expected_files):
            raise ValueError("Controlled rule or worker file set differs")
        frozen.update(expected_files)
    recorded = load_agent_json(retained.read("frozen-inputs.json"), max_bytes=MAX_REPORT_BYTES)
    if recorded != {"files": [frozen[p] for p in sorted(frozen)]}:
        raise ValueError("Frozen-input receipt differs from plan")
    if any(
        p not in frozen and p != "frozen-inputs.json" and not p.startswith(cell.case_id + "/")
        for p in retained.files
    ):
        raise ValueError("Unexpected controlled case or failed producer evidence")
    registry = cast(
        dict[str, Any], load_agent_json(retained.read("cases.json"), max_bytes=MAX_REPORT_BYTES)
    )
    cases = [c for c in registry["cases"] if c["id"] == cell.case_id]
    if (
        len(cases) != 1
        or semantic_hash(cases[0]) != cell.case_sha256
        or (2 if cases[0].get("repeat") is True else 1) != cell.internal_repetitions
    ):
        raise ValueError("Controlled case differs from the whole-case plan binding")
    case_root = retained.root / cell.case_id
    source, _ = load_research_source(case_root)
    if source.run_id != run_id:
        raise ValueError("Controlled run identity differs from retained manifest")
    summary = source.summary
    if summary.syntax_state != "not-run":
        process, cleaned = read_research_capture(retained, cell.case_id + "/syntax")
        docker = Path(process.argv[0])
        if docker.name.lower() not in {"docker", "docker.exe"}:
            raise ValueError("Controlled syntax command is not Docker")
        expected = build_agent_argv(
            docker=docker,
            tool=AgentAuditToolConfig.model_validate(
                tomllib.loads(retained.read("validator-tool.toml").decode())
            ),
            profile=ExecutionProfile.model_validate(
                tomllib.loads(retained.read("execution-profile.toml").decode())
            ),
            name="research-syntax-" + semantic_hash({"path": str(case_root)})[:20],
            target=case_root / "view/target",
            worker_source=retained.root / "worker-source",
            request=case_root / "request.json",
        )
        if list(process.argv) != expected or not cleaned:
            raise ValueError("Controlled syntax mounts, flags or cleanup differ")
    rows = []
    for row in summary.passes:
        process, cleaned = read_research_capture(retained, cell.case_id + "/" + row.key)
        docker = Path(process.argv[0])
        if docker.name.lower() not in {"docker", "docker.exe"} or summary.scope is None:
            raise ValueError("Controlled scanner command or selected scope differs")
        expected = build_research_argv(
            docker=docker,
            name="research-scan-" + semantic_hash({"path": str(case_root / row.key)})[:20],
            profile_bytes=retained.read("profile.json"),
            scope=summary.scope,
            role=row.evidence.role,
            rules=retained.root / "rules",
            target=case_root / "view/target",
            output=case_root / row.key,
        )
        if (
            list(process.argv) != expected
            or not cleaned
            or row.execution.analysis_state == "failed"
        ):
            raise ValueError("Controlled scanner mounts, flags, cleanup or execution failed")
        rows.append(
            ResearchPassRow.model_validate(
                {
                    "key": row.key,
                    "role": row.evidence.role,
                    "repetition": row.repetition,
                    "analysis_state": row.execution.analysis_state,
                    "native_exit_code": row.exit_code,
                    "finding_records": row.native_finding_records,
                    "semantic_sha256": semantic_hash(
                        row.evidence.model_dump(
                            mode="json",
                            exclude={"execution_id", "native_json_sha256", "native_sarif_sha256"},
                        )
                    ),
                }
            )
        )
    if summary.state == "observed" and len(rows) != cell.internal_repetitions * 2:
        raise ValueError("Controlled case has missing or additional internal repetitions")
    semantic = semantic_hash(
        {
            "contract": "benchmark-research-semantic-v1",
            "case_state": summary.state,
            "selected_file_count": summary.selected_file_count,
            "policy": summary.policy.model_dump(mode="json"),
            "scope": summary.scope.model_dump(mode="json") if summary.scope else None,
            "syntax_state": summary.syntax_state,
            "rows": [r.model_dump(mode="json") for r in rows],
        }
    )
    if read_retained_research(retained.root).manifest_sha256 != retained.manifest_sha256:
        raise ValueError("Controlled evidence changed during verification")
    for pin in plan.pins:
        if pin.path not in RETAINED_PINS:
            raw = bounded_file(environment / pin.path, MAX_REPORT_BYTES)
            if len(raw) != pin.bytes or sha256_bytes(raw) != pin.sha256:
                raise ValueError("Controlled environment changed during verification")
    return ResearchEvidence.model_validate(
        {
            "run_id": run_id,
            "state": "partial-analysis" if summary.state == "observed" else "refused",
            "case_state": summary.state,
            "manifest_sha256": retained.manifest_sha256,
            "semantic_sha256": semantic,
            "scanner_invocations": len(rows),
            "syntax_invocations": 0 if summary.syntax_state == "not-run" else 1,
            "rows": rows,
        }
    )
