"""Replay a completed whole-pilot attempt without running tools or scoring findings."""

from pathlib import Path
from typing import Any, Literal

from agentsec_evidence.agents.execution import AgentAuditToolConfig, build_agent_argv
from agentsec_evidence.benchmarks.attempt_models import PublicPilotEvidence
from agentsec_evidence.benchmarks.dependency_evidence import verify_dependency_execution
from agentsec_evidence.benchmarks.models import PublicPilotBenchmarkPlan, PublicPilotCell
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.execution.config import ExecutionProfile, load_toml_config
from agentsec_evidence.models.contracts import TargetSnapshot
from agentsec_evidence.pilot.inputs import LIMITS_PATH, PLAN_PATH, PROFILE_PATH, TOOL_PATH
from agentsec_evidence.pilot.validation import read_capture
from agentsec_evidence.reporting.pilot import load_pilot_source
from agentsec_evidence.research.execution import build_research_argv
from agentsec_evidence.research.models import SemgrepResearchScope
from agentsec_evidence.research.retained import plain_path, read_retained_research


def verify_public_pilot_attempt(
    project: Path,
    execution: Path,
    run_id: str | None,
    plan: PublicPilotBenchmarkPlan,
    cell: PublicPilotCell,
) -> PublicPilotEvidence:
    plain_path(execution, directory=True)
    if {p.name for p in execution.iterdir()} != {"pilot"} or cell.case_id != plan.case_id:
        raise ValueError("Pilot attempt must contain exactly its one admitted workflow")
    root = execution / "pilot"
    retained = read_retained_research(root, manifest_contract="source-pilot-evidence-v1")
    import json

    def document(path: str) -> Any:
        return json.loads(retained.read(path))

    pins = {p.path: p.sha256 for p in plan.pins}
    frozen = document("frozen/" + PLAN_PATH)
    for path in (*frozen["pins"], PLAN_PATH):
        if sha256_bytes(retained.read("frozen/" + path)) != pins[path]:
            raise ValueError("Retained pilot configuration differs from plan")
    for pin in plan.cache_files:
        if sha256_bytes(retained.read("preparation/raw/" + pin.path)) != pin.sha256:
            raise ValueError("Retained pilot cache differs from plan")
    for pin in plan.rule_files:
        if sha256_bytes(retained.read("rules/" + pin.path)) != pin.sha256:
            raise ValueError("Retained rule bytes differ from plan")
    expected_code = [{"path": p.path, "sha256": p.sha256} for p in plan.implementation]
    freeze = document("freeze.json")
    if (
        freeze["code"] != expected_code
        or freeze["pins"] != frozen["pins"]
        or freeze["database_sha256"] != plan.database.sha256
    ):
        raise ValueError("Pilot freeze differs from current bound implementation/resources")
    if {
        p.removeprefix("trusted-source/") for p in retained.files if p.startswith("trusted-source/")
    } != {p.path for p in plan.implementation}:
        raise ValueError("Retained pilot implementation set differs")
    for pin in plan.implementation:
        if sha256_bytes(retained.read("trusted-source/" + pin.path)) != pin.sha256:
            raise ValueError("Retained pilot implementation bytes differ")
    tool = load_toml_config(root / "frozen" / TOOL_PATH, AgentAuditToolConfig).value
    limits = load_toml_config(root / "frozen" / LIMITS_PATH, ExecutionProfile).value
    scope = SemgrepResearchScope.model_validate(document("semgrep-scope.json"))
    # Replay exact mounts, flags and images; matching command/process receipts alone is weaker.
    for repetition in range(1, 4):
        cell_root = root / f"repetition-{repetition}"
        for stage in ("syntax", "agent-audit", "semgrep-research", "semgrep-policy"):
            path = cell_root / stage
            capture, cleaned = read_capture(
                path / "capture" if stage.startswith("semgrep-") else path
            )
            argv = list(capture.argv)
            if Path(argv[0]).name.lower() not in {"docker", "docker.exe"} or not cleaned:
                raise ValueError("Pilot invocation or cleanup differs")
            name = argv[argv.index("--name") + 1]
            if stage.startswith("semgrep-"):
                role: Literal["research", "repository-policy"] = (
                    "research" if stage == "semgrep-research" else "repository-policy"
                )
                expected = build_research_argv(
                    docker=Path(argv[0]),
                    name=name,
                    profile_bytes=retained.read("frozen/" + PROFILE_PATH),
                    scope=scope,
                    role=role,
                    rules=root / "rules",
                    target=root / "semgrep-view/target",
                    output=path,
                )
            else:
                expected = build_agent_argv(
                    docker=Path(argv[0]),
                    name=name,
                    tool=tool,
                    profile=limits,
                    target=root / "agent-view/target",
                    worker_source=root / "trusted-source/src" if stage == "syntax" else None,
                    request=root / "request.json" if stage == "syntax" else None,
                )
            if argv != expected:
                raise ValueError("Pilot invocation differs from frozen treatment")
        dep_base = cell_root / "dependencies"
        bundles = list(plain_path(dep_base / "dependency-runs", directory=True).iterdir())
        if len(bundles) != 1:
            raise ValueError("Pilot repetition must contain exactly one dependency pair")
        dep = plain_path(bundles[0], directory=True)
        relative = dep.relative_to(root).as_posix()
        target = TargetSnapshot.model_validate(document(relative + "/inputs/snapshot.json"))
        snapshot = dep_base / "targets" / target.snapshot_id
        if (
            target.revision != frozen["revision"]
            or target.content_sha256 != frozen["content_sha256"]
        ):
            raise ValueError("Pilot dependency snapshot differs from source")
        if document(relative + "/harness-source.json") != {
            "files": expected_code,
            "uv_lock_sha256": pins["uv.lock"],
        }:
            raise ValueError("Pilot dependency implementation differs")
        for stage in ("osv-direct", "syft", "osv-sbom"):
            verify_dependency_execution(dep, snapshot, project / plan.database.path, stage)
    source, _ = load_pilot_source(project, root)
    if run_id is not None and source.run_id != run_id:
        raise ValueError("Pilot run identity differs from retained manifest")
    rows = source.summary.rows
    if any(row.state not in {"complete", "partial"} for row in rows):
        raise ValueError("Incomplete or failed pilot cannot be reused as a finished attempt")
    if (
        read_retained_research(root, manifest_contract="source-pilot-evidence-v1").manifest_sha256
        != retained.manifest_sha256
    ):
        raise ValueError("Pilot evidence changed during verification")
    return PublicPilotEvidence(
        run_id=source.run_id,
        manifest_sha256=retained.manifest_sha256,
        rows=rows,
        semantic_sha256=semantic_hash(
            [
                {
                    "repetition": r.repetition,
                    "stage": r.stage,
                    "state": r.state,
                    "semantic_sha256": r.semantic_sha256,
                }
                for r in rows
            ]
        ),
    )
