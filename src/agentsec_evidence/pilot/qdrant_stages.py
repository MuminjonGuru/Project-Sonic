"""Native stage receipts and offline replay for the separately admitted MCP pilot."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, cast

from jsonschema import Draft7Validator
from pydantic import Field, JsonValue, StrictInt, model_validator

from agentsec_evidence.adapters.agent_audit import normalize_agent_audit, parse_agent_audit_json
from agentsec_evidence.agents.execution import AgentAuditToolConfig, build_agent_argv
from agentsec_evidence.agents.records import AgentInputReport
from agentsec_evidence.agents.semantics import native_projection
from agentsec_evidence.agents.validation import canonical_artifact_path
from agentsec_evidence.agents.view_validation import assess_agent_view_report
from agentsec_evidence.benchmarks.dependency_evidence import verify_dependency_execution
from agentsec_evidence.core.identity import semantic_hash
from agentsec_evidence.core.io import atomic_write_jsonl
from agentsec_evidence.dependencies.analysis import dependency_semantic_hash
from agentsec_evidence.dependencies.database import inspect_database
from agentsec_evidence.dependencies.parsers import (
    parse_cyclonedx,
    parse_lockfile,
    parse_osv,
    parse_syft,
)
from agentsec_evidence.execution.config import ExecutionProfile, load_toml_config
from agentsec_evidence.execution.docker import portable_docker_argv
from agentsec_evidence.execution.process import ProcessCapture
from agentsec_evidence.exports.sarif import build_sarif
from agentsec_evidence.intake.git_verification import GitSourceVerification
from agentsec_evidence.intake.views import read_verified_source
from agentsec_evidence.models.contracts import ExecutionOutcome, Sha256, TargetSnapshot
from agentsec_evidence.orchestration.shared import make_execution
from agentsec_evidence.pilot.inputs import LIMITS_PATH, TOOL_PATH
from agentsec_evidence.pilot.qdrant_inputs import CONTENT, DATABASE, REVISION, QdrantInputs, bind
from agentsec_evidence.pilot.runner import invoke, load, ready_capture
from agentsec_evidence.pilot.validation import checked_retained_findings, read_capture
from agentsec_evidence.reporting.dependency import load_dependency_run, summarize_dependency
from agentsec_evidence.research.execution import assess_research_execution, build_research_argv
from agentsec_evidence.research.inputs import assess_research_syntax
from agentsec_evidence.research.models import ResearchModel
from agentsec_evidence.research.retained import bounded_file
from agentsec_evidence.research.semgrep import directory_skip_context, reconcile_semgrep_pass

type Stage = Literal[
    "semgrep-research",
    "semgrep-policy",
    "agent-python",
    "agent-mcp",
    "osv-direct",
    "syft",
    "osv-sbom",
]
STAGES: tuple[Stage, ...] = (
    "semgrep-research",
    "semgrep-policy",
    "agent-python",
    "agent-mcp",
    "osv-direct",
    "syft",
    "osv-sbom",
)


class QdrantRow(ResearchModel):
    repetition: StrictInt = Field(ge=1, le=3)
    stage: Stage
    state: Literal["not-run", "failed", "partial", "complete"] = "not-run"
    finding_records: StrictInt | None = Field(default=None, ge=0)
    package_identities: StrictInt | None = Field(default=None, ge=0)
    duration_ns: StrictInt | None = Field(default=None, ge=0)
    exit_code: StrictInt | None = None
    semantic_sha256: Sha256 | None = None
    unit: Literal["native-rule-reports", "package-advisory-occurrences", "package-identities"]
    evidence: str | None = None
    reasons: tuple[str, ...] = ("not-attempted",)

    @model_validator(mode="after")
    def check_observations(self) -> QdrantRow:
        if self.evidence:
            canonical_artifact_path(self.evidence)
        if self.state == "not-run" and any(
            value is not None
            for value in (
                self.finding_records,
                self.package_identities,
                self.duration_ns,
                self.exit_code,
                self.semantic_sha256,
                self.evidence,
            )
        ):
            raise ValueError("Unexecuted rows cannot contain observations")
        if self.state in {"complete", "partial"} and (
            not self.evidence
            or not self.semantic_sha256
            or self.duration_ns is None
            or self.exit_code is None
        ):
            raise ValueError("Observed rows need capture and evidence")
        expected_unit = (
            "package-identities"
            if self.stage == "syft"
            else "package-advisory-occurrences"
            if self.stage.startswith("osv-")
            else "native-rule-reports"
        )
        if self.unit != expected_unit:
            raise ValueError("Count unit differs from stage")
        return self


def planned_rows() -> list[QdrantRow]:
    return [
        QdrantRow(
            repetition=r,
            stage=s,
            unit=(
                "package-identities"
                if s == "syft"
                else "package-advisory-occurrences"
                if s.startswith("osv-")
                else "native-rule-reports"
            ),
        )
        for r in range(1, 4)
        for s in STAGES
    ]


def repeatability(rows: list[QdrantRow]) -> dict[str, bool | None]:
    if [(r.repetition, r.stage) for r in rows] != [(r.repetition, r.stage) for r in planned_rows()]:
        raise ValueError("Missing, duplicated or reordered pilot rows")
    return {
        s: (
            len({r.semantic_sha256 for r in rows if r.stage == s}) == 1
            if all(
                r.semantic_sha256 and r.state in {"complete", "partial"}
                for r in rows
                if r.stage == s
            )
            else None
        )
        for s in STAGES
    }


def container_name(directory: Path) -> str:
    return "qdrant-" + semantic_hash({"path": str(directory)})[:24]


def stage_capture(
    argv: list[str],
    path: Path,
    *,
    write: bool,
    project: Path,
    environment: dict[str, str],
    native_pair: bool = False,
) -> tuple[ProcessCapture, bool]:
    if write:
        return invoke(
            argv,
            path,
            project=project,
            docker=Path(argv[0]),
            name=argv[argv.index("--name") + 1],
            environment=environment,
            native_pair=native_pair,
        )
    capture, cleaned = read_capture(path)
    if list(capture.argv) != argv:
        raise ValueError("Native invocation differs from the admitted treatment")
    return capture, cleaned


def syntax_gates(
    inputs: QdrantInputs,
    cell: Path,
    *,
    project: Path,
    docker: Path,
    environment: dict[str, str],
    write: bool,
) -> dict[str, AgentInputReport]:
    tool = load_toml_config(inputs.root / "frozen" / TOOL_PATH, AgentAuditToolConfig).value
    limits = load_toml_config(inputs.root / "frozen" / LIMITS_PATH, ExecutionProfile).value
    reports = {}
    for name, request in inputs.requests.items():
        path = cell / (name + "-syntax")
        argv = build_agent_argv(
            docker=docker,
            tool=tool,
            profile=limits,
            name=container_name(path),
            target=inputs.root / (name + "-view/target"),
            worker_source=inputs.root / "trusted-source/src",
            request=inputs.root / (name + "-request.json"),
        )
        capture, cleaned = stage_capture(
            argv, path, write=write, project=project, environment=environment
        )
        if not ready_capture(capture, cleaned, {0}) or capture.stderr:
            raise ValueError("Syntax worker failed; security scanners not authorized")
        if name == "semgrep":
            if not assess_research_syntax(
                request, (inputs.root / (name + "-request.json")).read_bytes(), capture.stdout
            ):
                raise ValueError("Semgrep syntax gate refused")
        else:
            assessment = assess_agent_view_report(
                inputs.contexts[name], inputs.views[name], request, capture.stdout
            )
            bind(
                cell / (name + "-assessment.json"), assessment.model_dump(mode="json"), write=write
            )
            if not assessment.input_gate_passed:
                raise ValueError("Agent syntax/policy gate refused")
        reports[name] = AgentInputReport.model_validate_json(capture.stdout)
    return reports


def semgrep_stage(
    inputs: QdrantInputs,
    cell: Path,
    repetition: int,
    role: Literal["research", "repository-policy"],
    *,
    project: Path,
    docker: Path,
    environment: dict[str, str],
    write: bool,
) -> tuple[QdrantRow, Any]:
    stage: Stage = "semgrep-research" if role == "research" else "semgrep-policy"
    path = cell / stage
    if write:
        path.mkdir()
    scope = inputs.research.scope
    assert scope is not None
    argv = build_research_argv(
        docker=docker,
        name=container_name(path),
        profile_bytes=inputs.contexts["semgrep"].profile_bytes,
        scope=scope,
        role=role,
        rules=inputs.root / "rules",
        target=inputs.root / "semgrep-view/target",
        output=path,
    )
    capture, cleaned = stage_capture(
        argv,
        path / "capture",
        write=write,
        project=project,
        environment=environment,
        native_pair=True,
    )
    raw_json, raw_sarif = (
        bounded_file(path / f, 4 * 1024**2) for f in ("native.json", "native.sarif")
    )
    evidence = reconcile_semgrep_pass(
        profile_bytes=inputs.contexts["semgrep"].profile_bytes,
        scope=scope,
        execution_id=container_name(path),
        role=role,
        native_json=raw_json,
        native_sarif=raw_sarif,
        allow_policy_directory_skips=True,
    )
    Draft7Validator(load(project / "schemas/vendor/oasis/sarif-schema-2.1.0.json")).validate(
        load(path / "native.sarif")
    )
    assessment = assess_research_execution(capture, cleanup_succeeded=cleaned, evidence=evidence)
    projection: JsonValue = {
        "directory_skips": cast(JsonValue, directory_skip_context(scope, raw_json)),
        "evidence": evidence.model_dump(
            mode="json", exclude={"execution_id", "native_json_sha256", "native_sarif_sha256"}
        ),
        "assessment": assessment.model_dump(mode="json"),
        "exit_code": capture.exit_code,
    }
    bind(path / "evidence.json", evidence.model_dump(mode="json"), write=write)
    bind(path / "assessment.json", assessment.model_dump(mode="json"), write=write)
    bind(path / "semantic.json", projection, write=write)
    row = QdrantRow(
        repetition=repetition,
        stage=stage,
        state="failed" if assessment.analysis_state == "failed" else "partial",
        finding_records=len(evidence.findings),
        duration_ns=capture.duration_ns,
        exit_code=capture.exit_code,
        semantic_sha256=semantic_hash(projection),
        unit="native-rule-reports",
        evidence=path.relative_to(inputs.root).as_posix() + "/evidence.json",
        reasons=assessment.reasons or ("rule-by-file-completion-not-established",),
    )
    return row, evidence


def agent_stage(
    inputs: QdrantInputs,
    cell: Path,
    repetition: int,
    stage: Literal["agent-python", "agent-mcp"],
    worker: AgentInputReport,
    *,
    project: Path,
    docker: Path,
    environment: dict[str, str],
    write: bool,
) -> QdrantRow:
    path = cell / stage
    tool = load_toml_config(inputs.root / "frozen" / TOOL_PATH, AgentAuditToolConfig).value
    limits = load_toml_config(inputs.root / "frozen" / LIMITS_PATH, ExecutionProfile).value
    target = inputs.root / (stage + "-view/target")
    name = container_name(path)
    argv = build_agent_argv(docker=docker, tool=tool, profile=limits, name=name, target=target)
    capture, cleaned = stage_capture(
        argv, path, write=write, project=project, environment=environment
    )
    parsed = parse_agent_audit_json(capture.stdout)
    run_id = "qdrant-" + semantic_hash({"path": str(cell)})[:24]
    normalized = normalize_agent_audit(
        parsed,
        inputs=[c.checked_input() for c in worker.checks],
        run_id=run_id,
        execution_id=name,
        target_snapshot_id=inputs.contexts[stage].inventory.snapshot.snapshot_id,
    )
    findings = list(normalized.findings)
    if write:
        atomic_write_jsonl(path / "findings.jsonl", findings)
    else:
        findings = checked_retained_findings(
            findings, bounded_file(path / "findings.jsonl", 4 * 1024**2)
        )
    reasons = [
        "native-per-file-completion-not-observable",
        "FastMCP-dynamic-registration-coverage-unknown"
        if stage == "agent-python"
        else "declared-MCP-configuration-not-effective-host-permissions",
    ]
    if capture.stderr:
        reasons.append("native-stderr-retained-for-review")
    if parsed.document.scanned_files != len(inputs.requests[stage].selected):
        reasons.append("native-file-count-differs-from-selection")
    state: Literal["partial", "failed"] = (
        "partial" if ready_capture(capture, cleaned, {0, 1}) else "failed"
    )
    if state == "failed":
        reasons.append("process-or-cleanup-failed")
    projection: JsonValue = {
        "native": native_projection(capture.stdout),
        "state": state,
        "reasons": cast(JsonValue, reasons),
        "exit_code": capture.exit_code,
    }
    bind(path / "semantic.json", projection, write=write)
    execution = make_execution(
        execution_id=name,
        run_id=run_id,
        snapshot=inputs.contexts[stage].inventory.snapshot,
        tool=tool,
        profile=limits,
        config_sha256=semantic_hash(load(inputs.root / "freeze.json")),
        ruleset_sha256=semantic_hash(
            {"image": tool.image, "selection": "builtin-rules/severity-info/static-only"}
        ),
        portable_argv=list(
            portable_docker_argv(
                argv, docker_executable=docker, mount_replacements={target: "TARGET"}
            )
        ),
        environment=environment,
        capture=capture,
        outcome=ExecutionOutcome.PARTIAL if state == "partial" else ExecutionOutcome.FAILED,
        native_byte_length=len(capture.stdout),
        cleanup_attempted=True,
        cleanup_succeeded=cleaned,
    )
    bind(path / "execution.json", execution.model_dump(mode="json"), write=write)
    sarif = build_sarif(findings, execution=execution)
    Draft7Validator(load(project / "schemas/vendor/oasis/sarif-schema-2.1.0.json")).validate(sarif)
    bind(path / "results.sarif", sarif, write=write)
    return QdrantRow(
        repetition=repetition,
        stage=stage,
        state=state,
        finding_records=len(findings),
        duration_ns=capture.duration_ns,
        exit_code=capture.exit_code,
        semantic_sha256=semantic_hash(projection),
        unit="native-rule-reports",
        evidence=path.relative_to(inputs.root).as_posix() + "/findings.jsonl",
        reasons=tuple(reasons),
    )


def dependency_rows(
    root: Path, cell: Path, repetition: int, database: Path, *, write: bool
) -> list[QdrantRow]:
    candidates = list((cell / "dependencies/dependency-runs").iterdir())
    if len(candidates) != 1:
        raise ValueError("Exactly one dependency attempt is required per repetition")
    bundle = candidates[0]
    run = load_dependency_run(bundle)
    snapshot = TargetSnapshot.model_validate_json((bundle / "inputs/snapshot.json").read_bytes())
    if snapshot.content_sha256 != CONTENT or snapshot.revision != REVISION or run.scope is None:
        raise ValueError("Dependency evidence refers to a different source")
    target = cell / "dependencies/targets" / snapshot.snapshot_id
    proof = GitSourceVerification.model_validate_json(
        (root / "preparation/git-verification.json").read_bytes()
    )
    read_verified_source(
        proof,
        raw_commit=(root / "preparation/raw/commit.bin").read_bytes(),
        raw_tree=(root / "preparation/raw/tree-exact.json").read_bytes(),
        source_root=target / "content",
    )
    for name in ("tools.json", "osv.toml", "syft.yaml"):
        if (bundle / "configuration" / name).read_bytes() != (
            root / "frozen/configs/dependency" / name
        ).read_bytes():
            raise ValueError("Dependency configuration differs from frozen pins")
    lock, scope = parse_lockfile((root / "preparation/source/uv.lock").read_bytes())
    if scope != run.scope or len(scope.eligible) != 111 or len(scope.separate_local) != 1:
        raise ValueError("Dependency scope differs from admitted lockfile")
    # Reparse native results, not just their stored normalized derivatives.
    frozen = inspect_database(database, DATABASE, {n for n, _ in scope.eligible})
    rebuilt = {
        "lockfile": lock,
        "syft": parse_syft((bundle / "native/syft/syft.json").read_bytes()),
        "cyclonedx": parse_cyclonedx((bundle / "native/syft/bom.cdx.json").read_bytes()),
    }
    for stage in ("osv-direct", "osv-sbom"):
        process = verify_dependency_execution(bundle, target, database, stage)
        rebuilt[stage] = parse_osv(
            (bundle / f"native/{stage}/osv.json").read_bytes(),
            stage_name=stage,
            exit_code=cast(int, process["exit_code"]),
            alias_groups=frozen.aliases,
        )
    verify_dependency_execution(bundle, target, database, "syft")
    if rebuilt != run.stages:
        raise ValueError("Dependency native-to-normalized replay differs")
    summary = summarize_dependency(run)
    bind(cell / "dependency-summary.json", summary.model_dump(mode="json"), write=write)
    rows = []
    for stage in cast(tuple[Stage, ...], ("osv-direct", "syft", "osv-sbom")):
        observation = next(s for s in summary.stages if s.stage == stage)
        if observation.state not in {"complete", "partial", "failed"}:
            raise ValueError("Required dependency stage unavailable")
        process = load(bundle / f"native/{stage}/execution.json")
        rows.append(
            QdrantRow(
                repetition=repetition,
                stage=stage,
                state=observation.state,
                finding_records=observation.reported_match_occurrences if stage != "syft" else None,
                package_identities=observation.identified_unique_packages,
                duration_ns=process["duration_ns"],
                exit_code=process["exit_code"],
                semantic_sha256=dependency_semantic_hash([run.stages[stage]], scope),
                unit="package-identities" if stage == "syft" else "package-advisory-occurrences",
                evidence=bundle.relative_to(root).as_posix() + "/manifest.json",
                reasons=("identity-projection-limits-retained",)
                if stage == "syft"
                else ("per-package-matching-not-observable",),
            )
        )
    return rows
