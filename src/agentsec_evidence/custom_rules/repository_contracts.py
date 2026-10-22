"""Additive bindings for the two admitted pilots, not arbitrary repository admission."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, cast

from pydantic import Field

from agentsec_evidence.agents.records import AgentInputRequest
from agentsec_evidence.agents.validation import canonical_artifact_path, load_agent_json
from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.custom_rules.shared_execution import check_native
from agentsec_evidence.custom_rules.shared_inputs import partition_inputs
from agentsec_evidence.custom_rules.tool_execution_v2_worker import (
    ToolExecutionV2Report,
    exit_status,
)
from agentsec_evidence.models.contracts import ContractModel, InventoryEntry, Sha256
from agentsec_evidence.pilot.runner import load
from agentsec_evidence.reporting.custom_contracts import FAMILIES, IMAGE, Family, NativeReport
from agentsec_evidence.research.retained import bounded_file, read_retained_research

TARGETS = {
    "langgraph-cicd": (
        "https://github.com/langchain-samples/cicd-pipeline-example",
        "5ab0d0a0f3c90999f786f834d9c05484dfe5f2bf",
        "pilot-report.json",
        26,
    ),
    "qdrant-mcp": (
        "https://github.com/qdrant/mcp-server-qdrant",
        "c56ae5adf62bb78d852bf7bbcbc5d7b75e2bbe41",
        "repository-pilot-report.json",
        19,
    ),
}
CurrentNative = NativeReport | ToolExecutionV2Report


class RepositoryCustomPlan(ContractModel):
    contract: Literal["repository-custom-plan-v1"] = "repository-custom-plan-v1"
    target: Literal["langgraph-cicd", "qdrant-mcp"]
    split: Literal["formative-pilot-not-held-out"] = "formative-pilot-not-held-out"
    repository: str
    revision: str
    content_sha256: Sha256
    baseline_root: str
    baseline_manifest_sha256: Sha256
    baseline_report_sha256: Sha256
    source_pins: dict[str, Sha256]
    catalog_pins: dict[str, Sha256]
    image: str = Field(default=IMAGE, pattern="^" + IMAGE + "$")
    inventory: list[InventoryEntry]
    requests: list[AgentInputRequest]
    repetitions: int = Field(ge=1, le=3)
    execution_root: str
    target_execution: Literal[False] = False
    policy: Literal["research-only-no-suppressions-applied"] = (
        "research-only-no-suppressions-applied"
    )
    annotation_treatment: Literal["tool-execution-1.1.0"] = "tool-execution-1.1.0"


def verify_base(project: Path, root: Path, target: str, database: Path) -> dict[str, Any]:
    if target not in TARGETS:
        raise ValueError("Target is not admitted for this bounded rehearsal")
    if target == "qdrant-mcp":
        from agentsec_evidence.pilot.qdrant import verify_qdrant_pilot

        replay = verify_qdrant_pilot(project, root, database)
    else:
        from agentsec_evidence.pilot.validation import validate_source_pilot

        replay = validate_source_pilot(project, root)
    if replay["passed"] is not True:
        raise ValueError("Baseline evidence did not replay")
    retained = read_retained_research(root, manifest_contract="source-pilot-evidence-v1")
    repo, revision, report_path, _ = TARGETS[target]
    report = load(root / report_path)
    if report["repository"] != repo or report["revision"] != revision:
        raise ValueError("Baseline repository identity differs")
    report["retained_manifest_sha256"] = retained.manifest_sha256
    return cast(dict[str, Any], report)


def prepare_plan(
    project: Path, root: Path, target: str, database: Path, output: Path, repetitions: int
) -> tuple[RepositoryCustomPlan, dict[str, bytes], dict[str, bytes]]:
    report = verify_base(project, root, target, database)
    repo, revision, report_path, count = TARGETS[target]
    source = root / "preparation/source"
    # Parent Git evidence has already been replayed. Selection is all pinned .py files,
    # not a new walk over an arbitrary caller-supplied directory.
    proof = load(root / "preparation/git-verification.json")
    paths = sorted(
        f["source"]["path"] for f in proof["files"] if f["source"]["path"].endswith(".py")
    )
    if len(paths) != count:
        raise ValueError("Pinned Python selection changed")
    data = {p: bounded_file(source / p, 256 * 1024) for p in paths}
    inventory = [
        InventoryEntry(
            path=p, sha256=sha256_bytes(raw), byte_length=len(raw), media_type="text/x-python"
        )
        for p, raw in data.items()
    ]
    sources = {
        p.relative_to(project).as_posix(): bounded_file(p, 1024**2)
        for p in sorted((project / "src/agentsec_evidence").rglob("*.py"))
    }
    requests = [
        AgentInputRequest(
            target_snapshot_id=report["content_sha256"],
            inventory=batch,
            selected={e.path: "python-source" for e in batch},
        )
        for batch in partition_inputs(inventory, max_files=64)
    ]
    plan = RepositoryCustomPlan(
        target=cast(Literal["langgraph-cicd", "qdrant-mcp"], target),
        repository=repo,
        revision=revision,
        content_sha256=report["content_sha256"],
        baseline_root=str(root),
        baseline_manifest_sha256=report["retained_manifest_sha256"],
        baseline_report_sha256=sha256_file(root / report_path),
        source_pins={p: sha256_bytes(raw) for p, raw in sources.items()},
        catalog_pins={f.key: f.catalog_sha256 for f in FAMILIES},
        inventory=inventory,
        requests=requests,
        repetitions=repetitions,
        execution_root=str(output),
    )
    return plan, data, sources


def validate_plan(plan: RepositoryCustomPlan) -> None:
    repo, revision, _, count = TARGETS[plan.target]
    if plan.repository != repo or plan.revision != revision or len(plan.inventory) != count:
        raise ValueError("Unadmitted repository plan")
    if plan.image != IMAGE or plan.catalog_pins != {f.key: f.catalog_sha256 for f in FAMILIES}:
        raise ValueError("Worker image or catalogs differ")
    for p in plan.source_pins:
        canonical_artifact_path(p)
        if not p.startswith("src/agentsec_evidence/") or not p.endswith(".py"):
            raise ValueError("Invalid trusted source path")
    expected = [
        AgentInputRequest(
            target_snapshot_id=plan.content_sha256,
            inventory=batch,
            selected={e.path: "python-source" for e in batch},
        )
        for batch in partition_inputs(plan.inventory, max_files=64)
    ]
    if plan.requests != expected:
        raise ValueError("Custom partition differs from selected inputs")


def current_native(
    raw: bytes, request_raw: bytes, family: Family, code: int | None
) -> CurrentNative:
    if family.key != "tool-execution":
        return check_native(raw, request_raw, family, code)
    native = ToolExecutionV2Report.model_validate(load_agent_json(raw, max_bytes=2 * 1024**2))
    request = AgentInputRequest.model_validate(load_agent_json(request_raw, max_bytes=256 * 1024))
    if (
        native.request_sha256 != sha256_bytes(request_raw)
        or native.target_snapshot_id != request.target_snapshot_id
        or native.input_inventory != sorted(request.inventory, key=lambda e: e.path)
        or native.not_selected
        != sorted({e.path for e in request.inventory} - request.selected.keys())
        or [f.path for f in native.files] != sorted(request.selected)
        or native.catalog_sha256 != family.catalog_sha256
        or list(native.rules) != list(family.rules)
    ):
        raise ValueError("Annotation-aware native accounting differs")
    entries = {e.path: e for e in request.inventory}
    seen = set()
    for file in native.files:
        entry = entries[file.path]
        if (file.source_sha256, file.byte_length) != (entry.sha256, entry.byte_length):
            raise ValueError("Native source binding differs")
        if (file.findings is None) != (file.state != "analyzed"):
            raise ValueError("Incomplete input cannot be clean")
        if file.state != "analyzed" and (file.inventory or file.limitations_observed):
            raise ValueError("Incomplete input carries successful observations")
        if len(file.findings or []) + len(file.inventory) + len(file.limitations_observed) > 1000:
            raise ValueError("Native observation limit exceeded")
        for finding in file.findings or []:
            span = finding.location
            expected = sha256_bytes(
                f"{native.version}:{file.path}:{file.source_sha256}:"
                f"{finding.rule.rule_id}:{span.model_dump_json()}".encode()
            )
            if (
                finding.rule not in family.rules
                or finding.record_id != expected
                or expected in seen
                or (span.end_line, span.end_utf8_byte_column)
                < (span.start_line, span.start_utf8_byte_column)
            ):
                raise ValueError("Native condition identity or rule differs")
            seen.add(expected)
    state = (
        "empty"
        if not native.files
        else "partial"
        if any(f.state != "analyzed" for f in native.files)
        else "complete"
    )
    if native.execution_state != state or code != exit_status(native):
        raise ValueError("Native status differs")
    return native
