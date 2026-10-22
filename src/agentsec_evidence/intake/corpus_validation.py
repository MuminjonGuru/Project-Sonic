"""Exact corpus input bindings and syntax-derived eligibility, not scanner admission."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, StrictInt

from agentsec_evidence.agents.inputs import plan_agent_input_admission
from agentsec_evidence.agents.inventory import ArtifactInventory
from agentsec_evidence.agents.records import (
    AgentInputCheck,
    AgentInputReport,
    AgentInputRequest,
    verify_input_report,
)
from agentsec_evidence.agents.validation import canonical_artifact_path, load_agent_json
from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.intake.corpus import CorpusPreview, load_candidates, verify_preview
from agentsec_evidence.intake.repository import load_intake_spec
from agentsec_evidence.models.contracts import ContractModel, InventoryEntry, Sha256
from agentsec_evidence.reporting.custom_contracts import IMAGE
from agentsec_evidence.research.retained import bounded_file

REGISTRY = "test_cases/corpus/candidates-2026-10-21.json"
PROTOCOL = "docs/corpus-collection-protocol.md"
TOOL = "configs/tools/agent-audit-pilot.toml"


class CorpusValidationPlan(ContractModel):
    contract: Literal["corpus-input-validation-plan-v1"] = "corpus-input-validation-plan-v1"
    preview: CorpusPreview
    preview_sha256: Sha256
    registry_sha256: Sha256
    protocol_sha256: Sha256
    tool_sha256: Sha256
    source_pins: dict[str, Sha256]
    parent_paths: tuple[str, ...]
    requests: tuple[AgentInputRequest, ...]
    candidate_root: str
    execution_root: str
    image: str = Field(default=IMAGE, pattern="^" + IMAGE + "$")
    collection_repetitions: Literal[3] = 3
    security_scanner_authorization: Literal["not-granted"] = "not-granted"
    target_execution: Literal[False] = False


class CorpusStageGate(ContractModel):
    stage: Literal["custom-seven", "semgrep-paired-views", "agent-audit-python"]
    state: Literal[
        "input-eligible",
        "input-eligible-with-incomplete-files",
        "unsupported-size",
        "input-refused",
        "policy-refused",
        "no-input",
    ]
    reasons: tuple[str, ...]
    selected_files: StrictInt = Field(ge=0)
    scanner_invocations: Literal[0] = 0
    findings: None = None


class CorpusInputAssessment(ContractModel):
    contract: Literal["corpus-input-assessment-v1"] = "corpus-input-assessment-v1"
    candidate_id: str
    revision: str
    selection_sha256: Sha256
    checks: tuple[AgentInputCheck, ...]
    omitted_from_validation: tuple[InventoryEntry, ...]
    stages: tuple[CorpusStageGate, ...]
    potential_paired_comparison: bool
    scanner_admission: Literal["pending-execution-protocol-and-resource-review"] = (
        "pending-execution-protocol-and-resource-review"
    )
    security_scanner_invocations: Literal[0] = 0


def expected_requests(preview: CorpusPreview) -> tuple[AgentInputRequest, ...]:
    entries = {e.source.path: e.source for e in preview.selection}
    return tuple(
        AgentInputRequest(
            target_snapshot_id=preview.source_content_sha256,
            inventory=[entries[p] for p in paths],
            selected={p: "python-source" for p in paths},
        )
        for paths in preview.custom_partitions
    )


def validate_plan_structure(plan: CorpusValidationPlan) -> None:
    if plan.image != IMAGE or plan.requests != expected_requests(plan.preview):
        raise ValueError("Validation image or partition differs")
    if list(plan.parent_paths) != sorted(set(plan.parent_paths)):
        raise ValueError("Parent paths must be ordered and unique")
    for p in (*plan.parent_paths, *plan.source_pins):
        canonical_artifact_path(p)
    if not plan.source_pins or any(
        not p.startswith("src/agentsec_evidence/") or not p.endswith(".py")
        for p in plan.source_pins
    ):
        raise ValueError("Invalid trusted implementation membership")
    if [p for p in plan.parent_paths if p.endswith(".py")] != [
        e.source.path for e in plan.preview.selection
    ]:
        raise ValueError("Selected Python files differ from parent inventory")


def prepare_validation_plan(
    project: Path, candidate_root: Path, output: Path
) -> tuple[CorpusValidationPlan, dict[str, bytes]]:
    registry = load_candidates(project / REGISTRY)
    matches = [c for c in registry.candidates if c.candidate_id == candidate_root.name]
    if len(matches) != 1:
        raise ValueError("Candidate is absent from the frozen registry")
    spec = load_intake_spec(candidate_root / "intake-spec.json")
    preview = verify_preview(
        candidate_root / "preflight", matches[0], spec, candidate_root / "prepared"
    )
    inventory = ArtifactInventory.model_validate(
        load_agent_json(
            bounded_file(candidate_root / "prepared/artifact-inventory.json", 16 * 1024**2),
            max_bytes=16 * 1024**2,
        )
    )
    sources = {
        p.relative_to(project).as_posix(): bounded_file(p, 1024**2)
        for p in sorted((project / "src/agentsec_evidence").rglob("*.py"))
    }
    plan = CorpusValidationPlan(
        preview=preview,
        preview_sha256=sha256_file(candidate_root / "preflight/preview.json"),
        registry_sha256=sha256_file(project / REGISTRY),
        protocol_sha256=sha256_file(project / PROTOCOL),
        tool_sha256=sha256_file(project / TOOL),
        source_pins={p: sha256_bytes(raw) for p, raw in sources.items()},
        parent_paths=tuple(sorted(r.source.path for r in inventory.records)),
        requests=expected_requests(preview),
        candidate_root=str(candidate_root),
        execution_root=str(output),
    )
    validate_plan_structure(plan)
    return plan, sources


def verify_validation_parent(project: Path, plan: CorpusValidationPlan) -> None:
    """Replay external Git evidence without substituting current implementation for old pins."""
    validate_plan_structure(plan)
    root = Path(plan.candidate_root)
    if sha256_file(project / REGISTRY) != plan.registry_sha256:
        raise ValueError("Candidate registry changed")
    candidates = load_candidates(project / REGISTRY)
    matches = [c for c in candidates.candidates if c == plan.preview.candidate]
    if len(matches) != 1 or root.name != matches[0].candidate_id:
        raise ValueError("Candidate identity changed")
    actual = verify_preview(
        root / "preflight",
        matches[0],
        load_intake_spec(root / "intake-spec.json"),
        root / "prepared",
    )
    if (
        actual != plan.preview
        or sha256_file(root / "preflight/preview.json") != plan.preview_sha256
    ):
        raise ValueError("External preflight changed")
    inventory = ArtifactInventory.model_validate_json(
        bounded_file(root / "prepared/artifact-inventory.json", 16 * 1024**2)
    )
    if plan.parent_paths != tuple(sorted(r.source.path for r in inventory.records)):
        raise ValueError("Parent membership differs")


def assess_inputs(
    plan: CorpusValidationPlan, reports: list[AgentInputReport]
) -> CorpusInputAssessment:
    validate_plan_structure(plan)
    if len(reports) != len(plan.requests):
        raise ValueError("Missing or additional validation responses")
    for report, request in zip(reports, plan.requests, strict=True):
        verify_input_report(report, request, request.model_dump_json().encode())
    checks = tuple(
        sorted((c for r in reports for c in r.checks), key=lambda c: c.artifact.source.path)
    )
    expected = sorted(p for request in plan.requests for p in request.selected)
    if [c.artifact.source.path for c in checks] != expected:
        raise ValueError("Validation lost or duplicated selected inputs")
    entries = {e.source.path: e.source for e in plan.preview.selection}
    for check in checks:
        if (
            check.artifact.source != entries[check.artifact.source.path]
            or check.artifact.target_snapshot_id != plan.preview.source_content_sha256
            or check.artifact.kind != "python-source"
        ):
            raise ValueError("Validation input identity differs")
    omitted = tuple(e.source for e in plan.preview.selection if e.source.path not in expected)
    syntax = tuple(
        f"input-{c.artifact.parse_state}:{c.artifact.source.path}"
        for c in checks
        if c.artifact.parse_state != "parsed"
    )
    agent = plan_agent_input_admission(
        (c.checked_input() for c in checks), snapshot_paths=plan.parent_paths
    )
    stages = []
    for stage in plan.preview.stages:
        reasons = list(stage.reasons)
        state: str = "input-eligible" if stage.state == "pending-validation" else stage.state
        if stage.stage == "custom-seven":
            # File-local workers retain malformed/native refusal records; no input is removed.
            reasons.extend(syntax)
            if state == "input-eligible" and (syntax or omitted):
                state = "input-eligible-with-incomplete-files"
        else:
            reasons.extend(syntax)
            reasons.extend(f"input-not-validated:{e.path}" for e in omitted)
            if stage.stage == "agent-audit-python":
                reasons.extend(agent.blockers)
            if state == "input-eligible":
                if syntax or omitted:
                    state = "input-refused"
                elif stage.stage == "agent-audit-python" and agent.blockers:
                    state = "policy-refused"
        stages.append(
            CorpusStageGate.model_validate(
                {
                    "stage": stage.stage,
                    "state": state,
                    "reasons": sorted(set(reasons)),
                    "selected_files": stage.selected_files,
                }
            )
        )
    return CorpusInputAssessment(
        candidate_id=plan.preview.candidate.candidate_id,
        revision=plan.preview.candidate.revision,
        selection_sha256=plan.preview.selection_sha256,
        checks=checks,
        omitted_from_validation=omitted,
        stages=tuple(stages),
        potential_paired_comparison=all(s.state == "input-eligible" for s in stages),
    )
