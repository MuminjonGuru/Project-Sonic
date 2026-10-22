"""Frozen whole-selection core treatment; preparation does not authorize collection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from agentsec_evidence.agents.execution import AgentAuditToolConfig
from agentsec_evidence.agents.validation import canonical_artifact_path
from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.core.io import atomic_write_bytes
from agentsec_evidence.custom_rules.baseline_inputs import PROFILE_PATH, PROFILE_SHA
from agentsec_evidence.execution.config import load_toml_config
from agentsec_evidence.intake.corpus_validation import (
    PROTOCOL,
    CorpusInputAssessment,
    CorpusStageGate,
    CorpusValidationPlan,
    verify_validation_parent,
)
from agentsec_evidence.intake.corpus_validation_execution import verify_validation
from agentsec_evidence.models.contracts import ContractModel, Sha256
from agentsec_evidence.pilot.runner import evidence_records, save
from agentsec_evidence.reporting.custom_contracts import FAMILIES, IMAGE
from agentsec_evidence.research.models import (
    ResearchInput,
    SemgrepResearchScope,
    load_research_profile,
    verify_rule_bytes,
)
from agentsec_evidence.research.retained import (
    RetainedManifest,
    bounded_file,
    plain_path,
    read_retained_research,
)

SPEC = "docs/corpus-core-execution.md"
TOOL = "configs/tools/agent-audit-pilot.toml"
ELIGIBLE = {"input-eligible", "input-eligible-with-incomplete-files"}
ROLES = ("semgrep-research", "semgrep-policy", "agent-audit-python")


class CorpusCorePlan(ContractModel):
    contract: Literal["corpus-core-plan-v1"] = "corpus-core-plan-v1"
    validation_root: str
    validation_manifest_sha256: Sha256
    validation: CorpusValidationPlan
    assessment: CorpusInputAssessment
    frozen_pins: dict[str, Sha256]
    catalog_pins: dict[str, Sha256]
    repetitions: Literal[3] = 3
    worker_image: str = Field(default=IMAGE, pattern="^" + IMAGE + "$")
    annotation_treatment: Literal["tool-execution-1.1.0"] = "tool-execution-1.1.0"
    policy: Literal["custom-research-only;semgrep-dual-view-no-gitignore"] = (
        "custom-research-only;semgrep-dual-view-no-gitignore"
    )
    optional_stages: Literal["not-admitted-in-core"] = "not-admitted-in-core"
    execution_authorization: Literal["requires-bound-admission"] = "requires-bound-admission"
    target_execution: Literal[False] = False


class CorpusCoreAdmission(ContractModel):
    contract: Literal["corpus-core-admission-v1"] = "corpus-core-admission-v1"
    plan_sha256: Sha256
    reviewer: str = Field(min_length=1, max_length=200)
    provenance: Literal["student", "student-AI-assisted", "independent-reviewer"]
    intended_use: Literal["private-static-analysis-no-source-redistribution"] = (
        "private-static-analysis-no-source-redistribution"
    )
    license_evidence: dict[str, Sha256] = Field(min_length=1)
    license_review_note: str = Field(min_length=20, max_length=4000)
    optional_stage_review_note: str = Field(min_length=20, max_length=4000)
    resource_review_note: str = Field(min_length=20, max_length=4000)
    treatment_review_note: str = Field(min_length=20, max_length=4000)
    decision: Literal["admit-fixed-core-only"] = "admit-fixed-core-only"
    independent_outcome_approval: Literal[False] = False


def stage_gate(plan: CorpusCorePlan, producer: str) -> CorpusStageGate:
    name = (
        "custom-seven"
        if producer in {f.key for f in FAMILIES}
        else "semgrep-paired-views"
        if producer in ROLES[:2]
        else "agent-audit-python"
    )
    return next(s for s in plan.assessment.stages if s.stage == name)


def schedule(plan: CorpusCorePlan) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for rep in range(1, 4):
        for family in FAMILIES:
            gate = stage_gate(plan, family.key)
            batches: list[int | None] = (
                list(range(len(plan.validation.requests))) if gate.state in ELIGIBLE else [None]
            )
            rows.extend(_row(rep, family.key, batch, gate.state, gate.reasons) for batch in batches)
        for producer in ROLES:
            gate = stage_gate(plan, producer)
            rows.append(_row(rep, producer, None, gate.state, gate.reasons))
    return rows


def _row(
    rep: int, producer: str, batch: int | None, gate: str, reasons: tuple[str, ...]
) -> dict[str, Any]:
    suffix = f"/b{batch:03d}" if batch is not None else ""
    return {
        "key": f"runs/r{rep:02d}/{producer}{suffix}",
        "repetition": rep,
        "producer": producer,
        "batch": batch,
        "state": "not-run" if gate in ELIGIBLE else gate,
        "reasons": list(reasons),
        "finding_records": None,
        "duration_ns": None,
        "semantic_sha256": None,
    }


def semgrep_scope(plan: CorpusCorePlan) -> SemgrepResearchScope | None:
    if stage_gate(plan, "semgrep-research").state not in ELIGIBLE:
        return None
    preview = plan.validation.preview
    return SemgrepResearchScope(
        target_snapshot_id=preview.source_content_sha256,
        selection_sha256=preview.selection_sha256,
        profile_sha256=PROFILE_SHA,
        selected_files=tuple(
            ResearchInput.model_validate(e.source.model_dump()) for e in preview.selection
        ),
        policy_files=tuple(
            ResearchInput.model_validate(e.model_dump()) for e in preview.semgrep_policy.files
        ),
    )


def validate_structure(plan: CorpusCorePlan) -> None:
    if plan.catalog_pins != {f.key: f.catalog_sha256 for f in FAMILIES}:
        raise ValueError("Custom catalogs changed")
    preview, assessment = plan.validation.preview, plan.assessment
    if (
        assessment.candidate_id != preview.candidate.candidate_id
        or assessment.revision != preview.candidate.revision
        or assessment.selection_sha256 != preview.selection_sha256
    ):
        raise ValueError("Assessment candidate or selection differs")
    expected = {"custom-seven", "semgrep-paired-views", "agent-audit-python"}
    if len(assessment.stages) != 3 or {s.stage for s in assessment.stages} != expected:
        raise ValueError("Core stage gates differ")
    for path in plan.frozen_pins:
        canonical_artifact_path(path)
        if path.split("/")[0] not in {
            "implementation",
            "rules",
            "batches",
            "baseline",
            "licenses",
            "metadata",
        }:
            raise ValueError("Unexpected frozen material")
    if plan.frozen_pins.get("metadata/profile.json") != PROFILE_SHA:
        raise ValueError("Semgrep profile changed")
    semgrep_scope(plan)


def verify_frozen(root: Path, plan: CorpusCorePlan) -> None:
    validate_structure(plan)
    actual = set()
    for prefix in ("implementation", "rules", "batches", "baseline", "licenses", "metadata"):
        for path in (root / prefix).rglob("*"):
            if path.is_dir():
                plain_path(path, directory=True)
            else:
                actual.add(path.relative_to(root).as_posix())
    if actual != set(plan.frozen_pins):
        raise ValueError("Frozen material membership differs")
    for name, digest in plan.frozen_pins.items():
        if sha256_bytes(bounded_file(root / name, 4 * 1024**2)) != digest:
            raise ValueError("Frozen bytes changed: " + name)
    profile = load_research_profile(bounded_file(root / "metadata/profile.json", 1024**2))
    verify_rule_bytes(
        profile,
        {
            r.source_path: bounded_file(root / "rules" / r.source_path, 256 * 1024)
            for r in profile.rules
        },
        license_bytes=bounded_file(root / "rules/LICENSE", 256 * 1024),
    )
    tool = load_toml_config(root / "metadata/tool.toml", AgentAuditToolConfig).value
    if tool.treatment != "python-source-pilot-v1" or tool.validator_image != IMAGE:
        raise ValueError("Agent tool treatment differs")
    preview = plan.validation.preview
    entries = {e.source.path: e.source for e in preview.selection}
    expected_inputs: dict[str, Sha256] = {}
    for batch, request in enumerate(plan.validation.requests):
        base = f"batches/{batch:03d}"
        expected_inputs[base + "/request.json"] = sha256_bytes(request.model_dump_json().encode())
        expected_inputs.update({base + "/target/" + e.path: e.sha256 for e in request.inventory})
    if semgrep_scope(plan) is not None:
        expected_inputs.update({"baseline/semgrep/" + p: e.sha256 for p, e in entries.items()})
        expected_inputs.update(
            {"baseline/semgrep/" + e.path: e.sha256 for e in preview.semgrep_policy.files}
        )
    if stage_gate(plan, "agent-audit-python").state in ELIGIBLE:
        expected_inputs.update({"baseline/agent/" + p: e.sha256 for p, e in entries.items()})
    expected_inputs.update({"licenses/" + e.path: e.sha256 for e in preview.license_candidates})
    actual_inputs = {
        p: h
        for p, h in plan.frozen_pins.items()
        if p.split("/")[0] in {"batches", "baseline", "licenses"}
    }
    if actual_inputs != expected_inputs:
        raise ValueError("Materialized selections differ from validated source")


def verify_parent(project: Path, plan: CorpusCorePlan) -> None:
    replay = verify_validation(project, Path(plan.validation_root))
    original = CorpusValidationPlan.model_validate_json(
        bounded_file(Path(plan.validation_root) / "plan.json", 4 * 1024**2)
    )
    if (
        replay["evidence_manifest_sha256"] != plan.validation_manifest_sha256
        or replay["assessment"] != plan.assessment.model_dump(mode="json")
        or original != plan.validation
    ):
        raise ValueError("Validation parent changed")
    verify_validation_parent(project, plan.validation)


def prepare_core(project: Path, validation: Path, rules: Path, output: Path) -> CorpusCorePlan:
    project, validation, rules = (
        plain_path(p, directory=True) for p in (project, validation, rules)
    )
    output = output.absolute()
    plain_path(output.parent, directory=True)
    if (
        output.exists()
        or output == project / "workspace"
        or not output.is_relative_to(project / "workspace")
    ):
        raise ValueError("Use a fresh ignored workspace preparation")
    replay = verify_validation(project, validation)
    parent = CorpusValidationPlan.model_validate_json(
        bounded_file(validation / "plan.json", 4 * 1024**2)
    )
    assessment = CorpusInputAssessment.model_validate(replay["assessment"])
    profile_raw = bounded_file(project / PROFILE_PATH, 1024**2)
    if sha256_bytes(profile_raw) != PROFILE_SHA:
        raise ValueError("Pinned Semgrep profile changed")
    profile = load_research_profile(profile_raw)
    rule_files = {
        r.source_path: bounded_file(rules / r.source_path, 256 * 1024) for r in profile.rules
    }
    license_raw = bounded_file(rules / "LICENSE", 256 * 1024)
    verify_rule_bytes(profile, rule_files, license_bytes=license_raw)
    material = {
        "implementation/" + p.relative_to(project).as_posix(): bounded_file(p, 1024**2)
        for p in sorted((project / "src/agentsec_evidence").rglob("*.py"))
    }
    material.update({"rules/" + p: raw for p, raw in rule_files.items()})
    material.update(
        {
            "rules/LICENSE": license_raw,
            "metadata/profile.json": profile_raw,
            "metadata/tool.toml": bounded_file(project / TOOL, 1024**2),
            "metadata/protocol.md": bounded_file(project / PROTOCOL, 1024**2),
            "metadata/execution-spec.md": bounded_file(project / SPEC, 1024**2),
            "metadata/artifact-inventory.json": bounded_file(
                Path(parent.candidate_root) / "prepared/artifact-inventory.json", 4 * 1024**2
            ),
        }
    )
    source = Path(parent.candidate_root) / "prepared/source"
    for batch, request in enumerate(parent.requests):
        base = f"batches/{batch:03d}"
        material[base + "/request.json"] = request.model_dump_json().encode()
        for entry in request.inventory:
            material[base + "/target/" + entry.path] = bounded_file(source / entry.path, 256 * 1024)
    for stage, directory in (("semgrep-paired-views", "semgrep"), ("agent-audit-python", "agent")):
        if next(s for s in assessment.stages if s.stage == stage).state not in ELIGIBLE:
            continue
        entries = [e.source for e in parent.preview.selection]
        if directory == "semgrep":
            entries += list(parent.preview.semgrep_policy.files)
        for entry in entries:
            material[f"baseline/{directory}/" + entry.path] = bounded_file(
                source / entry.path, 256 * 1024
            )
    for entry in parent.preview.license_candidates:
        material["licenses/" + entry.path] = bounded_file(source / entry.path, 4 * 1024**2)
    plan = CorpusCorePlan(
        validation_root=str(validation),
        validation_manifest_sha256=replay["evidence_manifest_sha256"],
        validation=parent,
        assessment=assessment,
        frozen_pins={p: sha256_bytes(raw) for p, raw in sorted(material.items())},
        catalog_pins={f.key: f.catalog_sha256 for f in FAMILIES},
    )
    validate_structure(plan)
    output.mkdir()
    for path, raw in material.items():
        atomic_write_bytes(output / path, raw)
    save(output / "plan.json", plan.model_dump(mode="json"))
    save(output / "preview.json", dry_run(plan))
    verify_frozen(output, plan)
    save(
        output / "evidence-manifest.json",
        RetainedManifest.model_validate({"files": evidence_records(output)}).model_dump(
            mode="json"
        ),
    )
    return plan


def dry_run(plan: CorpusCorePlan) -> dict[str, Any]:
    rows = schedule(plan)
    return {
        "contract": "corpus-core-preview-v1",
        "candidate_id": plan.assessment.candidate_id,
        "selected_python_files": len(plan.validation.preview.selection),
        "planned_invocations": sum(r["state"] == "not-run" for r in rows),
        "scanner_invocations": 0,
        "rows": rows,
        "remaining_gate": "bound-core-admission",
        "optional_stages": plan.optional_stages,
    }


def load_preparation(project: Path, root: Path) -> CorpusCorePlan:
    retained = read_retained_research(root)
    plan = CorpusCorePlan.model_validate_json(retained.read("plan.json"))
    verify_frozen(root, plan)
    verify_parent(project, plan)
    if json.loads(retained.read("preview.json")) != dry_run(plan):
        raise ValueError("Dry run differs")
    if set(retained.files) != {*plan.frozen_pins, "plan.json", "preview.json"}:
        raise ValueError("Unexpected preparation membership")
    return plan


def verify_admission(plan: CorpusCorePlan, plan_raw: bytes, admission: CorpusCoreAdmission) -> None:
    expected = {e.path: e.sha256 for e in plan.validation.preview.license_candidates}
    if admission.plan_sha256 != sha256_bytes(plan_raw) or admission.license_evidence != expected:
        raise ValueError("Admission is not bound to this plan and its license evidence")


def current_implementation(project: Path, plan: CorpusCorePlan) -> None:
    actual = {
        "implementation/" + p.relative_to(project).as_posix(): sha256_file(p)
        for p in (project / "src/agentsec_evidence").rglob("*.py")
    }
    expected = {p: h for p, h in plan.frozen_pins.items() if p.startswith("implementation/")}
    if actual != expected:
        raise ValueError("Implementation changed; prepare a new treatment, never resume this one")
