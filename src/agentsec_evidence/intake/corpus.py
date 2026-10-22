"""Offline corpus preflight over replayed Git evidence; never scanning authorization."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import Field, StrictInt, model_validator

from agentsec_evidence.agents.inputs import POLICY_FILENAMES
from agentsec_evidence.agents.inventory import ArtifactInventory
from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes, sha256_file
from agentsec_evidence.core.io import atomic_write_model
from agentsec_evidence.custom_rules.shared_inputs import partition_inputs, view_entries
from agentsec_evidence.intake.git_verification import GitEvidenceModel, GitOid
from agentsec_evidence.intake.repository import RepositoryIntakeSpec, verify_repository
from agentsec_evidence.models.contracts import InventoryEntry, Sha256
from agentsec_evidence.research.models import MAX_FILE_BYTES, MAX_FILES, MAX_TOTAL_BYTES
from agentsec_evidence.research.policy import SemgrepPolicyAssessment, assess_semgrep_policy
from agentsec_evidence.research.retained import bounded_file, plain_path


class CorpusCandidate(GitEvidenceModel):
    candidate_id: str = Field(pattern=r"^R[0-9]{2}$")
    repository: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    revision: GitOid
    kind: Literal["mcp", "application", "template", "framework", "library"]
    role: Literal["existing-formative-pilot", "prospective-descriptive-candidate"]
    prescreen_files: StrictInt = Field(ge=1, le=1000)
    prescreen_python_files: StrictInt = Field(ge=0, le=1000)
    reported_license: str = Field(min_length=1, max_length=100)
    selection_rationale: str = Field(min_length=1, max_length=1000)
    lineage_note: str = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def validate_repository(self) -> CorpusCandidate:
        if any(p in {".", ".."} or p.startswith("-") for p in self.repository.split("/")):
            raise ValueError("Invalid GitHub repository")
        if self.prescreen_python_files > self.prescreen_files:
            raise ValueError("Python count exceeds parent count")
        return self

    @property
    def url(self) -> str:
        return "https://github.com/" + self.repository


class CorpusCandidates(GitEvidenceModel):
    contract: Literal["corpus-candidates-v1"] = "corpus-candidates-v1"
    scope: Literal["purposive-descriptive-not-confirmatory"] = (
        "purposive-descriptive-not-confirmatory"
    )
    selection_date: Literal["2026-10-21"] = "2026-10-21"
    candidates: tuple[CorpusCandidate, ...] = Field(min_length=1, max_length=20)
    scanning_authorization: Literal["not-granted"] = "not-granted"

    @model_validator(mode="after")
    def unique_candidates(self) -> CorpusCandidates:
        ids = [c.candidate_id for c in self.candidates]
        repos = [c.repository.casefold() for c in self.candidates]
        if ids != sorted(set(ids)) or len(repos) != len(set(repos)):
            raise ValueError("Candidates require ordered unique IDs and unique repositories")
        return self


def load_candidates(path: Path) -> CorpusCandidates:
    return CorpusCandidates.model_validate(
        load_agent_json(bounded_file(path, 128 * 1024), max_bytes=128 * 1024)
    )


class SelectionEntry(GitEvidenceModel):
    source: InventoryEntry
    path_role: Literal["ci", "tests", "examples", "documentation", "other-source"]
    custom_size_state: Literal["within-limit", "unsupported-file-size"]


class StagePreview(GitEvidenceModel):
    stage: Literal["custom-seven", "semgrep-paired-views", "agent-audit-python"]
    state: Literal["pending-validation", "unsupported-size", "policy-refused", "no-input"]
    reasons: tuple[str, ...]
    selected_files: StrictInt = Field(ge=0)
    selected_bytes: StrictInt = Field(ge=0)
    policy_files: StrictInt = Field(default=0, ge=0)
    batch_count: StrictInt = Field(default=0, ge=0)
    scanner_invocations: Literal[0] = 0
    findings: None = None


class CorpusPreview(GitEvidenceModel):
    contract: Literal["corpus-admission-preview-v1"] = "corpus-admission-preview-v1"
    candidate: CorpusCandidate
    candidate_sha256: Sha256
    intake_spec_sha256: Sha256
    intake_manifest_sha256: Sha256
    source_content_sha256: Sha256
    full_inventory_files: StrictInt
    full_inventory_bytes: StrictInt
    selection: tuple[SelectionEntry, ...]
    selection_sha256: Sha256
    custom_partitions: tuple[tuple[str, ...], ...]
    semgrep_policy: SemgrepPolicyAssessment
    agent_policy_paths: tuple[str, ...]
    stages: tuple[StagePreview, ...]
    license_candidates: tuple[InventoryEntry, ...]
    license_review: Literal["pending-source-specific-review"] = "pending-source-specific-review"
    artifact_inventory_sha256: Sha256
    optional_artifact_candidates: dict[str, tuple[str, ...]]
    metadata_differences: tuple[str, ...]
    scanning_authorization: Literal["not-granted"] = "not-granted"
    target_code_executed: Literal[False] = False
    syntax_validation: Literal["not-performed"] = "not-performed"
    scanner_invocations: Literal[0] = 0
    limitations: tuple[str, ...] = (
        "Size/policy preflight is not scanner admission or security analysis.",
        "Path roles and artifact candidates are filename heuristics, not effective deployment.",
        "Python syntax, AST budgets, inline suppressions and output bounds remain untested.",
        "Licenses require source-specific review; metadata and filename matches are not clearance.",
        "No held-out or confirmatory role is admitted by this contract.",
        "Baseline views cannot be sharded to bypass whole-selection limits.",
        "Optional stages require explicit input selection and validation before execution.",
    )


def path_role(path: str) -> Literal["ci", "tests", "examples", "documentation", "other-source"]:
    parts = PurePosixPath(path).parts
    lower = {p.casefold() for p in parts[:-1]}
    if parts[0] in {".github", ".gitlab"}:
        return "ci"
    if lower & {"test", "tests", "testing"} or parts[-1].startswith("test_"):
        return "tests"
    if lower & {"example", "examples", "demo", "demos", "samples"}:
        return "examples"
    if lower & {"doc", "docs", "documentation"}:
        return "documentation"
    return "other-source"


def _size_reasons(entries: list[InventoryEntry]) -> list[str]:
    reasons = []
    if len(entries) > MAX_FILES:
        reasons.append("combined-file-count-exceeds-64")
    if sum(e.byte_length for e in entries) > MAX_TOTAL_BYTES:
        reasons.append("combined-bytes-exceed-1-MiB")
    if any(e.byte_length > MAX_FILE_BYTES for e in entries):
        reasons.append("individual-file-exceeds-256-KiB")
    if view_entries([e.path for e in entries]) > 512:
        reasons.append("materialized-entry-count-exceeds-512")
    return reasons


def build_preview(
    candidate: CorpusCandidate, spec: RepositoryIntakeSpec, prepared: Path
) -> CorpusPreview:
    candidate = CorpusCandidate.model_validate(candidate.model_dump(mode="json"))
    if spec.source_label != candidate.url or spec.revision != candidate.revision:
        raise ValueError("Intake is not bound to the selected candidate")
    if spec.role != "formative-pilot":
        raise ValueError("Corpus preview requires the supported formative intake role")
    receipt = verify_repository(prepared, spec=spec)
    assert receipt.source_content_sha256 is not None
    inventory_raw = bounded_file(prepared / "artifact-inventory.json", 16 * 1024**2)
    inventory = ArtifactInventory.model_validate(
        load_agent_json(inventory_raw, max_bytes=16 * 1024**2)
    )
    records = [r.source for r in inventory.records]
    # Only bounded Git-verified bytes enter policy inspection. No Python AST or imports here.
    files = {e.path: bounded_file(prepared / "source" / e.path, 16 * 1024**2) for e in records}
    selected = sorted((e for e in records if e.path.endswith(".py")), key=lambda e: e.path)
    within_limit = [e for e in selected if e.byte_length <= MAX_FILE_BYTES]
    partitions = partition_inputs(within_limit)
    selection = tuple(
        SelectionEntry(
            source=e,
            path_role=path_role(e.path),
            custom_size_state=(
                "within-limit" if e.byte_length <= MAX_FILE_BYTES else "unsupported-file-size"
            ),
        )
        for e in selected
    )
    policy = assess_semgrep_policy(files)
    aa_policy = tuple(sorted(p for p in files if PurePosixPath(p).name in POLICY_FILENAMES))
    stages = []
    for stage in ("custom-seven", "semgrep-paired-views", "agent-audit-python"):
        extras = list(policy.files) if stage == "semgrep-paired-views" else []
        reasons = [] if stage == "custom-seven" else _size_reasons([*selected, *extras])
        state = "unsupported-size" if reasons else "pending-validation"
        if not selected:
            state = "no-input"
            reasons.append("no-selected-python-files")
        elif stage == "custom-seven" and len(within_limit) != len(selected):
            # Keep every selected path visible; oversized files never disappear into a batch.
            reasons.append("oversized-custom-inputs-remain-explicitly-unsupported")
            if not within_limit:
                state = "unsupported-size"
        if stage == "semgrep-paired-views" and policy.blockers:
            state = "policy-refused"
            reasons.extend("semgrep-policy:" + p.code + ":" + p.path for p in policy.blockers)
        if stage == "agent-audit-python" and aa_policy:
            state = "policy-refused"
            reasons.extend("target-policy:" + p for p in aa_policy)
        stages.append(
            StagePreview.model_validate(
                {
                    "stage": stage,
                    "state": state,
                    "reasons": reasons,
                    "selected_files": len(selected),
                    "selected_bytes": sum(e.byte_length for e in selected),
                    "policy_files": len(extras),
                    "batch_count": len(partitions) if stage == "custom-seven" else 0,
                }
            )
        )
    license_candidates = tuple(
        sorted(
            (
                e
                for e in records
                if PurePosixPath(e.path)
                .name.casefold()
                .startswith(("license", "licence", "copying", "notice"))
            ),
            key=lambda e: e.path,
        )
    )
    differences = []
    if len(records) != candidate.prescreen_files:
        differences.append("full-file-count-differs-from-metadata-prescreen")
    if len(selected) != candidate.prescreen_python_files:
        differences.append("python-filename-count-differs-from-metadata-prescreen")
    optional = {
        "uv-lock": tuple(sorted(p for p in files if PurePosixPath(p).name == "uv.lock")),
        "mcp-json-name-candidates": tuple(
            sorted(
                p
                for p in files
                if PurePosixPath(p).name in {"mcp.json", ".mcp.json", "claude_desktop_config.json"}
            )
        ),
        "terraform": tuple(sorted(p for p in files if p.endswith((".tf", ".tf.json")))),
        "yaml-needs-format-review": tuple(
            sorted(p for p in files if p.endswith((".yaml", ".yml")))
        ),
        "dockerfile-unsupported": tuple(
            sorted(p for p in files if PurePosixPath(p).name == "Dockerfile")
        ),
    }
    return CorpusPreview(
        candidate=candidate,
        candidate_sha256=semantic_hash(candidate.model_dump(mode="json")),
        intake_spec_sha256=semantic_hash(spec.model_dump(mode="json")),
        intake_manifest_sha256=sha256_file(prepared / "evidence-manifest.json"),
        source_content_sha256=receipt.source_content_sha256,
        full_inventory_files=len(records),
        full_inventory_bytes=sum(e.byte_length for e in records),
        selection=selection,
        selection_sha256=semantic_hash([e.model_dump(mode="json") for e in selected]),
        custom_partitions=tuple(tuple(e.path for e in batch) for batch in partitions),
        semgrep_policy=policy,
        agent_policy_paths=aa_policy,
        stages=tuple(stages),
        license_candidates=license_candidates,
        artifact_inventory_sha256=sha256_bytes(inventory_raw),
        optional_artifact_candidates=optional,
        metadata_differences=tuple(differences),
    )


def write_preview(preview: CorpusPreview, output: Path) -> None:
    plain_path(output.parent, directory=True)
    output.mkdir(exist_ok=False)
    atomic_write_model(output / "preview.json", preview)


def verify_preview(
    output: Path, candidate: CorpusCandidate, spec: RepositoryIntakeSpec, prepared: Path
) -> CorpusPreview:
    plain_path(output, directory=True)
    if {p.name for p in output.iterdir()} != {"preview.json"}:
        raise ValueError("Unexpected preflight package membership")
    actual = CorpusPreview.model_validate(
        load_agent_json(bounded_file(output / "preview.json", 4 * 1024**2), max_bytes=4 * 1024**2)
    )
    expected = build_preview(candidate, spec, prepared)
    if actual != expected:
        raise ValueError("Corpus preview differs from replayed candidate/input evidence")
    return actual
