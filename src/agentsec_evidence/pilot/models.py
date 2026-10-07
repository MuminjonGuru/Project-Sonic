from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, StrictInt, model_validator

from agentsec_evidence.agents.validation import canonical_artifact_path
from agentsec_evidence.models.contracts import Sha256
from agentsec_evidence.research.models import ResearchModel

REVISION = "5ab0d0a0f3c90999f786f834d9c05484dfe5f2bf"
CONTENT = "331a5f63efc0b8e07c0d9977c3a36c4b96cc3cd4dae39744877fd605c054d0af"
type PilotStage = Literal[
    "semgrep-research", "semgrep-policy", "agent-audit", "osv-direct", "syft", "osv-sbom"
]
STAGES: tuple[PilotStage, ...] = (
    "semgrep-research",
    "semgrep-policy",
    "agent-audit",
    "osv-direct",
    "syft",
    "osv-sbom",
)


class PilotPlan(ResearchModel):
    contract: Literal["same-repository-pilot-plan-v1"] = "same-repository-pilot-plan-v1"
    approval: Literal["student-approved-bounded-pilot-2026-10-06"]
    repository: Literal["https://github.com/langchain-samples/cicd-pipeline-example"]
    revision: Literal["5ab0d0a0f3c90999f786f834d9c05484dfe5f2bf"]
    content_sha256: Literal["331a5f63efc0b8e07c0d9977c3a36c4b96cc3cd4dae39744877fd605c054d0af"]
    database_sha256: Literal["6f7b248e44eeadbf0d669c2e2842adc19bc1929f1b9da8ae2e69991dab3cbbdd"]
    expected_files: Literal[47]
    python_paths: tuple[str, ...] = Field(min_length=26, max_length=26)
    repetitions: Literal[3]
    order: tuple[str, ...]
    pins: dict[str, Sha256] = Field(min_length=9)
    split: Literal["formative-pilot-not-held-out"] = "formative-pilot-not-held-out"
    target_execution: Literal[False] = False
    oracle: Literal["no-complete-public-vulnerability-oracle"] = (
        "no-complete-public-vulnerability-oracle"
    )
    implicit_git_filtering: Literal[False] = False
    dockerfile: Literal["present-unsupported-not-run"] = "present-unsupported-not-run"

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        if self.order != STAGES:
            raise ValueError("Pilot stage order differs from approved treatment")
        for path in (*self.python_paths, *self.pins):
            canonical_artifact_path(path)
        if (
            list(self.python_paths) != sorted(set(self.python_paths))
            or any(not p.endswith(".py") for p in self.python_paths)
            or len({p.casefold() for p in self.python_paths}) != 26
        ):
            raise ValueError("Pilot requires 26 unique sorted Python source paths")
        return self


class PilotRow(ResearchModel):
    repetition: StrictInt = Field(ge=1, le=3)
    stage: PilotStage
    state: Literal["not-run", "refused", "failed", "partial", "complete"] = "not-run"
    finding_records: StrictInt | None = Field(default=None, ge=0)
    package_identities: StrictInt | None = Field(default=None, ge=0)
    unit: Literal["native-rule-reports", "package-advisory-occurrences", "package-identities"]
    duration_ns: StrictInt | None = Field(default=None, ge=0)
    exit_code: StrictInt | None = None
    semantic_sha256: Sha256 | None = None
    evidence: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ("not-attempted",)

    @model_validator(mode="after")
    def validate_observation(self) -> Self:
        for path in self.evidence:
            canonical_artifact_path(path)
        if self.state in {"not-run", "refused"} and any(
            v is not None
            for v in (
                self.finding_records,
                self.package_identities,
                self.exit_code,
                self.duration_ns,
                self.semantic_sha256,
            )
        ):
            raise ValueError("Unexecuted stage must not invent observations")
        if self.state in {"complete", "partial"} and not self.evidence:
            raise ValueError("Observed stage needs evidence references")
        return self


def planned_rows() -> list[PilotRow]:
    return [
        PilotRow(
            repetition=repetition,
            stage=stage,
            unit="package-identities"
            if stage == "syft"
            else "package-advisory-occurrences"
            if stage.startswith("osv-")
            else "native-rule-reports",
        )
        for repetition in range(1, 4)
        for stage in STAGES
    ]


def repeatability(rows: list[PilotRow]) -> dict[str, bool | None]:
    if [(r.repetition, r.stage) for r in rows] != [(r.repetition, r.stage) for r in planned_rows()]:
        raise ValueError("Pilot rows are missing, duplicated or out of order")
    result: dict[str, bool | None] = {}
    for stage in STAGES:
        values = [r.semantic_sha256 for r in rows if r.stage == stage]
        result[stage] = None if any(v is None for v in values) else len(set(values)) == 1
    return result
