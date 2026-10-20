from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import Field, JsonValue, StrictInt, model_validator

from agentsec_evidence.agents.validation import canonical_artifact_path
from agentsec_evidence.dependencies.models import DependencyModel
from agentsec_evidence.models.contracts import Sha256

Count = Annotated[StrictInt, Field(ge=0)]


class Reference(DependencyModel):
    path: str
    sha256: Sha256
    pointer: str = ""

    @model_validator(mode="after")
    def check(self) -> Self:
        canonical_artifact_path(self.path)
        if self.pointer and not self.pointer.startswith("/"):
            raise ValueError("Evidence pointers must be JSON pointers")
        return self


class SessionInput(DependencyModel):
    session: Sha256
    plan_sha256: Sha256
    validation_sha256: Sha256
    role: Literal["development", "formative-pilot"]


class ReviewInput(DependencyModel):
    report: str
    review: str
    previous: str | None = None
    report_manifest_sha256: Sha256
    review_manifest_sha256: Sha256

    @model_validator(mode="after")
    def check(self) -> Self:
        for value in (self.report, self.review, self.previous):
            if value is not None:
                canonical_artifact_path(value)
        return self


class ScorePlan(DependencyModel):
    contract: Literal["evidence-scoring-plan-v1"] = "evidence-scoring-plan-v1"
    sessions: tuple[SessionInput, ...] = Field(min_length=1, max_length=32)
    reviews: tuple[ReviewInput, ...] = Field(default=(), max_length=8)
    selection_rationale: str = Field(min_length=20, max_length=4000)
    exclusions: tuple[str, ...]
    scope: Literal["development-and-formative-evidence-not-held-out"] = (
        "development-and-formative-evidence-not-held-out"
    )
    analysis_version: Literal["evidence-scoring-v1"] = "evidence-scoring-v1"

    @model_validator(mode="after")
    def check(self) -> Self:
        if len({s.session for s in self.sessions}) != len(self.sessions):
            raise ValueError("Duplicate governed session")
        if len({r.review for r in self.reviews}) != len(self.reviews):
            raise ValueError("Duplicate review input")
        return self


class Metric(DependencyModel):
    name: str
    status: Literal["measured", "undefined", "unknown", "not-applicable"]
    numerator: Count | None
    denominator: Count | None
    value: float | None
    unit: str
    eligibility: str
    excluded: Count
    unknown: Count | None
    version: Literal["evidence-scoring-v1"] = "evidence-scoring-v1"
    limitation: str

    @model_validator(mode="after")
    def check(self) -> Self:
        if (
            self.denominator is not None
            and self.numerator is not None
            and self.numerator > self.denominator
        ):
            raise ValueError("Metric numerator exceeds its eligible denominator")
        if self.status == "measured":
            if self.numerator is None or self.denominator == 0:
                raise ValueError("Measured metric requires a numerator and nonempty ratio scope")
            expected = (
                self.numerator / self.denominator
                if self.denominator
                else float(self.numerator)
                if self.denominator is None
                else None
            )
            if self.value != expected:
                raise ValueError("Metric value differs from its explicit counts")
        elif self.value is not None:
            raise ValueError("Unmeasured metrics must not have numeric values")
        if self.status == "undefined" and (self.denominator != 0 or self.numerator != 0):
            raise ValueError("Undefined ratio requires an observed empty denominator")
        return self


class MeasurementRow(DependencyModel):
    row_id: Sha256
    session: Sha256
    case_id: str
    evidence_role: Literal["development", "formative-pilot"]
    attempt_id: str
    repetition: Count
    stage: str
    state: str
    analysis_completeness: Literal["not-established", "incomplete", "not-run"]
    metrics: tuple[Metric, ...]
    observations: dict[str, JsonValue]
    references: tuple[Reference, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def check(self) -> Self:
        if len({m.name for m in self.metrics}) != len(self.metrics):
            raise ValueError("Duplicate metric in a measurement row")
        return self


class ScoreReport(DependencyModel):
    contract: Literal["evidence-scoring-v1"] = "evidence-scoring-v1"
    plan_sha256: Sha256
    analysis_sources: tuple[Reference, ...]
    rows: tuple[MeasurementRow, ...]
    attempts: tuple[dict[str, JsonValue], ...]
    reviews: tuple[dict[str, JsonValue], ...]
    vulnerability_total: None = None
    public_detection_accuracy: None = None
    human_productivity_improvement: None = None
    source_validation: Literal["pinned-historical-ledger-and-native-replay"] = (
        "pinned-historical-ledger-and-native-replay"
    )
    sensitivity: Literal["internal-not-release-cleared"] = "internal-not-release-cleared"
    limitations: tuple[str, ...]

    @model_validator(mode="after")
    def check(self) -> Self:
        if len({r.row_id for r in self.rows}) != len(self.rows):
            raise ValueError("Duplicate measurement row identity")
        return self


class ScoreFile(DependencyModel):
    path: Literal[
        "plan.json", "scores.json", "measurements.csv", "attempts.csv", "TABLES.md", "SUMMARY.md"
    ]
    sha256: Sha256
    bytes: Count


class ScoreManifest(DependencyModel):
    contract: Literal["evidence-scoring-manifest-v1"] = "evidence-scoring-manifest-v1"
    entries: tuple[ScoreFile, ...] = Field(min_length=6, max_length=6)

    @model_validator(mode="after")
    def check(self) -> Self:
        paths = [entry.path for entry in self.entries]
        if len(set(paths)) != 6 or paths != sorted(paths):
            raise ValueError("Scoring manifest paths must be unique and sorted")
        return self
