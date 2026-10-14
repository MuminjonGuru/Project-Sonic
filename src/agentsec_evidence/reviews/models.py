from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, Field, StrictInt, field_validator, model_validator

from agentsec_evidence.agents.validation import canonical_artifact_path
from agentsec_evidence.core.identity import semantic_hash
from agentsec_evidence.dependencies.models import DependencyModel
from agentsec_evidence.models.contracts import Finding, Sha256

Text = Annotated[str, Field(min_length=1, max_length=6000)]
Identity = Annotated[str, Field(min_length=1, max_length=200)]
ReviewId = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")]
Conclusion = Literal[
    "claim-not-substantiated",
    "condition-observed-context-unresolved",
    "condition-supported",
    "unresolved",
]


class Reviewer(DependencyModel):
    identity: Identity
    role: Literal["ai-assistant", "student", "external-reviewer"]
    authorship: Literal["ai-drafted", "ai-assisted", "human-authored"]

    @model_validator(mode="after")
    def validate_author(self) -> Self:
        if not self.identity.strip() or (
            (self.role == "ai-assistant") != (self.authorship == "ai-drafted")
        ):
            raise ValueError("Reviewer role and declared authorship disagree")
        return self


class ReviewSubject(DependencyModel):
    source_run_id: Identity
    source_manifest_sha256: Sha256
    finding_sha256: Sha256
    finding_snapshot: Finding

    @model_validator(mode="after")
    def validate_snapshot(self) -> Self:
        if self.finding_sha256 != semantic_hash(self.finding_snapshot.model_dump(mode="json")):
            raise ValueError("Review finding snapshot hash differs")
        return self

    @property
    def key(self) -> tuple[str, str, str, str]:
        finding = self.finding_snapshot
        return (self.source_run_id, finding.run_id, finding.execution_id, finding.record_id)


class ReviewContext(DependencyModel):
    """Source location asserted by the reviewer; the service checks its inventoried byte hash."""

    artifact_path: str = Field(min_length=1, max_length=4096)
    source_sha256: Sha256
    start_line: StrictInt | None = Field(default=None, ge=1)
    end_line: StrictInt | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def validate_location(self) -> Self:
        canonical_artifact_path(self.artifact_path)
        if self.end_line is not None and (
            self.start_line is None or self.end_line < self.start_line
        ):
            raise ValueError("Invalid review context line range")
        return self


class ReviewAnnotation(DependencyModel):
    review_id: ReviewId
    subject: ReviewSubject
    reviewer: Reviewer
    created_at: AwareDatetime
    decision: Literal["proposed", "accepted", "changed", "unresolved"]
    conclusion: Conclusion
    observed_condition: Text
    rationale: Text
    uncertainty: Text
    contexts: tuple[ReviewContext, ...] = Field(min_length=1, max_length=32)
    mapping_notes: tuple[Text, ...] = Field(default=(), max_length=16)
    supersedes_sha256: Sha256 | None = None
    measured_review_duration_ns: StrictInt | None = Field(default=None, ge=0)
    runtime_exploitability: Literal["not-tested"] = "not-tested"

    @field_validator("observed_condition", "rationale", "uncertainty")
    @classmethod
    def require_substance(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Review explanation must not be blank")
        return value

    @model_validator(mode="after")
    def validate_decision(self) -> Self:
        if self.reviewer.role == "ai-assistant" and self.decision != "proposed":
            raise ValueError("AI-authored interpretation must remain a proposal")
        if self.decision == "unresolved" and self.conclusion != "unresolved":
            raise ValueError("An unresolved decision cannot establish a conclusion")
        return self


def annotation_sha256(annotation: ReviewAnnotation) -> str:
    return semantic_hash(annotation.model_dump(mode="json"))


class ReviewBatch(DependencyModel):
    contract: Literal["finding-review-batch-v1"] = "finding-review-batch-v1"
    annotations: tuple[ReviewAnnotation, ...] = Field(min_length=1, max_length=256)


class ReviewSidecar(DependencyModel):
    contract: Literal["finding-review-sidecar-v1"] = "finding-review-sidecar-v1"
    report_manifest_sha256: Sha256
    previous_review_sha256: Sha256 | None = None
    previous_annotation_count: StrictInt = Field(default=0, ge=0)
    annotations: tuple[ReviewAnnotation, ...] = Field(min_length=1, max_length=4096)
    vulnerability_total: None = None
    reviewer_identity_assurance: Literal["declared-not-authenticated"] = (
        "declared-not-authenticated"
    )

    @model_validator(mode="after")
    def validate_history(self) -> Self:
        if (self.previous_review_sha256 is None) != (self.previous_annotation_count == 0):
            raise ValueError("Previous review reference and prefix count disagree")
        if self.previous_annotation_count >= len(self.annotations):
            raise ValueError("A new review revision must append annotations")
        current: dict[str, ReviewAnnotation] = {}
        subjects: dict[tuple[str, str, str, str], str] = {}
        for annotation in self.annotations:
            prior = current.get(annotation.review_id)
            owner = subjects.setdefault(annotation.subject.key, annotation.review_id)
            if owner != annotation.review_id:
                raise ValueError(
                    "One finding occurrence cannot acquire duplicate review identities"
                )
            if prior is None:
                if annotation.supersedes_sha256 is not None or annotation.decision != "proposed":
                    raise ValueError("A review must begin with a retained proposal")
            else:
                if annotation.supersedes_sha256 != annotation_sha256(prior):
                    raise ValueError(
                        "Correction must supersede the latest annotation for this review"
                    )
                if annotation.subject != prior.subject or annotation.created_at < prior.created_at:
                    raise ValueError(
                        "Review correction changes its subject or predates its predecessor"
                    )
                if annotation.decision == "accepted" and annotation.conclusion != prior.conclusion:
                    raise ValueError("Use a changed decision when replacing a proposed conclusion")
                if annotation.decision == "proposed" and prior.decision != "proposed":
                    raise ValueError("A new proposal cannot silently replace a human decision")
            current[annotation.review_id] = annotation
        return self


class ReviewManifest(DependencyModel):
    contract: Literal["finding-review-manifest-v1"] = "finding-review-manifest-v1"
    review_sha256: Sha256
    review_bytes: StrictInt = Field(ge=1, le=8 * 1024**2)
    report_manifest_sha256: Sha256
    annotation_count: StrictInt = Field(ge=1, le=4096)
