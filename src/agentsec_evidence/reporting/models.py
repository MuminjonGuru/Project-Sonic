from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, JsonValue

from agentsec_evidence.dependencies.models import DependencyModel, StageComparison
from agentsec_evidence.models.contracts import CoverageRecord, FailureRecord, Sha256, Summary

Count = Annotated[int, Field(ge=0)]


class DependencyStageSummary(DependencyModel):
    stage: str
    state: Literal["complete", "partial", "failed", "unsupported", "missing"]
    observations: Count | None
    identified_unique_packages: Count | None
    eligible_reported_packages: Count | None
    reported_package_advisory_matches: Count | None
    reported_match_occurrences: Count | None
    eligible_package_advisory_matches: Count | None
    unsupported_observations: Count | None
    relationships: Count | None
    per_package_matching_completion: Literal["not-observable"] = "not-observable"


class DependencySummary(DependencyModel):
    contract: Literal["dependency-summary-v1"] = "dependency-summary-v1"
    run_id: str
    state: Literal["complete", "partial", "failed"]
    scope_available: bool
    eligible_unique_packages: Count | None
    separate_local_packages: Count | None
    unsupported_scope_records: Count | None
    ambiguous_projections: Count | None
    database_sha256: Sha256 | None
    stages: list[DependencyStageSummary]
    comparisons: list[StageComparison]
    timing_ns: dict[str, Count]
    limitations: list[str]


class SourceBase(DependencyModel):
    run_id: str
    state: str
    label: str
    revision: str
    target_content_sha256: Sha256 | None
    source_manifest_sha256: Sha256
    source_semantic_sha256: Sha256 | None


class StaticSource(SourceBase):
    kind: Literal["static"] = "static"
    summary: Summary
    coverage: list[CoverageRecord]
    failures: list[FailureRecord]


class DependencySource(SourceBase):
    kind: Literal["dependency"] = "dependency"
    summary: DependencySummary


type ReportSource = Annotated[StaticSource | DependencySource, Field(discriminator="kind")]


class CommonReport(DependencyModel):
    contract: Literal["common-report-v1"] = "common-report-v1"
    generated_at: AwareDatetime
    sensitivity: Literal["internal"] = "internal"
    sources: list[ReportSource]
    sarif_runs: Count
    counting_policy: str = (
        "Keep sources and comparison paths separate; do not sum paired OSV results, "
        "package observations or heterogeneous finding units into a vulnerability total."
    )
    limitations: list[str] = Field(
        default_factory=lambda: [
            "This derivative is not a new scan or an independent security adjudication.",
            "Valid SARIF does not guarantee consumer support; upload compatibility is untested.",
            "Internal evidence has not passed public-release redaction or license clearance.",
        ]
    )
    exporter: str = "agentsec-evidence-common-report/1"
    provenance: dict[str, JsonValue] = Field(default_factory=dict)
