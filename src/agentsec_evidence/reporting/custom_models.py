"""Additive common-report v5; historical v1-v4 schemas remain unchanged."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, JsonValue, model_validator

from agentsec_evidence.core.identity import semantic_hash
from agentsec_evidence.dependencies.models import DependencyModel
from agentsec_evidence.reporting.custom_contracts import CustomSummary
from agentsec_evidence.reporting.models import (
    AgentSource,
    Count,
    DependencySource,
    PublicPilotSource,
    ResearchSource,
    SourceBase,
    StaticSource,
)


class CustomSource(SourceBase):
    kind: Literal["custom-repair"] = "custom-repair"
    target_content_sha256: None = None
    source_semantic_sha256: None = None
    summary: CustomSummary

    @model_validator(mode="after")
    def validate_source(self) -> CustomSource:
        expected = "custom-repair-" + semantic_hash({"manifest": self.source_manifest_sha256})[:32]
        state = (
            "partial"
            if any(row.native.execution_state != "complete" for row in self.summary.treatments)
            else "complete"
        )
        if (
            self.run_id != expected
            or self.state != state
            or self.revision != "1.0.0"
            or self.label != "Development repair: " + self.summary.family
        ):
            raise ValueError("Custom source identity or state differs")
        return self


type ExtendedSource = Annotated[
    StaticSource
    | DependencySource
    | AgentSource
    | ResearchSource
    | PublicPilotSource
    | CustomSource,
    Field(discriminator="kind"),
]


class CustomCommonReport(DependencyModel):
    contract: Literal["common-report-v5"] = "common-report-v5"
    generated_at: AwareDatetime
    sensitivity: Literal["internal"] = "internal"
    sources: list[ExtendedSource] = Field(min_length=1, max_length=32)
    sarif_runs: Count
    counting_policy: str = (
        "Keep sources, treatments, repeats and comparison paths separate. Inventory, deferred IDs "
        "and overlaps are not independent vulnerabilities; no summed vulnerability total."
    )
    limitations: list[str] = Field(
        default_factory=lambda: [
            "This derivative is not a new scan or independent security adjudication.",
            "Development repair cases are not one public repository or held-out benchmark.",
            "Evidence can contain source expressions; not release or screen-sharing cleared.",
            "Custom HTML, review-sidecar binding and benchmark scoring are not yet supported.",
        ]
    )
    exporter: Literal["agentsec-evidence-common-report/2"] = "agentsec-evidence-common-report/2"
    provenance: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def require_custom_source(self) -> CustomCommonReport:
        if not any(isinstance(source, CustomSource) for source in self.sources):
            raise ValueError("Version five requires a repaired-worker source")
        return self
