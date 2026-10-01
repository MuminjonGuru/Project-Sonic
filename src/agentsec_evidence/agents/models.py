from __future__ import annotations

from typing import Literal, Self

from pydantic import ConfigDict, Field, StrictInt, model_validator

from agentsec_evidence.models.contracts import (
    ContractModel,
    EvidenceReference,
    InventoryEntry,
    NonEmpty,
    Producer,
)

ArtifactKind = Literal[
    "python-source",
    "mcp-config",
    "agent-config",
    "prompt",
    "skill",
    "memory-config",
    "iac",
    "other",
]
ParseState = Literal["not-run", "parsed", "malformed", "unsupported", "failed"]
AnalysisState = Literal[
    "not-run", "complete", "partial", "failed", "unsupported", "skipped", "unknown"
]


class AgentModel(ContractModel):
    model_config = ConfigDict(frozen=True)


class AgentArtifact(AgentModel):
    """One source occurrence; recognizing or parsing it is not security coverage."""

    contract: Literal["agent-artifact-v1"] = "agent-artifact-v1"
    target_snapshot_id: NonEmpty
    source: InventoryEntry
    kind: ArtifactKind
    format_id: NonEmpty | None
    parse_state: ParseState
    reason: NonEmpty
    limitations: list[NonEmpty] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_input_state(self) -> Self:
        if self.source.path == ".":
            raise ValueError("An artifact must identify a file, not the snapshot root")
        if self.parse_state in {"parsed", "malformed"} and self.format_id is None:
            raise ValueError("A parse observation requires an identified input format")
        return self


class AgentProperty(AgentModel):
    """Finite observable condition, distinct from an upstream rule or proven exploit."""

    contract: Literal["agent-property-v1"] = "agent-property-v1"
    property_id: NonEmpty
    artifact_kind: ArtifactKind
    condition: NonEmpty
    scope: NonEmpty
    evidence_domain: Literal["repository-static"] = "repository-static"
    candidate_native_rules: list[NonEmpty] = Field(min_length=1)
    limitations: list[NonEmpty] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_rule_ids(self) -> Self:
        if len(set(self.candidate_native_rules)) != len(self.candidate_native_rules):
            raise ValueError("Candidate native rule identifiers must be unique")
        return self


class AgentAssessment(AgentModel):
    """Accounting for one artifact/property/producer, not a vulnerability verdict."""

    contract: Literal["agent-assessment-v1"] = "agent-assessment-v1"
    run_id: NonEmpty
    execution_id: NonEmpty | None = None
    artifact: AgentArtifact
    property_id: NonEmpty
    producer: Producer
    support: Literal["supported", "partial", "unsupported", "unknown"]
    state: AnalysisState
    finding_count: StrictInt | None = Field(default=None, ge=0)
    native_exit_code: StrictInt | None = None
    evidence: list[EvidenceReference] = Field(default_factory=list)
    reason: NonEmpty
    limitations: list[NonEmpty] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_analysis_state(self) -> Self:
        # Producer exit codes do not establish success; input/support/evidence must agree.
        if self.native_exit_code is not None and self.execution_id is None:
            raise ValueError("A native exit code requires an execution identifier")
        if self.finding_count is not None and self.execution_id is None:
            raise ValueError("Observed finding counts require an execution identifier")
        if self.state == "complete":
            if self.artifact.parse_state != "parsed" or self.support != "supported":
                raise ValueError("Complete analysis requires parsed input and supported analysis")
            if self.finding_count is None or not self.evidence:
                raise ValueError("Complete analysis requires a count and retained evidence")
        if (
            self.state in {"not-run", "skipped", "unsupported", "unknown"}
            and self.finding_count is not None
        ):
            raise ValueError("Unperformed or unknown analysis has no finding count, not zero")
        if self.finding_count is not None and not self.evidence:
            raise ValueError("Observed finding counts require retained evidence")
        if self.support == "unsupported" and self.state not in {
            "not-run",
            "unsupported",
            "skipped",
        }:
            raise ValueError("Unsupported analysis cannot claim an executed assessment")
        if self.state == "unsupported" and self.support != "unsupported":
            raise ValueError("Unsupported assessment must declare unsupported capability")
        if (
            self.state in {"partial", "failed", "skipped", "unsupported", "unknown"}
            and not self.limitations
        ):
            raise ValueError("Incomplete or unavailable analysis requires explicit limitations")
        return self
