from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, StrictInt, model_validator

from agentsec_evidence.agents.inputs import CheckedAgentInput
from agentsec_evidence.agents.models import AgentArtifact, AgentAssessment, AgentModel, ArtifactKind
from agentsec_evidence.agents.validation import canonical_artifact_path
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.models.contracts import InventoryEntry, NonEmpty, Sha256

Count = Annotated[StrictInt, Field(ge=0)]


class AgentInputRequest(AgentModel):
    contract: Literal["agent-input-request-v1"] = "agent-input-request-v1"
    target_snapshot_id: NonEmpty
    inventory: list[InventoryEntry] = Field(max_length=64)
    selected: dict[str, ArtifactKind]

    @model_validator(mode="after")
    def validate_paths(self) -> AgentInputRequest:
        paths = [canonical_artifact_path(item.path) for item in self.inventory]
        if len({path.casefold() for path in paths}) != len(paths):
            raise ValueError("Ambiguous input inventory")
        if not set(self.selected).issubset(paths):
            raise ValueError("Selected input absent from inventory")
        if sum(item.byte_length for item in self.inventory) > 1024 * 1024:
            raise ValueError("Development input view exceeds 1 MiB")
        return self


class AgentInputCheck(AgentModel):
    artifact: AgentArtifact
    line_count: Count | None
    suppression_lines: list[Annotated[StrictInt, Field(ge=1)]]

    def checked_input(self) -> CheckedAgentInput:
        return CheckedAgentInput(self.artifact, self.line_count, tuple(self.suppression_lines))


class AgentInputReport(AgentModel):
    contract: Literal["agent-input-report-v1"] = "agent-input-report-v1"
    request_sha256: Sha256
    checks: list[AgentInputCheck]


def verify_input_report(report: AgentInputReport, request: AgentInputRequest, raw: bytes) -> None:
    """Bind worker observations to the exact request and immutable file inventory."""
    if report.request_sha256 != sha256_bytes(raw):
        raise ValueError("Worker response refers to another request")
    paths = [item.artifact.source.path for item in report.checks]
    if len(set(paths)) != len(paths) or set(paths) != set(request.selected):
        raise ValueError("Worker response input accounting differs")
    expected = {item.path: item for item in request.inventory}
    for check in report.checks:
        artifact = check.artifact
        if (
            artifact.source != expected[artifact.source.path]
            or artifact.target_snapshot_id != request.target_snapshot_id
            or artifact.kind != request.selected[artifact.source.path]
        ):
            raise ValueError("Worker response does not match target identity")


class AgentParserReport(AgentModel):
    contract: Literal["agent-parser-report-v1"] = "agent-parser-report-v1"
    parser_id: Literal["agent-audit-json"] = "agent-audit-json"
    parser_version: Literal["0.1.0"] = "0.1.0"
    execution_id: NonEmpty
    source_blob_sha256: Sha256
    parsed_at: AwareDatetime
    native_result_count: Count
    native_error_count: Count = 0
    native_scanned_path_count: Count
    native_skipped_path_count: None = None
    native_skipped_rule_count: None = None
    normalized_finding_count: Count
    unknown_top_level_fields: list[str]
    complete: bool


class AgentRunDetails(AgentModel):
    contract: Literal["agent-run-details-v1"] = "agent-run-details-v1"
    run_id: NonEmpty
    execution_id: NonEmpty
    target_snapshot_id: NonEmpty
    case_id: NonEmpty
    policy_version: Literal["agent-input-policy-v1"] = "agent-input-policy-v1"
    admitted: bool
    blockers: list[str]
    validation_state: Literal["complete", "failed", "not-run"]
    scanner_launched: bool
    input_unchanged: bool
    validation_duration_ns: Count
    scanner_duration_ns: Count
    total_duration_ns: Count
    native_result_count: Count | None
    native_scanned_files: Count | None
    native_suppressed_count: Count | None
    native_tier_suppressed_count: Count | None
    per_file_completion: Literal["not-observable"] = "not-observable"
    assessments: list[AgentAssessment]
    limitations: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_execution(self) -> AgentRunDetails:
        if self.admitted != (self.validation_state == "complete" and not self.blockers):
            raise ValueError("Admission does not match validation/policy state")
        if self.scanner_launched and not self.admitted:
            raise ValueError("Scanner cannot launch without admission")
        if not self.scanner_launched and any(
            value is not None
            for value in (
                self.native_result_count,
                self.native_scanned_files,
                self.native_suppressed_count,
                self.native_tier_suppressed_count,
            )
        ):
            raise ValueError("Unexecuted scanner has unknown native counts")
        for assessment in self.assessments:
            if (
                assessment.run_id != self.run_id
                or assessment.execution_id != self.execution_id
                or assessment.artifact.target_snapshot_id != self.target_snapshot_id
            ):
                raise ValueError("Assessment identity does not match run")
        return self
