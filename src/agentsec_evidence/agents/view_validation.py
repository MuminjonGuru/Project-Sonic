from __future__ import annotations

from collections.abc import Mapping
from typing import Literal

from pydantic import Field, model_validator

from agentsec_evidence.agents.inputs import MAX_INPUT_BYTES, plan_agent_input_admission
from agentsec_evidence.agents.models import ArtifactKind
from agentsec_evidence.agents.records import (
    AgentInputReport,
    AgentInputRequest,
    verify_input_report,
)
from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.core.io import model_bytes
from agentsec_evidence.intake.git_verification import GitEvidenceModel
from agentsec_evidence.intake.views import ToolInputView, ToolViewContext, expected_tool_view
from agentsec_evidence.models.contracts import Sha256


class AgentViewAssessment(GitEvidenceModel):
    contract: Literal["agent-view-assessment-v1"] = "agent-view-assessment-v1"
    input_plan_sha256: Sha256
    view_sha256: Sha256
    request_sha256: Sha256
    worker_report_sha256: Sha256
    input_gate_passed: bool
    eligible_paths: tuple[str, ...]
    blocked_policy_paths: tuple[str, ...]
    blockers: tuple[str, ...]
    policy_version: Literal["agent-input-policy-v1"] = "agent-input-policy-v1"
    policy_context: Literal["full-parent-inventory"] = "full-parent-inventory"
    validation_state: Literal["complete"] = "complete"
    execution_authorization: Literal["not-granted"] = "not-granted"
    scanner_executed: Literal[False] = False
    limitations: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_gate(self) -> AgentViewAssessment:
        if self.input_gate_passed != (bool(self.eligible_paths) and not self.blockers):
            raise ValueError("Input gate result differs from validation and policy observations")
        return self


def build_agent_view_request(
    context: ToolViewContext,
    view: ToolInputView,
    *,
    selected_kinds: Mapping[str, ArtifactKind],
) -> AgentInputRequest:
    """Reuse the bounded worker protocol; applicability must be explicit, not filename guesses."""
    if context.plan.tool_id != "agent-audit" or view != expected_tool_view(context):
        raise ValueError("Agent validation requires its own verified tool view")
    paths = {file.source.path for file in view.files}
    if set(selected_kinds) != paths or any(
        kind not in {"python-source", "mcp-config"} for kind in selected_kinds.values()
    ):
        raise ValueError("Every selected file needs an explicit supported artifact kind")
    entries = [record.source for record in context.inventory.records if record.source.path in paths]
    if any(entry.byte_length > MAX_INPUT_BYTES for entry in entries):
        raise ValueError("Selected input exceeds the existing worker file budget")
    request = AgentInputRequest(
        target_snapshot_id=view.parent_snapshot_id,
        inventory=entries,
        selected=dict(selected_kinds),
    )
    if len(model_bytes(request)) > 256 * 1024:
        raise ValueError("Selected request exceeds the existing worker request budget")
    return request


def assess_agent_view_report(
    context: ToolViewContext,
    view: ToolInputView,
    request: AgentInputRequest,
    raw_report: bytes,
) -> AgentViewAssessment:
    expected = build_agent_view_request(context, view, selected_kinds=request.selected)
    raw_request = model_bytes(expected)
    if model_bytes(request) != raw_request:
        raise ValueError("Worker request does not match the verified view")
    report = AgentInputReport.model_validate(load_agent_json(raw_report, max_bytes=4 * 1024 * 1024))
    verify_input_report(report, expected, raw_request)
    # Selection cannot hide repository-level policy, even when the file is not mounted.
    admission = plan_agent_input_admission(
        (check.checked_input() for check in report.checks),
        snapshot_paths=[record.source.path for record in context.inventory.records],
    )
    return AgentViewAssessment(
        input_plan_sha256=view.input_plan_sha256,
        view_sha256=semantic_hash(view.model_dump(mode="json")),
        request_sha256=sha256_bytes(raw_request),
        worker_report_sha256=sha256_bytes(raw_report),
        input_gate_passed=admission.admitted,
        eligible_paths=admission.eligible_paths,
        blocked_policy_paths=admission.blocked_policy_paths,
        blockers=admission.blockers,
        limitations=(
            "Input validation is not research admission, scanner coverage or "
            "vulnerability detection",
            "Full inventory policy filenames and selected-input suppression markers are checked; "
            "excluded content is not parsed",
            "Parent/source replay and view-byte verification are required before "
            "and after execution",
            "Treatment eligibility, licenses and public-source admission remain separate gates",
        ),
    )
