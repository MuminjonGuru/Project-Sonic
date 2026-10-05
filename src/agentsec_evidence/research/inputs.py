from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from agentsec_evidence.agents.records import (
    AgentInputReport,
    AgentInputRequest,
    verify_input_report,
)
from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.core.io import atomic_write_model
from agentsec_evidence.intake.input_plan import build_tool_input_plan
from agentsec_evidence.intake.views import (
    ToolInputView,
    ToolViewContext,
    expected_tool_view,
    materialize_tool_view,
    replay_parent_source,
    verify_materialized_tool_view,
)
from agentsec_evidence.models.contracts import InventoryEntry
from agentsec_evidence.research.models import (
    MAX_REPORT_BYTES,
    ResearchInput,
    SemgrepResearchScope,
    load_research_profile,
)
from agentsec_evidence.research.policy import SemgrepPolicyAssessment, assess_semgrep_policy


@dataclass(frozen=True)
class ResearchPreparation:
    policy: SemgrepPolicyAssessment
    scope: SemgrepResearchScope | None


def prepare_research_inputs(context: ToolViewContext, source: Path) -> ResearchPreparation:
    profile = load_research_profile(context.profile_bytes)
    if context.plan.tool_id != "semgrep" or context.plan.profile_id != profile.profile_id:
        raise ValueError("Research plan must identify the pinned Semgrep candidate")
    selected = expected_tool_view(context)
    files = replay_parent_source(context, source)
    policy = assess_semgrep_policy(files)
    if policy.blockers:
        return ResearchPreparation(policy, None)
    scope = SemgrepResearchScope(
        target_snapshot_id=context.inventory.snapshot.snapshot_id,
        selection_sha256=selected.input_plan_sha256,
        profile_sha256=sha256_bytes(context.profile_bytes),
        selected_files=tuple(
            ResearchInput(
                path=f.source.path,
                sha256=f.sha256,
                byte_length=len(files[f.source.path]),
                media_type="text/x-python",
            )
            for f in selected.files
        ),
        policy_files=policy.files,
    )
    return ResearchPreparation(policy, scope)


def research_mount_context(
    context: ToolViewContext,
    preparation: ResearchPreparation,
) -> ToolViewContext:
    """A separate copy plan includes policy dependencies without selecting them for analysis."""
    scope = preparation.scope
    if scope is None or preparation.policy.blockers:
        raise ValueError("Refused policy cannot be materialized")
    paths = [entry.path for entry in (*scope.selected_files, *scope.policy_files)]
    plan = build_tool_input_plan(
        inventory=context.inventory,
        verification=context.verification,
        tool_id="semgrep",
        profile_id=context.plan.profile_id,
        profile_bytes=context.profile_bytes,
        selected_paths=paths,
        selected_reason="Scanner source or required policy bytes; see separate research scope",
        exclusions={
            f.source.path: "Not mounted; retained in full parent verification"
            for f in context.verification.files
            if f.source.path not in paths
        },
    )
    return ToolViewContext(
        context.inventory,
        context.verification,
        plan,
        context.profile_bytes,
        context.raw_commit,
        context.raw_tree,
    )


def materialize_research_inputs(
    context: ToolViewContext,
    *,
    source: Path,
    output: Path,
) -> tuple[ResearchPreparation, ToolInputView | None]:
    preparation = prepare_research_inputs(context, source)
    if preparation.scope is None:
        return preparation, None
    mount_context = research_mount_context(context, preparation)
    view = materialize_tool_view(mount_context, source_root=source, output=output)
    atomic_write_model(output / "policy.json", preparation.policy)
    atomic_write_model(output / "scope.json", preparation.scope)
    return preparation, view


def replay_research_inputs(
    context: ToolViewContext,
    *,
    source: Path,
    preparation: ResearchPreparation,
    view: ToolInputView,
    target: Path,
) -> None:
    if prepare_research_inputs(context, source) != preparation:
        raise ValueError("Research input or policy assessment changed")
    verify_materialized_tool_view(view, research_mount_context(context, preparation), target)


def research_worker_request(scope: SemgrepResearchScope) -> AgentInputRequest:
    scope = SemgrepResearchScope.model_validate(scope.model_dump(mode="json"))
    return AgentInputRequest(
        target_snapshot_id=scope.target_snapshot_id,
        inventory=[
            InventoryEntry.model_validate(item.model_dump(mode="json"))
            for item in (*scope.selected_files, *scope.policy_files)
        ],
        selected={entry.path: "python-source" for entry in scope.selected_files},
    )


def assess_research_syntax(
    request: AgentInputRequest, raw_request: bytes, raw_report: bytes
) -> bool:
    # A caller cannot substitute a valid report belonging to different serialized inputs.
    decoded = AgentInputRequest.model_validate(
        load_agent_json(raw_request, max_bytes=MAX_REPORT_BYTES)
    )
    if semantic_hash(decoded.model_dump(mode="json")) != semantic_hash(
        request.model_dump(mode="json")
    ):
        raise ValueError("Serialized worker request differs")
    report = AgentInputReport.model_validate(
        load_agent_json(raw_report, max_bytes=MAX_REPORT_BYTES)
    )
    verify_input_report(report, request, raw_request)
    return all(check.artifact.parse_state == "parsed" for check in report.checks)
