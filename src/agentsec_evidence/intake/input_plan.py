from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, StringConstraints, field_validator, model_validator

from agentsec_evidence.agents.inventory import ArtifactInventory, artifact_inventory_semantic_sha256
from agentsec_evidence.agents.validation import canonical_artifact_path
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.intake.git_verification import GitSourceVerification, bind_inventory_to_git
from agentsec_evidence.models.contracts import ContractModel, NonEmpty, Sha256

Reason = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=1000)]


class InputPlanModel(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class InputSelection(InputPlanModel):
    path: Annotated[str, StringConstraints(min_length=1, max_length=4096)]
    source_sha256: Sha256
    disposition: Literal["selected", "excluded"]
    reason: Reason

    @field_validator("path")
    @classmethod
    def canonical_path(cls, value: str) -> str:
        return canonical_artifact_path(value)


class ToolInputPlan(InputPlanModel):
    contract: Literal["tool-input-plan-v1"] = "tool-input-plan-v1"
    target_snapshot_id: NonEmpty
    artifact_inventory_semantic_sha256: Sha256
    git_verification_sha256: Sha256
    tool_id: NonEmpty
    profile_id: NonEmpty
    profile_sha256: Sha256
    selections: tuple[InputSelection, ...] = Field(max_length=10_000)
    execution_authorization: Literal["not-granted"] = "not-granted"
    policy_and_suppression_review: Literal["not-performed"] = "not-performed"
    parser_validation: Literal["not-run"] = "not-run"

    @model_validator(mode="after")
    def unique_paths(self) -> ToolInputPlan:
        paths = [selection.path for selection in self.selections]
        if paths != sorted(paths) or len({path.casefold() for path in paths}) != len(paths):
            raise ValueError("Selections must be sorted, unique and portable")
        return self


def _profile_hash(data: bytes) -> str:
    if not data or len(data) > 1024 * 1024:
        raise ValueError("A non-empty profile of at most 1 MiB is required")
    return sha256_bytes(data)


def verify_tool_input_plan(
    plan: ToolInputPlan,
    inventory: ArtifactInventory,
    verification: GitSourceVerification,
    *,
    profile_bytes: bytes,
) -> None:
    """Account for every file, but never convert a plan into scanner admission."""
    checked = ToolInputPlan.model_validate(plan.model_dump(mode="json"))
    bind_inventory_to_git(inventory, verification)
    if (
        checked.target_snapshot_id != inventory.snapshot.snapshot_id
        or checked.artifact_inventory_semantic_sha256
        != artifact_inventory_semantic_sha256(inventory)
        or checked.git_verification_sha256 != semantic_hash(verification.model_dump(mode="json"))
        or checked.profile_sha256 != _profile_hash(profile_bytes)
    ):
        raise ValueError("Input plan refers to different inventory, Git evidence or profile")
    expected = {r.source.path: r.source.sha256 for r in inventory.records}
    actual = {s.path: s.source_sha256 for s in checked.selections}
    if expected != actual:
        raise ValueError("Input plan must account for every repository file and content hash")


def build_tool_input_plan(
    *,
    inventory: ArtifactInventory,
    verification: GitSourceVerification,
    tool_id: str,
    profile_id: str,
    profile_bytes: bytes,
    selected_paths: Sequence[str],
    selected_reason: str,
    exclusions: Mapping[str, str],
) -> ToolInputPlan:
    selected = tuple(canonical_artifact_path(path) for path in selected_paths)
    excluded = {canonical_artifact_path(path): reason for path, reason in exclusions.items()}
    if len(set(selected)) != len(selected) or set(selected).intersection(excluded):
        raise ValueError("Ambiguous selected/excluded input paths")
    sources = {record.source.path: record.source.sha256 for record in inventory.records}
    if set(selected).union(excluded) != set(sources):
        raise ValueError("Every repository file needs an explicit selected/excluded decision")
    selected_set = set(selected)
    plan = ToolInputPlan(
        target_snapshot_id=inventory.snapshot.snapshot_id,
        artifact_inventory_semantic_sha256=artifact_inventory_semantic_sha256(inventory),
        git_verification_sha256=semantic_hash(verification.model_dump(mode="json")),
        tool_id=tool_id,
        profile_id=profile_id,
        profile_sha256=_profile_hash(profile_bytes),
        selections=tuple(
            InputSelection(
                path=path,
                source_sha256=digest,
                disposition="selected" if path in selected_set else "excluded",
                reason=selected_reason if path in selected_set else excluded[path],
            )
            for path, digest in sorted(sources.items())
        ),
    )
    verify_tool_input_plan(plan, inventory, verification, profile_bytes=profile_bytes)
    return plan
