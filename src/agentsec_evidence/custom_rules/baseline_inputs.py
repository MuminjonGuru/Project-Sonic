"""Finite authored baseline groups, not public-repository sharding or admission."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, cast

from pydantic import JsonValue

from agentsec_evidence.agents.inputs import plan_agent_input_admission
from agentsec_evidence.agents.records import (
    AgentInputCheck,
    AgentInputReport,
    AgentInputRequest,
    verify_input_report,
)
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.custom_rules.shared_inputs import PreparedShared
from agentsec_evidence.models.contracts import InventoryEntry
from agentsec_evidence.reporting.custom_contracts import FAMILIES
from agentsec_evidence.research.models import ResearchInput, SemgrepResearchScope

PROFILE_PATH = "configs/research/semgrep-python-candidate-v1.json"
PROFILE_SHA = "ce4b8517a4042bb247ac641250f5d9428e8a5f985db69d36f2d9fef28f09e23c"
ROLES = ("research", "repository-policy", "agent-audit")
Role = Literal["research", "repository-policy", "agent-audit"]


def authored_snapshot_id(sources: dict[str, bytes]) -> str:
    # Include all contract defaults (notably schema_version) in the canonical identity.
    return semantic_hash(
        cast(
            JsonValue,
            [
                InventoryEntry(
                    path=path,
                    sha256=sha256_bytes(raw),
                    byte_length=len(raw),
                    media_type="text/x-python",
                ).model_dump(mode="json")
                for path, raw in sorted(sources.items())
            ],
        )
    )


def group_requests(prepared: PreparedShared) -> dict[str, AgentInputRequest]:
    """Keep the original registry grouping; expected rule labels do not select inputs."""
    return {
        family.key: AgentInputRequest(
            target_snapshot_id=prepared.plan.snapshot_id,
            inventory=[
                item for item in prepared.plan.inventory if item.path.startswith(family.key + "/")
            ],
            selected={
                path: "python-source"
                for path in sorted(prepared.inputs)
                if path.startswith(family.key + "/")
            },
        )
        for family in FAMILIES
    }


@dataclass(frozen=True)
class BaselineSelection:
    scope: SemgrepResearchScope | None
    checks: tuple[AgentInputCheck, ...]
    exclusions: tuple[dict[str, Any], ...]
    agent_blockers: tuple[str, ...]

    def record(self) -> dict[str, Any]:
        return {
            "contract": "authored-baseline-selection-v1",
            "scope": self.scope.model_dump(mode="json") if self.scope else None,
            "excluded": list(self.exclusions),
            "agent_blockers": list(self.agent_blockers),
            "policy": "parsed-authored-cases-only; refuse-agent-group-on-policy-blocker",
        }


def select_baseline(
    request: AgentInputRequest, request_raw: bytes, report: AgentInputReport
) -> BaselineSelection:
    verify_input_report(report, request, request_raw)
    if request.model_dump_json().encode() != request_raw:
        raise ValueError("Unexpected request serialization")
    checks = tuple(sorted(report.checks, key=lambda c: c.artifact.source.path))
    # Only the isolated parser determines eligibility. A rule assertion is not a parser oracle.
    eligible = tuple(c for c in checks if c.artifact.parse_state == "parsed")
    excluded = tuple(
        {
            "path": c.artifact.source.path,
            "sha256": c.artifact.source.sha256,
            "state": c.artifact.parse_state,
            "reason": c.artifact.reason,
            "baseline_findings": None,
        }
        for c in checks
        if c.artifact.parse_state != "parsed"
    )
    admission = plan_agent_input_admission(
        (c.checked_input() for c in eligible), snapshot_paths=request.selected
    )
    scope = None
    if eligible:
        selected = tuple(
            ResearchInput.model_validate(c.artifact.source.model_dump()) for c in eligible
        )
        scope = SemgrepResearchScope(
            target_snapshot_id=request.target_snapshot_id,
            selection_sha256=semantic_hash(
                cast(
                    JsonValue,
                    {
                        "treatment": "authored-baseline-groups-v1",
                        "request_sha256": sha256_bytes(request_raw),
                        "selected": [e.model_dump(mode="json") for e in selected],
                        "excluded": list(excluded),
                    },
                )
            ),
            profile_sha256=PROFILE_SHA,
            selected_files=selected,
        )
    return BaselineSelection(scope, eligible, excluded, admission.blockers)


def planned_rows(repetitions: int) -> list[dict[str, Any]]:
    if type(repetitions) is not int or not 1 <= repetitions <= 3:
        raise ValueError("One to three fresh repetitions required")
    return [
        {
            "group": family.key,
            "repetition": repetition,
            "role": role,
            "key": f"runs/r{repetition:02d}/{family.key}/{role}",
            "state": "not-run",
            "finding_records": None,
            "duration_ns": None,
            "semantic_sha256": None,
            "reasons": [],
        }
        for repetition in range(1, repetitions + 1)
        for family in FAMILIES
        for role in ROLES
    ]


def repeatability(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results = []
    for family in FAMILIES:
        for role in ROLES:
            cells = [r for r in rows if r["group"] == family.key and r["role"] == role]
            observed = [r["semantic_sha256"] for r in cells if r["state"] == "observed"]
            results.append(
                {
                    "group": family.key,
                    "role": role,
                    "observed_repetitions": len(observed),
                    "state": "not-assessed"
                    if len(observed) < 2 or len(observed) != len(cells)
                    else "equal"
                    if len(set(observed)) == 1
                    else "different",
                }
            )
    return results
