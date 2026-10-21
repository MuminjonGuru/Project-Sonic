"""Finite source-condition contrasts; not an expanded scanner or vulnerability oracle."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from pydantic import Field

from agentsec_evidence.agents.development import DevelopmentCase
from agentsec_evidence.agents.models import AgentModel
from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.core.identity import sha256_bytes

CASE_SET = "agent-url-contrast-development-v1"
REGISTRY = "test_cases/development/agent-url-contrast/cases.json"
REGISTRY_SHA256 = "cf12a07e2f8a51cbf530944733d7abe91ebca80f97de11907579356473c5c3cc"
RULE_ID = "AGENT-026"
CASE_IDS = (
    "url-caller-tool",
    "url-fixed-helper",
    "url-fixed-tool",
    "url-allowlisted-tool",
)


class URLContrastCases(AgentModel):
    case_set: Literal["agent-url-contrast-development-v1"]
    role: Literal["development-not-held-out"]
    provenance: str
    condition: str
    limitations: list[str] = Field(min_length=1)
    cases: list[DevelopmentCase] = Field(min_length=4, max_length=4)


def load_url_contrast_case(project: Path, case_id: str) -> tuple[DevelopmentCase, bytes]:
    if case_id not in CASE_IDS:
        raise ValueError("Only the four approved request-URL contrast IDs are available")
    raw = (project / REGISTRY).read_bytes()
    if sha256_bytes(raw) != REGISTRY_SHA256:
        raise ValueError("Request-URL contrast registry differs from its frozen admission")
    registry = URLContrastCases.model_validate(load_agent_json(raw, max_bytes=256 * 1024))
    if tuple(case.id for case in registry.cases) != CASE_IDS:
        raise ValueError("Request-URL contrast registry IDs or ordering differ")
    return next(case for case in registry.cases if case.id == case_id), raw


def describe_rule_observation(
    expected_condition: Literal["present", "absent", "not-assessable"],
    rule_ids: Sequence[str] | None,
) -> str:
    """Compare the named claim only; no alert never establishes complete analysis or safety."""
    if rule_ids is None or expected_condition == "not-assessable":
        return "not-assessable"
    reported = RULE_ID in rule_ids
    if expected_condition == "present":
        return "condition-present-rule-reported" if reported else "condition-present-no-rule-report"
    return "condition-absent-rule-reported" if reported else "condition-absent-no-rule-report"
