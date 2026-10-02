from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field

from agentsec_evidence.agents.models import AgentModel, ArtifactKind, ParseState
from agentsec_evidence.agents.validation import canonical_artifact_path, load_agent_json
from agentsec_evidence.core.io import atomic_write_bytes

APPROVED_CASES = frozenset(
    {
        "python-positive",
        "python-corrected",
        "python-near-miss",
        "python-malformed",
        "python-inline-suppression",
        "python-excluded-yaml",
        "python-excluded-yml",
        "python-excluded-visible-yaml",
        "mcp-positive",
        "mcp-corrected",
        "mcp-near-miss",
        "mcp-malformed",
        "unsupported-text",
    }
)


class DevelopmentCase(AgentModel):
    id: str
    property_id: str
    artifact_kind: ArtifactKind
    input_path: str
    content: str
    expected_parse: ParseState
    expected_condition: Literal["present", "absent", "not-assessable"]
    policy_observation: Literal["none", "target-exclusion", "inline-suppression"]
    extra_files: dict[str, str]
    rationale: str


class DevelopmentCases(AgentModel):
    case_set: Literal["agent-artifact-development-v1"]
    role: Literal["development-not-held-out"]
    provenance: str
    cases: list[DevelopmentCase] = Field(min_length=13, max_length=13)


def load_development_case(project: Path, case_id: str) -> tuple[DevelopmentCase, bytes]:
    if case_id not in APPROVED_CASES:
        raise ValueError("Only the thirteen approved development case IDs are available")
    raw = (project / "test_cases/development/agent-artifacts/cases.json").read_bytes()
    cases = DevelopmentCases.model_validate(load_agent_json(raw, max_bytes=256 * 1024))
    if {case.id for case in cases.cases} != APPROVED_CASES:
        raise ValueError("Development case registry differs from admitted scope")
    case = next(item for item in cases.cases if item.id == case_id)
    return case, raw


def materialize_case(case: DevelopmentCase, destination: Path) -> None:
    files = {case.input_path: case.content, **case.extra_files}
    if case.input_path in case.extra_files:
        raise ValueError("Fixture path collision")
    names = [canonical_artifact_path(path) for path in files]
    if len({name.casefold() for name in names}) != len(names):
        raise ValueError("Portable fixture path collision")
    destination.mkdir(parents=True, exist_ok=False)
    for path, content in files.items():
        data = content.encode("utf-8")
        if len(data) > 256 * 1024:
            raise ValueError("Development fixture exceeds input budget")
        atomic_write_bytes(destination / path, data)
