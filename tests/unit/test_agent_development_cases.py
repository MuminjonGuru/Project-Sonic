from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Literal

import pytest
from pydantic import BaseModel, ConfigDict, TypeAdapter

from agentsec_evidence.agents.models import AgentArtifact, AgentProperty, ArtifactKind, ParseState
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.core.paths import normalize_relative_path
from agentsec_evidence.models.contracts import InventoryEntry

ROOT = Path(__file__).resolve().parents[2]


class FixtureCase(BaseModel):
    model_config = ConfigDict(extra="forbid")
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


class CaseSet(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_set: Literal["agent-artifact-development-v1"]
    role: Literal["development-not-held-out"]
    provenance: str
    cases: list[FixtureCase]


CASE_SET = CaseSet.model_validate_json(
    (ROOT / "test_cases/development/agent-artifacts/cases.json").read_bytes()
)


@pytest.mark.parametrize("case", CASE_SET.cases, ids=lambda case: case.id)
def test_authored_case_structure_and_condition(case: FixtureCase) -> None:
    # Only check our authored fixture syntax. This is not a reusable detector or target runner.
    assert normalize_relative_path(case.input_path) == case.input_path
    assert case.rationale
    for path in case.extra_files:
        assert normalize_relative_path(path) == path
        assert path != case.input_path
    if case.artifact_kind == "other":
        assert case.expected_parse == "unsupported"
        assert case.expected_condition == "not-assessable"
        return
    if case.expected_parse == "malformed":
        if case.artifact_kind == "python-source":
            with pytest.raises(SyntaxError):
                ast.parse(case.content)
        else:
            with pytest.raises(json.JSONDecodeError):
                json.loads(case.content)
        assert case.expected_condition == "not-assessable"
        return

    assert case.expected_parse == "parsed"
    if case.artifact_kind == "python-source":
        tree = ast.parse(case.content)
        tools = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
        assert len(tools) == 1
        tool = tools[0]
        assert any(isinstance(item, ast.Name) and item.id == "tool" for item in tool.decorator_list)
        parameters = {item.arg for item in tool.args.args}
        condition = any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "eval"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in parameters
            for node in ast.walk(tool)
        )
    else:
        document = json.loads(case.content)
        server = document["mcpServers"]["local-files"]
        assert server["command"] == "npx"
        assert "@modelcontextprotocol/server-filesystem" in server["args"]
        condition = "/" in server["args"]
    assert condition == (case.expected_condition == "present")


def test_case_set_covers_approved_conditions_and_policy_variants() -> None:
    assert len(CASE_SET.cases) == 13
    assert len({case.id for case in CASE_SET.cases}) == len(CASE_SET.cases)
    properties = TypeAdapter(list[AgentProperty]).validate_json(
        (ROOT / "configs/agent-artifacts/properties.json").read_bytes()
    )
    assert {case.property_id for case in CASE_SET.cases} == {
        record.property_id for record in properties
    }
    for prefix in ("python", "mcp"):
        for suffix in ("positive", "corrected", "near-miss", "malformed"):
            assert any(case.id == f"{prefix}-{suffix}" for case in CASE_SET.cases)
    exclusions = [case for case in CASE_SET.cases if case.policy_observation == "target-exclusion"]
    assert {path for case in exclusions for path in case.extra_files} == {
        ".agent-audit.yaml",
        ".agent-audit.yml",
        "agent-audit.yaml",
    }
    for case in exclusions:
        assert case.expected_condition == "present"
        assert list(case.extra_files.values()) == ["scan:\n  exclude:\n    - agent.py\n"]
    suppressed = next(case for case in CASE_SET.cases if case.id == "python-inline-suppression")
    assert "# noaudit" in suppressed.content
    assert suppressed.expected_condition == "present"


def test_fixture_artifact_records_retain_input_identity() -> None:
    for case in CASE_SET.cases:
        content = case.content.encode("utf-8")
        format_id = {
            "python-source": "python-3.13-source",
            "mcp-config": "mcp-servers-json",
        }.get(case.artifact_kind)
        record = AgentArtifact(
            target_snapshot_id=f"authored:{case.id}",
            source=InventoryEntry(
                path=case.input_path,
                sha256=sha256_bytes(content),
                byte_length=len(content),
                media_type="text/plain",
            ),
            kind=case.artifact_kind,
            format_id=format_id,
            parse_state=case.expected_parse,
            reason=case.rationale,
        )
        assert record.source.sha256 == sha256_bytes(content)
        assert AgentArtifact.model_validate_json(record.model_dump_json()) == record
