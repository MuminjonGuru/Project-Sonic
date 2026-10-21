from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from agentsec_evidence.agents.inputs import MAX_INPUT_BYTES
from agentsec_evidence.custom_rules import agent_to_agent as detector
from agentsec_evidence.custom_rules.agent_to_agent import AgentToAgentFileResult, scan_source
from agentsec_evidence.custom_rules.agent_to_agent_catalog import (
    BY_ID,
    CATALOG_SHA256,
    LEGACY_MARKERS,
    RULES,
)

CASES = json.loads(
    (Path(__file__).parents[2] / "test_cases/development/agent-to-agent-v1/cases.json").read_bytes()
)["cases"]


def scan(source: str) -> AgentToAgentFileResult:
    return scan_source(source.encode(), path="agent.py")


def ids(result: AgentToAgentFileResult) -> list[str]:
    return sorted({item.rule_id for item in result.inventory if item.rule_id})


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_declared_development_case(case: dict[str, Any]) -> None:
    result = scan(case["source"])
    assert result.findings == case["rules"]
    assert ids(result) == case["inventory"]
    assert result.state == ("malformed" if case["rules"] is None else "analyzed")


def test_all_actual_ids_and_no_invented_alerts() -> None:
    assert [rule.rule_id for rule in RULES] == [
        f"A2A-{n:03}" for n in (*range(1, 19), *range(101, 109))
    ]
    assert Counter(rule.status for rule in RULES) == {"inventory-only": 10, "deferred": 16}
    assert len(CATALOG_SHA256) == 64
    assert set(LEGACY_MARKERS) == {"A2A-099", "A2A-MCP-001"}
    assert {item for case in CASES for item in case["inventory"]} == {
        rule.rule_id for rule in RULES if rule.status == "inventory-only"
    }
    for rule in RULES:
        assert all(item in BY_ID and item != rule.rule_id for item in rule.related_ids)
    with pytest.raises(ValidationError):
        AgentToAgentFileResult.model_validate(scan("").model_dump() | {"findings": [{}]})


def test_fixed_and_nonliteral_shapes_are_not_risk_levels() -> None:
    fixed = scan("agent.call(agent='worker', task=['fixed'])")
    dynamic = scan("agent.call(agent=choice, task=llm.suggest())")
    assert fixed.findings == dynamic.findings == []
    assert ids(fixed) == ids(dynamic) == ["A2A-001"]
    assert [item.shape for item in fixed.inventory[0].argument_shapes] == ["literal-syntax"] * 2
    assert [item.shape for item in dynamic.inventory[0].argument_shapes] == [
        "nonliteral-syntax"
    ] * 2
    assert fixed.limitations_observed and dynamic.limitations_observed


def test_no_execution_or_raw_value_export(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    result = scan(
        f"open({str(marker)!r}, 'w').write('DO_NOT_EXPORT_SECRET')\n"
        "agent.forward(data=PRIVATE_MEMORY, PRIVATE_KEY='PRIVATE_VALUE')"
    )
    assert not marker.exists()
    payload = result.model_dump_json()
    for value in (
        "DO_NOT_EXPORT_SECRET",
        "PRIVATE_MEMORY",
        "PRIVATE_KEY",
        "PRIVATE_VALUE",
        str(marker),
    ):
        assert value not in payload
    assert result.inventory[0].argument_shapes[1].slot == "other-keyword"


@pytest.mark.parametrize(
    "source",
    [
        "agent.call(*values, **extra)",
        "agent.call(task=first, task=second)",
    ],
)
def test_ambiguous_arguments_remain_syntax(source: str) -> None:
    result = scan(source)
    assert ids(result) == ["A2A-001"]
    assert any(item.kind == "unresolved-arguments" for item in result.limitations_observed)


@pytest.mark.parametrize(
    "source",
    [
        "agent.call(agent2.call())",
        "agent.forward(data=agent3.route(task='fixed'))",
        "async def f():\n    agent.route(task=await agent2.call())",
    ],
)
def test_immediate_agent_like_nesting(source: str) -> None:
    result = scan(source)
    assert ids(result) == ["A2A-001", "A2A-101"] and result.findings == []
    assert sum(item.rule_id == "A2A-101" for item in result.inventory) == 1


@pytest.mark.parametrize(
    "source",
    [
        "agent.call(helper())",
        "agent.call(agent2.response)",
        "agent.call(agent2.call)",
        "agent.call(callback=lambda: agent2.call())",
        "agent.call([agent2.call()])",
        "agent.call(task=agent2.call() if ready else other)",
        "agent.call(*agent2.call())",
        "agent.sign(agent2.call())",
    ],
)
def test_no_inferred_nesting_outside_supported_shape(source: str) -> None:
    assert "A2A-101" not in ids(scan(source))


@pytest.mark.parametrize(
    "source",
    [
        "agent.context = agent2.memory",
        "self.agent2.input = app.agent1.state",
        "agent.memory: object = agent2.memory",
    ],
)
def test_direct_state_copy_is_inventory(source: str) -> None:
    result = scan(source)
    assert ids(result) == ["A2A-004"] and result.findings == []
    assert any(item.kind == "unresolved-property-semantics" for item in result.limitations_observed)


@pytest.mark.parametrize(
    "source",
    [
        "agent.role = agent2.role",
        "agent.permissions = agent2.permissions",
        "agent.role = agent.role",
    ],
)
def test_role_copy_does_not_establish_distinct_identity_or_drift(source: str) -> None:
    assert ids(scan(source)) == ["A2A-105"] and scan(source).findings == []


@pytest.mark.parametrize(
    "source",
    [
        "agent.role = get_role()",
        "agent.role = agent2.permissions",
        "agent.role, agent2.role = values",
        "agent.permissions += agent2.permissions",
        "agent.role = agent2.role if ready else backup",
    ],
)
def test_unsupported_property_flow_explicit(source: str) -> None:
    result = scan(source)
    assert ids(result) == []
    assert any(item.kind == "unsupported-property-flow" for item in result.limitations_observed)


def test_no_duplicate_assignment_observations() -> None:
    result = scan("agent.role = agent2.role = agent3.role")
    assert len(result.inventory) == 2
    assert len({item.record_id for item in result.inventory}) == 2


def test_authorize_and_verify_not_duplicate_or_vulnerable() -> None:
    result = scan("agent.authorize(agent2)\nagent.verify(agent2)\nagent.sign(agent2)")
    assert [item.rule_id for item in result.inventory] == ["A2A-003", "A2A-005", "A2A-005"]
    assert result.findings == []
    assert all(
        key not in result.model_dump_json() for key in ("risk_score", "severity", "confidence")
    )


@pytest.mark.parametrize(
    "source",
    [
        "agent.update(prompt='I am agent2')",
        "agent.update(prompt=llm.text)",
        "agent.rewrite_system_prompt(agent=agent2)",
        "agent.impersonate(agent=agent2)",
    ],
)
def test_identity_names_not_impersonation_verdict(source: str) -> None:
    assert ids(scan(source)) == ["A2A-002"] and scan(source).findings == []


@pytest.mark.parametrize(
    "source",
    [
        "worker.call(agent2)",
        "get_agent().call(agent2)",
        "agent02.call(agent2)",
        "agent.run(agent2)",
        "agent.update(response=answer)",
    ],
)
def test_unrecognized_candidates_explicit(source: str) -> None:
    result = scan(source)
    assert ids(result) == [] and result.limitations_observed


def test_named_receiver_not_an_inferred_type() -> None:
    result = scan(
        "class NonAgent:\n    def call(self, x): return x\nagent = NonAgent()\nagent.call(1)"
    )
    assert ids(result) == ["A2A-001"] and result.findings == []
    assert result.limitations_observed


@pytest.mark.parametrize(
    "module", ["langchain", "langchain_core", "langgraph", "langchain_classic"]
)
def test_framework_import_only(module: str) -> None:
    assert ids(scan(f"import {module} as alias")) == ["A2A-007"]
    assert ids(scan(f"# import {module}\ntext='{module}'")) == []


def test_no_framework_from_relative_or_lookalike_import() -> None:
    assert ids(scan("from .autogen import GroupChat\nimport autogen_fake")) == []
    assert ids(scan("if False:\n    import autogen")) == ["A2A-008"]


@pytest.mark.parametrize(
    "source",
    [
        "x: agent.call()",
        "def f(x: agent.call()): pass",
        "type Alias = agent.call()",
        "f = lambda: agent.call()",
        "[agent.call() for x in xs]",
    ],
)
def test_excluded_scopes(source: str) -> None:
    assert ids(scan(source)) == []


def test_defaults_and_bases_inspected_as_syntax() -> None:
    assert ids(scan("def f(x=agent.call()): pass")) == ["A2A-001"]
    assert ids(scan("class C(agent.call()): pass")) == ["A2A-001"]


def test_source_bound_ids_and_utf8_spans() -> None:
    source = "x='\u00e9'; agent.call(\n agent2\n)"
    result = scan(source)
    assert result.model_dump_json() == scan(source).model_dump_json()
    assert AgentToAgentFileResult.model_validate_json(result.model_dump_json()) == result
    assert result.inventory[0].location.start_utf8_byte_column == len("x='\u00e9'; ".encode())
    assert result.inventory[0].location.end_line == 3
    assert result.inventory[0].record_id != scan(source + "\n").inventory[0].record_id


def test_limits_and_null_not_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    for data in (b"def broken(:", b"\xff"):
        result = scan_source(data, path="broken.py")
        assert result.state == "malformed" and result.findings is None
    result = scan_source(b"{}", path="mcp.json")
    assert result.state == "unsupported" and result.findings is None
    assert scan_source(b"x" * (MAX_INPUT_BYTES + 1), path="large.py").state == "failed"
    with pytest.raises(ValueError):
        scan_source(b"", path="../escape.py")
    monkeypatch.setattr(detector, "MAX_AST_NODES", 3)
    assert scan("agent.call()").state == "failed"


def test_record_budget_never_truncated_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(detector, "MAX_RECORDS", 1)
    result = scan("agent.call()")
    assert result.state == "failed" and result.findings is None and not result.inventory


def test_argument_budget_never_truncated_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(detector, "MAX_ARGUMENTS", 1)
    result = scan("agent.call(agent=choice, task=value)")
    assert result.state == "failed" and result.findings is None
