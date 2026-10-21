from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from agentsec_evidence.agents.inputs import MAX_INPUT_BYTES
from agentsec_evidence.custom_rules import orchestration as detector
from agentsec_evidence.custom_rules.orchestration import OrchestrationFileResult, scan_source
from agentsec_evidence.custom_rules.orchestration_catalog import (
    BY_ID,
    CATALOG_SHA256,
    LEGACY_MARKERS,
    RULES,
)

CASES = json.loads(
    (Path(__file__).parents[2] / "test_cases/development/orchestration-v1/cases.json").read_bytes()
)["cases"]


def scan(source: str) -> OrchestrationFileResult:
    return scan_source(source.encode(), path="agent.py")


def ids(result: OrchestrationFileResult) -> list[str]:
    return sorted({item.rule_id for item in result.inventory if item.rule_id})


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_declared_development_case(case: dict[str, Any]) -> None:
    result = scan(case["source"])
    assert result.findings == case["rules"]
    assert ids(result) == case["inventory"]
    assert result.state == ("malformed" if case["rules"] is None else "analyzed")


def test_catalog_preserves_22_ids_without_inventing_alerts() -> None:
    assert [rule.rule_id for rule in RULES] == [f"ORG-{n:03}" for n in range(1, 23)]
    assert Counter(rule.status for rule in RULES) == {"inventory-only": 9, "deferred": 13}
    assert len(CATALOG_SHA256) == 64
    assert set(LEGACY_MARKERS) == {"ORG-099", "ORG-MCP-001"}
    assert {item for case in CASES for item in case["inventory"]} == {
        rule.rule_id for rule in RULES if rule.status == "inventory-only"
    }
    for rule in RULES:
        for related in rule.related_ids:
            assert related in BY_ID and related != rule.rule_id
    with pytest.raises(ValidationError):
        OrchestrationFileResult.model_validate(scan("").model_dump() | {"findings": [{}]})


def test_fixed_vs_nonliteral_arguments_not_risk_levels() -> None:
    fixed = scan("orchestrator.route(agent='worker', task=['fixed'])")
    dynamic = scan("orchestrator.route(agent=choice, task=llm.suggest())")
    assert fixed.findings == dynamic.findings == []
    assert ids(fixed) == ["ORG-002"] and ids(dynamic) == ["ORG-002", "ORG-011"]
    assert [item.shape for item in fixed.inventory[0].argument_shapes] == [
        "literal-syntax",
        "literal-syntax",
    ]
    assert [item.shape for item in dynamic.inventory[0].argument_shapes] == [
        "nonliteral-syntax",
        "nonliteral-syntax",
    ]
    assert fixed.limitations_observed and dynamic.limitations_observed


def test_no_raw_values_or_unrecognized_keyword_names(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    result = scan(
        f"open({str(marker)!r}, 'w').write('DO_NOT_EXPORT_SECRET')\n"
        "orchestrator.forward(data=PRIVATE_MEMORY, PRIVATE_CUSTOM_KEY='PRIVATE_VALUE')"
    )
    assert not marker.exists()
    payload = result.model_dump_json()
    for value in (
        "DO_NOT_EXPORT_SECRET",
        "PRIVATE_MEMORY",
        "PRIVATE_CUSTOM_KEY",
        "PRIVATE_VALUE",
        str(marker),
    ):
        assert value not in payload
    assert result.inventory[0].argument_shapes[1].slot == "other-keyword"


@pytest.mark.parametrize(
    "source",
    [
        "orchestrator.send(data=memory, **extra)",
        "orchestrator.forward(data=memory, data='fixed')",
        "orchestrator.share(*values, memory=state)",
    ],
)
def test_ambiguous_arguments_do_not_become_payload_attribution(source: str) -> None:
    result = scan(source)
    assert ids(result) == ["ORG-001"]
    assert any(item.kind == "unresolved-arguments" for item in result.limitations_observed)


@pytest.mark.parametrize(
    "source",
    [
        "orchestrator.forward(data=memory)",
        "orchestrator.forward(context=agent.history)",
        "orchestrator.share(data=memory['recent'])",
        "orchestrator.send(prompt=f'History: {messages}')",
        "orchestrator.send(data={'value': context})",
        "orchestrator.handoff(memory=['fixed', state])",
    ],
)
def test_memory_like_syntax_only(source: str) -> None:
    result = scan(source)
    assert ids(result) == ["ORG-001", "ORG-004"] and result.findings == []


@pytest.mark.parametrize(
    "source",
    [
        "orchestrator.forward(data='memory')",
        "orchestrator.send(agent=memory)",
        "orchestrator.forward(data={'memory': 'fixed'})",
        "orchestrator.forward(data=values[memory])",
        "orchestrator.forward(data=memory if ready else other)",
        "orchestrator.forward(memory)",
    ],
)
def test_no_confused_selector_target_or_positional_flow(source: str) -> None:
    assert ids(scan(source)) == ["ORG-001"]


@pytest.mark.parametrize(
    "source",
    [
        "orchestrator.route(worker.call())",
        "orchestrator.route(agent=choose())",
        "async def f():\n    orchestrator.dispatch(task=await choose())",
    ],
)
def test_only_immediate_call_nesting(source: str) -> None:
    assert ids(scan(source)) == ["ORG-002", "ORG-011"]


@pytest.mark.parametrize(
    "source",
    [
        "orchestrator.route(callback=lambda: worker.call())",
        "orchestrator.route(tasks=[worker.call()])",
        "orchestrator.route(agent=worker.call)",
    ],
)
def test_non_immediate_calls_not_counted_as_nested(source: str) -> None:
    assert ids(scan(source)) == ["ORG-002"]


@pytest.mark.parametrize(
    "source",
    [
        "controller.route(agent=choice)",
        "get_orchestrator().route(agent=choice)",
        "orchestrator_factory.forward(data=memory)",
        "orchestrator.update(response=llm)",
    ],
)
def test_unrecognized_candidates_explicit(source: str) -> None:
    result = scan(source)
    assert ids(result) == [] and result.limitations_observed


def test_receiver_name_is_not_a_verified_type() -> None:
    result = scan(
        "class NonAgent:\n    def send(self, **kwargs): return None\n"
        "orchestrator = NonAgent()\norchestrator.send(data='fixed')"
    )
    assert ids(result) == ["ORG-001"] and result.findings == []
    assert any(item.kind == "unresolved-api" for item in result.limitations_observed)


def test_ordinary_security_controls_and_features_never_alert() -> None:
    result = scan(
        "orchestrator.update_routing_policy(validate(policy))\n"
        "orchestrator.state.get('key')\nsave_orchestrator(state)"
    )
    assert result.findings == []
    assert ids(result) == ["ORG-003", "ORG-005", "ORG-010", "ORG-011"]
    assert all(
        key not in result.model_dump_json() for key in ("risk_score", "confidence", "severity")
    )


@pytest.mark.parametrize(
    "module", ["langchain", "langchain_core", "langgraph", "langchain_classic"]
)
def test_framework_import_not_runtime_support(module: str) -> None:
    assert ids(scan(f"import {module}")) == ["ORG-007"]
    assert ids(scan(f"# import {module}\ntext='{module}'")) == []


def test_import_alias_does_not_change_spelling_inventory() -> None:
    assert ids(scan("import autogen as ag")) == ["ORG-008"]
    assert ids(scan("from .autogen import GroupChat\nimport autogen_fake")) == []
    assert ids(scan("if False:\n    import langchain")) == ["ORG-007"]


@pytest.mark.parametrize(
    "source",
    [
        "x: orchestrator.route()",
        "def f(x: orchestrator.route()): pass",
        "type Alias = orchestrator.route()",
        "f = lambda: orchestrator.route()",
        "[orchestrator.route() for x in xs]",
    ],
)
def test_excluded_annotation_and_scopes(source: str) -> None:
    assert ids(scan(source)) == []


def test_function_defaults_and_class_bases_are_inspected_as_syntax() -> None:
    assert ids(scan("def f(x=orchestrator.route()): pass")) == ["ORG-002"]
    assert ids(scan("class C(orchestrator.route()): pass")) == ["ORG-002"]


def test_stable_source_bound_observation_ids_and_utf8_spans() -> None:
    source = "x='\u00e9'; orchestrator.route(\n agent=choice\n)"
    result = scan(source)
    assert result.model_dump_json() == scan(source).model_dump_json()
    assert OrchestrationFileResult.model_validate_json(result.model_dump_json()) == result
    assert result.inventory[0].location.start_utf8_byte_column == len("x='\u00e9'; ".encode())
    assert result.inventory[0].location.end_line == 3
    changed = scan(source + "\n")
    assert result.inventory[0].record_id != changed.inventory[0].record_id


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
    assert scan("orchestrator.route()").state == "failed"


def test_record_budget_never_truncated_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(detector, "MAX_RECORDS", 1)
    result = scan("orchestrator.route()")
    assert result.state == "failed" and result.findings is None and not result.inventory


def test_argument_budget_never_truncated_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(detector, "MAX_ARGUMENTS", 1)
    result = scan("orchestrator.route(agent=choice, task=value)")
    assert result.state == "failed" and result.findings is None


def test_nested_inventory_has_no_duplicate_ids() -> None:
    result = scan("orchestrator.route(agent=choose(), task=next_task())")
    assert ids(result) == ["ORG-002", "ORG-011"]
    assert len(result.inventory) == 2
    assert len({item.record_id for item in result.inventory + result.limitations_observed}) == (
        len(result.inventory) + len(result.limitations_observed)
    )
