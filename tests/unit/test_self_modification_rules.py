from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from agentsec_evidence.agents.inputs import MAX_INPUT_BYTES
from agentsec_evidence.custom_rules import self_modification as detector
from agentsec_evidence.custom_rules.self_modification import SelfModificationFileResult, scan_source
from agentsec_evidence.custom_rules.self_modification_catalog import (
    BY_ID,
    CATALOG_SHA256,
    LEGACY_MARKERS,
    RULES,
)

CASES = json.loads(
    (
        Path(__file__).parents[2]
        / "test_cases"
        / "development"
        / "self-modification-v1"
        / "cases.json"
    ).read_bytes()
)["cases"]


def scan(source: str) -> SelfModificationFileResult:
    return scan_source(source.encode(), path="agent.py")


def ids(result: SelfModificationFileResult) -> list[str] | None:
    return None if result.findings is None else [item.rule_id for item in result.findings]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_development_case(case: dict[str, Any]) -> None:
    result = scan(case["source"])
    assert ids(result) == case["rules"]
    assert sorted({item.rule_id for item in result.inventory if item.rule_id}) == case["inventory"]
    assert result.state == ("malformed" if case["rules"] is None else "analyzed")


def test_catalog_actual_ids_and_no_duplicate_alert_inflation() -> None:
    assert [rule.rule_id for rule in RULES] == [
        f"SELF-MOD-{n:03}" for n in (*range(1, 16), *range(101, 113))
    ]
    assert Counter(rule.status for rule in RULES) == {
        "active-condition": 3,
        "inventory-only": 10,
        "deferred": 14,
    }
    assert len(CATALOG_SHA256) == 64
    assert set(LEGACY_MARKERS) == {"SELF-MOD-099", "SELF-MOD-MCP-001"}
    assert {item for case in CASES for item in case["rules"] or []} == {
        rule.rule_id for rule in RULES if rule.status == "active-condition"
    }
    assert {item for case in CASES for item in case["inventory"]} == {
        rule.rule_id for rule in RULES if rule.status == "inventory-only"
    }
    assert "MEM-SEC-103" in BY_ID["SELF-MOD-101"].related_ids
    assert "TOOL-EXEC-002" in BY_ID["SELF-MOD-011"].related_ids
    for rule in RULES:
        for related in rule.related_ids:
            if related.startswith("SELF-MOD"):
                assert related in BY_ID and related != rule.rule_id


@pytest.mark.parametrize(
    "source",
    [
        "eval(response, globals=g, locals=l)",
        "import builtins as b\nb.exec(reply, g, l, closure=None)",
        "from builtins import exec as run\nrun(completion)",
        "async def f(response):\n    eval(response)",
        "eval(response.content)",
        "eval('prefix' + response)",
        "eval(f'{reply}')",
    ],
)
def test_known_direct_response_condition(source: str) -> None:
    assert ids(scan(source)) == ["SELF-MOD-011"]


@pytest.mark.parametrize(
    "source",
    [
        "eval = other\neval(response)",
        "exec = other\nexec(memory)",
        "from .custom import eval\neval(response)",
        "def f(response):\n    eval(response)\n    eval = other",
        "import builtins\nbuiltins = other\nbuiltins.eval(response)",
        "eval(response())",
        "eval(response if ready else other)",
        "eval(values[response])",
        "eval({'response': value})",
        "code = response\neval(code)",
        "eval('response')",
    ],
)
def test_no_invented_resolution_or_flow(source: str) -> None:
    assert ids(scan(source)) == []


@pytest.mark.parametrize(
    "source",
    [
        "eval()",
        "eval(source=response)",
        "eval(response, g, globals=h)",
        "eval(response, closure=cells)",
        "exec(response, g, h, cells)",
        "exec(response, source=other)",
        "exec(response, **options)",
        "eval(response, locals=l, locals=m)",
        "exec(*values)",
    ],
)
def test_invalid_or_unknown_call_shape_is_explicit(source: str) -> None:
    result = scan(source)
    assert not result.findings and result.limitations_observed


@pytest.mark.parametrize(
    "source",
    [
        "agent.system_prompt = user_input",
        "self.prompt += value",
        "agent.system_prompt: str = f'{name}'",
        "agent.prompt = format_prompt(value)",
        "agent.prompt = ['fixed', user_input]",
        "agent.prompt = {'content': value}",
        "agent.prompt = {**unknown}",
    ],
)
def test_nonliteral_attribute_syntax_not_taint_claim(source: str) -> None:
    result = scan(source)
    assert ids(result) == ["SELF-MOD-001"]
    assert result.findings and result.findings[0].priority == "low"
    assert any(item.kind == "unresolved-receiver" for item in result.limitations_observed)


@pytest.mark.parametrize(
    "source",
    [
        "agent.prompt = 'fixed'",
        "agent.prompt = f'fixed'",
        "agent.prompt = ['fixed', {'content': 'value'}]",
        "agent.prompt = None",
        "agent.prompt: str",
        "system_prompt = response",
        "agent.user_prompt = response",
        "agent['system_prompt'] = response",
        "setattr(agent, 'prompt', response)",
        "agent.prompt *= response",
        "agent.update_system_prompt(response)",
    ],
)
def test_prompt_near_misses_are_not_injection_claims(source: str) -> None:
    assert not scan(source).findings


def test_fixed_controls_are_not_safe_verdict() -> None:
    result = scan("agent.prompt = 'fixed'")
    assert not result.findings and result.limitations_observed
    assert result.state == "analyzed"


def test_same_statement_prompt_targets_count_once() -> None:
    assert ids(scan("a.prompt = b.system_prompt = value")) == ["SELF-MOD-001"]


def test_annotation_expression_not_executed_or_scanned() -> None:
    assert not scan("agent.prompt: eval(response)\ndef f(x: exec(memory)): pass").findings
    result = scan("type Alias = eval(response)")
    assert not result.findings and result.limitations_observed


@pytest.mark.parametrize("name", ["langchain", "langgraph", "langchain_core", "langchain_classic"])
def test_framework_import_spelling_only(name: str) -> None:
    assert [item.rule_id for item in scan(f"import {name}").inventory] == ["SELF-MOD-008"]
    assert not scan(f"# import {name}\ntext = '{name}'").inventory


def test_relative_or_lookalike_framework_not_claimed() -> None:
    assert not scan("from .langchain import Agent\nimport langchain_fake").inventory


def test_ordinary_controls_do_not_become_risk_scores() -> None:
    result = scan("validate_self(candidate)\nrollback_self()\nversion_tag = 'v2'")
    assert not result.findings
    assert {item.rule_id for item in result.inventory} == {"SELF-MOD-012", "SELF-MOD-013"}
    assert all(word not in result.model_dump_json() for word in ("risk_score", "confidence"))


@pytest.mark.parametrize("loop", ["for i in items", "while ready", "async for i in items"])
def test_loop_inventory_is_not_infinite_loop_claim(loop: str) -> None:
    result = scan(f"async def run():\n    {loop}:\n        agent.update()\n        break")
    assert [item.rule_id for item in result.inventory] == ["SELF-MOD-014"]
    assert not result.findings


def test_nested_function_and_loop_else_not_body_execution() -> None:
    result = scan(
        "for i in items:\n    def later():\n        agent.update()\nelse:\n    agent.update()\n"
    )
    assert not result.findings and not result.inventory


@pytest.mark.parametrize(
    "source",
    [
        "handler = lambda response: eval(response)",
        "[eval(response) for response in values]",
        "eval(sanitize(response))",
        "setattr(agent, 'prompt', value)",
    ],
)
def test_unsupported_constructs_reported(source: str) -> None:
    result = scan(source)
    assert not result.findings and result.limitations_observed


def test_source_bound_ids_locations_and_roundtrip() -> None:
    source = "x='\u00e9'; eval(\n response\n)"
    result = scan(source)
    assert result.model_dump_json() == scan(source).model_dump_json()
    assert SelfModificationFileResult.model_validate_json(result.model_dump_json()) == result
    assert result.findings and result.findings[0].location.end_line == 3
    assert result.findings[0].location.start_utf8_byte_column == len("x='\u00e9'; ".encode())
    changed = scan(source + "\n")
    assert changed.findings and result.findings[0].record_id != changed.findings[0].record_id


def test_source_not_executed_or_leaked(tmp_path: Path) -> None:
    marker = tmp_path / "never-created"
    result = scan(
        f"open({str(marker)!r}, 'w').write('DO_NOT_EXPORT_SECRET')\n"
        "eval(PRIVATE_RESPONSE)\nagent.prompt = PRIVATE_VALUE\n"
    )
    assert not marker.exists()
    assert ids(result) == ["SELF-MOD-011", "SELF-MOD-001"]
    assert all(
        value not in result.model_dump_json()
        for value in (
            "DO_NOT_EXPORT_SECRET",
            "PRIVATE_RESPONSE",
            "PRIVATE_VALUE",
            str(marker),
        )
    )


def test_bounds_and_nulls(monkeypatch: pytest.MonkeyPatch) -> None:
    for data in (b"def broken(:", b"\xff"):
        result = scan_source(data, path="broken.py")
        assert result.state == "malformed" and result.findings is None
    result = scan_source(b"{}", path="state.json")
    assert result.state == "unsupported" and result.findings is None
    assert scan_source(b"x" * (MAX_INPUT_BYTES + 1), path="large.py").state == "failed"
    with pytest.raises(ValueError):
        scan_source(b"", path="../escape.py")
    monkeypatch.setattr(detector, "MAX_AST_NODES", 3)
    assert scan("eval(response)").state == "failed"


def test_record_budget_is_failure_not_truncated_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(detector, "MAX_RECORDS", 1)
    result = scan("eval(response)\nexec(memory)")
    assert result.state == "failed" and result.findings is None
