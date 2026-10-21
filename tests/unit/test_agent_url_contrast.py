from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from agentsec_evidence.agents.url_contrast import (
    CASE_IDS,
    REGISTRY,
    RULE_ID,
    describe_rule_observation,
    load_url_contrast_case,
)

PROJECT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_frozen_authored_case(case_id: str) -> None:
    case, raw = load_url_contrast_case(PROJECT, case_id)
    assert len(json.loads(raw)["cases"]) == 4
    assert case.input_path == "agent.py" and case.artifact_kind == "python-source"
    assert case.policy_observation == "none" and not case.extra_files
    assert case.expected_parse == "parsed"
    assert case.expected_condition == ("present" if case_id == "url-caller-tool" else "absent")
    # Only our authored fixture is parsed here; external sources still use the isolated worker.
    tree = ast.parse(case.content)
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef))
    assert bool(function.decorator_list) == (case_id != "url-fixed-helper")
    if case_id in {"url-fixed-helper", "url-fixed-tool"}:
        assert not function.args.args
        assignment = next(node for node in function.body if isinstance(node, ast.Assign))
        assert isinstance(assignment.value, ast.Constant)
        assert assignment.value.value == "https://example.com/data.txt"


def test_direct_and_restricted_destinations_are_distinct_source_facts() -> None:
    caller, _ = load_url_contrast_case(PROJECT, "url-caller-tool")
    restricted, _ = load_url_contrast_case(PROJECT, "url-allowlisted-tool")

    def request_argument(content: str) -> ast.expr:
        calls = [
            node
            for node in ast.walk(ast.parse(content))
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
        ]
        assert len(calls) == 1
        return calls[0].args[0]

    direct = request_argument(caller.content)
    assert isinstance(direct, ast.Name) and direct.id == "url"
    chosen = request_argument(restricted.content)
    assert isinstance(chosen, ast.Subscript)
    tree = ast.parse(restricted.content)
    mapping = next(node for node in ast.walk(tree) if isinstance(node, ast.Dict))
    assert all(isinstance(value, ast.Constant) for value in mapping.values)
    assert any(isinstance(node, ast.Raise) for node in ast.walk(tree))


def test_unknown_case_rejected_before_registry_access(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="four approved"):
        load_url_contrast_case(tmp_path, "arbitrary-directory")


@pytest.mark.parametrize("change", ["source", "expectation", "duplicate", "extra"])
def test_changed_registry_refused(tmp_path: Path, change: str) -> None:
    document = json.loads((PROJECT / REGISTRY).read_bytes())
    if change == "source":
        document["cases"][0]["content"] = "raise RuntimeError('changed')"
    elif change == "expectation":
        document["cases"][0]["expected_condition"] = "absent"
    elif change == "duplicate":
        document["cases"][1] = document["cases"][0]
    else:
        document["cases"].append(document["cases"][0])
    path = tmp_path / REGISTRY
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="frozen admission"):
        load_url_contrast_case(tmp_path, CASE_IDS[0])


@pytest.mark.parametrize(
    "expected,rules,observation",
    [
        ("present", [RULE_ID], "condition-present-rule-reported"),
        ("present", [], "condition-present-no-rule-report"),
        ("absent", [RULE_ID], "condition-absent-rule-reported"),
        ("absent", ["OTHER"], "condition-absent-no-rule-report"),
        ("present", None, "not-assessable"),
        ("absent", None, "not-assessable"),
        ("not-assessable", [], "not-assessable"),
    ],
)
def test_observations_do_not_turn_missing_evidence_into_clean_results(
    expected: str, rules: list[str] | None, observation: str
) -> None:
    from typing import Literal, cast

    assert (
        describe_rule_observation(
            cast(Literal["present", "absent", "not-assessable"], expected), rules
        )
        == observation
    )
