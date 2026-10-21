from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agentsec_evidence.agents.inputs import MAX_INPUT_BYTES
from agentsec_evidence.custom_rules import tool_execution as detector
from agentsec_evidence.custom_rules.tool_execution import RULES, FileResult, scan_source

CASES = json.loads(
    (Path(__file__).parents[2] / "test_cases/development/tool-execution-v1/cases.json").read_text(
        encoding="utf-8"
    )
)["cases"]


def scan(source: str) -> FileResult:
    return scan_source(source.encode("utf-8"), path="tools.py")


def ids(result: FileResult) -> list[str] | None:
    if result.findings is None:
        return None
    return [finding.rule.rule_id for finding in result.findings]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_frozen_development_contrasts(case: dict[str, Any]) -> None:
    result = scan(case["source"])
    assert ids(result) == case["rules"]
    assert result.state == ("malformed" if case["rules"] is None else "analyzed")


def test_catalog_has_five_unique_versioned_conditions() -> None:
    assert [rule.rule_id for rule in RULES] == [f"TOOL-EXEC-00{i}" for i in range(1, 6)]
    assert len(detector.CATALOG_SHA256) == 64
    assert all("unsanitized" not in rule.title.lower() for rule in RULES)


@pytest.mark.parametrize(
    "source",
    [
        "import builtins as b\nb.eval(value)",
        "from builtins import exec as run_code\nrun_code(value)",
        "def f():\n    import builtins as b\n    b.exec(value)",
        "import builtins\ndef f():\n    return builtins.eval(value)",
    ],
)
def test_explicit_builtin_aliases(source: str) -> None:
    assert ids(scan(source)) == ["TOOL-EXEC-001"]


@pytest.mark.parametrize(
    "source",
    [
        "eval = helper\neval(value)",
        "def eval(x):\n    return x\neval(value)",
        "class eval:\n    pass\neval(value)",
        "from other import eval\neval(value)",
        "from other import *\neval(value)",
        "import subprocess as s\ns = other\ns.run(value, shell=True)",
        "if condition:\n    import subprocess\nsubprocess.run(value, shell=True)",
        "def f(value):\n    global eval\n    return eval(value)",
        "def outer(eval):\n    def inner(value):\n        return eval(value)",
        "try:\n    action()\nexcept Exception as eval:\n    eval(value)",
        "match value:\n    case {'eval': eval}:\n        eval(value)",
        "match value:\n    case {'other': _, **eval}:\n        eval(value)",
        "match value:\n    case [*eval]:\n        eval(value)",
    ],
)
def test_ambiguous_bindings_do_not_claim_known_sink(source: str) -> None:
    result = scan(source)
    assert ids(result) == []
    assert result.limitations_observed


def test_unrelated_function_parameter_does_not_shadow_outer_builtin() -> None:
    assert ids(scan("def f(eval):\n    return eval(value)\neval(code)")) == ["TOOL-EXEC-001"]


def test_class_binding_does_not_shadow_method_builtin() -> None:
    source = "class C:\n    eval = other\n    def f(self, value):\n        return eval(value)"
    assert ids(scan(source)) == ["TOOL-EXEC-001"]


def test_no_cross_call_pattern_leakage_or_duplicate_regex_hits() -> None:
    result = scan("eval(value)\nexec(code)\neval('exec(user_input)')")
    assert ids(result) == ["TOOL-EXEC-001", "TOOL-EXEC-001"]
    assert [item.location.start_line for item in result.findings or []] == [1, 2]
    assert len({item.record_id for item in result.findings or []}) == 2


def test_multiline_and_utf8_locations_are_explicit_byte_offsets() -> None:
    result = scan("label = '\u00e9'; eval(\n  value\n)\n")
    finding = (result.findings or [])[0]
    assert finding.location.start_line == 1
    assert finding.location.end_line == 3
    assert finding.location.start_utf8_byte_column == len("label = '\u00e9'; ".encode())
    assert finding.argument == "value"


def test_stable_native_json_and_source_bound_record_identity() -> None:
    first = scan("eval(value)")
    assert first.model_dump_json() == scan("eval(value)").model_dump_json()
    assert FileResult.model_validate_json(first.model_dump_json()) == first
    second = scan("eval(value)\n")
    assert (first.findings or [])[0].record_id != (second.findings or [])[0].record_id
    other = scan_source(b"eval(value)", path="other.py")
    assert (first.findings or [])[0].record_id != (other.findings or [])[0].record_id


def test_tool_registration_is_inventory_not_a_finding() -> None:
    result = scan("from langchain_core.tools import tool\n@tool\ndef f(x):\n    return x")
    assert ids(result) == []
    assert [item.kind for item in result.inventory] == ["tool-registration"]


def test_only_direct_unreassigned_parameter_gets_tool_flow_condition() -> None:
    result = scan(
        "from langchain_core.tools import tool\n"
        "@tool\ndef f(value):\n    alias = value\n    return eval(alias)"
    )
    assert ids(result) == ["TOOL-EXEC-001"]


@pytest.mark.parametrize(
    "source",
    [
        "import subprocess\nsubprocess.run(command, shell=1)",
        "import subprocess\nsubprocess.run(command, shell=True, shell=False)",
        "import subprocess\nsubprocess.run(command, **options)",
        "eval()",
        "eval(source=value)",
        "import importlib\nimportlib.import_module(*args)",
    ],
)
def test_unmodeled_arguments_are_explicit(source: str) -> None:
    result = scan(source)
    assert ids(result) == []
    assert result.limitations_observed


@pytest.mark.parametrize(
    "source",
    [
        "f = lambda x: eval(x)",
        "values = [eval(x) for x in items]",
        "values = {eval(x) for x in items}",
        "values = {x: eval(x) for x in items}",
        "values = (eval(x) for x in items)",
    ],
)
def test_unsupported_inner_scopes_never_become_clean_coverage(source: str) -> None:
    result = scan(source)
    assert ids(result) == []
    assert result.limitations_observed[0].kind == "unsupported-scope"


def test_literal_import_and_eval_do_not_assert_safety() -> None:
    result = scan("__import__('json')\neval('malicious()')")
    assert ids(result) == []
    assert [item.kind for item in result.inventory] == [
        "literal-module-import",
        "literal-code-call",
    ]


def test_parse_or_resource_errors_are_not_security_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for data in (b"def broken(:", b"\xff"):
        result = scan_source(data, path="bad.py")
        assert result.state == "malformed"
        assert result.findings is None
    monkeypatch.setattr(detector, "MAX_AST_NODES", 3)
    result = scan("eval(value)")
    assert result.state == "failed"
    assert result.findings is None


def test_observation_budget_failure_is_not_a_truncated_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(detector, "MAX_RECORDS", 1)
    result = scan("eval(value)\nexec(code)")
    assert result.state == "failed"
    assert result.findings is None


def test_input_size_extension_and_path_guards() -> None:
    result = scan_source(b"x" * (MAX_INPUT_BYTES + 1), path="large.py")
    assert result.state == "failed"
    assert result.findings is None
    result = scan_source(b"{}", path="mcp.json")
    assert result.state == "unsupported"
    assert result.findings is None
    with pytest.raises(ValueError):
        scan_source(b"eval(value)", path="../escape.py")


def test_target_is_never_executed(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    result = scan(f"from pathlib import Path\nPath({str(marker)!r}).touch()\neval(value)")
    assert ids(result) == ["TOOL-EXEC-001"]
    assert not marker.exists()


def test_argument_evidence_is_bounded_without_silent_truncation() -> None:
    result = scan("eval(" + "long_identifier_" * 40 + ")")
    finding = (result.findings or [])[0]
    assert len(finding.argument) == 512
    assert finding.argument_truncated


@pytest.mark.parametrize(
    "callee", ["os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"]
)
def test_other_explicit_shell_functions(callee: str) -> None:
    assert ids(scan(f"import {callee.split('.')[0]}\n{callee}(value)")) == ["TOOL-EXEC-003"]


@pytest.mark.parametrize("callee", ["Popen", "call", "check_call", "check_output"])
def test_supported_subprocess_shell_keywords(callee: str) -> None:
    assert ids(scan(f"import subprocess\nsubprocess.{callee}(value, shell=True)")) == [
        "TOOL-EXEC-003"
    ]


def test_third_response_shape_is_still_only_syntactic() -> None:
    result = scan("eval(agent.response)")
    assert ids(result) == ["TOOL-EXEC-001", "TOOL-EXEC-002"]
    assert (result.findings or [])[1].rule.evidence_kind.endswith("not-proven-llm-origin")
