"""Authored syntax contrasts, not execution of repository code or independent labels."""

from pathlib import Path

import pytest

from agentsec_evidence.custom_rules.shared_inputs import prepare_shared
from agentsec_evidence.custom_rules.tool_execution import scan_source as old_scan
from agentsec_evidence.custom_rules.tool_execution_v2 import scan_source


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("from __future__ import annotations\nx: eval(memory)", 0),
        ("x: eval(memory)", 1),
        ("class C:\n x: eval(memory)", 1),
        ("def f():\n x: eval(memory)", 0),
        ("async def f():\n x: eval(memory)", 0),
        ("from __future__ import annotations\nx: eval(memory) = eval(code)", 1),
        ("def f():\n x: eval(memory) = eval(code)", 1),
        ("from __future__ import annotations\nobj[eval(index)]: eval(memory)", 1),
        ("def f():\n class C:\n  x: eval(memory)", 1),
        ("from __future__ import annotations\ndef f(x=eval(code)):\n pass", 1),
        ("from __future__ import annotations\n@eval(code)\ndef f():\n pass", 1),
        ("type Alias = eval(memory)", 0),
        ("eval(code)", 1),
        ("def f(eval):\n eval(code)", 0),
    ],
)
def test_annotation_semantics(source: str, expected: int) -> None:
    result = scan_source(source.encode(), path="case.py")
    assert result.state == "analyzed"
    assert len(result.findings or []) == expected


def test_legacy_preserved_and_ids_versioned() -> None:
    source = b"from __future__ import annotations\nx: eval(memory)"
    assert len(old_scan(source, path="case.py").findings or []) == 1
    result = scan_source(source, path="case.py")
    assert result.findings == []
    assert result.limitations_observed[0].kind == "annotation-not-ordinary-execution"
    old = old_scan(b"eval(code)", path="case.py").findings
    new = scan_source(b"eval(code)", path="case.py").findings
    assert old and new and old[0].record_id != new[0].record_id
    assert old[0].rule == new[0].rule


def test_malformed_is_not_clean() -> None:
    result = scan_source(b"def broken(", path="case.py")
    assert result.state == "malformed"
    assert result.findings is None


def test_only_identified_condition_changes_across_authored_union() -> None:
    prepared = prepare_shared(Path(__file__).resolve().parents[1])
    changed = []
    for path, raw in prepared.inputs.items():
        old = old_scan(raw, path=path)
        new = scan_source(raw, path=path)
        assert old.state == new.state
        if [f.rule.rule_id for f in old.findings or []] != [
            f.rule.rule_id for f in new.findings or []
        ]:
            changed.append(path)
    assert changed == ["memory-state/annotation-not-code.py"]
