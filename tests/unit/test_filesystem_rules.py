from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from agentsec_evidence.agents.inputs import MAX_INPUT_BYTES
from agentsec_evidence.custom_rules import filesystem as detector
from agentsec_evidence.custom_rules.filesystem import FilesystemFileResult, scan_source
from agentsec_evidence.custom_rules.filesystem_catalog import CATALOG_SHA256, LEGACY_MARKERS, RULES

CASES = json.loads(
    (Path(__file__).parents[2] / "test_cases/development/filesystem-v1/cases.json").read_text(
        encoding="utf-8"
    )
)["cases"]


def scan(source: str) -> FilesystemFileResult:
    return scan_source(source.encode(), path="files.py")


def ids(result: FilesystemFileResult) -> list[str] | None:
    return None if result.findings is None else [item.rule_id for item in result.findings]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_controlled_case(case: dict[str, Any]) -> None:
    result = scan(case["source"])
    assert ids(result) == case["rules"]
    assert sorted({item.rule_id for item in result.inventory if item.rule_id}) == case["inventory"]
    assert result.state == ("malformed" if case["rules"] is None else "analyzed")


def test_actual_catalog_and_legacy_markers_not_fabricated_rule_count() -> None:
    assert [rule.rule_id for rule in RULES] == [f"FS-ACCESS-{number:03}" for number in range(1, 13)]
    assert Counter(rule.status for rule in RULES) == {
        "active-condition": 5,
        "inventory-only": 5,
        "deferred": 2,
    }
    assert len(CATALOG_SHA256) == 64
    assert set(LEGACY_MARKERS) == {"FS-ACCESS-099", "FS-ACCESS-MCP-001"}
    assert {rule for case in CASES for rule in case["rules"] or []} == {
        rule.rule_id for rule in RULES if rule.status == "active-condition"
    }


@pytest.mark.parametrize(
    "source",
    [
        "import builtins as b\nb.open(path)",
        "from io import open as f\nf(path)",
        "from pathlib import Path as P\nP(path).read_text()",
        "import pathlib as p\np.Path(path).read_bytes()",
        "def f(path):\n    import io\n    return io.open(path)",
        "class C:\n    open = other\n    def f(self, path):\n        return open(path)",
    ],
)
def test_resolved_aliases(source: str) -> None:
    assert ids(scan(source)) == ["FS-ACCESS-001"]


@pytest.mark.parametrize(
    "source",
    [
        "open = helper\nopen(path)",
        "from custom import open\nopen(path)",
        "from custom import *\nopen(path)",
        "def f(open, path):\n    return open(path)",
        "import io\nio = other\nio.open(path)",
        "if flag:\n    import io\nio.open(path)",
        "from .io import open\nopen(path)",
        "try:\n    operation()\nexcept Exception as open:\n    open(path)",
    ],
)
def test_ambiguous_binding_not_assumed_builtin(source: str) -> None:
    assert ids(scan(source)) == []


@pytest.mark.parametrize("mode", ["w", "a", "x", "w+", "r+", "a+", "wb", "xb+", "r+b"])
def test_write_capability_comes_from_actual_mode_syntax(mode: str) -> None:
    assert ids(scan(f"open(path, {mode!r})")) == ["FS-ACCESS-001", "FS-ACCESS-003"]


@pytest.mark.parametrize("mode", ["r", "rb", "rt"])
def test_read_modes_do_not_become_writes(mode: str) -> None:
    assert ids(scan(f"open(path, {mode!r})")) == ["FS-ACCESS-001"]


@pytest.mark.parametrize("mode", ["'rr'", "'rw'", "'rbt'", "'zz'", "unknown", "None"])
def test_invalid_or_unknown_modes_are_visible(mode: str) -> None:
    result = scan(f"open(path, {mode})")
    assert "FS-ACCESS-003" not in (ids(result) or [])
    assert any(item.kind == "unresolved-mode" for item in result.limitations_observed)


def test_posix_and_windows_parent_evidence_separate() -> None:
    posix = scan("open('../file.txt')")
    windows = scan("open(r'..\\file.txt')")
    assert posix.findings and windows.findings
    assert posix.findings[0].evidence_kinds == [
        "literal-parent-component-posix",
        "literal-parent-component-windows",
    ]
    assert windows.findings[0].evidence_kinds == ["literal-parent-component-windows"]


def test_normalization_is_neither_traversal_proof_nor_safety_proof() -> None:
    assert ids(scan("from pathlib import Path\nPath(path).resolve()")) == []
    result = scan("from pathlib import Path\nPath(path).resolve().read_text()")
    assert ids(result) == ["FS-ACCESS-001"]
    assert any(item.kind == "unresolved-transformation" for item in result.limitations_observed)


def test_depth_and_temp_paths_have_no_scores_or_safety_exemption() -> None:
    result = scan("open('/tmp/a/b/c/d/e/file.txt', 'w')")
    assert ids(result) == []
    depth = next(item for item in result.inventory if item.rule_id == "FS-ACCESS-009")
    assert depth.measurements == {"posix_components": 7, "windows_components": 7}
    assert "risk_score" not in result.model_dump_json()
    dynamic = scan("open(f'/tmp/{name}', 'w')")
    assert ids(dynamic) == ["FS-ACCESS-001", "FS-ACCESS-003"]


def test_interpolation_counts_not_entropy_or_llm_attribution() -> None:
    result = scan("open(f'{first}/{second}.txt')")
    observation = next(item for item in result.inventory if item.rule_id == "FS-ACCESS-008")
    assert observation.measurements == {"formatted_expressions": 2}
    assert ids(result) == ["FS-ACCESS-001"]


@pytest.mark.parametrize(
    "source",
    [
        "from pathlib import Path\np = Path(path)\np.read_text()",
        "handle = open('file.txt', 'w')\nhandle.write(secret)",
        "from pathlib import Path\nPath('base', name).read_text()",
        "f = lambda name: open(name)",
        "files = [open(name) for name in names]",
    ],
)
def test_unsupported_constructs_explicit(source: str) -> None:
    assert scan(source).limitations_observed


@pytest.mark.parametrize(
    "source",
    [
        "from pathlib import Path\nexec(Path('code.py').read_text())",
        "import builtins as b\nb.eval(b.open('expr.txt').read())",
        "from io import open as f\nexec(f('code.py', 'r').read())",
    ],
)
def test_direct_file_read_to_code_only(source: str) -> None:
    assert "FS-ACCESS-011" in (ids(scan(source)) or [])


@pytest.mark.parametrize(
    "source",
    [
        "def exec(value):\n    return value\nexec(open('code.py').read())",
        "exec(handle.read())",
        "exec(open('code.py', 'w').read())",
        "import yaml\nyaml.load(text, Loader=yaml.SafeLoader)",
        "from pathlib import Path\nsource = Path('code.py').read_text()\nexec(source)",
    ],
)
def test_no_invented_code_flow_or_unsafe_yaml_claim(source: str) -> None:
    assert "FS-ACCESS-011" not in (ids(scan(source)) or [])


@pytest.mark.parametrize(
    "call",
    [
        "Path('file.txt').write_text(password)",
        "Path('file.txt').write_bytes(data=access_token)",
        "open('file.txt', 'w').write(credentials)",
    ],
)
def test_direct_write_name_heuristic(call: str) -> None:
    assert ids(scan(f"from pathlib import Path\n{call}")) == ["FS-ACCESS-006"]


def test_generic_key_and_transformation_not_secret_proof() -> None:
    assert ids(scan("from pathlib import Path\nPath('file.txt').write_text(key)")) == []
    result = scan("from pathlib import Path\nPath('file.txt').write_text(mask(secret))")
    assert ids(result) == [] and result.limitations_observed


def test_inline_readonly_handle_not_assumed_writable() -> None:
    result = scan("open('file.txt').write(password)")
    assert ids(result) == [] and result.limitations_observed


def test_no_file_contents_target_paths_or_secret_names_in_report() -> None:
    result = scan(
        "from pathlib import Path\nPath('PRIVATE_SOURCE_PATH.txt').write_text(CUSTOM_SECRET_VALUE)"
    )
    payload = result.model_dump_json()
    assert "PRIVATE_SOURCE_PATH" not in payload and "CUSTOM_SECRET_VALUE" not in payload
    assert ids(result) == ["FS-ACCESS-006"]


def test_runtime_path_is_never_opened_or_written(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    result = scan(f"open({str(marker)!r}, 'w').write('marker')")
    assert ids(result) == [] and not marker.exists()


def test_stable_records_and_utf8_positions() -> None:
    source = "label = '\u00e9'; open(\n path\n)"
    result = scan(source)
    assert result.model_dump_json() == scan(source).model_dump_json()
    assert FilesystemFileResult.model_validate_json(result.model_dump_json()) == result
    assert result.findings
    assert result.findings[0].location.start_utf8_byte_column == len("label = '\u00e9'; ".encode())
    assert result.findings[0].location.end_line == 3
    changed = scan(source + "\n")
    assert changed.findings and changed.findings[0].record_id != result.findings[0].record_id


def test_parse_failure_is_state_not_099_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    for data in (b"def broken(:", b"\xff"):
        result = scan_source(data, path="broken.py")
        assert result.state == "malformed" and result.findings is None
    monkeypatch.setattr(detector, "MAX_AST_NODES", 3)
    assert scan("open(path)").state == "failed"


def test_budget_failure_does_not_report_truncated_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(detector, "MAX_RECORDS", 1)
    result = scan("open(path)\nopen(other)")
    assert result.state == "failed" and result.findings is None


def test_size_path_and_nonpython_guards() -> None:
    assert scan_source(b"x" * (MAX_INPUT_BYTES + 1), path="large.py").state == "failed"
    result = scan_source(b'{"filesystem":"/"}', path="mcp.json")
    assert result.state == "unsupported" and result.findings is None
    with pytest.raises(ValueError):
        scan_source(b"", path="../outside.py")


@pytest.mark.parametrize(
    "source",
    [
        "open(path, typo=True)",
        "from pathlib import Path\nPath(path).read_bytes('invalid')",
        "from pathlib import Path\nPath(path).write_text(secret, data=other)",
        "from pathlib import Path\nPath(path).write_bytes()",
        "from pathlib import Path\nPath(path).open(opener=custom)",
        "import shutil\nshutil.copy(src, dst, invalid=True)",
        "import shutil\nshutil.move(src, dst, dst=other)",
    ],
)
def test_invalid_call_shapes_not_reported_as_valid_operations(source: str) -> None:
    result = scan(source)
    assert ids(result) == []
    assert result.limitations_observed


@pytest.mark.parametrize(
    "source",
    [
        "from pathlib import Path\nexec(Path(path).read_bytes(123))",
        "exec(open(path, bad=True).read())",
        "exec(open(path).read(invalid=True))",
        "from pathlib import Path\nexec(Path('a', 'b').read_text())",
        "exec(open('code.py').read(), source=other)",
        "eval(open('code.py').read(), bad=True)",
    ],
)
def test_invalid_read_expressions_do_not_create_code_flow(source: str) -> None:
    assert "FS-ACCESS-011" not in (ids(scan(source)) or [])


def test_annotations_are_outside_inspected_body() -> None:
    assert ids(scan("from __future__ import annotations\nvalue: open(path)")) == []
    assert ids(scan("value: Type = open(path)")) == ["FS-ACCESS-001"]
