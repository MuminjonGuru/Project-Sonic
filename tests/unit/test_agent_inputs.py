from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from agentsec_evidence.agents.inputs import (
    MAX_INPUT_BYTES,
    POLICY_FILENAMES,
    PYTHON_SKIPPED_DIRECTORIES,
    plan_agent_input_admission,
    validate_agent_input,
)
from agentsec_evidence.agents.models import ArtifactKind
from agentsec_evidence.agents.validation import (
    AgentDataError,
    canonical_artifact_path,
    load_agent_json,
)
from agentsec_evidence.core.identity import sha256_bytes

ROOT = Path(__file__).resolve().parents[2]
CASES = json.loads((ROOT / "test_cases/development/agent-artifacts/cases.json").read_bytes())[
    "cases"
]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_authored_input_admission(case: dict[str, object]) -> None:
    content = str(case["content"]).encode()
    path = str(case["input_path"])
    checked = validate_agent_input(
        content,
        path=path,
        kind=cast(ArtifactKind, case["artifact_kind"]),
        target_snapshot_id="fixture",
    )
    assert checked.artifact.parse_state == case["expected_parse"]
    assert checked.artifact.source.sha256 == sha256_bytes(content)
    extras = cast(dict[str, str], case["extra_files"])
    plan = plan_agent_input_admission([checked], snapshot_paths=[path, *extras])
    assert plan.admitted == (
        case["expected_parse"] == "parsed" and case["policy_observation"] == "none"
    )
    assert plan.blocked_policy_paths == tuple(sorted(extras))
    assert not plan.admitted or not plan.blockers


@pytest.mark.parametrize(
    "path",
    [
        "../secret",
        "/target/a.py",
        "a\\b.py",
        "./a.py",
        "a//b.py",
        "a/../b.py",
        ".",
        "a.py ",
        "a./b.py",
        "nul.py",
        "a/COM1",
        "a.py:stream",
        "a?.py",
        "a\x00.py",
    ],
)
def test_noncanonical_paths_rejected(path: str) -> None:
    with pytest.raises(ValueError):
        canonical_artifact_path(path)


@pytest.mark.parametrize(
    "data",
    [
        b'{"x":1,"x":2}',
        b'{"x":{"y":1,"y":2}}',
        b'{"x":NaN}',
        b'{"x":1e999}',
        b'{"x":"\\ud800"}',
        b'{"\\ud800":1}',
        b"[]",
        b"null",
        b"\xff",
        b"{",
        b'{"x":' + b"[" * 65 + b"0" + b"]" * 65 + b"}",
    ],
)
def test_strict_json_rejects_ambiguous_or_invalid_data(data: bytes) -> None:
    with pytest.raises(AgentDataError):
        load_agent_json(data, max_bytes=MAX_INPUT_BYTES)


def test_json_byte_and_node_budgets() -> None:
    with pytest.raises(AgentDataError):
        load_agent_json(b"{}", max_bytes=1)
    with pytest.raises(AgentDataError):
        load_agent_json(b'{"x":[' + b"0," * 100_000 + b"0]}", max_bytes=MAX_INPUT_BYTES)


@pytest.mark.parametrize(
    ("document", "state"),
    [
        ({"servers": {}}, "unsupported"),
        ({"mcpServers": []}, "malformed"),
        ({"mcpServers": {"x": None}}, "malformed"),
        ({"mcpServers": {"": {"command": "npx", "args": []}}}, "malformed"),
        ({"mcpServers": {"x": {"url": "https://example.invalid"}}}, "unsupported"),
        (
            {"mcpServers": {"x": {"command": "npx", "args": [], "url": "https://example.invalid"}}},
            "unsupported",
        ),
        ({"mcpServers": {"x": {"command": " ", "args": []}}}, "malformed"),
        ({"mcpServers": {"x": {"command": 5, "args": []}}}, "malformed"),
        ({"mcpServers": {"x": {"command": "npx"}}}, "malformed"),
        ({"mcpServers": {"x": {"command": "npx", "args": [1]}}}, "malformed"),
        ({"mcpServers": {"x": {"command": "npx", "args": [], "env": {"X": 1}}}}, "malformed"),
        ({"mcpServers": {}}, "parsed"),
        ({"mcpServers": {"x": {"command": "npx", "args": [], "extra": "retained"}}}, "parsed"),
    ],
)
def test_mcp_shapes(document: dict[str, object], state: str) -> None:
    checked = validate_agent_input(
        json.dumps(document).encode(),
        path="mcp.json",
        kind="mcp-config",
        target_snapshot_id="s",
    )
    assert checked.artifact.parse_state == state


def test_no_input_code_is_executed(tmp_path: Path) -> None:
    sentinel = tmp_path / "must-not-exist"
    source = f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('executed')\n"
    result = validate_agent_input(
        source.encode(),
        path="agent.py",
        kind="python-source",
        target_snapshot_id="s",
    )
    assert result.artifact.parse_state == "parsed"
    assert not sentinel.exists()


@pytest.mark.parametrize(
    ("data", "state"),
    [
        (b"x = 1\n" * (MAX_INPUT_BYTES // 6 + 1), "failed"),
        (b"x=1\n" * 13_000, "failed"),
        (b"\xff", "malformed"),
        (b"x=\x00", "malformed"),
        (b"", "parsed"),
    ],
    ids=["byte-limit", "node-limit", "invalid-utf8", "nul-source", "empty-source"],
)
def test_python_encoding_and_budgets(data: bytes, state: str) -> None:
    result = validate_agent_input(data, path="a.py", kind="python-source", target_snapshot_id="s")
    assert result.artifact.parse_state == state


@pytest.mark.parametrize("filename", sorted(POLICY_FILENAMES))
def test_config_anywhere_in_snapshot_blocks_admission(filename: str) -> None:
    checked = validate_agent_input(
        b"x=1", path="a.py", kind="python-source", target_snapshot_id="s"
    )
    for path in (filename, f"nested/{filename}", filename.upper()):
        plan = plan_agent_input_admission([checked], snapshot_paths=["a.py", path])
        assert not plan.admitted
        assert plan.blocked_policy_paths == (path,)


@pytest.mark.parametrize("directory", sorted(PYTHON_SKIPPED_DIRECTORIES))
def test_native_default_exclusions_are_not_admitted(directory: str) -> None:
    path = f"{directory}/a.py"
    checked = validate_agent_input(b"x=1", path=path, kind="python-source", target_snapshot_id="s")
    plan = plan_agent_input_admission([checked], snapshot_paths=[path])
    assert not plan.admitted
    assert f"native-default-exclusion:{path}" in plan.blockers


def test_admission_identity_and_empty_scope_guards() -> None:
    checked = validate_agent_input(
        b"x=1", path="a.py", kind="python-source", target_snapshot_id="s"
    )
    for paths in (["a.py", "A.py"], ["a.py", "a.py"], ["other.py"]):
        with pytest.raises(AgentDataError):
            plan_agent_input_admission([checked], snapshot_paths=paths)
    with pytest.raises(AgentDataError):
        plan_agent_input_admission([checked, checked], snapshot_paths=["a.py"])
    second = validate_agent_input(
        b"x=1", path="b.py", kind="python-source", target_snapshot_id="other"
    )
    with pytest.raises(AgentDataError):
        plan_agent_input_admission([checked, second], snapshot_paths=["a.py", "b.py"])
    assert not plan_agent_input_admission([], snapshot_paths=[]).admitted


def test_marker_in_string_also_requires_explicit_policy() -> None:
    checked = validate_agent_input(
        b'x = "# NOAUDIT"\n',
        path="a.py",
        kind="python-source",
        target_snapshot_id="s",
    )
    assert checked.suppression_lines == (1,)
    assert not plan_agent_input_admission([checked], snapshot_paths=["a.py"]).admitted


def test_source_line_count_uses_python_newlines_not_unicode_separators() -> None:
    checked = validate_agent_input(
        'x = "a\u2028b"\r\ny=1\rz=2\n'.encode(),
        path="a.py",
        kind="python-source",
        target_snapshot_id="s",
    )
    assert checked.artifact.parse_state == "parsed"
    assert checked.line_count == 3


def test_mcp_resource_limit_is_not_mislabelled_as_invalid_syntax() -> None:
    data = b'{"mcpServers":{},"extra":' + b"[" * 65 + b"0" + b"]" * 65 + b"}"
    checked = validate_agent_input(data, path="mcp.json", kind="mcp-config", target_snapshot_id="s")
    assert checked.artifact.parse_state == "failed"
    assert "resource" in checked.artifact.reason
