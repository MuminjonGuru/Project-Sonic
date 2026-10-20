from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from agentsec_evidence.agents.records import AgentInputRequest
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.custom_rules.tool_execution_worker import (
    ToolExecutionReport,
    exit_status,
    scan_view,
)
from agentsec_evidence.models.contracts import InventoryEntry


def request_for(root: Path) -> bytes:
    entries = [
        InventoryEntry(
            path=path.name,
            sha256=sha256_bytes(path.read_bytes()),
            byte_length=path.stat().st_size,
            media_type="text/x-python",
        )
        for path in sorted(root.iterdir())
    ]
    return (
        AgentInputRequest(
            target_snapshot_id="development-tool-execution-v1",
            inventory=entries,
            selected={entry.path: "python-source" for entry in entries},
        )
        .model_dump_json()
        .encode()
    )


def test_exact_inventory_and_repeatability(tmp_path: Path) -> None:
    (tmp_path / "tool.py").write_bytes(b"eval(code)\n")
    request = request_for(tmp_path)
    report = scan_view(tmp_path, request)
    assert report.execution_state == "complete"
    assert report.request_sha256 == sha256_bytes(request)
    assert len(report.files[0].findings or []) == 1
    assert report.model_dump_json() == scan_view(tmp_path, request).model_dump_json()
    assert ToolExecutionReport.model_validate_json(report.model_dump_json()) == report


@pytest.mark.parametrize("mutation", ["extra", "missing", "changed"])
def test_rejects_snapshot_drift(tmp_path: Path, mutation: str) -> None:
    target = tmp_path / "tool.py"
    target.write_bytes(b"eval(value)\n")
    request = request_for(tmp_path)
    if mutation == "extra":
        (tmp_path / "extra.py").write_bytes(b"")
    elif mutation == "missing":
        target.unlink()
    else:
        target.write_bytes(b"eval(other)\n")
    with pytest.raises(ValueError):
        scan_view(tmp_path, request)


def test_parse_failure_partial_and_findings_null(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_bytes(b"def broken(:")
    (tmp_path / "working.py").write_bytes(b"eval(value)")
    report = scan_view(tmp_path, request_for(tmp_path))
    assert report.execution_state == "partial"
    assert report.files[0].findings is None
    assert len(report.files[1].findings or []) == 1
    assert exit_status(report, "low") == 2


def test_nonselected_is_recorded_and_not_analyzed(tmp_path: Path) -> None:
    (tmp_path / "policy.txt").write_bytes(b"not executable")
    (tmp_path / "tool.py").write_bytes(b"eval(value)")
    request = AgentInputRequest.model_validate_json(request_for(tmp_path))
    del request.selected["policy.txt"]
    report = scan_view(tmp_path, request.model_dump_json().encode())
    assert report.not_selected == ["policy.txt"]
    assert len(report.input_inventory) == 2
    assert [item.path for item in report.files] == ["tool.py"]


def test_mcp_is_unsupported_not_scanned_by_python_rules(tmp_path: Path) -> None:
    (tmp_path / "mcp.json").write_bytes(b'{"mcpServers":{}}')
    request = AgentInputRequest.model_validate_json(request_for(tmp_path))
    request.selected["mcp.json"] = "mcp-config"
    report = scan_view(tmp_path, request.model_dump_json().encode())
    assert report.execution_state == "partial"
    assert report.files[0].state == "unsupported"
    assert report.files[0].findings is None


def test_empty_selection_is_not_a_clean_scan(tmp_path: Path) -> None:
    report = scan_view(tmp_path, request_for(tmp_path))
    assert report.execution_state == "empty"
    assert exit_status(report, None) == 2


@pytest.mark.parametrize(
    ("threshold", "expected"),
    [(None, 0), ("low", 1), ("medium", 1), ("high", 1), ("critical", 0)],
)
def test_numeric_policy_order_not_alphabetical(
    tmp_path: Path, threshold: str | None, expected: int
) -> None:
    (tmp_path / "tool.py").write_bytes(b"eval(value)")
    report = scan_view(tmp_path, request_for(tmp_path))
    assert exit_status(report, threshold) == expected


def test_unknown_severity_rejected(tmp_path: Path) -> None:
    report = scan_view(tmp_path, request_for(tmp_path))
    with pytest.raises(ValueError, match="severity"):
        exit_status(report, "urgent")


@pytest.mark.parametrize(("source", "expected"), [(b"eval(value)", 1), (b"def broken(:", 2)])
def test_worker_cli_retains_json_before_policy_or_partial_exit(
    tmp_path: Path, source: bytes, expected: int
) -> None:
    root = tmp_path / "input"
    root.mkdir()
    (root / "tool.py").write_bytes(source)
    request = tmp_path / "request.json"
    request.write_bytes(request_for(root))
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(Path(__file__).parents[2] / "src")
    result = subprocess.run(
        [
            sys.executable,
            "-P",
            "-X",
            "utf8",
            "-m",
            "agentsec_evidence.custom_rules.tool_execution_worker",
            str(request),
            str(root),
            "--fail-on",
            "high",
        ],
        capture_output=True,
        check=False,
        timeout=30,
        env=environment,
    )
    assert result.returncode == expected, result.stderr
    assert not result.stderr
    report = ToolExecutionReport.model_validate_json(result.stdout)
    assert report.files[0].source_sha256 == sha256_bytes(source)


def test_duplicate_request_keys_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        scan_view(tmp_path, b'{"contract":"x","contract":"y"}')


def test_worker_refuses_symlinked_input(tmp_path: Path) -> None:
    root = tmp_path / "view"
    root.mkdir()
    external = tmp_path / "outside.py"
    external.write_bytes(b"eval(value)")
    try:
        (root / "linked.py").symlink_to(external)
    except OSError:
        pytest.skip("Creating symlinks is not permitted on this host")
    with pytest.raises(ValueError, match="link"):
        scan_view(root, request_for(root))


def test_worker_entry_budget(tmp_path: Path) -> None:
    for index in range(513):
        (tmp_path / f"directory-{index}").mkdir()
    with pytest.raises(ValueError, match="entry budget"):
        scan_view(tmp_path, b"{}")
