from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from agentsec_evidence.agents.records import AgentInputRequest
from agentsec_evidence.agents.worker import validate_view
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.custom_rules.filesystem_worker import (
    FilesystemReport,
    exit_status,
    scan_view,
)
from agentsec_evidence.models.contracts import InventoryEntry

SOURCE = b"open(path)\n"


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
            target_snapshot_id="development-filesystem-v1",
            inventory=entries,
            selected={entry.path: "python-source" for entry in entries},
        )
        .model_dump_json()
        .encode()
    )


def test_exact_inventory_and_repeatability(tmp_path: Path) -> None:
    (tmp_path / "files.py").write_bytes(SOURCE)
    request = request_for(tmp_path)
    report = scan_view(tmp_path, request)
    assert report.execution_state == "complete"
    assert report.request_sha256 == sha256_bytes(request)
    assert len(report.rules) == 12
    assert len(report.files[0].findings or []) == 1
    assert report.model_dump_json() == scan_view(tmp_path, request).model_dump_json()
    assert FilesystemReport.model_validate_json(report.model_dump_json()) == report


@pytest.mark.parametrize("mutation", ["extra", "missing", "changed"])
def test_snapshot_drift_refused(tmp_path: Path, mutation: str) -> None:
    path = tmp_path / "files.py"
    path.write_bytes(SOURCE)
    request = request_for(tmp_path)
    if mutation == "extra":
        (tmp_path / "extra.py").write_bytes(b"")
    elif mutation == "missing":
        path.unlink()
    else:
        path.write_bytes(SOURCE + b"\n")
    with pytest.raises(ValueError):
        scan_view(tmp_path, request)


def test_partial_and_unknown_not_clean(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_bytes(b"def broken(:")
    (tmp_path / "working.py").write_bytes(SOURCE)
    report = scan_view(tmp_path, request_for(tmp_path))
    assert report.execution_state == "partial"
    assert report.files[0].findings is None
    assert report.files[1].findings
    assert exit_status(report, "low") == 2


def test_nonselected_and_nonpython_are_distinct(tmp_path: Path) -> None:
    (tmp_path / "policy.txt").write_bytes(b"not executable")
    (tmp_path / "mcp.json").write_bytes(b'{"mcpServers":{}}')
    request = AgentInputRequest.model_validate_json(request_for(tmp_path))
    del request.selected["policy.txt"]
    request.selected["mcp.json"] = "mcp-config"
    report = scan_view(tmp_path, request.model_dump_json().encode())
    assert report.not_selected == ["policy.txt"]
    assert len(report.input_inventory) == 2
    assert report.files[0].state == "unsupported"
    assert report.files[0].findings is None
    assert report.execution_state == "partial"


def test_empty_is_not_clean(tmp_path: Path) -> None:
    report = scan_view(tmp_path, request_for(tmp_path))
    assert report.execution_state == "empty" and exit_status(report, None) == 2


@pytest.mark.parametrize(
    ("threshold", "expected"),
    [(None, 0), ("low", 1), ("medium", 1), ("high", 0), ("critical", 0)],
)
def test_priority_threshold_is_numeric_not_alphabetical(
    tmp_path: Path,
    threshold: str | None,
    expected: int,
) -> None:
    (tmp_path / "files.py").write_bytes(SOURCE)
    assert exit_status(scan_view(tmp_path, request_for(tmp_path)), threshold) == expected


def test_low_priority_write_name_heuristic_does_not_breach_medium(tmp_path: Path) -> None:
    (tmp_path / "files.py").write_bytes(b"open('output.txt', 'w').write(secret)\n")
    report = scan_view(tmp_path, request_for(tmp_path))
    assert exit_status(report, "low") == 1
    assert exit_status(report, "medium") == 0


def test_unknown_threshold_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="priority"):
        exit_status(scan_view(tmp_path, request_for(tmp_path)), "urgent")


@pytest.mark.parametrize(("source", "expected"), [(SOURCE, 1), (b"def broken(:", 2)])
def test_cli_json_preserved_before_exit(tmp_path: Path, source: bytes, expected: int) -> None:
    root = tmp_path / "input"
    root.mkdir()
    (root / "files.py").write_bytes(source)
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
            "agentsec_evidence.custom_rules.filesystem_worker",
            str(request),
            str(root),
            "--fail-on",
            "low",
        ],
        capture_output=True,
        check=False,
        timeout=30,
        env=environment,
    )
    assert result.returncode == expected, result.stderr
    assert not result.stderr
    report = FilesystemReport.model_validate_json(result.stdout)
    assert report.files[0].source_sha256 == sha256_bytes(source)


def test_duplicate_keys_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        scan_view(tmp_path, b'{"contract":"x","contract":"y"}')


def test_link_refused(tmp_path: Path) -> None:
    root = tmp_path / "view"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_bytes(SOURCE)
    try:
        (root / "linked.py").symlink_to(outside)
    except OSError:
        pytest.skip("Host does not permit symlink creation")
    with pytest.raises(ValueError, match="link"):
        scan_view(root, request_for(root))


def test_worker_entry_budget(tmp_path: Path) -> None:
    for index in range(513):
        (tmp_path / f"directory-{index}").mkdir()
    with pytest.raises(ValueError, match="entry budget"):
        scan_view(tmp_path, b"{}")


def test_post_validation_mutation_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agentsec_evidence.custom_rules import filesystem_worker

    path = tmp_path / "files.py"
    path.write_bytes(SOURCE)
    request = request_for(tmp_path)

    def mutate(root: Path, payload: bytes) -> None:
        validate_view(root, payload)
        path.write_bytes(b"# altered after validation\n")

    monkeypatch.setattr(filesystem_worker, "validate_view", mutate)
    with pytest.raises(ValueError, match="changed"):
        scan_view(tmp_path, request)


def test_mcp_legacy_markers_cannot_emit_findings(tmp_path: Path) -> None:
    (tmp_path / "files.py").write_bytes(b"# FS-ACCESS-099 FS-ACCESS-MCP-001\n")
    report = scan_view(tmp_path, request_for(tmp_path))
    assert set(report.legacy_markers) == {"FS-ACCESS-099", "FS-ACCESS-MCP-001"}
    assert not report.files[0].findings
    assert {rule.rule_id for rule in report.rules if rule.status == "deferred"} == {
        "FS-ACCESS-002",
        "FS-ACCESS-010",
    }
