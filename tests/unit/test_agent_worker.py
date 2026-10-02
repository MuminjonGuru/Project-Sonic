from __future__ import annotations

from pathlib import Path

import pytest

from agentsec_evidence.agents.development import load_development_case, materialize_case
from agentsec_evidence.agents.execution import AgentAuditToolConfig, build_agent_argv
from agentsec_evidence.agents.records import AgentInputRequest, verify_input_report
from agentsec_evidence.agents.worker import validate_view
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.execution.config import ExecutionProfile, load_toml_config
from agentsec_evidence.models.contracts import InventoryEntry

PROJECT = Path(__file__).resolve().parents[2]


def request_for(root: Path) -> AgentInputRequest:
    entries = [
        InventoryEntry(
            path=path.name,
            sha256=sha256_bytes(path.read_bytes()),
            byte_length=path.stat().st_size,
            media_type="text/x-python",
        )
        for path in sorted(root.iterdir())
    ]
    return AgentInputRequest(
        target_snapshot_id="authored-worker",
        inventory=entries,
        selected={entry.path: "python-source" for entry in entries},
    )


def test_worker_parses_without_execution(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    marker = tmp_path / "must-not-exist"
    (target / "agent.py").write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
    request = request_for(target)
    raw = request.model_dump_json().encode()
    report = validate_view(target, raw)
    verify_input_report(report, request, raw)
    assert report.checks[0].artifact.parse_state == "parsed"
    assert not marker.exists()


@pytest.mark.parametrize("change", ["missing", "extra", "changed", "too-large", "wrong-request"])
def test_worker_binds_full_inventory(tmp_path: Path, change: str) -> None:
    target = tmp_path / "target"
    target.mkdir()
    path = target / "agent.py"
    path.write_bytes(b"x = 1\n")
    request = request_for(target)
    raw = request.model_dump_json().encode()
    if change == "missing":
        path.unlink()
    elif change == "extra":
        (target / "new.py").write_bytes(b"x = 2")
    elif change == "changed":
        path.write_bytes(b"x = 2\n")
    elif change == "too-large":
        path.write_bytes(b"x" * (256 * 1024 + 1))
    else:
        raw = b" " * (256 * 1024 + 1)
    with pytest.raises(ValueError):
        validate_view(target, raw)


def test_request_rejects_collision_and_unknown_selection(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_bytes(b"x = 1")
    request = request_for(tmp_path)
    with pytest.raises(ValueError, match="Ambiguous"):
        AgentInputRequest(
            target_snapshot_id="example",
            selected={},
            inventory=[
                request.inventory[0],
                request.inventory[0].model_copy(update={"path": "AGENT.py"}),
            ],
        )
    with pytest.raises(ValueError, match="absent"):
        AgentInputRequest(
            target_snapshot_id="example",
            selected={"missing.py": "python-source"},
            inventory=request.inventory,
        )


def test_commands_are_pinned_and_confined(tmp_path: Path) -> None:
    case, _ = load_development_case(PROJECT, "python-positive")
    target = tmp_path / "target"
    materialize_case(case, target)
    docker = tmp_path / "docker"
    docker.write_bytes(b"fake")
    request = tmp_path / "request.json"
    request.write_bytes(b"{}")
    tool = load_toml_config(PROJECT / "configs/tools/agent-audit.toml", AgentAuditToolConfig).value
    profile = load_toml_config(
        PROJECT / "configs/profiles/agent-development.toml", ExecutionProfile
    ).value
    scanner = build_agent_argv(
        docker=docker, tool=tool, profile=profile, name="test-agent", target=target
    )
    worker = build_agent_argv(
        docker=docker,
        tool=tool,
        profile=profile,
        name="test-agent",
        target=target,
        worker_source=PROJECT / "src",
        request=request,
    )
    assert tool.image in scanner and tool.validator_image in worker
    for argv in (scanner, worker):
        assert argv[argv.index("--pull") + 1] == "never"
        assert argv[argv.index("--network") + 1] == "none"
        assert argv[argv.index("--user") + 1] == "65534:65534"
        assert "--read-only" in argv and "no-new-privileges" in argv
        assert not any("docker.sock" in item or "API_KEY" in item for item in argv)
    assert "--live" not in scanner and "--llm" not in scanner
    with pytest.raises(ValueError, match="together"):
        build_agent_argv(
            docker=docker,
            tool=tool,
            profile=profile,
            name="test-agent",
            target=target,
            worker_source=PROJECT / "src",
        )
