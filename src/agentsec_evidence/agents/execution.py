from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from agentsec_evidence.execution.config import ExecutionProfile, StrictConfigModel


class AgentAuditToolConfig(StrictConfigModel):
    tool_id: Literal["agent-audit"]
    tool_version: Literal["0.20.0"]
    adapter_id: Literal["agent-audit-json"]
    adapter_version: Literal["0.1.0"]
    image: Literal["sha256:e4b41016ff8cd5b5c769f171cca3f3f145a8312a3fb2a0ad72993b11a636e79a"]
    validator_image: Literal[
        "sha256:3bfa1ba1294f1c4683ebbbbff98921e67b8230299fe35e0f5e82deefc6a73080"
    ]
    source_revision: Literal["8c4c5cb9bddd4758b064577c912ee8afcaf5330f"]
    treatment: Literal["authored-agent-static-v1", "python-source-pilot-v1"]
    network: Literal["denied"]
    executes_target_code: Literal[False]


def _mount(path: Path, destination: str) -> str:
    source = str(path.resolve(strict=True))
    if any(character in source for character in (",", "\r", "\n", "\0")):
        raise ValueError("Invalid Docker mount source")
    return f"type=bind,source={source},target={destination},readonly"


def build_agent_argv(
    *,
    docker: Path,
    tool: AgentAuditToolConfig,
    profile: ExecutionProfile,
    name: str,
    target: Path,
    worker_source: Path | None = None,
    request: Path | None = None,
) -> list[str]:
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]+", name):
        raise ValueError("Invalid container name")
    if (worker_source is None) != (request is None):
        raise ValueError("Worker source and request must be supplied together")
    limits = profile.limits
    argv = [
        str(docker.resolve(strict=True)),
        "run",
        "--rm",
        "--pull",
        "never",
        "--name",
        name,
        "--network",
        "none",
        "--read-only",
        "--user",
        "65534:65534",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(limits.pids),
        "--cpus",
        str(limits.cpu_count),
        "--memory",
        f"{limits.memory_mb}m",
        "--memory-swap",
        f"{limits.memory_mb}m",
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,size={limits.tmpfs_mb}m",
        "--workdir",
        "/tmp",
        "--env",
        "HOME=/tmp",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "--mount",
        _mount(target, "/target"),
    ]
    if worker_source is not None and request is not None:
        argv += [
            "--mount",
            _mount(worker_source, "/app/src"),
            "--mount",
            _mount(request, "/request.json"),
            "--env",
            "PYTHONPATH=/app/src",
            tool.validator_image,
            "/app/.venv/bin/python",
            "-P",
            "-m",
            "agentsec_evidence.agents.worker",
            "/request.json",
            "/target",
        ]
    else:
        argv += [
            tool.image,
            "scan",
            "/target",
            "--format",
            "json",
            "--severity",
            "info",
            "--fail-on",
            "high",
            "--no-color",
        ]
    return argv
