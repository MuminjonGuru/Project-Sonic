from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path

from agentsec_evidence.execution.config import ExecutionProfile, SemgrepToolConfig

_CONTAINER_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]+$")


def _mount(source: Path, target: str, *, read_only: bool) -> str:
    resolved = str(source.resolve(strict=True))
    if any(character in resolved for character in (",", "\n", "\r", "\x00")):
        msg = "Docker mount source contains an unsupported character"
        raise ValueError(msg)
    suffix = ",readonly" if read_only else ""
    return f"type=bind,source={resolved},target={target}{suffix}"


def build_semgrep_argv(
    *,
    docker_executable: Path,
    tool: SemgrepToolConfig,
    profile: ExecutionProfile,
    container_name: str,
    target_root: Path,
    rule_file: Path,
    output_root: Path,
) -> list[str]:
    if not _CONTAINER_NAME.fullmatch(container_name):
        msg = "Invalid Docker container name"
        raise ValueError(msg)
    output_root.mkdir(parents=True, exist_ok=True)

    limits = profile.limits
    return [
        str(docker_executable.resolve(strict=True)),
        "run",
        "--rm",
        "--pull",
        "never",
        "--name",
        container_name,
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,size={limits.tmpfs_mb}m",
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
        "--user",
        "65534:65534",
        "--env",
        "HOME=/tmp",
        "--env",
        "SEMGREP_SEND_METRICS=off",
        "--mount",
        _mount(target_root, "/src", read_only=True),
        "--mount",
        _mount(rule_file, "/rules.yml", read_only=True),
        "--mount",
        _mount(output_root, "/output", read_only=False),
        tool.image,
        "semgrep",
        "scan",
        "--config",
        "/rules.yml",
        "--json",
        "--json-output",
        "/output/semgrep.json",
        "--metrics=off",
        "--disable-version-check",
        "--strict",
        "--no-git-ignore",
        "--exclude",
        "ignored/**",
        "/src",
    ]


def build_container_cleanup_argv(*, docker_executable: Path, container_name: str) -> list[str]:
    if not _CONTAINER_NAME.fullmatch(container_name):
        raise ValueError("Invalid Docker container name")
    return [
        str(docker_executable.resolve(strict=True)),
        "container",
        "rm",
        "--force",
        container_name,
    ]


def portable_docker_argv(
    argv: Sequence[str],
    *,
    docker_executable: Path,
    mount_replacements: Mapping[Path, str],
) -> list[str]:
    """Remove machine-local executable and mount paths from persisted argv."""
    portable = list(argv)
    portable[0] = "docker"
    replacements = {
        str(path.resolve(strict=True)): f"<{label}>" for path, label in mount_replacements.items()
    }
    for index, argument in enumerate(portable[1:], start=1):
        for source, replacement in replacements.items():
            argument = argument.replace(f"source={source}", f"source={replacement}")
        portable[index] = argument
    return portable
