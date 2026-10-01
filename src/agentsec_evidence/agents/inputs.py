from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import PurePosixPath

from pydantic import JsonValue

from agentsec_evidence.agents.models import AgentArtifact, ArtifactKind, ParseState
from agentsec_evidence.agents.validation import (
    AgentDataError,
    AgentResourceLimit,
    canonical_artifact_path,
    load_agent_json,
)
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.models.contracts import InventoryEntry

MAX_INPUT_BYTES = 256 * 1024
MAX_AST_NODES = 50_000
POLICY_FILENAMES = frozenset({".agent-audit.yaml", ".agent-audit.yml", "agent-audit.yaml"})
INPUT_POLICY_VERSION = "agent-input-policy-v1"
PYTHON_SKIPPED_DIRECTORIES = frozenset(
    {
        ".git",
        "venv",
        ".venv",
        "__pycache__",
        "dist",
        "build",
        "node_modules",
        ".tox",
        ".pytest_cache",
    }
)
_INLINE_MARKER = re.compile(r"#\s*noaudit\b", re.IGNORECASE)


@dataclass(frozen=True)
class CheckedAgentInput:
    artifact: AgentArtifact
    line_count: int | None
    suppression_lines: tuple[int, ...]


@dataclass(frozen=True)
class AgentInputAdmission:
    admitted: bool
    eligible_paths: tuple[str, ...]
    blocked_policy_paths: tuple[str, ...]
    blockers: tuple[str, ...]
    policy_version: str = INPUT_POLICY_VERSION


def _mcp_shape(document: dict[str, JsonValue]) -> tuple[ParseState, str]:
    if "mcpServers" not in document:
        return "unsupported", "Only the explicit mcpServers configuration shape is supported"
    servers = document["mcpServers"]
    if not isinstance(servers, dict):
        return "malformed", "mcpServers must be an object"
    for name, server in servers.items():
        if not name.strip() or not isinstance(server, dict):
            return "malformed", "Server entries require names and object values"
        command = server.get("command")
        if "url" in server or "transport" in server:
            return "unsupported", "Remote or mixed transport declarations are outside initial scope"
        if not isinstance(command, str) or not command.strip():
            return "malformed", "A local server requires a non-empty command string"
        args = server.get("args")
        if not isinstance(args, list) or any(not isinstance(value, str) for value in args):
            return "malformed", "Local server args must be an explicit list of strings"
        if "env" in server:
            environment = server["env"]
            if not isinstance(environment, dict) or any(
                not isinstance(value, str) for value in environment.values()
            ):
                return "malformed", "Server env must map names to strings"
    return "parsed", "Local mcpServers syntax and field shapes validated; commands not executed"


def validate_agent_input(
    data: bytes, *, path: str, kind: ArtifactKind, target_snapshot_id: str
) -> CheckedAgentInput:
    """Inspect explicit input bytes. Run untrusted Python parsing in a bounded container."""
    canonical_artifact_path(path)
    media_type = "text/x-python" if kind == "python-source" else "application/json"
    source = InventoryEntry(
        path=path,
        sha256=sha256_bytes(data),
        byte_length=len(data),
        media_type=media_type
        if kind in {"python-source", "mcp-config"}
        else "application/octet-stream",
    )
    format_id = {"python-source": "python-3.13-source", "mcp-config": "mcp-servers-json"}.get(kind)
    state: ParseState = "unsupported"
    reason = "Artifact kind is outside the initial Python/MCP input scope"
    limitations: list[str] = []
    line_count: int | None = None
    markers: tuple[int, ...] = ()
    if format_id is not None:
        if len(data) > MAX_INPUT_BYTES:
            state, reason = "failed", "Input exceeds the 256 KiB validation budget"
        else:
            try:
                text = data.decode("utf-8", errors="strict")
                lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
                if lines[-1] == "":
                    lines.pop()
                line_count = len(lines)
                markers = tuple(
                    number for number, line in enumerate(lines, 1) if _INLINE_MARKER.search(line)
                )
                if kind == "python-source":
                    if PurePosixPath(path).suffix != ".py":
                        state, reason = "unsupported", "Python input must use the .py extension"
                    else:
                        tree = ast.parse(text, filename="<agent-input>", mode="exec")
                        if sum(1 for _node in ast.walk(tree)) > MAX_AST_NODES:
                            state, reason = "failed", "Python AST node budget exceeded"
                        else:
                            state, reason = (
                                "parsed",
                                "Python AST parsed; no imports or code executed",
                            )
                elif PurePosixPath(path).suffix != ".json":
                    state, reason = "unsupported", "MCP input must use the .json extension"
                else:
                    state, reason = _mcp_shape(load_agent_json(data, max_bytes=MAX_INPUT_BYTES))
            except AgentResourceLimit:
                state, reason = "failed", "JSON parser resource limit reached"
            except (UnicodeError, SyntaxError, ValueError):
                state, reason = "malformed", "Input syntax, encoding or JSON structure is invalid"
            except (RecursionError, MemoryError):
                state, reason = "failed", "Input parser resource limit reached"
        limitations.append(
            "Parsed syntax is not detection coverage, runtime reachability or safety"
        )
        if markers:
            limitations.append("Potential suppression marker found; baseline admission is blocked")
    artifact = AgentArtifact(
        target_snapshot_id=target_snapshot_id,
        source=source,
        kind=kind,
        format_id=format_id,
        parse_state=state,
        reason=reason,
        limitations=limitations,
    )
    return CheckedAgentInput(artifact, line_count, markers)


def plan_agent_input_admission(
    checks: Iterable[CheckedAgentInput], *, snapshot_paths: Iterable[str]
) -> AgentInputAdmission:
    """Fail closed on unhandled policy. No YAML loading, host-parent lookup or rewriting."""
    paths = tuple(canonical_artifact_path(path) for path in snapshot_paths)
    if len(set(path.casefold() for path in paths)) != len(paths):
        raise AgentDataError("Duplicate or case-colliding snapshot paths")
    items = tuple(checks)
    checked_paths = [item.artifact.source.path for item in items]
    if len(set(checked_paths)) != len(checked_paths) or not set(checked_paths).issubset(paths):
        raise AgentDataError("Input checks do not uniquely identify snapshot files")
    if len({item.artifact.target_snapshot_id for item in items}) > 1:
        raise AgentDataError("Input checks span multiple snapshots")
    policy_paths = tuple(
        sorted(path for path in paths if PurePosixPath(path).name.casefold() in POLICY_FILENAMES)
    )
    blockers = [f"target-policy:{path}" for path in policy_paths]
    eligible: list[str] = []
    for item in items:
        artifact = item.artifact
        if artifact.parse_state == "parsed":
            eligible.append(artifact.source.path)
        else:
            blockers.append(f"input-{artifact.parse_state}:{artifact.source.path}")
        if artifact.kind == "python-source" and any(
            part in PYTHON_SKIPPED_DIRECTORIES
            for part in PurePosixPath(artifact.source.path).parts[:-1]
        ):
            blockers.append(f"native-default-exclusion:{artifact.source.path}")
        if item.suppression_lines:
            blockers.append(f"suppression-marker:{artifact.source.path}")
    if not eligible:
        blockers.append("no-eligible-inputs")
    return AgentInputAdmission(
        not blockers, tuple(sorted(eligible)), policy_paths, tuple(sorted(blockers))
    )
