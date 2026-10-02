"""Syntax-only worker. Invoke inside the restricted validation container, not on target hosts."""

from __future__ import annotations

import sys
from pathlib import Path

from agentsec_evidence.agents.inputs import MAX_INPUT_BYTES, validate_agent_input
from agentsec_evidence.agents.records import AgentInputCheck, AgentInputReport, AgentInputRequest
from agentsec_evidence.agents.validation import canonical_artifact_path, load_agent_json
from agentsec_evidence.core.identity import sha256_bytes


def validate_view(root: Path, request_bytes: bytes) -> AgentInputReport:
    request = AgentInputRequest.model_validate(load_agent_json(request_bytes, max_bytes=256 * 1024))
    files: dict[str, Path] = {}
    for path in root.rglob("*"):
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            raise ValueError("Unsafe input view entry")
        if path.is_file():
            files[canonical_artifact_path(path.relative_to(root).as_posix())] = path
        if len(files) > 64:
            raise ValueError("Input file budget exceeded")
    if set(files) != {item.path for item in request.inventory}:
        raise ValueError("Input view and inventory differ")
    checks: list[AgentInputCheck] = []
    for entry in request.inventory:
        with files[entry.path].open("rb") as stream:
            data = stream.read(MAX_INPUT_BYTES + 1)
        if (
            len(data) > MAX_INPUT_BYTES
            or len(data) != entry.byte_length
            or sha256_bytes(data) != entry.sha256
        ):
            raise ValueError("Input bytes differ from bounded inventory")
        if entry.path not in request.selected:
            continue
        checked = validate_agent_input(
            data,
            path=entry.path,
            kind=request.selected[entry.path],
            target_snapshot_id=request.target_snapshot_id,
        )
        checks.append(
            AgentInputCheck(
                artifact=checked.artifact.model_copy(update={"source": entry}),
                line_count=checked.line_count,
                suppression_lines=list(checked.suppression_lines),
            )
        )
    return AgentInputReport(request_sha256=sha256_bytes(request_bytes), checks=checks)


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(2)
    try:
        with Path(sys.argv[1]).open("rb") as stream:
            request = stream.read(256 * 1024 + 1)
        report = validate_view(Path(sys.argv[2]), request)
        sys.stdout.buffer.write(report.model_dump_json().encode("utf-8") + b"\n")
    except (OSError, ValueError, RecursionError, MemoryError):
        sys.stderr.write("Input worker failed validation or a resource guard\n")
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
