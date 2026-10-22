"""Isolated annotation-aware tool worker; no historical contract or payload is rewritten."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Literal

from agentsec_evidence.agents.records import AgentInputRequest
from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.agents.worker import validate_view
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.custom_rules.tool_execution import (
    CATALOG_SHA256,
    RULES,
    SEVERITY_ORDER,
    FileResult,
    RuleSpec,
)
from agentsec_evidence.custom_rules.tool_execution_v2 import LIMITATIONS, scan_source
from agentsec_evidence.models.contracts import ContractModel, InventoryEntry, Sha256


class ToolExecutionV2Report(ContractModel):
    contract: Literal["tool-execution-static-v2"] = "tool-execution-static-v2"
    producer: Literal["student-tool-execution"] = "student-tool-execution"
    version: Literal["1.1.0"] = "1.1.0"
    request_sha256: Sha256
    target_snapshot_id: str
    catalog_sha256: Sha256 = CATALOG_SHA256
    rules: list[RuleSpec]
    execution_state: Literal["complete", "partial", "empty"]
    input_inventory: list[InventoryEntry]
    not_selected: list[str]
    files: list[FileResult]
    limitations: list[str]
    policy: Literal["research-only-no-suppressions-applied"] = (
        "research-only-no-suppressions-applied"
    )


def scan_view(root: Path, request_bytes: bytes) -> ToolExecutionV2Report:
    if root.is_symlink() or root.is_junction() or not root.is_dir():
        raise ValueError("Input root must be a regular directory")
    for count, path in enumerate(root.rglob("*"), 1):
        if count > 512 or path.is_symlink() or path.is_junction():
            raise ValueError("Input view exceeds its entry budget or contains a link")
    request = AgentInputRequest.model_validate(load_agent_json(request_bytes, max_bytes=256 * 1024))
    if any(kind != "python-source" for kind in request.selected.values()):
        raise ValueError("This treatment selects Python only; MCP uses its own analyzer")
    validate_view(root, request_bytes)
    files = []
    for entry in sorted(request.inventory, key=lambda e: e.path):
        if entry.path not in request.selected:
            continue
        path = root / entry.path
        if path.is_symlink() or path.is_junction():
            raise ValueError("Input changed after validation")
        with path.open("rb") as stream:
            raw = stream.read(256 * 1024 + 1)
        if len(raw) != entry.byte_length or sha256_bytes(raw) != entry.sha256:
            raise ValueError("Input changed after validation")
        files.append(scan_source(raw, path=entry.path))
    return ToolExecutionV2Report(
        request_sha256=sha256_bytes(request_bytes),
        target_snapshot_id=request.target_snapshot_id,
        rules=list(RULES),
        input_inventory=sorted(request.inventory, key=lambda e: e.path),
        not_selected=sorted({e.path for e in request.inventory} - request.selected.keys()),
        files=files,
        limitations=list(LIMITATIONS),
        execution_state="empty"
        if not files
        else "partial"
        if any(f.state != "analyzed" for f in files)
        else "complete",
    )


def exit_status(report: ToolExecutionV2Report) -> int:
    if report.execution_state != "complete":
        return 2
    return int(
        any(
            SEVERITY_ORDER[f.rule.severity] >= SEVERITY_ORDER["high"]
            for file in report.files
            for f in file.findings or []
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", type=Path)
    parser.add_argument("target", type=Path)
    parser.add_argument("--fail-on", choices=("high",), default="high")
    args = parser.parse_args()
    try:
        with args.request.open("rb") as stream:
            report = scan_view(args.target, stream.read(256 * 1024 + 1))
    except (OSError, ValueError, RecursionError, MemoryError):
        sys.stderr.write("Annotation-aware worker refused invalid input or a resource limit\n")
        raise SystemExit(2) from None
    sys.stdout.buffer.write(report.model_dump_json().encode() + b"\n")
    raise SystemExit(exit_status(report))


if __name__ == "__main__":
    main()
