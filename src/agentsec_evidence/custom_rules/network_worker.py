"""Development-only network detector worker; invoke inside the restricted Docker image."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Literal

from agentsec_evidence.agents.inputs import MAX_INPUT_BYTES
from agentsec_evidence.agents.records import AgentInputRequest
from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.agents.worker import validate_view
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.custom_rules.network_catalog import CATALOG_SHA256, RULES, NetworkRule
from agentsec_evidence.custom_rules.network_data import (
    LIMITATIONS,
    VERSION,
    NetworkFileResult,
    scan_source,
)
from agentsec_evidence.models.contracts import ContractModel, InventoryEntry, Sha256

PRIORITIES = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class NetworkReport(ContractModel):
    contract: Literal["network-data-development-v1"] = "network-data-development-v1"
    producer: Literal["student-network-data-repaired"] = "student-network-data-repaired"
    version: Literal["1.0.0"] = VERSION
    request_sha256: Sha256
    target_snapshot_id: str
    catalog_sha256: Sha256 = CATALOG_SHA256
    rules: list[NetworkRule]
    execution_state: Literal["complete", "partial", "empty"]
    input_inventory: list[InventoryEntry]
    not_selected: list[str]
    files: list[NetworkFileResult]
    limitations: list[str]
    policy: Literal["research-only-no-suppressions-applied"] = (
        "research-only-no-suppressions-applied"
    )


def scan_view(root: Path, request_bytes: bytes) -> NetworkReport:
    if root.is_symlink() or root.is_junction() or not root.is_dir():
        raise ValueError("Input root must be a regular directory")
    for count, candidate in enumerate(root.rglob("*"), 1):
        if count > 512 or candidate.is_symlink() or candidate.is_junction():
            raise ValueError("Input view contains a link or exceeds its entry budget")
    request = AgentInputRequest.model_validate(load_agent_json(request_bytes, max_bytes=256 * 1024))
    validate_view(root, request_bytes)
    results: list[NetworkFileResult] = []
    for entry in sorted(request.inventory, key=lambda item: item.path):
        if entry.path not in request.selected:
            continue
        path = root / entry.path
        if path.is_symlink() or path.is_junction():
            raise ValueError("Input changed after validation")
        with path.open("rb") as stream:
            data = stream.read(MAX_INPUT_BYTES + 1)
        if len(data) != entry.byte_length or sha256_bytes(data) != entry.sha256:
            raise ValueError("Input changed after validation")
        if request.selected[entry.path] != "python-source":
            results.append(
                NetworkFileResult(
                    path=entry.path,
                    source_sha256=entry.sha256,
                    byte_length=entry.byte_length,
                    state="unsupported",
                    reason="Not Python source; MCP uses its existing analyzer",
                    findings=None,
                    inventory=[],
                    limitations_observed=[],
                )
            )
        else:
            results.append(scan_source(data, path=entry.path))
    state: Literal["complete", "partial", "empty"] = "complete"
    if not results:
        state = "empty"
    elif any(file.state != "analyzed" for file in results):
        state = "partial"
    return NetworkReport(
        request_sha256=sha256_bytes(request_bytes),
        target_snapshot_id=request.target_snapshot_id,
        rules=list(RULES),
        execution_state=state,
        input_inventory=sorted(request.inventory, key=lambda item: item.path),
        not_selected=sorted(set(item.path for item in request.inventory) - request.selected.keys()),
        files=results,
        limitations=list(LIMITATIONS),
    )


def exit_status(report: NetworkReport, fail_on: str | None) -> int:
    if fail_on is not None and fail_on not in PRIORITIES:
        raise ValueError("Unknown priority threshold")
    if report.execution_state != "complete":
        return 2
    if fail_on is not None and any(
        PRIORITIES[finding.priority] >= PRIORITIES[fail_on]
        for file in report.files
        for finding in file.findings or []
    ):
        return 1
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", type=Path)
    parser.add_argument("target", type=Path)
    parser.add_argument("--fail-on", choices=tuple(PRIORITIES))
    args = parser.parse_args()
    try:
        with args.request.open("rb") as stream:
            request = stream.read(256 * 1024 + 1)
        report = scan_view(args.target, request)
        payload = report.model_dump_json().encode("utf-8") + b"\n"
    except (OSError, ValueError, RecursionError, MemoryError):
        sys.stderr.write("Network worker refused invalid input or exceeded a resource guard\n")
        raise SystemExit(2) from None
    sys.stdout.buffer.write(payload)
    raise SystemExit(exit_status(report, args.fail_on))


if __name__ == "__main__":
    main()
