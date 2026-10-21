"""Offline finite development rehearsal; does not accept arbitrary repositories."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from verify_tool_execution_repair import IMAGE, docker_argv, write_json

from agentsec_evidence.agents.records import AgentInputRequest
from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.custom_rules.network_worker import NetworkReport
from agentsec_evidence.models.contracts import InventoryEntry

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "test_cases/development/network-data-v1/cases.json"


def rehearse(output: Path) -> None:
    output = output.resolve()
    if not output.is_relative_to((ROOT / "outputs").resolve()):
        raise ValueError("Output must stay below the development outputs directory")
    output.mkdir(parents=True, exist_ok=False)
    registry = json.loads(REGISTRY.read_bytes())
    if registry["contract"] != "network-data-repair-cases-v1":
        raise ValueError("Unexpected development registry")
    cases = registry["cases"]
    target = output / "input"
    target.mkdir()
    for case in cases:
        if not case["id"].isascii() or not case["id"].replace("-", "").isalnum():
            raise ValueError("Invalid fixed case identifier")
        (target / f"{case['id']}.py").write_bytes(case["source"].encode())
    inventory = [
        InventoryEntry(
            path=path.name,
            sha256=sha256_file(path),
            byte_length=path.stat().st_size,
            media_type="text/x-python",
        )
        for path in sorted(target.iterdir())
    ]
    implementation = {
        path.relative_to(ROOT).as_posix(): sha256_file(path)
        for path in sorted((ROOT / "src").rglob("*.py"))
    }
    for path in (REGISTRY, Path(__file__), ROOT / "tools/verify_tool_execution_repair.py"):
        implementation[path.relative_to(ROOT).as_posix()] = sha256_file(path)
    write_json(output / "implementation.json", implementation)
    snapshot = output / "source-snapshot"
    for relative, digest in implementation.items():
        destination = snapshot / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
        if sha256_file(destination) != digest:
            raise ValueError("Source snapshot differs")
    inspect = subprocess.run(
        ["docker", "image", "inspect", IMAGE],
        capture_output=True,
        check=False,
        timeout=30,
    )
    (output / "image-inspect.stdout.json").write_bytes(inspect.stdout)
    (output / "image-inspect.stderr.txt").write_bytes(inspect.stderr)
    if inspect.returncode or json.loads(inspect.stdout)[0]["Id"] != IMAGE:
        raise ValueError("Pinned local validation image unavailable or differs")
    corrected = {"fixed-http", "fixed-tool", "auth-header-not-leak", "fixed-s3", "fixed-proxy"}
    treatments = [
        ("all-repeat-1", cases, 2),
        ("all-repeat-2", cases, 2),
        ("valid-only", [case for case in cases if case["rules"] is not None], 1),
        ("corrected-controls", [case for case in cases if case["id"] in corrected], 0),
    ]
    rows: list[dict[str, Any]] = []
    repeated: list[bytes] = []
    for name, selected, expected_exit in treatments:
        attempt = output / name
        attempt.mkdir()
        request = AgentInputRequest(
            target_snapshot_id="development-network-data-v1",
            inventory=inventory,
            selected={f"{case['id']}.py": "python-source" for case in selected},
        )
        request_path = attempt / "request.json"
        request_path.write_bytes(request.model_dump_json().encode() + b"\n")
        container = f"network-repair-{sha256_bytes(str(output).encode())[:10]}-{name}"
        argv = docker_argv(container, target, request_path, snapshot / "src")
        # Retain the proven isolation settings; only worker and review threshold differ.
        argv[argv.index("agentsec_evidence.custom_rules.tool_execution_worker")] = (
            "agentsec_evidence.custom_rules.network_worker"
        )
        argv[-1] = "low"
        write_json(attempt / "invocation.json", {"argv": argv, "expected_exit": expected_exit})
        start = time.perf_counter_ns()
        try:
            result = subprocess.run(argv, capture_output=True, check=False, timeout=90)
        except subprocess.TimeoutExpired as error:
            (attempt / "stdout.json").write_bytes(error.stdout or b"")
            (attempt / "stderr.txt").write_bytes(error.stderr or b"")
            cleanup = subprocess.run(
                ["docker", "rm", "-f", container],
                capture_output=True,
                check=False,
                timeout=30,
            )
            write_json(
                attempt / "failure.json",
                {
                    "state": "timeout",
                    "cleanup_exit": cleanup.returncode,
                },
            )
            raise
        duration = time.perf_counter_ns() - start
        (attempt / "stdout.json").write_bytes(result.stdout)
        (attempt / "stderr.txt").write_bytes(result.stderr)
        write_json(
            attempt / "process.json",
            {
                "exit_code": result.returncode,
                "duration_ns": duration,
            },
        )
        if result.returncode != expected_exit or result.stderr:
            raise ValueError(f"Unexpected status in {name}; original outputs retained")
        report = NetworkReport.model_validate_json(result.stdout)
        if report.request_sha256 != sha256_file(request_path):
            raise ValueError("Exact request binding differs")
        actual = {item.path: item for item in report.files}
        if set(actual) != set(request.selected):
            raise ValueError("Selected-file accounting differs")
        for case in selected:
            file = actual[f"{case['id']}.py"]
            ids = None if file.findings is None else [item.rule_id for item in file.findings]
            observed = sorted({item.rule_id for item in file.inventory if item.rule_id})
            if ids != case["rules"] or observed != case["inventory"]:
                raise ValueError(f"Expected observations differ: {name}/{case['id']}")
            if file.state != ("malformed" if case["rules"] is None else "analyzed"):
                raise ValueError("File state differs")
        if b"DO_NOT_EXPORT_SECRET" in result.stdout:
            raise ValueError("Synthetic credential sentinel leaked into report")
        if name.startswith("all-repeat"):
            repeated.append(result.stdout)
        rows.append(
            {
                "treatment": name,
                "selected_files": len(selected),
                "execution_state": report.execution_state,
                "native_findings": sum(len(file.findings or []) for file in report.files),
                "inventory_rule_observations": sum(
                    sum(item.rule_id is not None for item in file.inventory)
                    for file in report.files
                ),
                "files_with_unknown_or_unsupported_constructs": sum(
                    bool(file.limitations_observed) for file in report.files
                ),
                "exit_code": result.returncode,
                "duration_ns": duration,
                "stdout_sha256": sha256_bytes(result.stdout),
            }
        )
    if repeated[0] != repeated[1]:
        raise ValueError("Repeated native reports differ")
    for relative, digest in implementation.items():
        if sha256_file(ROOT / relative) != digest or sha256_file(snapshot / relative) != digest:
            raise ValueError("Implementation changed during rehearsal")
    for entry in inventory:
        if sha256_file(target / entry.path) != entry.sha256:
            raise ValueError("Authored input changed during rehearsal")
    write_json(
        output / "verification.json",
        {
            "contract": "network-data-repair-verification-v1",
            "scope": "finite syntax development cases, not public accuracy or exploitability",
            "registry_sha256": sha256_file(REGISTRY),
            "image_id": IMAGE,
            "case_count": len(cases),
            "repeated_native_bytes_equal": True,
            "credential_sentinel_absent": True,
            "rows": rows,
            "expectations": registry["expectation_provenance"],
        },
    )
    write_json(
        output / "manifest.json",
        {
            path.relative_to(output).as_posix(): sha256_file(path)
            for path in sorted(output.rglob("*"))
            if path.is_file()
        },
    )
    print(f"Verified {len(cases)} cases across four isolated treatments: {output}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rehearse(args.output)


if __name__ == "__main__":
    main()
