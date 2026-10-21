"""Finite offline rehearsal of the repaired tool-execution worker, not public-target intake."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from agentsec_evidence.agents.records import AgentInputRequest
from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.custom_rules.tool_execution_worker import ToolExecutionReport
from agentsec_evidence.models.contracts import InventoryEntry

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "sha256:3bfa1ba1294f1c4683ebbbbff98921e67b8230299fe35e0f5e82deefc6a73080"
REGISTRY = ROOT / "test_cases/development/tool-execution-v1/cases.json"


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def docker_argv(name: str, target: Path, request: Path, source: Path) -> list[str]:
    return [
        "docker",
        "run",
        "--name",
        name,
        "--rm",
        "--pull",
        "never",
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
        "64",
        "--memory",
        "512m",
        "--memory-swap",
        "512m",
        "--cpus",
        "1",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--workdir",
        "/tmp",
        "--env",
        "HOME=/tmp",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "--env",
        "PYTHONPATH=/app/src",
        "--mount",
        f"type=bind,src={source},dst=/app/src,readonly",
        "--mount",
        f"type=bind,src={target},dst=/target,readonly",
        "--mount",
        f"type=bind,src={request},dst=/request.json,readonly",
        IMAGE,
        "/app/.venv/bin/python",
        "-P",
        "-X",
        "utf8",
        "-m",
        "agentsec_evidence.custom_rules.tool_execution_worker",
        "/request.json",
        "/target",
        "--fail-on",
        "high",
    ]


def rehearse(output: Path) -> None:
    output = output.resolve()
    if not output.is_relative_to((ROOT / "outputs").resolve()):
        raise ValueError("Rehearsal output must stay under this project's outputs")
    output.mkdir(parents=True, exist_ok=False)
    registry = json.loads(REGISTRY.read_bytes())
    if registry["contract"] != "tool-execution-repair-cases-v1":
        raise ValueError("Unexpected development case contract")
    cases = registry["cases"]
    # These are trusted, authored fixture bytes; never import or execute them.
    target = output / "input"
    target.mkdir()
    for case in cases:
        if not case["id"].isascii() or not case["id"].replace("-", "").isalnum():
            raise ValueError("Invalid fixed case identifier")
        (target / f"{case['id']}.py").write_bytes(case["source"].encode("utf-8"))
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
    implementation[REGISTRY.relative_to(ROOT).as_posix()] = sha256_file(REGISTRY)
    implementation[Path(__file__).relative_to(ROOT).as_posix()] = sha256_file(Path(__file__))
    write_json(output / "implementation.json", implementation)
    snapshot = output / "source-snapshot"
    for relative, digest in implementation.items():
        destination = snapshot / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
        if sha256_file(destination) != digest:
            raise ValueError("Code snapshot differs from its receipt")
    inspect = subprocess.run(
        ["docker", "image", "inspect", IMAGE],
        capture_output=True,
        check=False,
        timeout=30,
    )
    (output / "image-inspect.stdout.json").write_bytes(inspect.stdout)
    (output / "image-inspect.stderr.txt").write_bytes(inspect.stderr)
    if inspect.returncode or json.loads(inspect.stdout)[0]["Id"] != IMAGE:
        raise ValueError("Pinned validation image unavailable or differs")
    clean_controls = {"corrected-literal-parser", "tool-corrected", "shell-false", "fixed-import"}
    treatments = [
        ("all-repeat-1", cases, 2),
        ("all-repeat-2", cases, 2),
        ("valid-only", [case for case in cases if case["rules"] is not None], 1),
        ("corrected-controls", [case for case in cases if case["id"] in clean_controls], 0),
    ]
    rows = []
    repeat_bytes: list[bytes] = []
    for name, selected, expected_exit in treatments:
        attempt = output / name
        attempt.mkdir()
        request = AgentInputRequest(
            target_snapshot_id="development-tool-execution-v1",
            inventory=inventory,
            selected={f"{case['id']}.py": "python-source" for case in selected},
        )
        request_path = attempt / "request.json"
        request_path.write_bytes(request.model_dump_json().encode() + b"\n")
        container_name = f"tool-exec-repair-{sha256_bytes(str(output).encode())[:10]}-{name}"
        argv = docker_argv(container_name, target, request_path, snapshot / "src")
        write_json(attempt / "invocation.json", {"argv": argv, "expected_exit": expected_exit})
        start = time.perf_counter_ns()
        try:
            result = subprocess.run(argv, capture_output=True, check=False, timeout=90)
        except subprocess.TimeoutExpired as error:
            (attempt / "stdout.json").write_bytes(error.stdout or b"")
            (attempt / "stderr.txt").write_bytes(error.stderr or b"")
            cleanup = subprocess.run(
                ["docker", "rm", "-f", container_name],
                capture_output=True,
                check=False,
                timeout=30,
            )
            write_json(
                attempt / "failure.json",
                {"state": "timeout", "cleanup_exit": cleanup.returncode},
            )
            raise
        duration = time.perf_counter_ns() - start
        (attempt / "stdout.json").write_bytes(result.stdout)
        (attempt / "stderr.txt").write_bytes(result.stderr)
        write_json(
            attempt / "process.json", {"exit_code": result.returncode, "duration_ns": duration}
        )
        if result.returncode != expected_exit or result.stderr:
            raise ValueError(f"Unexpected worker status in {name}; retained raw outputs")
        report = ToolExecutionReport.model_validate_json(result.stdout)
        if report.request_sha256 != sha256_file(request_path):
            raise ValueError("Worker response does not bind the exact request")
        actual = {file.path: file for file in report.files}
        if set(actual) != set(request.selected):
            raise ValueError("Selected-file accounting differs")
        for case in selected:
            file = actual[f"{case['id']}.py"]
            rule_ids = (
                [item.rule.rule_id for item in file.findings] if file.findings is not None else None
            )
            if rule_ids != case["rules"]:
                raise ValueError(f"Unexpected rule observations in {name}/{case['id']}")
            expected_state = "malformed" if case["rules"] is None else "analyzed"
            if file.state != expected_state:
                raise ValueError("File analysis state differs")
        if name.startswith("all-repeat"):
            repeat_bytes.append(result.stdout)
        rows.append(
            {
                "treatment": name,
                "selected_files": len(selected),
                "execution_state": report.execution_state,
                "native_findings": sum(len(file.findings or []) for file in report.files),
                "files_with_unknown_or_unsupported_constructs": sum(
                    bool(file.limitations_observed) for file in report.files
                ),
                "exit_code": result.returncode,
                "duration_ns": duration,
                "stdout_sha256": sha256_bytes(result.stdout),
            }
        )
    if repeat_bytes[0] != repeat_bytes[1]:
        raise ValueError("Repeated native reports differ")
    for relative, digest in implementation.items():
        if sha256_file(ROOT / relative) != digest or sha256_file(snapshot / relative) != digest:
            raise ValueError("Implementation changed during rehearsal")
    for entry in inventory:
        if sha256_file(target / entry.path) != entry.sha256:
            raise ValueError("Fixture bytes changed during rehearsal")
    write_json(
        output / "verification.json",
        {
            "contract": "tool-execution-repair-verification-v1",
            "scope": "finite development cases, not public accuracy or runtime exploitability",
            "registry_sha256": sha256_file(REGISTRY),
            "image_id": IMAGE,
            "case_count": len(cases),
            "repeated_native_bytes_equal": True,
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
    print(f"Verified {len(cases)} development cases across four Docker treatments: {output}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rehearse(args.output)


if __name__ == "__main__":
    main()
