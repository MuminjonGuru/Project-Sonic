"""Exercise the finite authored agent CLI matrix; requires both pinned local Docker images."""

from __future__ import annotations

import argparse
import dataclasses
import json
import shutil
import sys
from pathlib import Path

from agentsec_evidence.agents.development import APPROVED_CASES
from agentsec_evidence.agents.records import AgentRunDetails
from agentsec_evidence.core.identity import sha256_file
from agentsec_evidence.core.io import atomic_write_bytes, json_bytes
from agentsec_evidence.execution.process import run_bounded_process
from agentsec_evidence.operations.offline import (
    load_existing_run,
    normalize_existing_run,
    validate_existing_run,
)
from agentsec_evidence.orchestration.shared import minimal_environment
from agentsec_evidence.reporting.service import validate_common_report, write_common_report

ADMITTED = {
    "python-positive",
    "python-corrected",
    "python-near-miss",
    "mcp-positive",
    "mcp-corrected",
    "mcp-near-miss",
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New private evidence directory")
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    workspace = output / "workspace"
    environment = minimal_environment(output / "runtime")
    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError("Docker CLI is unavailable")
    # The child CLI needs discovery; pass only Docker's directory, not the host PATH.
    environment["PATH"] = str(Path(docker).resolve().parent)
    rows = []
    bundles = []
    cases = [*sorted(APPROVED_CASES), "python-positive", "python-positive"]
    for index, case in enumerate(cases, 1):
        capture = run_bounded_process(
            [
                sys.executable,
                "-m",
                "agentsec_evidence",
                "scan",
                "agent-audit",
                case,
                "--project-root",
                str(project),
                "--workspace",
                str(workspace),
                "--json",
            ],
            cwd=project,
            environment=environment,
            timeout_seconds=360,
            max_stdout_bytes=4 * 1024 * 1024,
            max_stderr_bytes=2 * 1024 * 1024,
        )
        record_root = output / "cli" / f"{index:02d}-{case}"
        atomic_write_bytes(record_root / "stdout.bin", capture.stdout)
        atomic_write_bytes(record_root / "stderr.bin", capture.stderr)
        record = dataclasses.asdict(capture)
        del record["stdout"], record["stderr"]
        atomic_write_bytes(
            record_root / "capture.json", json.dumps(record, indent=2, default=str).encode()
        )
        expected_exit = 8 if case in ADMITTED else 6
        if (
            capture.exit_code != expected_exit
            or capture.timed_out
            or capture.output_limited
            or capture.stderr
        ):
            raise RuntimeError(f"CLI matrix case {case} failed; retained {record_root}")
        payload = json.loads(capture.stdout)
        existing = load_existing_run(workspace, payload["run_id"])
        validation = validate_existing_run(
            project_root=project, workspace_root=workspace, run_id=payload["run_id"]
        )
        if not validation.passed:
            raise RuntimeError(f"Invalid finalized evidence for {case}")
        details = AgentRunDetails.model_validate(payload["agent_details"])
        if details.admitted != (case in ADMITTED) or not details.input_unchanged:
            raise RuntimeError(f"Admission or input-integrity discrepancy: {case}")
        bundles.append(existing.root)
        row = {
            "case": case,
            "run_id": existing.run.run_id,
            "state": payload["terminal_state"],
            "cli_exit": capture.exit_code,
            "native_exit": existing.execution.exit_code,
            "native_findings": details.native_result_count,
            "native_files": details.native_scanned_files,
            "blockers": details.blockers,
            "rules": [finding.rule.native_id for finding in existing.findings],
            "semantic_sha256": existing.run.semantic_sha256,
            "manifest_sha256": sha256_file(existing.root / "bundle-manifest.json"),
            "validation_duration_ns": details.validation_duration_ns,
            "scanner_duration_ns": details.scanner_duration_ns,
            "total_duration_ns": details.total_duration_ns,
            "valid": True,
        }
        rows.append(row)
        atomic_write_bytes(output / "progress.json", json_bytes(rows))
        print(json.dumps(row), flush=True)
    repeats = [row for row in rows if row["case"] == "python-positive"]
    if len({row["semantic_sha256"] for row in repeats}) != 1:
        raise RuntimeError("Positive-case semantic repeats differ; originals retained")
    write_common_report(project_root=project, bundles=bundles, output=output / "common-report")
    validate_common_report(project, output / "common-report")
    normalize_existing_run(
        project_root=project,
        workspace_root=workspace,
        run_id=repeats[0]["run_id"],
        output_root=output / "offline-derivative",
    )
    atomic_write_bytes(
        output / "matrix.json",
        json_bytes(
            {
                "role": "authored-engineering-integration-not-held-out",
                "passed": True,
                "cases": 13,
                "runs": len(rows),
                "scanner_invocations": sum(row["case"] in ADMITTED for row in rows),
                "positive_semantic_sha256": repeats[0]["semantic_sha256"],
                "rows": rows,
            }
        ),
    )


if __name__ == "__main__":
    main()
