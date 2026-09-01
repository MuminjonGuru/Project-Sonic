from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentsec_evidence.cli.app import app
from agentsec_evidence.core.time import utc_now
from agentsec_evidence.execution.process import ProcessCapture
from agentsec_evidence.orchestration import pipeline


def test_cli_offline_workflow_does_not_rerun_producer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project_root = Path(__file__).resolve().parents[2]
    target = project_root / "test_cases" / "development" / "semgrep-basic" / "target"
    native_data = (project_root / "tests" / "fixtures" / "semgrep" / "finding.json").read_bytes()
    workspace = tmp_path / "workspace"
    fake_docker = tmp_path / "docker.exe"
    fake_docker.write_bytes(b"test double")
    calls = 0

    def fake_run(
        argv: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> ProcessCapture:
        nonlocal calls
        del cwd, environment, timeout_seconds, max_stdout_bytes, max_stderr_bytes
        calls += 1
        roots = list((workspace / "staging").glob("execution_*"))
        assert len(roots) == 1
        (roots[0] / "output" / "semgrep.json").write_bytes(native_data)
        instant = utc_now()
        return ProcessCapture(
            argv=tuple(argv),
            started_at=instant,
            ended_at=instant,
            duration_ns=100,
            exit_code=0,
            stdout=b"",
            stderr=b"",
            timed_out=False,
            output_limited=False,
            stdout_truncated=False,
            stderr_truncated=False,
            peak_rss_bytes=1,
        )

    monkeypatch.setattr(pipeline, "_resolve_docker", lambda _explicit: fake_docker)
    monkeypatch.setattr(pipeline, "run_bounded_process", fake_run)
    runner = CliRunner()
    common = ["--project-root", str(project_root), "--workspace", str(workspace)]

    scan = runner.invoke(
        app,
        [
            "scan",
            "semgrep",
            str(target),
            "--label",
            "fixture:cli",
            "--revision",
            "fixture-v1",
            "--source-kind",
            "project-fixture",
            "--license-status",
            "project-authored-private",
            *common,
            "--json",
        ],
    )
    assert scan.exit_code == 0, scan.output
    run_id = json.loads(scan.stdout)["run_id"]
    assert calls == 1

    validation = runner.invoke(app, ["validate", run_id, *common, "--json"])
    inspection = runner.invoke(app, ["inspect", run_id, *common, "--json"])
    summary = runner.invoke(app, ["summarize", run_id, *common, "--json"])
    export_path = tmp_path / "derived" / "result.sarif"
    export = runner.invoke(
        app,
        ["export", "sarif", run_id, "--output", str(export_path), *common, "--json"],
    )
    normalization_path = tmp_path / "derived" / "normalization"
    normalization = runner.invoke(
        app,
        ["normalize", run_id, "--output", str(normalization_path), *common, "--json"],
    )

    assert validation.exit_code == 0, validation.output
    assert json.loads(validation.stdout)["passed"] is True
    assert inspection.exit_code == 0, inspection.output
    assert summary.exit_code == 0, summary.output
    assert json.loads(summary.stdout)["normalized_finding_count"] == 1
    assert export.exit_code == 0, export.output
    assert export_path.is_file()
    assert normalization.exit_code == 0, normalization.output
    assert (normalization_path / "findings.jsonl").is_file()
    assert calls == 1
