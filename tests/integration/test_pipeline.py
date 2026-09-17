from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from agentsec_evidence.core.time import utc_now
from agentsec_evidence.execution.process import ProcessCapture
from agentsec_evidence.models.contracts import ExecutionRecord, RunRecord, RunState
from agentsec_evidence.orchestration import pipeline
from agentsec_evidence.orchestration.pipeline import SemgrepScanRequest, run_semgrep_scan
from agentsec_evidence.validation.checks import validate_bundle


def _fixture(name: str) -> bytes:
    return (Path(__file__).resolve().parents[1] / "fixtures" / "semgrep" / name).read_bytes()


def _request(
    *, project_root: Path, workspace: Path, target: Path, docker: Path
) -> SemgrepScanRequest:
    return SemgrepScanRequest(
        project_root=project_root,
        workspace_root=workspace,
        target_source=target,
        source_label="fixture:pipeline",
        revision="fixture-v1",
        run_label="pipeline-test",
        source_kind="project-fixture",
        license_status="project-authored-private",
        docker_executable=docker,
    )


def _install_fake_runner(
    monkeypatch: pytest.MonkeyPatch,
    *,
    workspace: Path,
    native_data: bytes,
    exit_code: int = 0,
) -> None:
    def fake_run(
        argv: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> ProcessCapture:
        del cwd, environment, timeout_seconds, max_stdout_bytes, max_stderr_bytes
        execution_roots = list((workspace / "staging").glob("execution_*"))
        assert len(execution_roots) == 1
        (execution_roots[0] / "output" / "semgrep.json").write_bytes(native_data)
        instant = utc_now()
        return ProcessCapture(
            argv=tuple(argv),
            started_at=instant,
            ended_at=instant,
            duration_ns=123,
            exit_code=exit_code,
            stdout=b"bounded stdout",
            stderr=b"",
            timed_out=False,
            output_limited=False,
            stdout_truncated=False,
            stderr_truncated=False,
            peak_rss_bytes=4096,
        )

    monkeypatch.setattr(pipeline, "run_bounded_process", fake_run)


@pytest.mark.parametrize(
    ("native_fixture", "expected_state", "finding_count", "failure_count"),
    [
        ("finding.json", RunState.COMPLETE, 1, 0),
        ("clean.json", RunState.COMPLETE, 0, 0),
        ("finding-with-error.json", RunState.PARTIAL, 1, 1),
        ("malformed.json", RunState.PARSE_FAILED, 0, 1),
    ],
)
def test_pipeline_finalizes_explicit_outcomes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    native_fixture: str,
    expected_state: RunState,
    finding_count: int,
    failure_count: int,
) -> None:
    project_root = Path(__file__).resolve().parents[2]
    target = project_root / "test_cases" / "development" / "semgrep-basic" / "target"
    workspace = tmp_path / "workspace"
    docker = tmp_path / "docker.exe"
    docker.write_bytes(b"test double")
    _install_fake_runner(monkeypatch, workspace=workspace, native_data=_fixture(native_fixture))

    result = run_semgrep_scan(
        _request(project_root=project_root, workspace=workspace, target=target, docker=docker)
    )

    run = RunRecord.model_validate_json((result.run_root / "run.json").read_bytes())
    assert run.state is RunState.FINALIZED
    assert run.terminal_state is expected_state
    assert result.terminal_state is expected_state
    assert validate_bundle(result.run_root).passed
    assert (
        len((result.run_root / "normalized" / "findings.jsonl").read_text().splitlines())
        == finding_count
    )
    assert (
        len((result.run_root / "normalized" / "failures.jsonl").read_text().splitlines())
        == failure_count
    )
    assert json.loads((result.run_root / "validation" / "schema.json").read_text())["passed"]
    assert json.loads((result.run_root / "validation" / "sarif.json").read_text())["passed"]
    assert json.loads((result.run_root / "validation" / "provenance.json").read_text())["passed"]
    assert not list((workspace / "staging").glob("execution_*"))
    if native_fixture == "finding-with-error.json":
        assert b"\x1b" not in (result.run_root / "normalized" / "failures.jsonl").read_bytes()


def test_semantic_hash_repeats_for_same_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project_root = Path(__file__).resolve().parents[2]
    target = project_root / "test_cases" / "development" / "semgrep-basic" / "target"
    workspace = tmp_path / "workspace"
    docker = tmp_path / "docker.exe"
    docker.write_bytes(b"test double")
    _install_fake_runner(monkeypatch, workspace=workspace, native_data=_fixture("finding.json"))

    first = run_semgrep_scan(
        _request(project_root=project_root, workspace=workspace, target=target, docker=docker)
    )
    second = run_semgrep_scan(
        _request(project_root=project_root, workspace=workspace, target=target, docker=docker)
    )

    assert first.run_id != second.run_id
    assert first.semantic_sha256 == second.semantic_sha256


def test_missing_docker_is_a_finalized_failure_bundle(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[2]
    target = project_root / "test_cases" / "development" / "semgrep-basic" / "target"
    result = run_semgrep_scan(
        _request(
            project_root=project_root,
            workspace=tmp_path / "workspace",
            target=target,
            docker=tmp_path / "missing-docker.exe",
        )
    )

    assert result.terminal_state is RunState.EXECUTION_FAILED
    assert validate_bundle(result.run_root).passed
    failure = json.loads((result.run_root / "normalized" / "failures.jsonl").read_text().strip())
    assert failure["category"] == "missing-tool"


def test_timeout_invokes_cleanup_and_records_terminal_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project_root = Path(__file__).resolve().parents[2]
    target = project_root / "test_cases" / "development" / "semgrep-basic" / "target"
    workspace = tmp_path / "workspace"
    docker = tmp_path / "docker.exe"
    docker.write_bytes(b"test double")
    cleanup_calls = 0

    def fake_timeout(
        argv: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> ProcessCapture:
        del cwd, environment, timeout_seconds, max_stdout_bytes, max_stderr_bytes
        instant = utc_now()
        return ProcessCapture(
            argv=tuple(argv),
            started_at=instant,
            ended_at=instant,
            duration_ns=1,
            exit_code=-1,
            stdout=b"",
            stderr=b"",
            timed_out=True,
            output_limited=False,
            stdout_truncated=False,
            stderr_truncated=False,
            peak_rss_bytes=0,
        )

    def fake_cleanup(**_kwargs: object) -> bool:
        nonlocal cleanup_calls
        cleanup_calls += 1
        return True

    monkeypatch.setattr(pipeline, "run_bounded_process", fake_timeout)
    monkeypatch.setattr(pipeline, "cleanup_container", fake_cleanup)
    result = run_semgrep_scan(
        _request(project_root=project_root, workspace=workspace, target=target, docker=docker)
    )

    execution_id = RunRecord.model_validate_json(
        (result.run_root / "run.json").read_bytes()
    ).execution_ids[0]
    execution = ExecutionRecord.model_validate_json(
        (result.run_root / "executions" / execution_id / "execution.json").read_bytes()
    )
    assert result.terminal_state is RunState.TIMED_OUT
    assert cleanup_calls == 1
    assert execution.container_cleanup_attempted is True
    assert execution.container_cleanup_succeeded is True
    assert validate_bundle(result.run_root).passed


def test_secret_canary_is_not_copied_into_evidence_products(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project_root = Path(__file__).resolve().parents[2]
    target = tmp_path / "target"
    target.mkdir()
    canary = b"PROJECT_TEST_SECRET_CANARY_NOT_A_REAL_SECRET_9f2a"
    (target / "clean.py").write_bytes(b"API_TOKEN = b'" + canary + b"'\n")
    workspace = tmp_path / "workspace"
    docker = tmp_path / "docker.exe"
    docker.write_bytes(b"test double")
    _install_fake_runner(monkeypatch, workspace=workspace, native_data=_fixture("clean.json"))

    result = run_semgrep_scan(
        _request(project_root=project_root, workspace=workspace, target=target, docker=docker)
    )

    assert result.terminal_state is RunState.COMPLETE
    assert any(
        canary in path.read_bytes() for path in (workspace / "targets").rglob("*") if path.is_file()
    )
    assert all(
        canary not in path.read_bytes() for path in result.run_root.rglob("*") if path.is_file()
    )
