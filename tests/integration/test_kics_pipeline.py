from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from agentsec_evidence.core.time import utc_now
from agentsec_evidence.execution.process import ProcessCapture
from agentsec_evidence.models.contracts import ExecutionRecord, RunRecord, RunState
from agentsec_evidence.orchestration import kics_pipeline
from agentsec_evidence.orchestration.kics_pipeline import KicsScanRequest, run_kics_scan
from agentsec_evidence.validation.checks import validate_bundle


def _fixture(name: str) -> bytes:
    return (Path(__file__).resolve().parents[1] / "fixtures" / "kics" / name).read_bytes()


def _request(*, project_root: Path, workspace: Path, target: Path, docker: Path) -> KicsScanRequest:
    return KicsScanRequest(
        project_root=project_root,
        workspace_root=workspace,
        target_source=target,
        source_label="fixture:kics-pipeline",
        revision="fixture-v1",
        run_label="kics-pipeline-test",
        source_kind="project-fixture",
        license_status="project-authored-private",
        docker_executable=docker,
    )


def _native_sarif(result_count: int) -> bytes:
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "KICS", "version": "v2.1.20"}},
                "results": [{} for _ in range(result_count)],
            }
        ],
    }
    return json.dumps(document, separators=(",", ":")).encode()


def _install_fake_runner(
    monkeypatch: pytest.MonkeyPatch,
    *,
    workspace: Path,
    native_data: bytes,
    sarif_result_count: int = 0,
    write_sarif: bool = True,
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
        output = execution_roots[0] / "output"
        (output / "results.json").write_bytes(native_data)
        if write_sarif:
            (output / "results.sarif").write_bytes(_native_sarif(sarif_result_count))
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

    monkeypatch.setattr(kics_pipeline, "run_bounded_process", fake_run)


@pytest.mark.parametrize(
    (
        "native_fixture",
        "target_case",
        "sarif_count",
        "expected_state",
        "expected_outcome",
        "finding_count",
        "failure_count",
    ),
    [
        ("finding.json", "kics-basic", 2, RunState.COMPLETE, "success", 2, 0),
        ("clean.json", "kics-clean", 0, RunState.COMPLETE, "success", 0, 0),
        ("partial-parse.json", "kics-malformed", 0, RunState.PARTIAL, "partial", 0, 1),
        ("unsupported.json", "kics-unsupported", 0, RunState.COMPLETE, "unsupported", 0, 0),
        ("malformed.json", "kics-basic", 0, RunState.PARSE_FAILED, "failed", 0, 1),
    ],
)
def test_kics_pipeline_finalizes_explicit_outcomes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    native_fixture: str,
    target_case: str,
    sarif_count: int,
    expected_state: RunState,
    expected_outcome: str,
    finding_count: int,
    failure_count: int,
) -> None:
    project_root = Path(__file__).resolve().parents[2]
    target = project_root / "test_cases" / "development" / target_case / "target"
    workspace = tmp_path / "workspace"
    docker = tmp_path / "docker.exe"
    docker.write_bytes(b"test double")
    _install_fake_runner(
        monkeypatch,
        workspace=workspace,
        native_data=_fixture(native_fixture),
        sarif_result_count=sarif_count,
    )

    result = run_kics_scan(
        _request(project_root=project_root, workspace=workspace, target=target, docker=docker)
    )

    run = RunRecord.model_validate_json((result.run_root / "run.json").read_bytes())
    execution = ExecutionRecord.model_validate_json(
        (result.run_root / "executions" / run.execution_ids[0] / "execution.json").read_bytes()
    )
    assert run.state is RunState.FINALIZED
    assert run.terminal_state is expected_state
    assert result.terminal_state is expected_state
    assert execution.outcome.value == expected_outcome
    assert validate_bundle(result.run_root).passed
    assert (
        len((result.run_root / "normalized" / "findings.jsonl").read_text().splitlines())
        == finding_count
    )
    assert (
        len((result.run_root / "normalized" / "failures.jsonl").read_text().splitlines())
        == failure_count
    )
    assert not list((workspace / "staging").glob("execution_*"))


def test_kics_pipeline_archives_exact_effective_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project_root = Path(__file__).resolve().parents[2]
    target = project_root / "test_cases" / "development" / "kics-basic" / "target"
    workspace = tmp_path / "workspace"
    docker = tmp_path / "docker.exe"
    docker.write_bytes(b"test double")
    _install_fake_runner(
        monkeypatch,
        workspace=workspace,
        native_data=_fixture("finding.json"),
        sarif_result_count=2,
    )

    result = run_kics_scan(
        _request(project_root=project_root, workspace=workspace, target=target, docker=docker)
    )
    run = RunRecord.model_validate_json((result.run_root / "run.json").read_bytes())
    input_root = result.run_root / "executions" / run.execution_ids[0] / "inputs"

    assert (input_root / "profile.toml").read_bytes() == (
        project_root / "configs" / "profiles" / "development.toml"
    ).read_bytes()
    assert (input_root / "tool-config.toml").read_bytes() == (
        project_root / "configs" / "tools" / "kics.toml"
    ).read_bytes()
    manifest = json.loads((input_root / "query-selection.json").read_bytes())
    assert manifest["query_pack_sha256"] == (
        "b53f3e080b7da5ccc160aa171f633d01d63d1770b991cf49c837a68367e324da"
    )
    assert len(manifest["include_queries"]) == 2


def test_kics_semantic_hash_repeats_for_same_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project_root = Path(__file__).resolve().parents[2]
    target = project_root / "test_cases" / "development" / "kics-basic" / "target"
    workspace = tmp_path / "workspace"
    docker = tmp_path / "docker.exe"
    docker.write_bytes(b"test double")
    _install_fake_runner(
        monkeypatch,
        workspace=workspace,
        native_data=_fixture("finding.json"),
        sarif_result_count=2,
    )

    request = _request(project_root=project_root, workspace=workspace, target=target, docker=docker)
    first = run_kics_scan(request)
    second = run_kics_scan(request)

    assert first.run_id != second.run_id
    assert first.semantic_sha256 == second.semantic_sha256


def test_missing_native_sarif_is_an_explicit_partial_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project_root = Path(__file__).resolve().parents[2]
    target = project_root / "test_cases" / "development" / "kics-basic" / "target"
    workspace = tmp_path / "workspace"
    docker = tmp_path / "docker.exe"
    docker.write_bytes(b"test double")
    _install_fake_runner(
        monkeypatch,
        workspace=workspace,
        native_data=_fixture("finding.json"),
        sarif_result_count=2,
        write_sarif=False,
    )

    result = run_kics_scan(
        _request(project_root=project_root, workspace=workspace, target=target, docker=docker)
    )

    assert result.terminal_state is RunState.PARTIAL
    failure = json.loads((result.run_root / "normalized" / "failures.jsonl").read_text())
    assert failure["affected_scope"] == "kics native SARIF"
    assert validate_bundle(result.run_root).passed


def test_missing_docker_is_a_finalized_failure_bundle(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[2]
    target = project_root / "test_cases" / "development" / "kics-basic" / "target"
    result = run_kics_scan(
        _request(
            project_root=project_root,
            workspace=tmp_path / "workspace",
            target=target,
            docker=tmp_path / "missing-docker.exe",
        )
    )

    assert result.terminal_state is RunState.EXECUTION_FAILED
    assert validate_bundle(result.run_root).passed
    failure = json.loads((result.run_root / "normalized" / "failures.jsonl").read_text())
    assert failure["category"] == "missing-tool"
