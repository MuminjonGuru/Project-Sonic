from __future__ import annotations

import json
import os
import shutil
from dataclasses import replace
from pathlib import Path
from typing import Any

import portalocker
import pytest
from typer.testing import CliRunner

from agentsec_evidence.agents.worker import validate_view
from agentsec_evidence.benchmarks import attempts
from agentsec_evidence.benchmarks.attempt_models import (
    AdmittedProgress,
    AttemptFinish,
    AttemptStart,
    AttemptStartV2,
    BenchmarkProgress,
    BenchmarkProgressV2,
)
from agentsec_evidence.benchmarks.attempts import inspect_benchmark, retry_benchmark, run_benchmark
from agentsec_evidence.benchmarks.evidence import bundle_inventory
from agentsec_evidence.benchmarks.models import BenchmarkDryRunV3, BenchmarkPlan, BenchmarkPlanV2
from agentsec_evidence.benchmarks.service import (
    ADMITTED_PINS,
    build_development_plan,
    plan_bytes,
    validate_plan,
)
from agentsec_evidence.cli.app import app
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.core.time import utc_now
from agentsec_evidence.execution.process import ProcessCapture
from agentsec_evidence.orchestration import agent_pipeline

PROJECT = Path(__file__).resolve().parents[2]


@pytest.fixture
def project(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    for name in ADMITTED_PINS:
        destination = project / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(PROJECT / name, destination)
    shutil.copytree(PROJECT / "schemas", project / "schemas")
    source = project / "src/agentsec_evidence/benchmarks/attempts.py"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"# Test-only worker identity; the process double never imports it.\n")
    return project


def plan_file(project: Path, *cases: str, repetitions: int = 1, retry: bool = False) -> Path:
    path = project / "plan.json"
    path.write_bytes(
        plan_bytes(
            build_development_plan(
                project,
                plan_id="attempt-tests",
                case_ids=cases or ("python-positive",),
                repetitions=repetitions,
                allow_prelaunch_retry=retry,
            )
        )
    )
    return path


@pytest.fixture
def producer(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> list[str]:
    """Exercise the real runner/validators with authored empty native output, never Docker."""
    calls: list[str] = []
    docker = tmp_path / "docker.exe"
    docker.write_bytes(b"test double")
    monkeypatch.setattr(agent_pipeline, "resolve_docker", lambda _: docker)
    monkeypatch.setattr(attempts, "resolve_docker", lambda _: docker)
    monkeypatch.setattr(agent_pipeline, "cleanup_container", lambda **_: True)

    def capture(argv: list[str], **_: Any) -> ProcessCapture:
        worker = "agentsec_evidence.agents.worker" in argv
        calls.append("validation" if worker else "scanner")
        mounts = {}
        for value in argv:
            if value.startswith("type=bind,"):
                parts = dict(part.split("=", 1) for part in value.split(",") if "=" in part)
                mounts[parts["target"]] = Path(parts["source"])
        if worker:
            raw = (
                validate_view(mounts["/target"], mounts["/request.json"].read_bytes())
                .model_dump_json()
                .encode()
            )
        else:
            raw = json_bytes(
                {
                    "version": "0.20.0",
                    "scan_timestamp": "2026-10-13T00:00:00",
                    "scan_path": "/target",
                    "scanned_files": 1,
                    "summary": {
                        "total": 0,
                        "actionable": 0,
                        "suppressed": 0,
                        "by_severity": {},
                        "by_category": {},
                        "by_tier": {"BLOCK": 0, "WARN": 0, "INFO": 0, "SUPPRESSED": 0},
                        "risk_score": 0.0,
                        "risk_label": "LOW",
                    },
                    "findings": [],
                }
            )
        now = utc_now()
        return ProcessCapture(
            argv=tuple(argv),
            started_at=now,
            ended_at=now,
            duration_ns=100,
            exit_code=0,
            stdout=raw,
            stderr=b"",
            timed_out=False,
            output_limited=False,
            stdout_truncated=False,
            stderr_truncated=False,
            peak_rss_bytes=4096,
        )

    monkeypatch.setattr(agent_pipeline, "run_bounded_process", capture)
    return calls


def history(result: AdmittedProgress) -> list[Path]:
    return sorted((Path(result.session) / "attempts").iterdir())


def test_no_attempt_status_has_no_writes_or_invocations(project: Path, producer: list[str]) -> None:
    result = inspect_benchmark(project, plan_file(project))
    assert not (project / "workspace").exists()
    assert result.cells[0].state == "not-attempted"
    assert result.cells[0].finding_records is None
    assert not result.workflow_complete and not result.blocked and not producer


def test_pause_resume_reuses_verified_partial_and_refusal(
    project: Path, producer: list[str]
) -> None:
    plan = plan_file(project, "python-positive", "python-malformed", "mcp-corrected")
    first = run_benchmark(project, plan, max_new_cells=1)
    assert first.newly_attempted_cells == 1 and not first.workflow_complete
    assert [c.state for c in first.cells] == ["partial-analysis", "not-attempted", "not-attempted"]
    assert first.cells[0].finding_records == 0 and not first.analysis_complete
    preserved = {p: p.read_bytes() for p in history(first)[0].rglob("*") if p.is_file()}
    resumed = run_benchmark(project, plan)
    assert resumed.workflow_complete and not resumed.analysis_complete
    assert resumed.newly_attempted_cells == 2 and resumed.reused_verified_cells == 1
    assert [c.state for c in resumed.cells] == ["partial-analysis", "refused", "partial-analysis"]
    assert resumed.cells[1].finding_records is None
    assert producer == ["validation", "scanner", "validation", "validation", "scanner"]
    repeated = run_benchmark(project, plan)
    assert repeated.newly_attempted_cells == 0 and repeated.reused_verified_cells == 3
    assert repeated.cells == resumed.cells == inspect_benchmark(project, plan).cells
    assert all(p.read_bytes() == raw for p, raw in preserved.items())
    starts = [
        AttemptStart.model_validate_json((p / "start.json").read_bytes()) for p in history(first)
    ]
    assert len({s.attempt_id for s in starts}) == 3
    assert starts[0].previous_finish_sha256 is None
    assert all(s.previous_finish_sha256 for s in starts[1:])


def test_repetitions_are_distinct_cells_not_duplicates(project: Path, producer: list[str]) -> None:
    result = run_benchmark(project, plan_file(project, repetitions=2))
    assert result.workflow_complete
    assert len({c.run_id for c in result.cells}) == 2
    assert [c.repetition for c in result.cells] == [1, 2]
    assert producer == ["validation", "scanner"] * 2


@pytest.mark.parametrize(
    "case",
    ["python-excluded-yaml", "python-inline-suppression", "mcp-malformed", "unsupported-text"],
)
def test_explicit_refusals_remain_unknown_not_negatives(
    project: Path, producer: list[str], case: str
) -> None:
    result = run_benchmark(project, plan_file(project, case))
    assert result.workflow_complete and result.cells[0].state == "refused"
    assert result.cells[0].finding_records is None and result.cells[0].scanner_invocations == 0
    assert producer == ["validation"]


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_failed_or_interrupted_attempt_never_relaunches(
    project: Path, monkeypatch: pytest.MonkeyPatch, error: type[BaseException]
) -> None:
    plan = plan_file(project, "python-positive", "mcp-positive")
    calls = []

    def broken(*_: Any) -> Any:
        calls.append(True)
        raise error("sensitive raw exception must not enter portable history")

    monkeypatch.setattr(attempts, "run_agent_scan", broken)
    if error is RuntimeError:
        result = run_benchmark(project, plan)
        assert result.blocked and result.cells[0].state == "execution-failed"
    else:
        with pytest.raises(error):
            run_benchmark(project, plan)
        result = inspect_benchmark(project, plan)
        assert result.blocked and result.cells[0].state == "interrupted"
    assert result.cells[1].state == "not-attempted"
    assert run_benchmark(project, plan).blocked and calls == [True]
    assert result.cells[0].finding_records is None
    assert all(b"sensitive raw" not in p.read_bytes() for p in Path(result.session).rglob("*.json"))


@pytest.mark.parametrize(
    "tamper",
    [
        "native",
        "extra",
        "finish",
        "start",
        "plan",
        "validation",
        "order",
        "duplicate",
        "missing-start",
        "torn-finish",
    ],
)
def test_tampering_blocks_resume_before_scanner(
    project: Path, producer: list[str], tamper: str
) -> None:
    plan = plan_file(project, "python-positive", "mcp-positive")
    result = run_benchmark(project, plan, max_new_cells=1)
    attempt = history(result)[0]
    if tamper == "native":
        next((attempt / "execution/runs").rglob("native.json")).write_bytes(b"{}")
    elif tamper == "extra":
        next((attempt / "execution/runs").iterdir()).joinpath("extra.txt").write_bytes(b"extra")
    elif tamper == "order":
        attempt.rename(attempt.with_name("0002_" + attempt.name[5:]))
    elif tamper == "duplicate":
        shutil.copytree(attempt, attempt.with_name("0002_attempt_" + "0" * 32))
    elif tamper == "missing-start":
        (attempt / "start.json").unlink()
    elif tamper == "torn-finish":
        (attempt / "finish.json").write_bytes(b'{"contract":')
    else:
        file = (
            attempt if tamper in {"finish", "start"} else Path(result.session)
        ) / f"{tamper}.json"
        data = json.loads(file.read_bytes())
        if tamper == "finish":
            data["evidence"]["finding_records"] = 900
        elif tamper == "start":
            data["case_id"] = "mcp-positive"
        elif tamper == "plan":
            data["plan_id"] = "changed"
        else:
            data["plan_sha256"] = "0" * 64
        file.write_bytes(json_bytes(data))
    with pytest.raises((ValueError, OSError)):
        run_benchmark(project, plan)
    assert producer == ["validation", "scanner"]


@pytest.mark.parametrize("change", ["profile", "registry", "source", "extra-source"])
def test_protected_drift_blocks_before_new_attempt(
    project: Path, producer: list[str], change: str
) -> None:
    plan = plan_file(project)
    result = run_benchmark(project, plan)
    files = {
        "profile": "configs/profiles/agent-development.toml",
        "registry": "test_cases/development/agent-artifacts/cases.json",
        "source": "src/agentsec_evidence/benchmarks/attempts.py",
        "extra-source": "src/extra.py",
    }
    file = project / files[change]
    file.write_bytes((file.read_bytes() if file.exists() else b"") + b"\n")
    with pytest.raises(ValueError):
        run_benchmark(project, plan)
    assert len(history(result)) == 1 and producer == ["validation", "scanner"]


def test_live_writer_lock_prevents_launch(project: Path, producer: list[str]) -> None:
    plan = plan_file(project)
    root = project / "workspace/benchmarks"
    root.mkdir(parents=True)
    with (
        portalocker.Lock(str(root / ".writer.lock"), mode="a+", timeout=0),
        pytest.raises(ValueError, match="writer is active"),
    ):
        run_benchmark(project, plan)
    assert not producer
    assert run_benchmark(project, plan).workflow_complete
    assert (root / ".writer.lock").exists()


@pytest.mark.parametrize("value", [0, 40, True, 1.5])
def test_invalid_dispatch_budget_rejected(project: Path, producer: list[str], value: Any) -> None:
    with pytest.raises(ValueError):
        run_benchmark(project, plan_file(project), max_new_cells=value)
    assert not producer and not (project / "workspace").exists()


def test_evidence_link_rejected_before_resume(project: Path, producer: list[str]) -> None:
    plan = plan_file(project)
    result = run_benchmark(project, plan)
    native = next(Path(result.session).rglob("native.json"))
    # Hard links are available without Windows symlink privileges.
    os.link(native, native.parent / "linked.json")
    with pytest.raises(ValueError, match="hard-linked"):
        run_benchmark(project, plan)
    assert producer == ["validation", "scanner"]


def test_missing_docker_is_failure_not_policy_refusal(
    project: Path, producer: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(agent_pipeline, "resolve_docker", lambda _: None)
    result = run_benchmark(project, plan_file(project))
    assert result.blocked and result.cells[0].state == "execution-failed"
    assert result.cells[0].scanner_invocations == 0 and result.cells[0].finding_records is None
    assert not producer


def test_cli_runs_resumes_and_reports_status(project: Path, producer: list[str]) -> None:
    plan = plan_file(project)
    runner = CliRunner()
    args = [str(plan), "--project-root", str(project)]
    first = runner.invoke(app, ["benchmark", "run", *args])
    assert first.exit_code == 0, first.output
    assert json.loads(first.output)["workflow_complete"] is True
    second = runner.invoke(app, ["benchmark", "run", *args])
    assert second.exit_code == 0 and json.loads(second.output)["newly_attempted_cells"] == 0
    status = runner.invoke(app, ["benchmark", "status", *args])
    assert status.exit_code == 0 and json.loads(status.output)["analysis_complete"] is False
    assert producer == ["validation", "scanner"]


def test_generated_attempt_schemas_match_models() -> None:
    for name, model in (
        ("attempt-start", AttemptStart),
        ("attempt-finish", AttemptFinish),
        ("progress", BenchmarkProgress),
    ):
        assert (
            json.loads((PROJECT / f"schemas/benchmark-v1/{name}.schema.json").read_bytes())
            == model.model_json_schema()
        )


def test_wrong_case_bundle_cannot_satisfy_planned_cell(
    project: Path, producer: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    original = agent_pipeline.run_agent_scan

    def other(request: agent_pipeline.AgentScanRequest) -> Any:
        return original(
            agent_pipeline.AgentScanRequest(
                request.project_root, request.workspace_root, "mcp-corrected"
            )
        )

    monkeypatch.setattr(attempts, "run_agent_scan", other)
    result = run_benchmark(project, plan_file(project))
    assert result.blocked and result.cells[0].state == "execution-failed"
    assert result.cells[0].run_id is None
    assert list(Path(result.session).rglob("bundle-manifest.json"))
    assert producer == ["validation", "scanner"]


def test_treatment_plan_remains_development_only(project: Path, producer: list[str]) -> None:
    path = plan_file(project)
    plan = BenchmarkPlan.model_validate_json(path.read_bytes())
    raw = plan.model_dump(mode="json")
    raw["split"] = "held-out"
    path.write_bytes(json_bytes(raw))
    with pytest.raises(ValueError):
        run_benchmark(project, path)
    assert not producer


def test_bundle_inventory_refuses_unreadable_or_oversized_file(tmp_path: Path) -> None:
    (tmp_path / "large.bin").write_bytes(b"x" * (16 * 1024**2 + 1))
    with pytest.raises(ValueError, match="byte limit"):
        bundle_inventory(tmp_path)


@pytest.mark.parametrize("stage", ["validation", "scanner"])
def test_keyboard_interrupt_runs_existing_container_cleanup(
    project: Path, producer: list[str], monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    # Wrap the fixture-patched internal process boundary, not the real process launcher.
    capture = agent_pipeline.run_bounded_process  # type: ignore[attr-defined]
    cleaned: list[str] = []

    def cleanup(**kwargs: Any) -> bool:
        cleaned.append(str(kwargs["container_name"]))
        return True

    def cancel(argv: list[str], **kwargs: Any) -> ProcessCapture:
        worker = "agentsec_evidence.agents.worker" in argv
        if ("validation" if worker else "scanner") == stage:
            raise KeyboardInterrupt
        return capture(argv, **kwargs)

    monkeypatch.setattr(agent_pipeline, "cleanup_container", cleanup)
    monkeypatch.setattr(agent_pipeline, "run_bounded_process", cancel)
    plan = plan_file(project)
    with pytest.raises(KeyboardInterrupt):
        run_benchmark(project, plan)
    assert any(name.startswith(f"agent-{stage}-") for name in cleaned)
    result = inspect_benchmark(project, plan)
    assert result.blocked and result.cells[0].state == "interrupted"
    assert run_benchmark(project, plan).blocked


def test_cli_blocked_status_does_not_look_successful(
    project: Path, producer: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(agent_pipeline, "resolve_docker", lambda _: None)
    args = [str(plan_file(project)), "--project-root", str(project)]
    runner = CliRunner()
    for command in ("run", "status", "run"):
        result = runner.invoke(app, ["benchmark", command, *args])
        assert result.exit_code == 5
        assert json.loads(result.output)["blocked"] is True
    assert not producer


def test_unsafe_execution_id_rejected_before_legacy_reader(
    project: Path, producer: list[str]
) -> None:
    plan = plan_file(project)
    result = run_benchmark(project, plan)
    run = next(Path(result.session).rglob("run.json"))
    data = json.loads(run.read_bytes())
    data["execution_ids"] = ["../../outside"]
    run.write_bytes(json_bytes(data))
    with pytest.raises(ValueError, match="Unsafe or ambiguous"):
        run_benchmark(project, plan)
    assert producer == ["validation", "scanner"]


def retry_latest(project: Path, plan: Path) -> BenchmarkProgressV2:
    prior = inspect_benchmark(project, plan).cells[0].attempt_id
    assert prior is not None
    return retry_benchmark(
        project,
        plan,
        attempt_id=prior,
        cause="docker-unavailable-before-launch",
        remediation="docker-command-availability-restored",
    )


def fail_without_docker(
    project: Path, plan: Path, monkeypatch: pytest.MonkeyPatch
) -> AdmittedProgress:
    with monkeypatch.context() as patch:
        patch.setattr(agent_pipeline, "resolve_docker", lambda _: None)
        return run_benchmark(project, plan)


def test_retry_policy_is_opt_in_frozen_and_dry_run_launches_nothing(
    project: Path,
    producer: list[str],
) -> None:
    path = plan_file(project, retry=True)
    plan = BenchmarkPlanV2.model_validate_json(path.read_bytes())
    assert plan.automatic_retries == 0 and plan.retry_policy.max_manual_retries_per_cell == 1
    preview = validate_plan(project, path)
    assert isinstance(preview, BenchmarkDryRunV3) and not preview.execution_authorized
    assert not producer and not (project / "workspace").exists()


def test_explicit_retry_preserves_failure_then_normal_resume(
    project: Path,
    producer: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = plan_file(project, "python-positive", "python-malformed", retry=True)
    first = fail_without_docker(project, plan, monkeypatch)
    assert first.blocked and not producer
    preserved = {p: p.read_bytes() for p in Path(first.session).rglob("*") if p.is_file()}
    assert run_benchmark(project, plan).blocked and not producer
    second = retry_latest(project, plan)
    assert not second.blocked and not second.workflow_complete
    assert second.newly_created_attempts == 1 and second.newly_attempted_cells == 0
    assert second.manual_retry_attempts == 1
    assert [a.state for a in second.attempts] == ["execution-failed", "partial-analysis"]
    assert second.cells[1].state == "not-attempted"
    assert len({a.attempt_id for a in second.attempts}) == 2
    assert len({a.run_id for a in second.attempts}) == 2
    start = AttemptStartV2.model_validate_json((history(second)[1] / "start.json").read_bytes())
    assert start.retry and start.retry.prior_attempt_id == first.cells[0].attempt_id
    assert all(p.read_bytes() == raw for p, raw in preserved.items())
    third = run_benchmark(project, plan)
    assert third.workflow_complete and not third.analysis_complete
    assert isinstance(third, BenchmarkProgressV2) and len(third.attempts) == 3
    assert producer == ["validation", "scanner", "validation"]
    stable = {p: p.read_bytes() for p in Path(first.session).rglob("*") if p.is_file()}
    repeated = run_benchmark(project, plan)
    assert repeated.newly_attempted_cells == 0 and repeated.reused_verified_cells == 2
    assert inspect_benchmark(project, plan).cells == repeated.cells
    assert all(p.read_bytes() == raw for p, raw in stable.items())


def test_legacy_plan_never_gains_retry_permission(
    project: Path,
    producer: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = plan_file(project)
    first = fail_without_docker(project, plan, monkeypatch)
    with pytest.raises(ValueError, match="does not authorize"):
        retry_latest(project, plan)
    assert len(history(first)) == 1 and not producer


def test_still_missing_docker_does_not_consume_retry(
    project: Path,
    producer: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = plan_file(project, retry=True)
    first = fail_without_docker(project, plan, monkeypatch)
    with monkeypatch.context() as patch:
        patch.setattr(attempts, "resolve_docker", lambda _: None)
        with pytest.raises(ValueError, match="still unavailable"):
            retry_latest(project, plan)
    assert len(history(first)) == 1 and not producer
    assert retry_latest(project, plan).workflow_complete


def test_failed_retry_consumes_budget_and_is_never_overwritten(
    project: Path,
    producer: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = plan_file(project, retry=True)
    first = fail_without_docker(project, plan, monkeypatch)
    with monkeypatch.context() as patch:
        patch.setattr(agent_pipeline, "resolve_docker", lambda _: None)
        second = retry_latest(project, plan)
    assert second.blocked and len(second.attempts) == 2
    assert [a.state for a in second.attempts] == ["execution-failed"] * 2
    with pytest.raises(ValueError, match="exhausted"):
        retry_latest(project, plan)
    assert run_benchmark(project, plan).blocked and len(history(first)) == 2 and not producer


@pytest.mark.parametrize(
    "case", ["python-positive", "python-corrected", "python-malformed", "python-inline-suppression"]
)
def test_terminal_observations_and_refusals_cannot_be_retried(
    project: Path,
    producer: list[str],
    case: str,
) -> None:
    plan = plan_file(project, case, retry=True)
    first = run_benchmark(project, plan)
    calls = producer.copy()
    with pytest.raises(ValueError, match="not eligible"):
        retry_latest(project, plan)
    assert len(history(first)) == 1 and producer == calls


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_unverified_and_interrupted_failures_cannot_be_retried(
    project: Path,
    producer: list[str],
    monkeypatch: pytest.MonkeyPatch,
    error: type[BaseException],
) -> None:
    plan = plan_file(project, retry=True)

    def fail(*_: Any) -> Any:
        raise error()

    with monkeypatch.context() as patch:
        patch.setattr(attempts, "run_agent_scan", fail)
        if error is RuntimeError:
            run_benchmark(project, plan)
        else:
            with pytest.raises(error):
                run_benchmark(project, plan)
    with pytest.raises(ValueError, match="not eligible"):
        retry_latest(project, plan)
    assert not producer


@pytest.mark.parametrize("problem", ["parser", "worker-exit", "cleanup"])
def test_post_launch_failures_cannot_be_retried(
    project: Path,
    producer: list[str],
    monkeypatch: pytest.MonkeyPatch,
    problem: str,
) -> None:
    plan = plan_file(project, retry=True)
    capture = agent_pipeline.run_bounded_process  # type: ignore[attr-defined]

    def broken(argv: list[str], **kwargs: Any) -> ProcessCapture:
        result = capture(argv, **kwargs)
        worker = "agentsec_evidence.agents.worker" in argv
        if problem == "worker-exit" and worker:
            return replace(result, exit_code=125, stdout=b"")
        if problem == "parser" and not worker:
            return replace(result, stdout=b"{broken")
        return result

    monkeypatch.setattr(agent_pipeline, "run_bounded_process", broken)
    if problem == "cleanup":
        monkeypatch.setattr(agent_pipeline, "cleanup_container", lambda **_: False)
    first = run_benchmark(project, plan)
    assert first.blocked
    count = len(producer)
    with pytest.raises(ValueError):
        retry_latest(project, plan)
    assert len(producer) == count and len(history(first)) == 1


@pytest.mark.parametrize("change", ["cause", "remediation", "attempt-id"])
def test_retry_requires_exact_explicit_selection_and_cause(
    project: Path,
    producer: list[str],
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    plan = plan_file(project, retry=True)
    first = fail_without_docker(project, plan, monkeypatch)
    args = {
        "attempt_id": first.cells[0].attempt_id,
        "cause": "docker-unavailable-before-launch",
        "remediation": "docker-command-availability-restored",
    }
    args[change.replace("-", "_")] = "attempt_" + "0" * 32 if change == "attempt-id" else "other"
    with pytest.raises(ValueError):
        retry_benchmark(project, plan, **args)  # type: ignore[arg-type]
    assert len(history(first)) == 1 and not producer


@pytest.mark.parametrize(
    "tamper", ["prior-evidence", "retry-link", "retry-cause", "omit-authorization", "finish-chain"]
)
def test_recovery_history_replays_the_original_failure_and_authorization(
    project: Path,
    producer: list[str],
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    plan = plan_file(project, retry=True)
    first = fail_without_docker(project, plan, monkeypatch)
    second = retry_latest(project, plan)
    if tamper == "prior-evidence":
        next(history(first)[0].rglob("agent-details.json")).write_bytes(b"{}")
    else:
        path = history(second)[1] / "start.json"
        raw = json.loads(path.read_bytes())
        if tamper == "retry-link":
            raw["retry"]["prior_attempt_id"] = "attempt_" + "0" * 32
        elif tamper == "retry-cause":
            raw["retry"]["cause"] = "parser-error"
        elif tamper == "omit-authorization":
            raw["retry"] = None
        else:
            raw["previous_finish_sha256"] = "0" * 64
        path.write_bytes(json_bytes(raw))
    with pytest.raises(ValueError):
        run_benchmark(project, plan)
    assert producer == ["validation", "scanner"]


def test_retry_respects_writer_lock_and_source_drift(
    project: Path,
    producer: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = plan_file(project, retry=True)
    first = fail_without_docker(project, plan, monkeypatch)
    with (
        portalocker.Lock(str(Path(first.session).parent / ".writer.lock"), mode="a+", timeout=0),
        pytest.raises(ValueError, match="writer is active"),
    ):
        retry_latest(project, plan)
    source = project / "src/agentsec_evidence/benchmarks/attempts.py"
    source.write_bytes(source.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="pins differ"):
        retry_latest(project, plan)
    assert not producer and len(history(first)) == 1


def test_cli_explicit_retry_is_a_separate_command(
    project: Path,
    producer: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = plan_file(project, retry=True)
    first = fail_without_docker(project, plan, monkeypatch)
    assert first.cells[0].attempt_id
    args = [
        "benchmark",
        "retry",
        str(plan),
        "--project-root",
        str(project),
        "--attempt-id",
        first.cells[0].attempt_id,
        "--cause",
        "docker-unavailable-before-launch",
        "--remediation",
        "docker-command-availability-restored",
    ]
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    body = json.loads(result.output)
    assert body["manual_retry_attempts"] == 1 and len(body["attempts"]) == 2
    repeated = CliRunner().invoke(app, args)
    assert repeated.exit_code == 5 and producer == ["validation", "scanner"]


def test_additive_retry_schemas_match_models() -> None:
    for folder, name, model in (
        ("benchmark-v2", "plan", BenchmarkPlanV2),
        ("benchmark-v2", "attempt-start", AttemptStartV2),
        ("benchmark-v2", "progress", BenchmarkProgressV2),
        ("benchmark-v3", "dry-run", BenchmarkDryRunV3),
    ):
        assert (
            json.loads((PROJECT / f"schemas/{folder}/{name}.schema.json").read_bytes())
            == model.model_json_schema()
        )


@pytest.mark.parametrize("mutation", ["extra-retry", "automatic", "interrupted", "missing-policy"])
def test_v2_plan_rejects_broader_retry_permission(
    project: Path,
    producer: list[str],
    mutation: str,
) -> None:
    path = plan_file(project, retry=True)
    raw = json.loads(path.read_bytes())
    if mutation == "extra-retry":
        raw["retry_policy"]["max_manual_retries_per_cell"] = 2
    elif mutation == "automatic":
        raw["automatic_retries"] = 1
    elif mutation == "interrupted":
        raw["retry_policy"]["interrupted_attempts"] = "retry"
    else:
        del raw["retry_policy"]
    path.write_bytes(json_bytes(raw))
    with pytest.raises(ValueError):
        run_benchmark(project, path)
    assert not producer and not (project / "workspace").exists()


def test_retry_does_not_reuse_attempt_identity(
    project: Path,
    producer: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = plan_file(project, retry=True)
    first = fail_without_docker(project, plan, monkeypatch)
    second = retry_latest(project, plan)
    path = history(second)[1]
    raw = json.loads((path / "start.json").read_bytes())
    raw["attempt_id"] = first.cells[0].attempt_id
    (path / "start.json").write_bytes(json_bytes(raw))
    path.rename(path.with_name(f"0002_{first.cells[0].attempt_id}"))
    with pytest.raises(ValueError, match="Duplicate attempt identity"):
        inspect_benchmark(project, plan)
    assert producer == ["validation", "scanner"]


def test_cancellation_during_retry_leaves_both_attempts_blocked(
    project: Path,
    producer: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = plan_file(project, retry=True)
    first = fail_without_docker(project, plan, monkeypatch)

    def interrupt(*_: Any) -> Any:
        raise KeyboardInterrupt

    with monkeypatch.context() as patch:
        patch.setattr(attempts, "run_agent_scan", interrupt)
        with pytest.raises(KeyboardInterrupt):
            retry_latest(project, plan)
    status = inspect_benchmark(project, plan)
    assert isinstance(status, BenchmarkProgressV2)
    assert status.blocked and [a.state for a in status.attempts] == [
        "execution-failed",
        "interrupted",
    ]
    with pytest.raises(ValueError, match="not eligible"):
        retry_latest(project, plan)
    assert len(history(first)) == 2 and not producer
