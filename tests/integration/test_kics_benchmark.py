from __future__ import annotations

import json
import shutil
from collections.abc import Sequence
from pathlib import Path

import portalocker
import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from agentsec_evidence.benchmarks import attempts
from agentsec_evidence.benchmarks.attempt_models import KicsProgress
from agentsec_evidence.benchmarks.kics_plan import ADMITTED_PINS, CASE_ROOTS, build_kics_plan
from agentsec_evidence.benchmarks.models import KicsCaseId, KicsPreview
from agentsec_evidence.benchmarks.service import plan_bytes, validate_plan
from agentsec_evidence.cli.app import app
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.core.time import utc_now
from agentsec_evidence.execution.process import ProcessCapture
from agentsec_evidence.orchestration import kics_pipeline

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    for name in ADMITTED_PINS:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / name, path)
    for relative in CASE_ROOTS.values():
        shutil.copytree(REPO / relative / "target", root / relative / "target")
    shutil.copytree(REPO / "schemas", root / "schemas")
    (root / "src").mkdir()
    (root / "src/test_identity.py").write_bytes(b"# Test-only implementation identity.\n")
    (root / "workspace").mkdir()
    return root


def plan_file(
    project: Path, case_ids: tuple[str, ...] = ("dev-kics-basic-v1",), repetitions: int = 2
) -> Path:
    path = project / "workspace/plan.json"
    path.write_bytes(
        plan_bytes(
            build_kics_plan(
                project, plan_id="kics-test", case_ids=case_ids, repetitions=repetitions
            )
        )
    )
    return path


def fake_producer(
    monkeypatch: pytest.MonkeyPatch,
    project: Path,
    fixture: str = "finding.json",
    *,
    exit_code: int = 0,
    sarif_mode: str = "valid",
    mutation: str | None = None,
    timeout: bool = False,
    output_limited: bool = False,
    cleanup_succeeds: bool = True,
) -> list[tuple[str, ...]]:
    docker = project / "docker.exe"
    docker.write_bytes(b"test double")
    monkeypatch.setattr(kics_pipeline, "resolve_docker", lambda _value: docker)
    monkeypatch.setattr(kics_pipeline, "cleanup_container", lambda **_kwargs: cleanup_succeeds)
    calls: list[tuple[str, ...]] = []

    def capture(argv: Sequence[str], **kwargs: object) -> ProcessCapture:
        del kwargs
        calls.append(tuple(argv))
        mount = next(a for a in argv if a.endswith("target=/output"))
        output = Path(mount.split("source=", 1)[1].split(",target=", 1)[0])
        raw = (REPO / "tests/fixtures/kics" / fixture).read_bytes()
        count = 0
        if fixture != "malformed.json":
            doc = json.loads(raw)
            count = doc["total_counter"]
            if mutation == "version":
                doc["kics_version"] = "unadmitted"
            elif mutation == "query":
                doc["queries"][0]["query_id"] = "unexpected-query"
            elif mutation == "path":
                doc["queries"][0]["files"][0]["file_name"] = "../../src/notes.txt"
            elif mutation == "counters":
                doc["files_parsed"] = 99
            raw = json.dumps(doc).encode()
        (output / "results.json").write_bytes(raw)
        if sarif_mode != "missing":
            sarif = {
                "version": "2.1.0",
                "runs": [
                    {"tool": {"driver": {"name": "KICS"}}, "results": [{} for _ in range(count)]}
                ],
            }
            if sarif_mode == "mismatch":
                sarif["runs"] = []
            (output / "results.sarif").write_bytes(json.dumps(sarif).encode())
        now = utc_now()
        return ProcessCapture(
            argv=tuple(argv),
            started_at=now,
            ended_at=now,
            duration_ns=123,
            exit_code=exit_code,
            stdout=b"",
            stderr=b"",
            timed_out=timeout,
            output_limited=output_limited,
            stdout_truncated=False,
            stderr_truncated=False,
            peak_rss_bytes=0,
        )

    monkeypatch.setattr(kics_pipeline, "run_bounded_process", capture)
    return calls


def tree(root: Path) -> dict[str, str]:
    return {
        p.relative_to(root).as_posix(): sha256_bytes(p.read_bytes())
        for p in root.rglob("*")
        if p.is_file()
    }


def test_offline_preview_preserves_all_cases_and_scope(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Offline operation invoked a producer")

    monkeypatch.setattr(attempts, "run_kics_scan", forbidden)
    path = plan_file(project, tuple(CASE_ROOTS), 3)
    dry = validate_plan(project, path)
    assert isinstance(dry, KicsPreview) and len(dry.cells) == 12
    assert len(dry.cells[0].input_files) == 5 and len(dry.cells[0].selected_paths) == 4
    assert dry.cells[-1].selected_paths == () and len(dry.cells[-1].input_files) == 1
    status = attempts.inspect_benchmark(project, path)
    assert isinstance(status, KicsProgress)
    assert all(
        row.state == "not-attempted"
        and row.finding_records is None
        and row.native_files_scanned is None
        for row in status.cells
    )
    assert not (project / "workspace/benchmarks").exists()


@pytest.mark.parametrize(
    ("case", "fixture", "state", "count", "scanned", "parsed"),
    [
        ("dev-kics-basic-v1", "finding.json", "completed-with-findings", 2, 4, 4),
        ("dev-kics-clean-v1", "clean.json", "completed-without-findings", 0, 2, 2),
        ("dev-kics-malformed-v1", "partial-parse.json", "partial-analysis", 0, 1, 0),
        ("dev-kics-unsupported-v1", "unsupported.json", "unsupported", 0, 0, 0),
    ],
)
def test_terminal_outcomes_resume_without_rewriting(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: KicsCaseId,
    fixture: str,
    state: str,
    count: int,
    scanned: int,
    parsed: int,
) -> None:
    calls = fake_producer(monkeypatch, project, fixture)
    path = plan_file(project, (case,))
    first = attempts.run_benchmark(project, path, max_new_cells=1)
    assert isinstance(first, KicsProgress)
    row = first.cells[0]
    assert row.state == state and row.finding_records == count
    assert row.native_files_scanned == scanned and row.native_files_parsed == parsed
    assert row.verified_terminal_attempt and not first.blocked and not first.workflow_complete
    first_path = next((Path(first.session) / "attempts").iterdir())
    original = tree(first_path)
    second = attempts.run_benchmark(project, path)
    assert second.workflow_complete and len(calls) == 2 and tree(first_path) == original
    before = tree(Path(second.session))
    again = attempts.run_benchmark(project, path)
    inspected = attempts.inspect_benchmark(project, path)
    assert again.cells == inspected.cells == second.cells
    assert tree(Path(second.session)) == before and len(calls) == 2
    assert not again.analysis_complete and not again.scoring_implemented
    assert again.reused_verified_cells == 2 and again.newly_attempted_cells == 0


@pytest.mark.parametrize(
    "failure",
    [
        "malformed",
        "exit",
        "missing-sarif",
        "bad-sarif",
        "version",
        "query",
        "path",
        "counters",
        "timeout",
        "output-limit",
    ],
)
def test_failed_or_unverifiable_attempt_stays_blocked(
    project: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    calls = fake_producer(
        monkeypatch,
        project,
        "malformed.json" if failure == "malformed" else "finding.json",
        exit_code=126 if failure == "exit" else 0,
        sarif_mode={"missing-sarif": "missing", "bad-sarif": "mismatch"}.get(failure, "valid"),
        mutation=failure,
        timeout=failure == "timeout",
        output_limited=failure == "output-limit",
    )
    path = plan_file(project)
    result = attempts.run_benchmark(project, path)
    assert result.blocked and result.cells[0].state == "execution-failed"
    assert result.cells[1].state == "not-attempted"
    if failure in {"malformed", "timeout", "output-limit"}:
        assert result.cells[0].finding_records is None
    before = tree(Path(result.session))
    assert attempts.run_benchmark(project, path).blocked
    assert tree(Path(result.session)) == before and len(calls) == 1


def test_missing_docker_is_verified_failure_without_retry(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(kics_pipeline, "resolve_docker", lambda _value: None)
    path = plan_file(project)
    result = attempts.run_benchmark(project, path)
    assert result.blocked and result.cells[0].verified_terminal_attempt
    assert result.cells[0].scanner_invocations == 0 and result.cells[0].finding_records is None
    before = tree(Path(result.session))
    with pytest.raises(ValueError, match="does not authorize"):
        attempts.retry_benchmark(
            project,
            path,
            attempt_id=result.cells[0].attempt_id or "",
            cause="docker-unavailable-before-launch",
            remediation="docker-command-availability-restored",
        )
    assert tree(Path(result.session)) == before


@pytest.mark.parametrize(
    "field", ["tool", "profile", "oracle", "source", "fixture", "extra-file", "extra-dir"]
)
def test_changed_admission_blocks_before_dispatch(
    project: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    path = plan_file(project)
    calls = fake_producer(monkeypatch, project)
    locations = {
        "tool": "configs/tools/kics.toml",
        "profile": "configs/profiles/development.toml",
        "oracle": "test_cases/development/kics-basic/case.toml",
        "source": "src/test_identity.py",
        "fixture": "test_cases/development/kics-basic/target/corrected.tf",
    }
    if field in locations:
        item = project / locations[field]
        item.write_bytes(item.read_bytes() + b"\n# changed\n")
    elif field == "extra-file":
        (project / "test_cases/development/kics-basic/target/.gitignore").write_bytes(
            b"vulnerable.tf\n"
        )
    else:
        (project / "test_cases/development/kics-basic/target/unlisted").mkdir()
    with pytest.raises(ValueError):
        attempts.run_benchmark(project, path)
    assert not calls and not (project / "workspace/benchmarks").exists()


@pytest.mark.parametrize(
    "field",
    [
        "split",
        "family",
        "expectation",
        "selection",
        "input",
        "implementation",
        "pins",
        "retry",
        "case",
    ],
)
def test_plan_forgery_is_rejected(project: Path, field: str) -> None:
    path = plan_file(project)
    raw = json.loads(path.read_bytes())
    case = raw["cases"][0]
    if field == "split":
        raw["split"] = "held-out"
    elif field == "family":
        case["source_family"] = "public-pilot"
    elif field == "expectation":
        case["expectation_sha256"] = "0" * 64
    elif field == "selection":
        case["selected_paths"] = ["notes.txt"]
    elif field == "input":
        case["files"][0]["sha256"] = "0" * 64
    elif field == "implementation":
        raw["implementation"][0]["sha256"] = "0" * 64
    elif field == "pins":
        raw["pins"][0]["sha256"] = "0" * 64
    elif field == "case":
        case["case_id"] = "public-dockerfile"
    else:
        raw["manual_retries"] = 1
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError):
        validate_plan(project, path)


@pytest.mark.parametrize(
    "artifact",
    [
        "native",
        "native-sarif",
        "finding",
        "snapshot",
        "query-selection",
        "summary",
        "export",
        "execution",
        "finish",
        "start",
    ],
)
def test_retained_mutation_refuses_resume(
    project: Path, monkeypatch: pytest.MonkeyPatch, artifact: str
) -> None:
    calls = fake_producer(monkeypatch, project)
    path = plan_file(project)
    first = attempts.run_benchmark(project, path, max_new_cells=1)
    assert first.cells[0].state == "completed-with-findings"
    attempt = next((Path(first.session) / "attempts").iterdir())
    run = attempt / "execution/runs" / (first.cells[0].run_id or "")
    patterns = {
        "native": "executions/*/native/results.json",
        "native-sarif": "executions/*/native/results.sarif",
        "finding": "normalized/findings.jsonl",
        "query-selection": "executions/*/inputs/query-selection.json",
        "summary": "exports/summary.json",
        "export": "exports/results.sarif",
        "execution": "executions/*/execution.json",
    }
    if artifact == "snapshot":
        target = next((attempt / "execution/targets").glob("*/content/corrected.tf"))
    elif artifact in patterns:
        target = next(run.glob(patterns[artifact]))
    else:
        target = attempt / f"{artifact}.json"
    target.write_bytes(target.read_bytes() + b" ")
    with pytest.raises(ValueError):
        attempts.run_benchmark(project, path)
    assert len(calls) == 1


@pytest.mark.parametrize("interrupt", [True, False])
def test_unverified_producer_error_blocks_and_requests_cleanup(
    project: Path, monkeypatch: pytest.MonkeyPatch, interrupt: bool
) -> None:
    fake_producer(monkeypatch, project)
    cleaned: list[str] = []

    def fail(*_args: object, **_kwargs: object) -> ProcessCapture:
        if interrupt:
            raise KeyboardInterrupt
        raise RuntimeError("sensitive exception text")

    def cleanup(**kwargs: object) -> bool:
        cleaned.append(str(kwargs["container_name"]))
        return True

    monkeypatch.setattr(kics_pipeline, "run_bounded_process", fail)
    monkeypatch.setattr(kics_pipeline, "cleanup_container", cleanup)
    path = plan_file(project)
    if interrupt:
        with pytest.raises(KeyboardInterrupt):
            attempts.run_benchmark(project, path)
    else:
        assert attempts.run_benchmark(project, path).blocked
    status = attempts.inspect_benchmark(project, path)
    assert len(cleaned) == 1 and status.blocked and not status.cells[0].verified_terminal_attempt
    assert status.cells[0].state == ("interrupted" if interrupt else "execution-failed")
    assert b"sensitive exception text" not in b"".join(
        p.read_bytes() for p in Path(status.session).rglob("*.json")
    )


def test_shared_lock_blocks_kics_dispatch(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = fake_producer(monkeypatch, project)
    path = plan_file(project)
    root = project / "workspace/benchmarks"
    root.mkdir()
    with (
        portalocker.Lock(str(root / ".writer.lock"), mode="a+", timeout=0),
        pytest.raises(ValueError, match="writer is active"),
    ):
        attempts.run_benchmark(project, path)
    assert not calls


def test_cli_and_additive_schemas(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_producer(monkeypatch, project)
    path = plan_file(project, repetitions=1)
    runner = CliRunner()
    for command in ("validate", "dry-run", "run", "status"):
        result = runner.invoke(
            app, ["benchmark", command, str(path), "--project-root", str(project)]
        )
        assert result.exit_code == 0, result.output
    status = attempts.inspect_benchmark(project, path)
    finish = next(Path(status.session).glob("attempts/*/finish.json"))
    for name, doc in (
        ("plan", json.loads(path.read_bytes())),
        ("dry-run", validate_plan(project, path).model_dump(mode="json")),
        ("progress", status.model_dump(mode="json")),
        ("attempt-finish", json.loads(finish.read_bytes())),
    ):
        Draft202012Validator(
            json.loads((REPO / f"schemas/benchmark-kics-v1/{name}.schema.json").read_bytes())
        ).validate(doc)


@pytest.mark.parametrize("cases", [(), ("dev-kics-basic-v1", "dev-kics-basic-v1"), ("unadmitted",)])
def test_invalid_case_selection(project: Path, cases: tuple[str, ...]) -> None:
    with pytest.raises(ValueError):
        build_kics_plan(project, plan_id="invalid", case_ids=cases)


def test_rehashing_changed_fixture_does_not_grant_admission(project: Path) -> None:
    path = plan_file(project)
    raw = json.loads(path.read_bytes())
    target = project / "test_cases/development/kics-basic/target/corrected.tf"
    target.write_bytes(target.read_bytes() + b"\n# changed\n")
    record = next(f for f in raw["cases"][0]["files"] if f["path"] == "corrected.tf")
    record.update(bytes=target.stat().st_size, sha256=sha256_bytes(target.read_bytes()))
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="does not grant admission"):
        validate_plan(project, path)


def test_expected_count_is_not_used_as_workflow_verdict(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_producer(monkeypatch, project, "clean.json")
    path = plan_file(project, repetitions=1)
    result = attempts.run_benchmark(project, path)
    assert result.workflow_complete and result.cells[0].state == "completed-without-findings"
    dry = validate_plan(project, path)
    assert isinstance(dry, KicsPreview)
    assert dry.cells[0].expectation.expected_native_results == 2
    assert result.cells[0].finding_records == 0 and not result.scoring_implemented


def test_forged_unsupported_finish_is_not_clean(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agentsec_evidence.benchmarks.attempt_models import KicsAttemptFinish
    from agentsec_evidence.core.io import model_bytes

    calls = fake_producer(monkeypatch, project, "unsupported.json")
    path = plan_file(project, ("dev-kics-unsupported-v1",))
    first = attempts.run_benchmark(project, path, max_new_cells=1)
    finish = next(Path(first.session).glob("attempts/*/finish.json"))
    raw = json.loads(finish.read_bytes())
    raw["state"] = raw["evidence"]["state"] = "completed-without-findings"
    finish.write_bytes(model_bytes(KicsAttemptFinish.model_validate(raw)))
    with pytest.raises(ValueError, match="Retained attempt evidence changed"):
        attempts.run_benchmark(project, path)
    assert len(calls) == 1


def test_cleanup_failure_stays_blocked(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = fake_producer(monkeypatch, project, timeout=True, cleanup_succeeds=False)
    path = plan_file(project)
    result = attempts.run_benchmark(project, path)
    assert result.blocked and result.cells[0].state == "execution-failed"
    assert attempts.inspect_benchmark(project, path).blocked and len(calls) == 1


def test_admitted_findings_exit_is_not_platform_failure(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_producer(monkeypatch, project, exit_code=20)
    result = attempts.run_benchmark(project, plan_file(project, repetitions=1))
    assert result.workflow_complete and result.cells[0].state == "completed-with-findings"


@pytest.mark.parametrize("results", [None, "invalid", {}, 0, False])
def test_invalid_native_sarif_results_are_not_zero(results: object) -> None:
    from agentsec_evidence.benchmarks.kics_evidence import _comparison_matches

    raw = json.dumps({"version": "2.1.0", "runs": [{"results": results}]}).encode()
    assert not _comparison_matches(raw, 0)


def test_native_sarif_can_omit_an_empty_results_array() -> None:
    from agentsec_evidence.benchmarks.kics_evidence import _comparison_matches

    raw = b'{"version":"2.1.0","runs":[{}]}'
    assert _comparison_matches(raw, 0)
    assert not _comparison_matches(raw, 1)
