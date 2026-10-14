from __future__ import annotations

import json
import shutil
from collections.abc import Sequence
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from agentsec_evidence.benchmarks import attempts
from agentsec_evidence.benchmarks.attempt_models import SemgrepProgress
from agentsec_evidence.benchmarks.models import SemgrepBenchmarkPlan, SemgrepPreview
from agentsec_evidence.benchmarks.semgrep_plan import ADMITTED_PINS, CASE_ROOT, build_semgrep_plan
from agentsec_evidence.benchmarks.service import plan_bytes, validate_plan
from agentsec_evidence.cli.app import app
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.core.time import utc_now
from agentsec_evidence.execution.process import ProcessCapture
from agentsec_evidence.orchestration import pipeline

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    for name in ADMITTED_PINS:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / name, path)
    shutil.copytree(REPO / CASE_ROOT / "target", root / CASE_ROOT / "target")
    shutil.copytree(REPO / "schemas", root / "schemas")
    (root / "src").mkdir()
    (root / "src/test_identity.py").write_bytes(b"# Test-only implementation identity.\n")
    (root / "workspace").mkdir()
    return root


def plan_file(project: Path, repetitions: int = 2) -> Path:
    path = project / "workspace/plan.json"
    path.write_bytes(
        plan_bytes(build_semgrep_plan(project, plan_id="semgrep-test", repetitions=repetitions))
    )
    return path


def fake_producer(
    monkeypatch: pytest.MonkeyPatch,
    project: Path,
    fixture: str = "finding.json",
    exit_code: int = 0,
) -> list[tuple[str, ...]]:
    docker = project / "docker.exe"
    docker.write_bytes(b"test double")
    monkeypatch.setattr(pipeline, "resolve_docker", lambda _value: docker)
    calls: list[tuple[str, ...]] = []

    def capture(argv: Sequence[str], **kwargs: object) -> ProcessCapture:
        del kwargs
        calls.append(tuple(argv))
        output_mount = next(a for a in argv if a.endswith("target=/output"))
        output = Path(output_mount.split("source=", 1)[1].split(",target=", 1)[0])
        (output / "semgrep.json").write_bytes(
            (REPO / "tests/fixtures/semgrep" / fixture).read_bytes()
        )
        now = utc_now()
        return ProcessCapture(
            argv=tuple(argv),
            started_at=now,
            ended_at=now,
            duration_ns=123,
            exit_code=exit_code,
            stdout=b"",
            stderr=b"",
            timed_out=False,
            output_limited=False,
            stdout_truncated=False,
            stderr_truncated=False,
            peak_rss_bytes=0,
        )

    monkeypatch.setattr(pipeline, "run_bounded_process", capture)
    return calls


def tree(root: Path) -> dict[str, str]:
    return {
        p.relative_to(root).as_posix(): sha256_bytes(p.read_bytes())
        for p in root.rglob("*")
        if p.is_file()
    }


def test_dry_run_and_status_do_not_launch(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Offline operation invoked a producer")

    monkeypatch.setattr(attempts, "run_semgrep_scan", forbidden)
    path = plan_file(project, 3)
    dry = validate_plan(project, path)
    assert isinstance(dry, SemgrepPreview) and len(dry.cells) == 3
    assert len(dry.cells[0].input_files) == 3 and len(dry.cells[0].selected_paths) == 2
    status = attempts.inspect_benchmark(project, path)
    assert isinstance(status, SemgrepProgress)
    assert all(row.state == "not-attempted" and row.finding_records is None for row in status.cells)
    assert not (project / "workspace/benchmarks").exists()


@pytest.mark.parametrize(
    ("fixture", "exit_code", "state", "count", "blocked"),
    [
        ("finding.json", 0, "completed-with-findings", 1, False),
        ("clean.json", 0, "completed-without-findings", 0, False),
        ("finding-with-error.json", 0, "partial-analysis", 1, False),
        ("finding.json", 2, "execution-failed", 1, True),
        ("malformed.json", 0, "execution-failed", None, True),
    ],
)
def test_attempt_outcomes_and_verified_reuse(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    fixture: str,
    exit_code: int,
    state: str,
    count: int | None,
    blocked: bool,
) -> None:
    calls = fake_producer(monkeypatch, project, fixture, exit_code)
    path = plan_file(project)
    first = attempts.run_benchmark(project, path, max_new_cells=1)
    assert first.cells[0].state == state
    assert first.cells[0].finding_records == count and first.cells[0].verified_terminal_attempt
    assert first.blocked == blocked and not first.workflow_complete
    first_path = next((Path(first.session) / "attempts").iterdir())
    original = tree(first_path)
    second = attempts.run_benchmark(project, path)
    assert tree(first_path) == original
    assert len(calls) == (1 if blocked else 2)
    assert second.workflow_complete != blocked
    before = tree(Path(second.session))
    again = attempts.run_benchmark(project, path)
    inspected = attempts.inspect_benchmark(project, path)
    assert again.cells == inspected.cells == second.cells
    assert tree(Path(second.session)) == before
    assert len(calls) == (1 if blocked else 2)
    assert not again.analysis_complete and not again.scoring_implemented


def test_missing_docker_failure_is_retained_and_no_retry(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pipeline, "resolve_docker", lambda _value: None)
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
    assert attempts.run_benchmark(project, path).blocked and tree(Path(result.session)) == before


@pytest.mark.parametrize(
    "field", ["tool", "profile", "rule", "oracle", "source", "fixture", "extra-file", "extra-dir"]
)
def test_changed_admission_blocks_before_dispatch(
    project: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    path = plan_file(project)
    calls = fake_producer(monkeypatch, project)
    locations = {
        "tool": "configs/tools/semgrep.toml",
        "profile": "configs/profiles/development.toml",
        "rule": "rules/project-authored/semgrep-first-slice.yml",
        "oracle": f"{CASE_ROOT}/case.toml",
        "source": "src/test_identity.py",
        "fixture": f"{CASE_ROOT}/target/clean.py",
    }
    if field in locations:
        item = project / locations[field]
        item.write_bytes(item.read_bytes() + b"\n# changed\n")
    elif field == "extra-file":
        (project / CASE_ROOT / "target/.semgrepignore").write_bytes(b"vulnerable.py\n")
    else:
        (project / CASE_ROOT / "target/unlisted").mkdir()
    with pytest.raises(ValueError):
        attempts.run_benchmark(project, path)
    assert not calls and not (project / "workspace/benchmarks").exists()


@pytest.mark.parametrize(
    "field",
    ["split", "family", "expectation", "selection", "input", "implementation", "pins", "retry"],
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
        case["selected_paths"] = ["ignored/ignored.py"]
    elif field == "input":
        case["files"][0]["sha256"] = "0" * 64
    elif field == "implementation":
        raw["implementation"][0]["sha256"] = "0" * 64
    elif field == "pins":
        raw["pins"][0]["sha256"] = "0" * 64
    else:
        raw["manual_retries"] = 1
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError):
        validate_plan(project, path)


@pytest.mark.parametrize(
    "artifact", ["native", "finding", "snapshot", "extra-snapshot", "finish", "start"]
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
    if artifact == "native":
        target = next(run.glob("executions/*/native/semgrep.json"))
    elif artifact == "finding":
        target = run / "normalized/findings.jsonl"
    elif artifact == "snapshot":
        target = next((attempt / "execution/targets").glob("*/content/clean.py"))
    elif artifact == "extra-snapshot":
        target = next((attempt / "execution/targets").glob("*/content")) / "extra.txt"
        target.write_bytes(b"unexpected")
    else:
        target = attempt / f"{artifact}.json"
    target.write_bytes(target.read_bytes() + b" ")
    with pytest.raises(ValueError):
        attempts.run_benchmark(project, path)
    assert len(calls) == 1


@pytest.mark.parametrize("interrupt", [True, False])
def test_unverified_producer_error_blocks(
    project: Path, monkeypatch: pytest.MonkeyPatch, interrupt: bool
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        if interrupt:
            raise KeyboardInterrupt
        raise RuntimeError("sensitive exception text")

    monkeypatch.setattr(attempts, "run_semgrep_scan", fail)
    path = plan_file(project)
    if interrupt:
        with pytest.raises(KeyboardInterrupt):
            attempts.run_benchmark(project, path)
    else:
        assert attempts.run_benchmark(project, path).blocked
    status = attempts.inspect_benchmark(project, path)
    assert status.blocked and not status.cells[0].verified_terminal_attempt
    assert status.cells[0].state == ("interrupted" if interrupt else "execution-failed")
    assert b"sensitive exception text" not in b"".join(
        p.read_bytes() for p in Path(status.session).rglob("*.json")
    )


def test_cli_and_additive_schema(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_producer(monkeypatch, project)
    path = plan_file(project, 1)
    runner = CliRunner()
    result = runner.invoke(app, ["benchmark", "run", str(path), "--project-root", str(project)])
    assert result.exit_code == 0, result.output
    for name, document in (
        ("plan", json.loads(path.read_bytes())),
        ("dry-run", validate_plan(project, path).model_dump(mode="json")),
        ("progress", attempts.inspect_benchmark(project, path).model_dump(mode="json")),
    ):
        Draft202012Validator(
            json.loads((REPO / f"schemas/benchmark-semgrep-v1/{name}.schema.json").read_bytes())
        ).validate(document)
    assert (
        SemgrepBenchmarkPlan.model_validate_json(path.read_bytes())
        .cases[0]
        .expectation.expected_native_results
        == 1
    )


def test_interrupted_native_process_requests_cleanup(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_producer(monkeypatch, project)
    cleaned: list[str] = []

    def interrupt(*_args: object, **_kwargs: object) -> ProcessCapture:
        raise KeyboardInterrupt

    def cleanup(**kwargs: object) -> bool:
        cleaned.append(str(kwargs["container_name"]))
        return True

    monkeypatch.setattr(pipeline, "run_bounded_process", interrupt)
    monkeypatch.setattr(pipeline, "cleanup_container", cleanup)
    path = plan_file(project)
    with pytest.raises(KeyboardInterrupt):
        attempts.run_benchmark(project, path)
    assert len(cleaned) == 1
    assert attempts.inspect_benchmark(project, path).blocked


def test_semgrep_respects_shared_writer_lock(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import portalocker

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
