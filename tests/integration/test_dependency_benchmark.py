from __future__ import annotations

import json
import shutil
import zipfile
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path

import portalocker
import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from agentsec_evidence.benchmarks import (
    attempts,
    dependency_boundary_plan,
    dependency_evidence,
    dependency_mutation_plan,
    dependency_plan,
)
from agentsec_evidence.benchmarks.attempt_models import (
    DependencyBoundaryFinish,
    DependencyBoundaryProgress,
    DependencyMutationProgress,
    DependencyProgress,
)
from agentsec_evidence.benchmarks.dependency_evidence import verify_dependency_attempt
from agentsec_evidence.benchmarks.models import (
    DependencyBenchmarkPlan,
    DependencyBoundaryPlan,
    DependencyBoundaryPreview,
    DependencyCaseId,
    DependencyMutationPlan,
    DependencyMutationPreview,
    DependencyPreview,
)
from agentsec_evidence.benchmarks.service import load_plan, plan_bytes, validate_plan
from agentsec_evidence.cli.app import app
from agentsec_evidence.core.identity import sha256_file
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.core.time import utc_now
from agentsec_evidence.dependencies import pipeline
from agentsec_evidence.dependencies.analysis import dependency_semantic_hash
from agentsec_evidence.dependencies.database import FrozenDatabase, inspect_database
from agentsec_evidence.dependencies.models import DependencyScope, StageEvidence
from agentsec_evidence.execution.process import ProcessCapture

REPO = Path(__file__).resolve().parents[2]
DB = "workspace/database.zip"


@pytest.fixture
def boundary_project(project: Path) -> Path:
    for relative in dependency_boundary_plan.CASE_ROOTS.values():
        shutil.copytree(REPO / relative / "target", project / relative / "target")
    helper = project / dependency_mutation_plan.EXPECTATIONS
    helper.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(REPO / dependency_mutation_plan.EXPECTATIONS, helper)
    return project


def boundary_plan_file(project: Path, case: str = "empty", repetitions: int = 2) -> Path:
    path = project / "workspace/boundary-plan.json"
    path.write_bytes(
        plan_bytes(
            dependency_boundary_plan.build_dependency_boundary_plan(
                project,
                plan_id="boundary-test",
                case_ids=(f"dev-dependency-{case}-v1",),
                repetitions=repetitions,
                database=DB,
            )
        )
    )
    return path


def empty_producer(monkeypatch: pytest.MonkeyPatch, project: Path) -> list[tuple[str, ...]]:
    def transform(result: ProcessCapture, output: Path) -> ProcessCapture:
        if output.name == "syft":
            (output / "syft.json").write_bytes(
                json_bytes({"schema": {"version": "16.1.10"}, "artifacts": []})
            )
            (output / "bom.cdx.json").write_bytes(
                json_bytes(
                    {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}
                )
            )
            return result
        (output / "osv.json").unlink()
        return replace(result, exit_code=128)

    return fake_producer(monkeypatch, project, after_capture=transform)


def test_boundary_preview_no_execution_and_old_admission_stays_fixed(
    boundary_project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        attempts, "run_dependency_scan", lambda **_kw: pytest.fail("scan during preview")
    )
    plan = dependency_boundary_plan.build_dependency_boundary_plan(
        boundary_project,
        plan_id="all",
        case_ids=tuple(dependency_boundary_plan.CASE_ROOTS),
        repetitions=3,
        database=DB,
    )
    path = boundary_project / "workspace/plan.json"
    path.write_bytes(plan_bytes(plan))
    dry = validate_plan(boundary_project, path)
    assert isinstance(dry, DependencyBoundaryPreview) and len(dry.cells) == 12
    assert isinstance(load_plan(path), DependencyBoundaryPlan)
    assert len({c.source_family for c in plan.cases}) == 1
    progress = attempts.inspect_benchmark(boundary_project, path)
    assert isinstance(progress, DependencyBoundaryProgress)
    assert all(r.scanner_invocations is None and r.stages is None for r in progress.cells)
    assert not (boundary_project / "workspace/benchmarks").exists()
    with pytest.raises(ValueError, match="Unknown or unadmitted"):
        dependency_plan.build_dependency_plan(
            boundary_project, plan_id="old", case_ids=(plan.cases[0].case_id,), database=DB
        )


@pytest.mark.parametrize("case", ["empty", "unresolved"])
def test_boundary_partial_resume_and_missing_output_is_not_zero(
    boundary_project: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    calls = (
        empty_producer(monkeypatch, boundary_project)
        if case == "empty"
        else fake_producer(monkeypatch, boundary_project)
    )
    path = boundary_plan_file(boundary_project, case)
    result = attempts.run_benchmark(boundary_project, path, max_new_cells=1)
    assert isinstance(result, DependencyBoundaryProgress) and not result.blocked
    row = result.cells[0]
    assert row.state == "partial-analysis" and row.verified_terminal_attempt
    assert row.scanner_invocations == 3 and row.finding_records is None
    assert row.eligible_packages == 0 and row.stages is not None
    osv = [s for s in row.stages if s.stage.startswith("osv-")]
    if case == "empty":
        assert all(
            s.state == "not-produced"
            and s.advisory_match_records is None
            and s.package_observations is None
            and s.native_exit_code == 128
            for s in osv
        )
    first = next(Path(result.session).glob("attempts/*"))
    seal = tree(first)
    completed = attempts.run_benchmark(boundary_project, path)
    assert completed.workflow_complete and len(calls) == 6 and tree(first) == seal
    seal = tree(Path(result.session))
    reused = attempts.run_benchmark(boundary_project, path)
    assert reused.reused_verified_cells == 2 and reused.newly_attempted_cells == 0
    assert len(calls) == 6 and tree(Path(result.session)) == seal
    assert reused.cells == attempts.inspect_benchmark(boundary_project, path).cells


@pytest.mark.parametrize("case", ["malformed", "unsupported"])
def test_boundary_parser_failure_is_verified_blocked_and_never_clean(
    boundary_project: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    monkeypatch.setattr(
        pipeline, "resolve_docker", lambda _x: pytest.fail("Docker resolution after failed parse")
    )
    path = boundary_plan_file(boundary_project, case)
    result = attempts.run_benchmark(boundary_project, path)
    assert isinstance(result, DependencyBoundaryProgress)
    row = result.cells[0]
    assert result.blocked and not result.workflow_complete
    assert row.state == "execution-failed" and row.verified_terminal_attempt
    assert (
        row.scanner_invocations == 0
        and row.finding_records is None
        and row.eligible_packages is None
    )
    assert row.input_failure == (
        "malformed-lockfile" if case == "malformed" else "unsupported-lockfile-version"
    )
    assert result.cells[1].state == "not-attempted"
    assert row.stages and row.stages[0].state == "failed"
    assert all(s.package_observations is None for s in row.stages)
    seal = tree(Path(result.session))
    assert attempts.run_benchmark(boundary_project, path).cells == result.cells
    assert tree(Path(result.session)) == seal
    with pytest.raises(ValueError, match="does not authorize"):
        attempts.retry_benchmark(
            boundary_project,
            path,
            attempt_id=str(row.attempt_id),
            cause="docker-unavailable-before-launch",
            remediation="docker-command-availability-restored",
        )


@pytest.mark.parametrize(
    "field",
    [
        "case_id",
        "split",
        "source_family",
        "expectation_sha256",
        "automatic_retries",
        "manual_retries",
        "database",
        "files",
    ],
)
def test_boundary_repinning_does_not_grant_admission(boundary_project: Path, field: str) -> None:
    path = boundary_plan_file(boundary_project)
    data = json.loads(path.read_bytes())
    if field.endswith("retries"):
        data[field] = 1
    elif field == "database":
        data[field]["sha256"] = "0" * 64
    elif field == "files":
        data["cases"][0][field][0]["sha256"] = "0" * 64
    else:
        data["cases"][0][field] = {
            "case_id": "dev-dependency-basic-v1",
            "split": "held-out",
            "source_family": "independent",
            "expectation_sha256": "0" * 64,
        }[field]
    path.write_bytes(json_bytes(data))
    with pytest.raises(ValueError):
        validate_plan(boundary_project, path)


@pytest.mark.parametrize("case", ["empty", "unresolved", "malformed", "unsupported"])
def test_boundary_changed_source_refused_before_execution(
    boundary_project: Path, case: str
) -> None:
    path = boundary_plan_file(boundary_project, case)
    source = boundary_project / f"test_cases/development/dependency-{case}/target/uv.lock"
    source.write_bytes(source.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="re-pinning"):
        attempts.run_benchmark(boundary_project, path)
    assert not (boundary_project / "workspace/benchmarks").exists()


@pytest.mark.parametrize(
    "change", ["exit", "report", "invent-output", "normalized", "input-command", "timeout"]
)
def test_empty_resealed_evidence_does_not_become_valid(
    boundary_project: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    empty_producer(monkeypatch, boundary_project)
    path = boundary_plan_file(boundary_project, repetitions=1)
    result = attempts.run_benchmark(boundary_project, path)
    assert result.workflow_complete
    bundle = next(Path(result.session).glob("attempts/*/execution/dependency-runs/*"))
    metadata = bundle / "native/osv-direct/execution.json"
    doc = json.loads(metadata.read_bytes())
    if change in {"exit", "input-command", "timeout"}:
        if change == "exit":
            doc["exit_code"] = 127
        elif change == "timeout":
            doc["timed_out"] = True
        else:
            doc["argv"][-1] = "/output/other.json"
        metadata.write_bytes(json_bytes(doc))
    elif change == "invent-output":
        (bundle / "native/osv-direct/osv.json").write_bytes(b'{"results": []}')
    elif change == "normalized":
        (bundle / "normalized/osv-direct.json").write_bytes(b"{}")
    else:
        report = json.loads((bundle / "report.json").read_bytes())
        report["state"] = "complete"
        (bundle / "report.json").write_bytes(json_bytes(report))
    (bundle / "manifest.json").unlink()
    pipeline.seal_bundle(bundle)
    with pytest.raises(ValueError):
        attempts.inspect_benchmark(boundary_project, path)


@pytest.mark.parametrize("change", ["error", "state", "extra-native", "snapshot"])
def test_failed_boundary_replay_rejects_resealed_evidence(
    boundary_project: Path, change: str
) -> None:
    path = boundary_plan_file(boundary_project, "malformed", 1)
    result = attempts.run_benchmark(boundary_project, path)
    assert result.cells[0].verified_terminal_attempt
    execution = next(Path(result.session).glob("attempts/*/execution"))
    bundle = next((execution / "dependency-runs").iterdir())
    if change in {"error", "state"}:
        data = json.loads((bundle / "report.json").read_bytes())
        data[change] = "changed"
        (bundle / "report.json").write_bytes(json_bytes(data))
    elif change == "snapshot":
        next((execution / "targets").glob("*/content/uv.lock")).write_bytes(b"version = 1\n")
    else:
        (bundle / "native").mkdir()
        (bundle / "native/unadmitted.json").write_bytes(b"{}")
    (bundle / "manifest.json").unlink()
    pipeline.seal_bundle(bundle)
    with pytest.raises(ValueError):
        attempts.inspect_benchmark(boundary_project, path)


def test_boundary_contracts_cli_and_schemas(boundary_project: Path) -> None:
    path = boundary_plan_file(boundary_project, "unsupported", 1)
    preview = validate_plan(boundary_project, path)
    result = attempts.run_benchmark(boundary_project, path)
    finish = DependencyBoundaryFinish.model_validate_json(
        next(Path(result.session).glob("attempts/*/finish.json")).read_bytes()
    )
    for name, value in (
        ("plan", load_plan(path)),
        ("dry-run", preview),
        ("progress", result),
        ("attempt-finish", finish),
    ):
        schema = json.loads(
            (REPO / f"schemas/benchmark-dependency-boundary-v1/{name}.schema.json").read_bytes()
        )
        assert schema == type(value).model_json_schema()
        Draft202012Validator(schema).validate(value.model_dump(mode="json"))
    for command in ("validate", "dry-run", "status"):
        outcome = CliRunner().invoke(
            app, ["benchmark", command, str(path), "--project-root", str(boundary_project)]
        )
        assert outcome.exit_code == (5 if command == "status" else 0), outcome.output


@pytest.mark.parametrize("case", ["empty", "unresolved"])
@pytest.mark.parametrize("mode", ["exit", "timeout", "output-limit", "malformed"])
def test_boundary_unexpected_execution_failure_blocks(
    boundary_project: Path, monkeypatch: pytest.MonkeyPatch, case: str, mode: str
) -> None:
    calls = fake_producer(monkeypatch, boundary_project, mode=mode)
    path = boundary_plan_file(boundary_project, case)
    result = attempts.run_benchmark(boundary_project, path)
    assert result.blocked and result.cells[0].state == "execution-failed"
    assert not result.cells[0].verified_terminal_attempt
    assert result.cells[1].state == "not-attempted"
    before, count = tree(Path(result.session)), len(calls)
    assert attempts.run_benchmark(boundary_project, path).blocked
    assert len(calls) == count and tree(Path(result.session)) == before


def test_boundary_helper_change_and_interruption_are_not_reusable(
    boundary_project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = boundary_plan_file(boundary_project)
    helper = boundary_project / dependency_mutation_plan.EXPECTATIONS
    original = helper.read_bytes()
    helper.write_bytes(original + b"\n")
    with pytest.raises(ValueError, match="re-pinning"):
        attempts.run_benchmark(boundary_project, path)
    helper.write_bytes(original)
    fake_producer(monkeypatch, boundary_project)

    def interrupt(*_args: object, **_kwargs: object) -> ProcessCapture:
        raise KeyboardInterrupt

    monkeypatch.setattr(pipeline, "run_bounded_process", interrupt)
    with pytest.raises(KeyboardInterrupt):
        attempts.run_benchmark(boundary_project, path)
    result = attempts.inspect_benchmark(boundary_project, path)
    assert result.blocked and result.cells[0].state == "interrupted"
    before = tree(Path(result.session))
    assert attempts.run_benchmark(boundary_project, path).cells == result.cells
    assert tree(Path(result.session)) == before


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "project"
    for name in dependency_plan.ADMITTED_PINS:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / name, path)
    for relative in dependency_plan.CASE_ROOTS.values():
        shutil.copytree(REPO / relative / "target", root / relative / "target")
    (root / "src").mkdir()
    (root / "src/test_identity.py").write_bytes(b"# Test-only implementation identity.\n")
    (root / "workspace").mkdir()
    with zipfile.ZipFile(root / DB, "w") as archive:
        archive.writestr(
            "test.json",
            json.dumps(
                {
                    "id": "GHSA-test",
                    "aliases": ["CVE-2099-0001"],
                    "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"}}],
                }
            ),
        )
    # Resource substitution is test-only; production still requires the admitted archive hash.
    monkeypatch.setattr(dependency_plan, "DATABASE_SHA256", sha256_file(root / DB))
    return root


def plan_file(
    project: Path, cases: tuple[str, ...] = ("dev-dependency-basic-v1",), repetitions: int = 2
) -> Path:
    path = project / "workspace/plan.json"
    path.write_bytes(
        plan_bytes(
            dependency_plan.build_dependency_plan(
                project,
                plan_id="dependency-test",
                case_ids=cases,
                repetitions=repetitions,
                database=DB,
            )
        )
    )
    return path


def fake_producer(
    monkeypatch: pytest.MonkeyPatch,
    project: Path,
    *,
    mode: str = "findings",
    after_capture: Callable[[ProcessCapture, Path], ProcessCapture] | None = None,
) -> list[tuple[str, ...]]:
    docker = project / "docker.exe"
    docker.write_bytes(b"test double")
    monkeypatch.setattr(pipeline, "resolve_docker", lambda _value: docker)
    monkeypatch.setattr(pipeline, "cleanup_container", lambda **_kwargs: True)
    calls: list[tuple[str, ...]] = []

    def capture(argv: Sequence[str], **_kwargs: object) -> ProcessCapture:
        calls.append(tuple(argv))
        output_mount = next(a for a in argv if a.endswith("target=/output"))
        output = Path(output_mount.split("source=", 1)[1].split(",target=", 1)[0])
        syft = output.name == "syft"
        version = "2.33.0" if mode == "clean" else "2.31.0"
        purl = f"pkg:pypi/requests@{version}"
        if syft:
            doc = {
                "schema": {"version": "16.1.10"},
                "artifacts": [
                    {
                        "id": "a",
                        "type": "python",
                        "name": "requests",
                        "version": version,
                        "purl": purl,
                    }
                ],
            }
            (output / "syft.json").write_text(json.dumps(doc), encoding="utf-8")
            cdx = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "components": [
                    {
                        "type": "library",
                        "bom-ref": "a",
                        "name": "requests",
                        "version": version,
                        "purl": purl,
                    }
                ],
            }
            (output / "bom.cdx.json").write_text(json.dumps(cdx), encoding="utf-8")
        else:
            doc = {
                "results": [
                    {
                        "source": {"path": "/src/uv.lock", "type": "lockfile"},
                        "packages": [
                            {
                                "package": {
                                    "name": "requests",
                                    "version": version,
                                    "ecosystem": "PyPI",
                                },
                                "vulnerabilities": []
                                if mode in {"clean", "contradiction"}
                                else [{"id": "GHSA-test"}],
                            }
                        ],
                    }
                ]
            }
            (output / "osv.json").write_text(json.dumps(doc), encoding="utf-8")
        if mode == "malformed" and not syft:
            (output / "osv.json").write_bytes(b"{")
        code = 0 if syft or mode == "clean" else 1
        if mode == "exit":
            code = 127
        if mode == "unsupported":
            code = 128
        now = utc_now()
        result = ProcessCapture(
            argv=tuple(argv),
            started_at=now,
            ended_at=now,
            duration_ns=123,
            exit_code=code,
            stdout=b"",
            stderr=b"",
            timed_out=mode == "timeout",
            output_limited=mode == "output-limit",
            stdout_truncated=False,
            stderr_truncated=False,
            peak_rss_bytes=0,
        )
        return after_capture(result, output) if after_capture is not None else result

    monkeypatch.setattr(pipeline, "run_bounded_process", capture)
    return calls


def tree(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): sha256_file(p) for p in root.rglob("*") if p.is_file()}


def test_preview_is_offline_and_counts_remain_unknown(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        attempts, "run_dependency_scan", lambda **_kwargs: pytest.fail("Scan during preview")
    )
    path = plan_file(project, tuple(dependency_plan.CASE_ROOTS), 3)
    dry = validate_plan(project, path)
    assert isinstance(dry, DependencyPreview) and len(dry.cells) == 6
    status = attempts.inspect_benchmark(project, path)
    assert isinstance(status, DependencyProgress)
    assert all(
        r.stages is None and r.finding_records is None and r.state == "not-attempted"
        for r in status.cells
    )
    assert not (project / "workspace/benchmarks").exists()


@pytest.mark.parametrize(
    ("case", "mode", "state", "matches"),
    [
        ("dev-dependency-basic-v1", "findings", "completed-with-findings", 1),
        ("dev-dependency-clean-v1", "clean", "completed-without-findings", 0),
        ("dev-dependency-basic-v1", "contradiction", "partial-analysis", 0),
    ],
)
def test_paired_resume_and_no_cross_path_sum(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: DependencyCaseId,
    mode: str,
    state: str,
    matches: int,
) -> None:
    calls = fake_producer(monkeypatch, project, mode=mode)
    path = plan_file(project, (case,))
    first = attempts.run_benchmark(project, path, max_new_cells=1)
    assert isinstance(first, DependencyProgress)
    row = first.cells[0]
    assert row.state == state and row.verified_terminal_attempt
    assert row.finding_records is None and row.scanner_invocations == 3
    assert row.stages is not None
    assert [s.advisory_match_records for s in row.stages if s.stage.startswith("osv")] == [
        matches,
        matches,
    ]
    initial = next((Path(first.session) / "attempts").iterdir())
    original = tree(initial)
    completed = attempts.run_benchmark(project, path)
    assert completed.workflow_complete and len(calls) == 6 and tree(initial) == original
    before = tree(Path(completed.session))
    reused = attempts.run_benchmark(project, path)
    assert reused.cells == attempts.inspect_benchmark(project, path).cells == completed.cells
    assert reused.reused_verified_cells == 2 and reused.newly_attempted_cells == 0
    assert tree(Path(reused.session)) == before and len(calls) == 6
    assert not reused.analysis_complete and not reused.scoring_implemented


@pytest.mark.parametrize("mode", ["malformed", "exit", "unsupported", "timeout", "output-limit"])
def test_invalid_pair_blocks_without_retry(
    project: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    calls = fake_producer(monkeypatch, project, mode=mode)
    path = plan_file(project)
    result = attempts.run_benchmark(project, path)
    assert result.blocked and not result.workflow_complete
    assert result.cells[0].state == "execution-failed" and result.cells[1].state == "not-attempted"
    before, count = tree(Path(result.session)), len(calls)
    again = attempts.run_benchmark(project, path)
    assert again.blocked and len(calls) == count and tree(Path(result.session)) == before


@pytest.mark.parametrize("failure", [KeyboardInterrupt, RuntimeError, OSError, ValueError])
@pytest.mark.parametrize("cleanup_raises", [False, True])
def test_interruption_requests_container_cleanup(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: type[BaseException],
    cleanup_raises: bool,
) -> None:
    fake_producer(monkeypatch, project)
    cleaned: list[str] = []

    def stop(*_args: object, **_kwargs: object) -> ProcessCapture:
        raise failure()

    def cleanup(**kwargs: object) -> bool:
        cleaned.append(str(kwargs["container_name"]))
        if cleanup_raises:
            raise OSError("Test-only cleanup failure")
        return True

    monkeypatch.setattr(pipeline, "run_bounded_process", stop)
    monkeypatch.setattr(pipeline, "cleanup_container", cleanup)
    path = plan_file(project)
    if failure is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt):
            attempts.run_benchmark(project, path)
    else:
        assert attempts.run_benchmark(project, path).blocked
    assert len(cleaned) == 1 and cleaned[0].startswith("sonic-dep-")
    assert attempts.inspect_benchmark(project, path).blocked


@pytest.mark.parametrize("mode", ["timeout", "output-limit"])
@pytest.mark.parametrize("cleanup_raises", [False, True])
def test_resource_failure_does_not_launch_following_stage(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    cleanup_raises: bool,
) -> None:
    calls = fake_producer(monkeypatch, project, mode=mode)

    def cleanup(**_kwargs: object) -> bool:
        if cleanup_raises:
            raise OSError("Test-only cleanup failure")
        return False

    monkeypatch.setattr(pipeline, "cleanup_container", cleanup)
    result = attempts.run_benchmark(project, plan_file(project))
    assert result.blocked and len(calls) == 1
    assert result.cells[0].state == "execution-failed"
    root = next(Path(result.session).glob("attempts/*/execution/dependency-runs/*"))
    report = json.loads((root / "report.json").read_bytes())
    assert report["state"] == "failed"
    assert report["stages"]["osv-direct"]["cleanup_succeeded"] is False
    assert not (root / "native/syft").exists()


@pytest.mark.parametrize(
    "case_ids",
    [
        (),
        ("unknown",),
        ("dev-dependency-basic-v1",) * 2,
        ("dev-dependency-malformed-v1",),
        ("pilot",),
    ],
)
def test_case_admission(project: Path, case_ids: tuple[str, ...]) -> None:
    with pytest.raises(ValueError):
        plan_file(project, case_ids)


@pytest.mark.parametrize(
    "field",
    [
        "split",
        "treatment",
        "admission",
        "manual_retries",
        "mutation",
        "implementation",
        "database",
        "case",
    ],
)
def test_repinning_does_not_admit_changed_plan(project: Path, field: str) -> None:
    path = plan_file(project)
    doc = json.loads(path.read_bytes())
    if field == "database":
        doc[field]["sha256"] = "0" * 64
    elif field == "implementation":
        doc[field][0]["sha256"] = "0" * 64
    elif field == "case":
        doc["cases"][0]["files"][0]["sha256"] = "0" * 64
    else:
        doc[field] = 1 if field == "manual_retries" else "changed"
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(ValueError):
        validate_plan(project, path)


@pytest.mark.parametrize(
    "relative",
    [
        *dependency_plan.ADMITTED_PINS,
        "test_cases/development/dependency-basic/target/uv.lock",
        "test_cases/development/dependency-clean/target/uv.lock",
        "src/test_identity.py",
        DB,
    ],
)
def test_changed_protected_bytes_stop_before_launch(
    project: Path, monkeypatch: pytest.MonkeyPatch, relative: str
) -> None:
    calls = fake_producer(monkeypatch, project)
    path = plan_file(project)
    (project / relative).write_bytes((project / relative).read_bytes() + b"\n")
    with pytest.raises(ValueError):
        attempts.run_benchmark(project, path)
    assert calls == [] and not (project / "workspace/benchmarks").exists()


def reseal(root: Path) -> None:
    (root / "manifest.json").unlink()
    pipeline.seal_bundle(root)


@pytest.mark.parametrize(
    "change",
    [
        "normalized",
        "command",
        "database",
        "oracle",
        "harness",
        "comparison",
        "snapshot",
        "raw",
        "report",
        "config",
        "mutation",
        "duplicate",
    ],
)
def test_resealed_evidence_cannot_bypass_replay(
    project: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    calls = fake_producer(monkeypatch, project)
    path = plan_file(project, repetitions=1)
    result = attempts.run_benchmark(project, path)
    assert result.workflow_complete
    attempt = next((Path(result.session) / "attempts").iterdir())
    execution = attempt / "execution"
    bundle = next((execution / "dependency-runs").iterdir())
    files = {
        "normalized": "normalized/osv-direct.json",
        "command": "native/osv-direct/execution.json",
        "database": "database/manifest.json",
        "oracle": "inputs/finite-oracle.json",
        "harness": "harness-source.json",
        "comparison": "comparisons.json",
        "raw": "native/osv-direct/osv.json",
        "report": "report.json",
        "config": "configuration/tools.json",
    }
    if change == "snapshot":
        target = next((execution / "targets").glob("*/content/uv.lock"))
        target.write_bytes(target.read_bytes() + b"\n")
    elif change == "mutation":
        (bundle / "mutations").mkdir()
        (bundle / "mutations/change.json").write_bytes(b"{}")
    elif change == "duplicate":
        shutil.copytree(bundle, bundle.parent / ("dep-run-" + "f" * 32))
    else:
        file = bundle / files[change]
        doc = json.loads(file.read_bytes())
        if change == "command":
            doc["argv"][doc["argv"].index("none")] = "host"
        elif change == "report":
            doc["eligible_packages"] = 99
        elif change == "normalized":
            doc["matches"] = []
        else:
            doc = [] if change == "comparison" else {}
        file.write_text(json.dumps(doc), encoding="utf-8")
    reseal(bundle)
    with pytest.raises((ValueError, KeyError, TypeError)):
        attempts.inspect_benchmark(project, path)
    assert len(calls) == 3


def test_shared_writer_lock(project: Path) -> None:
    path = plan_file(project)
    root = project / "workspace/benchmarks"
    root.mkdir()
    with (
        portalocker.Lock(str(root / ".writer.lock"), mode="a+", timeout=0),
        pytest.raises(ValueError, match="writer"),
    ):
        attempts.run_benchmark(project, path)


def test_consistent_rehash_cannot_replace_native_meaning(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_producer(monkeypatch, project)
    path = plan_file(project, repetitions=1)
    result = attempts.run_benchmark(project, path)
    assert result.workflow_complete
    execution = next(Path(result.session).glob("attempts/*/execution"))
    root = next((execution / "dependency-runs").iterdir())
    stage_path = root / "normalized/osv-direct.json"
    doc = json.loads(stage_path.read_bytes())
    doc["matches"] = []
    stage_path.write_text(json.dumps(doc), encoding="utf-8")
    scope = DependencyScope.model_validate_json((root / "scope.json").read_bytes())
    stages = [
        StageEvidence.model_validate_json(p.read_bytes())
        for p in (root / "normalized").glob("*.json")
    ]
    report_path = root / "report.json"
    report = json.loads(report_path.read_bytes())
    report["semantic_sha256"] = dependency_semantic_hash(stages, scope)
    report_path.write_text(json.dumps(report), encoding="utf-8")
    reseal(root)
    assert pipeline.validate_dependency_bundle(root)["passed"]
    plan = load_plan(path)
    preview = validate_plan(project, path)
    assert isinstance(plan, DependencyBenchmarkPlan) and isinstance(preview, DependencyPreview)
    with pytest.raises(ValueError, match="normalization replay"):
        verify_dependency_attempt(project, execution, root.name, plan, preview.cells[0])


def test_changed_source_extra_input_and_no_retry(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = fake_producer(monkeypatch, project)
    path = plan_file(project)
    with pytest.raises(ValueError, match="does not authorize"):
        attempts.retry_benchmark(
            project,
            path,
            attempt_id="attempt_" + "a" * 32,
            cause="docker-unavailable-before-launch",
            remediation="docker-command-availability-restored",
        )
    (project / "test_cases/development/dependency-clean/target/extra.txt").write_bytes(b"extra")
    with pytest.raises(ValueError, match="Unadmitted"):
        attempts.run_benchmark(project, path)
    assert calls == []


def test_missing_database_stops_preflight(project: Path) -> None:
    path = plan_file(project)
    (project / DB).unlink()
    with pytest.raises((ValueError, FileNotFoundError)):
        validate_plan(project, path)


def test_large_frozen_index_uses_exact_reconstructed_bytes(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def large(path: Path, digest: str, names: set[str]) -> FrozenDatabase:
        frozen = inspect_database(path, digest, names)
        # Synthetic archive-index size, not a real second vulnerability corpus.
        return replace(
            frozen, entries=[{**frozen.entries[0], "path": f"test-{i}.json"} for i in range(25_001)]
        )

    monkeypatch.setattr(pipeline, "inspect_database", large)
    monkeypatch.setattr(dependency_evidence, "inspect_database", large)
    fake_producer(monkeypatch, project)
    path = plan_file(project, repetitions=1)
    result = attempts.run_benchmark(project, path)
    assert result.workflow_complete and not result.blocked


@pytest.mark.parametrize(
    "name", ["../escape.zip", "D:/database.zip", "test_cases/db.zip", "workspace/../database.zip"]
)
def test_database_path_rejected(project: Path, name: str) -> None:
    with pytest.raises(ValueError):
        dependency_plan.build_dependency_plan(
            project, plan_id="bad", case_ids=("dev-dependency-basic-v1",), database=name
        )


def test_schemas_match_models_and_cli(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_producer(monkeypatch, project)
    path = plan_file(project, repetitions=1)
    preview = validate_plan(project, path)
    status = attempts.run_benchmark(project, path)
    for name, document in (
        ("plan", json.loads(path.read_bytes())),
        ("dry-run", preview.model_dump(mode="json")),
        ("progress", status.model_dump(mode="json")),
    ):
        schema = json.loads(
            (REPO / f"schemas/benchmark-dependency-v1/{name}.schema.json").read_bytes()
        )
        Draft202012Validator(schema).validate(document)
    finish = next(Path(status.session).glob("attempts/*/finish.json"))
    Draft202012Validator(
        json.loads(
            (REPO / "schemas/benchmark-dependency-v1/attempt-finish.schema.json").read_bytes()
        )
    ).validate(json.loads(finish.read_bytes()))
    runner = CliRunner()
    result = runner.invoke(app, ["benchmark", "status", str(path), "--project-root", str(project)])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["contract"] == "benchmark-dependency-progress-v1"


@pytest.fixture
def mutation_project(project: Path) -> Path:
    for name in dependency_mutation_plan.ADMITTED_MUTATION_PINS:
        path = project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / name, path)
    return project


def mutation_plan_file(project: Path, mutation: str | None = None, repetitions: int = 1) -> Path:
    cases = (
        tuple(dependency_mutation_plan.MUTATIONS)
        if mutation is None
        else (f"dev-dependency-{mutation}-v1",)
    )
    path = project / "workspace/mutation-plan.json"
    path.write_bytes(
        plan_bytes(
            dependency_mutation_plan.build_dependency_mutation_plan(
                project,
                plan_id="mutation-test",
                case_ids=cases,
                database=DB,
                repetitions=repetitions,
            )
        )
    )
    return path


def fake_mutation_producer(monkeypatch: pytest.MonkeyPatch, project: Path) -> list[tuple[str, ...]]:
    def transform(result: ProcessCapture, output: Path) -> ProcessCapture:
        argv = result.argv
        if output.name == "syft":
            syft = json.loads((output / "syft.json").read_bytes())
            syft["artifacts"].append(
                {
                    "id": "b",
                    "type": "python",
                    "name": "packaging",
                    "version": "25.0",
                    "purl": "pkg:pypi/packaging@25.0",
                }
            )
            (output / "syft.json").write_bytes(json_bytes(syft))
            cdx = json.loads((output / "bom.cdx.json").read_bytes())
            cdx["components"].append(
                {
                    "type": "library",
                    "bom-ref": "b",
                    "name": "packaging",
                    "version": "25.0",
                    "purl": "pkg:pypi/packaging@25.0",
                }
            )
            cdx["dependencies"] = [{"ref": "a", "dependsOn": ["b"]}, {"ref": "b", "dependsOn": []}]
            (output / "bom.cdx.json").write_bytes(json_bytes(cdx))
        elif output.name == "osv-sbom":
            source_mount = next(a for a in argv if ",target=/src/bom.cdx.json," in a)
            source = Path(source_mount.split("source=", 1)[1].split(",target=", 1)[0])
            cdx = json.loads(source.read_bytes())
            packages = [
                {
                    "package": {"name": c["name"], "version": c["version"], "ecosystem": "PyPI"},
                    "vulnerabilities": [{"id": "GHSA-test"}] if c["name"] == "requests" else [],
                }
                for c in cdx["components"]
                if "purl" in c
            ]
            document = {
                "results": [
                    {"source": {"path": "/src/bom.cdx.json", "type": "sbom"}, "packages": packages}
                ]
            }
            (output / "osv.json").write_text(json.dumps(document), encoding="utf-8")
            result = replace(result, exit_code=int(any(p["vulnerabilities"] for p in packages)))
        return result

    return fake_producer(monkeypatch, project, after_capture=transform)


def test_mutation_preview_offline_and_old_contracts_unchanged(
    mutation_project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        attempts, "run_dependency_scan", lambda **_kw: pytest.fail("preview executed")
    )
    path = mutation_plan_file(mutation_project, repetitions=3)
    plan, preview = load_plan(path), validate_plan(mutation_project, path)
    assert isinstance(plan, DependencyMutationPlan) and isinstance(
        preview, DependencyMutationPreview
    )
    assert len(preview.cells) == 9
    assert len({c.source_family for c in plan.cases}) == 1
    assert all(c.source_case == "dev-dependency-basic-v1" for c in plan.cases)
    status = attempts.inspect_benchmark(mutation_project, path)
    assert isinstance(status, DependencyMutationProgress)
    assert all(c.stages is None and c.scanner_invocations is None for c in status.cells)
    old = dependency_plan.build_dependency_plan(
        mutation_project, plan_id="old", case_ids=("dev-dependency-basic-v1",), database=DB
    )
    assert old.contract == "benchmark-dependency-plan-v1" and len(old.pins) == 9
    with pytest.raises(ValueError):
        dependency_plan.build_dependency_plan(
            mutation_project, plan_id="bad", case_ids=(preview.cells[0].case_id,), database=DB
        )


@pytest.mark.parametrize("mutation", ["remove-component", "remove-purl", "change-version"])
def test_mutation_pair_replay_resume_and_preservation(
    mutation_project: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    calls = fake_mutation_producer(monkeypatch, mutation_project)
    path = mutation_plan_file(mutation_project, mutation, repetitions=2)
    result = attempts.run_benchmark(mutation_project, path, max_new_cells=1)
    assert not result.blocked
    row = result.cells[0]
    assert row.state == (
        "partial-analysis" if mutation == "remove-purl" else "completed-with-findings"
    )
    assert row.finding_records is None and row.scanner_invocations == 3
    execution = next(Path(result.session).glob("attempts/*/execution"))
    bundle = next((execution / "dependency-runs").iterdir())
    original = json.loads((bundle / "native/syft/bom.cdx.json").read_bytes())
    assert original["components"][0]["version"] == "2.31.0"
    assert "purl" in original["components"][0]
    differences = json.loads((bundle / "comparisons.json").read_bytes())
    handoff = next(d for d in differences if d["left"] == "syft" and d["right"] == "cyclonedx")
    assert ["requests", "2.31.0"] in handoff["missing"]
    if mutation == "remove-purl":
        assert handoff["missing_identifiers"]
    before = tree(execution)
    complete = attempts.run_benchmark(mutation_project, path)
    assert complete.workflow_complete and len(calls) == 6
    assert tree(execution) == before
    seal = tree(Path(result.session))
    reused = attempts.run_benchmark(mutation_project, path)
    assert reused.reused_verified_cells == 2 and reused.newly_attempted_cells == 0
    assert tree(Path(result.session)) == seal and len(calls) == 6
    assert reused.cells == attempts.inspect_benchmark(mutation_project, path).cells


@pytest.mark.parametrize(
    "field",
    ["mutation", "case_id", "source_case", "split", "automatic_retries", "database", "expectation"],
)
def test_mutation_repinning_not_admission(mutation_project: Path, field: str) -> None:
    path = mutation_plan_file(mutation_project, "remove-component")
    data = json.loads(path.read_bytes())
    if field == "automatic_retries":
        data[field] = 1
    elif field == "database":
        data[field]["sha256"] = "0" * 64
    else:
        key = "expectation_sha256" if field == "expectation" else field
        data["cases"][0][key] = {
            "mutation": "change-version",
            "case_id": "dev-dependency-clean-v1",
            "source_case": "dev-dependency-clean-v1",
            "split": "held-out",
            "expectation": "0" * 64,
        }[field]
    path.write_bytes(json_bytes(data))
    with pytest.raises(ValueError):
        validate_plan(mutation_project, path)
    assert not (mutation_project / "workspace/benchmarks").exists()


@pytest.mark.parametrize("name", list(dependency_mutation_plan.ADMITTED_MUTATION_PINS))
def test_mutation_frozen_transform_and_expectations(mutation_project: Path, name: str) -> None:
    path = mutation_plan_file(mutation_project)
    source = mutation_project / name
    source.write_bytes(source.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="Mutation transformation/expectations"):
        validate_plan(mutation_project, path)


@pytest.mark.parametrize(
    "change",
    [
        "mutated",
        "change-record",
        "original",
        "input-command",
        "extra",
        "missing",
        "report",
        "coherent-rehash",
    ],
)
def test_mutation_evidence_resealing_cannot_bypass_replay(
    mutation_project: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    calls = fake_mutation_producer(monkeypatch, mutation_project)
    path = mutation_plan_file(mutation_project, "change-version")
    result = attempts.run_benchmark(mutation_project, path)
    assert result.workflow_complete
    execution = next(Path(result.session).glob("attempts/*/execution"))
    root = next((execution / "dependency-runs").iterdir())
    changed = root / "mutations/bom.cdx.json"
    if change == "extra":
        (root / "mutations/extra.json").write_bytes(b"{}")
    elif change == "missing":
        (root / "mutations/change.json").unlink()
    elif change in {"mutated", "coherent-rehash"}:
        data = json.loads(changed.read_bytes())
        data["serialNumber"] = "urn:uuid:00000000-0000-4000-8000-000000000001"
        changed.write_bytes(json_bytes(data))
        if change == "coherent-rehash":
            receipt = root / "mutations/change.json"
            data = json.loads(receipt.read_bytes())
            data["mutated_sha256"] = sha256_file(changed)
            receipt.write_bytes(json_bytes(data))
            normalized = root / "normalized/cyclonedx.json"
            data = json.loads(normalized.read_bytes())
            data["raw_sha256"] = sha256_file(changed)
            normalized.write_bytes(json_bytes(data))
    elif change == "original":
        (root / "native/syft/bom.cdx.json").write_bytes(b"{}")
    elif change == "input-command":
        record = root / "native/osv-sbom/execution.json"
        data = json.loads(record.read_bytes())
        data["argv"] = [a.replace("mutations", "native/syft") for a in data["argv"]]
        record.write_bytes(json_bytes(data))
    elif change == "report":
        report = root / "report.json"
        data = json.loads(report.read_bytes())
        data["mutation"] = None
        report.write_bytes(json_bytes(data))
    else:
        receipt = root / "mutations/change.json"
        data = json.loads(receipt.read_bytes())
        data["target"] = "requests@2.33.0"
        receipt.write_bytes(json_bytes(data))
    reseal(root)
    if change == "coherent-rehash":
        assert pipeline.validate_dependency_bundle(root)["passed"]
        plan, preview = load_plan(path), validate_plan(mutation_project, path)
        assert isinstance(plan, DependencyMutationPlan) and isinstance(
            preview, DependencyMutationPreview
        )
        with pytest.raises(ValueError, match="exact transformation replay"):
            verify_dependency_attempt(
                mutation_project, execution, root.name, plan, preview.cells[0]
            )
    else:
        with pytest.raises((ValueError, KeyError, TypeError)):
            attempts.inspect_benchmark(mutation_project, path)
    assert len(calls) == 3


def test_mutation_schema_cli_and_interruption(
    mutation_project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = mutation_plan_file(mutation_project)
    plan, preview = load_plan(path), validate_plan(mutation_project, path)
    status = attempts.inspect_benchmark(mutation_project, path)
    for name, data in (
        ("plan", plan.model_dump(mode="json")),
        ("dry-run", preview.model_dump(mode="json")),
        ("progress", status.model_dump(mode="json")),
    ):
        schema = json.loads(
            (REPO / f"schemas/benchmark-dependency-mutation-v1/{name}.schema.json").read_bytes()
        )
        Draft202012Validator(schema).validate(data)
    result = CliRunner().invoke(
        app, ["benchmark", "dry-run", str(path), "--project-root", str(mutation_project)]
    )
    assert result.exit_code == 0, result.output
    fake_mutation_producer(monkeypatch, mutation_project)

    def interrupt(*_args: object, **_kwargs: object) -> ProcessCapture:
        raise KeyboardInterrupt

    monkeypatch.setattr(pipeline, "run_bounded_process", interrupt)
    with pytest.raises(KeyboardInterrupt):
        attempts.run_benchmark(mutation_project, path)
    result_status = attempts.inspect_benchmark(mutation_project, path)
    assert result_status.blocked and result_status.cells[0].state == "interrupted"
    original = tree(Path(result_status.session))
    assert attempts.run_benchmark(mutation_project, path).blocked
    assert tree(Path(result_status.session)) == original
