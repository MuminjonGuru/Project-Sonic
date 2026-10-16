from __future__ import annotations

import json
import shutil
import zipfile
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

import portalocker
import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from agentsec_evidence.benchmarks import attempts, dependency_evidence, dependency_plan
from agentsec_evidence.benchmarks.attempt_models import DependencyProgress
from agentsec_evidence.benchmarks.dependency_evidence import verify_dependency_attempt
from agentsec_evidence.benchmarks.models import (
    DependencyBenchmarkPlan,
    DependencyCaseId,
    DependencyPreview,
)
from agentsec_evidence.benchmarks.service import load_plan, plan_bytes, validate_plan
from agentsec_evidence.cli.app import app
from agentsec_evidence.core.identity import sha256_file
from agentsec_evidence.core.time import utc_now
from agentsec_evidence.dependencies import pipeline
from agentsec_evidence.dependencies.analysis import dependency_semantic_hash
from agentsec_evidence.dependencies.database import FrozenDatabase, inspect_database
from agentsec_evidence.dependencies.models import DependencyScope, StageEvidence
from agentsec_evidence.execution.process import ProcessCapture

REPO = Path(__file__).resolve().parents[2]
DB = "workspace/database.zip"


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
    monkeypatch: pytest.MonkeyPatch, project: Path, *, mode: str = "findings"
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
        return ProcessCapture(
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
