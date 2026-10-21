from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import portalocker
import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from agentsec_evidence.benchmarks import attempts, dependency_plan, public_pilot_plan
from agentsec_evidence.benchmarks.attempt_models import PublicPilotEvidence, PublicPilotProgress
from agentsec_evidence.benchmarks.models import PublicPilotBenchmarkPlan, PublicPilotPreview
from agentsec_evidence.benchmarks.service import load_plan, plan_bytes, validate_plan
from agentsec_evidence.cli.app import app
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes, sha256_file
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.pilot.inputs import PLAN_PATH, PROFILE_PATH, SPEC_PATH
from agentsec_evidence.pilot.models import planned_rows

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Synthetic resources test governance only; production pins are not changed on disk."""
    admitted = json.loads((ROOT / PLAN_PATH).read_bytes())
    for relative in {*admitted["pins"], *public_pilot_plan.EXTRA_PINS, PLAN_PATH}:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, path)
    code = tmp_path / "src/example.py"
    code.parent.mkdir()
    code.write_text("# Synthetic implementation binding\n")
    spec = json.loads((tmp_path / SPEC_PATH).read_bytes())
    for name, field in (
        ("commit.json", "commit_response_sha256"),
        ("tree-exact.json", "tree_response_sha256"),
        ("source.zip", "archive_sha256"),
    ):
        path = tmp_path / "workspace/cache" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"synthetic-" + name.encode())
        spec[field] = sha256_file(path)
    (tmp_path / SPEC_PATH).write_bytes(json_bytes(spec))
    profile = json.loads((tmp_path / PROFILE_PATH).read_bytes())
    for rule in profile["rules"]:
        path = tmp_path / "workspace/rules" / rule["source_path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"synthetic rule")
        rule["sha256"] = sha256_file(path)
    license_path = tmp_path / "workspace/rules/LICENSE"
    license_path.write_bytes(b"synthetic license")
    profile["source_license_sha256"] = sha256_file(license_path)
    (tmp_path / PROFILE_PATH).write_bytes(json_bytes(profile))
    for path in (SPEC_PATH, PROFILE_PATH):
        admitted["pins"][path] = sha256_file(tmp_path / path)
    (tmp_path / PLAN_PATH).write_bytes(json_bytes(admitted))
    monkeypatch.setattr(public_pilot_plan, "PILOT_SHA256", sha256_file(tmp_path / PLAN_PATH))
    database = tmp_path / "workspace/database.zip"
    database.write_bytes(b"synthetic frozen database")
    monkeypatch.setattr(dependency_plan, "DATABASE_SHA256", sha256_file(database))
    return tmp_path


def prepared(project: Path) -> Path:
    path = project / "workspace/plan.json"
    plan = public_pilot_plan.build_public_pilot_plan(
        project,
        plan_id="pilot-test",
        cache_path="workspace/cache",
        rule_source="workspace/rules",
        database="workspace/database.zip",
    )
    path.write_bytes(plan_bytes(plan))
    return path


def tree(path: Path) -> dict[str, str]:
    return {p.relative_to(path).as_posix(): sha256_file(p) for p in path.rglob("*") if p.is_file()}


def synthetic_producer(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    calls: list[Path] = []

    def run(**kwargs: Any) -> dict[str, Any]:
        output = kwargs["output"]
        output.mkdir()
        (output / "evidence-manifest.json").write_bytes(b"synthetic evidence")
        calls.append(output)
        return {"instrument_finished": True}

    def verify(project: Path, execution: Path, run_id: str, *_args: Any) -> PublicPilotEvidence:
        raw = (execution / "pilot/evidence-manifest.json").read_bytes()
        if raw != b"synthetic evidence":
            raise ValueError("Altered synthetic evidence")
        rows = tuple(
            row.model_copy(
                update={
                    "state": "partial",
                    "reasons": ("synthetic",),
                    "evidence": ("synthetic.json",),
                }
            )
            for row in planned_rows()
        )
        return PublicPilotEvidence(
            run_id=run_id,
            manifest_sha256=sha256_bytes(raw),
            semantic_sha256=semantic_hash([]),
            rows=rows,
        )

    monkeypatch.setattr(attempts, "run_source_pilot", run)
    monkeypatch.setattr(attempts, "verify_public_pilot_attempt", verify)
    return calls


def test_preview_is_offline_separate_role_and_single_whole_attempt(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(attempts, "run_source_pilot", lambda **_kw: pytest.fail("unexpected scan"))
    path = prepared(project)
    plan = load_plan(path)
    assert isinstance(plan, PublicPilotBenchmarkPlan)
    assert plan.split == "formative-pilot-not-held-out" and plan.internal_repetitions == 3
    dry = validate_plan(project, path)
    assert isinstance(dry, PublicPilotPreview) and len(dry.cells) == 1
    assert dry == validate_plan(project, path)
    result = attempts.inspect_benchmark(project, path)
    assert isinstance(result, PublicPilotProgress)
    assert result.cells[0].rows is None and result.cells[0].scanner_invocations is None
    assert not (project / "workspace/benchmarks").exists()
    for name, model in (("plan", plan), ("dry-run", dry), ("progress", result)):
        schema = json.loads(
            (ROOT / f"schemas/benchmark-public-pilot-v1/{name}.schema.json").read_bytes()
        )
        Draft202012Validator(schema).validate(model.model_dump(mode="json"))
    cli = CliRunner().invoke(
        app, ["benchmark", "validate", str(path), "--project-root", str(project)]
    )
    assert cli.exit_code == 0, cli.output


def test_whole_pilot_reuse_no_scans_and_no_summed_findings(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = synthetic_producer(monkeypatch)
    path = prepared(project)
    first = attempts.run_benchmark(project, path)
    assert isinstance(first, PublicPilotProgress) and first.workflow_complete
    assert len(calls) == 1 and not first.analysis_complete and not first.scoring_implemented
    assert first.cells[0].state == "partial-analysis" and first.cells[0].finding_records is None
    assert first.cells[0].rows is not None and len(first.cells[0].rows) == 18
    before = tree(Path(first.session))
    again = attempts.run_benchmark(project, path)
    assert again.reused_verified_cells == 1 and again.newly_attempted_cells == 0
    assert len(calls) == 1 and before == tree(Path(first.session))
    assert attempts.inspect_benchmark(project, path).cells == first.cells
    (calls[0] / "evidence-manifest.json").write_bytes(b"changed")
    with pytest.raises(ValueError):
        attempts.run_benchmark(project, path)
    assert len(calls) == 1


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_failure_and_interruption_remain_blocked_without_retry(
    project: Path, monkeypatch: pytest.MonkeyPatch, error: type[BaseException]
) -> None:
    def fail(**kwargs: Any) -> None:
        kwargs["output"].mkdir()
        (kwargs["output"] / "failure.txt").write_text("retained")
        raise error()

    monkeypatch.setattr(attempts, "run_source_pilot", fail)
    path = prepared(project)
    if error is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt):
            attempts.run_benchmark(project, path)
    else:
        assert attempts.run_benchmark(project, path).blocked
    result = attempts.inspect_benchmark(project, path)
    assert isinstance(result, PublicPilotProgress)
    assert result.blocked and result.cells[0].rows is None
    before = tree(Path(result.session))
    monkeypatch.setattr(attempts, "run_source_pilot", lambda **_kw: pytest.fail("retry"))
    assert attempts.run_benchmark(project, path).blocked
    assert before == tree(Path(result.session))


@pytest.mark.parametrize(
    "relative",
    [
        PLAN_PATH,
        SPEC_PATH,
        PROFILE_PATH,
        "src/example.py",
        "workspace/cache/source.zip",
        "workspace/rules/LICENSE",
        "workspace/database.zip",
    ],
)
def test_changed_inputs_block_before_launch(
    project: Path, monkeypatch: pytest.MonkeyPatch, relative: str
) -> None:
    path = prepared(project)
    target = project / relative
    target.write_bytes(target.read_bytes() + b"\nchanged")
    monkeypatch.setattr(
        attempts, "run_source_pilot", lambda **_kw: pytest.fail("scan after tamper")
    )
    with pytest.raises(ValueError):
        attempts.run_benchmark(project, path)
    assert not (project / "workspace/benchmarks").exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("split", "held-out"),
        ("internal_repetitions", 1),
        ("repetitions", 2),
        ("manual_retries", 1),
        ("cache_path", "../outside"),
        ("rule_source", "workspace/benchmarks/bad"),
    ],
)
def test_scope_changes_rejected(project: Path, field: str, value: object) -> None:
    path = prepared(project)
    data = json.loads(path.read_bytes())
    data[field] = value
    path.write_bytes(json_bytes(data))
    with pytest.raises(ValueError):
        validate_plan(project, path)


def test_writer_lock_prevents_launch(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = prepared(project)
    root = project / "workspace/benchmarks"
    root.mkdir()
    monkeypatch.setattr(attempts, "run_source_pilot", lambda **_kw: pytest.fail("duplicate launch"))
    with (
        portalocker.Lock(str(root / ".writer.lock"), mode="a+", timeout=0),
        pytest.raises(ValueError, match="writer"),
    ):
        attempts.run_benchmark(project, path)
