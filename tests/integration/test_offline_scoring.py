from __future__ import annotations

import json
import runpy
import socket
import subprocess
import sys
from pathlib import Path

import pytest
from test_semgrep_benchmark import fake_producer, plan_file, tree
from test_semgrep_benchmark import project as project
from typer.testing import CliRunner

from agentsec_evidence.benchmarks import attempts
from agentsec_evidence.cli.app import app
from agentsec_evidence.core.identity import sha256_file
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.scoring.models import ScorePlan, SessionInput
from agentsec_evidence.scoring.service import calculate_scores, validate_scores, write_scores


def scoring_plan(project: Path, session: Path) -> Path:
    plan = ScorePlan(
        sessions=(
            SessionInput(
                session=session.name,
                plan_sha256=sha256_file(session / "plan.json"),
                validation_sha256=sha256_file(session / "validation.json"),
                role="development",
            ),
        ),
        selection_rationale=(
            "Synthetic retained-session integration tests, not real scanner measurements"
        ),
        exclusions=(),
    )
    path = project / "workspace/scoring-plan.json"
    path.write_bytes(json_bytes(plan.model_dump(mode="json")))
    return path


def no_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("Offline scoring attempted process or network access")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(attempts, "run_semgrep_scan", forbidden)


def test_frozen_history_after_source_change_is_offline_and_deterministic(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_producer(monkeypatch, project)
    original_plan = plan_file(project)
    result = attempts.run_benchmark(project, original_plan)
    session = Path(result.session)
    before = tree(session)
    plan = scoring_plan(project, session)
    (project / "src/test_identity.py").write_bytes(b"# Changed scoring-era implementation.\n")
    with pytest.raises(ValueError):
        attempts.inspect_benchmark(project, original_plan)
    no_execution(monkeypatch)
    first = write_scores(project, plan, project / "workspace/score-1")
    second = write_scores(project, plan, project / "workspace/score-2")
    assert first == second and tree(project / "workspace/score-1") == tree(
        project / "workspace/score-2"
    )
    assert validate_scores(project, project / "workspace/score-1", replay=True)["passed"]
    assert tree(session) == before
    assert first.vulnerability_total is None and first.public_detection_accuracy is None
    repeat = next(r for r in first.rows if r.stage == "case-repeatability")
    assert repeat.metrics[0].value == 1
    source_row = next(r for r in first.rows if r.stage == "semgrep")
    agreement = next(m for m in source_row.metrics if m.name == "finite-rule-path-agreement")
    assert (agreement.numerator, agreement.denominator) == (2, 2)


@pytest.mark.parametrize("fixture", ["clean.json", "finding-with-error.json", "malformed.json"])
def test_incomplete_and_clean_states_not_accuracy_labels(
    project: Path, monkeypatch: pytest.MonkeyPatch, fixture: str
) -> None:
    fake_producer(monkeypatch, project, fixture)
    result = attempts.run_benchmark(project, plan_file(project))
    plan = scoring_plan(project, Path(result.session))
    no_execution(monkeypatch)
    scores = calculate_scores(project, plan)
    assert scores.attempts[0]["state"] == result.cells[0].state
    assert scores.public_detection_accuracy is None
    if fixture == "malformed.json":
        assert scores.attempts[0]["finding_records"] is None
        assert scores.attempts[1]["state"] == "not-attempted"


@pytest.mark.parametrize(
    "path", ["plan.json", "validation.json", "start.json", "finish.json", "native"]
)
def test_protected_evidence_mutation_rejected(
    project: Path, monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    fake_producer(monkeypatch, project)
    result = attempts.run_benchmark(project, plan_file(project, 1))
    session = Path(result.session)
    plan = scoring_plan(project, session)
    if path in {"plan.json", "validation.json"}:
        target = session / path
    elif path == "native":
        target = next(session.glob("**/native/semgrep.json"))
    else:
        target = next(session.glob("attempts/*/" + path))
    target.write_bytes(target.read_bytes() + b" ")
    no_execution(monkeypatch)
    with pytest.raises(ValueError):
        calculate_scores(project, plan)


def test_score_derivative_and_cli(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_producer(monkeypatch, project)
    result = attempts.run_benchmark(project, plan_file(project, 1))
    plan = scoring_plan(project, Path(result.session))
    no_execution(monkeypatch)
    output = project / "workspace/scored"
    runner = CliRunner()
    response = runner.invoke(
        app, ["score", "build", str(plan), "--output", str(output), "--project-root", str(project)]
    )
    assert response.exit_code == 0, response.output
    response = runner.invoke(
        app, ["score", "validate", str(output), "--replay", "--project-root", str(project)]
    )
    assert response.exit_code == 0, response.output
    with pytest.raises(ValueError):
        write_scores(project, plan, output)
    (output / "measurements.csv").write_bytes(b"wrong table\n")
    with pytest.raises(ValueError):
        validate_scores(project, output)


def test_session_role_cannot_be_relabelled_as_pilot(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_producer(monkeypatch, project)
    result = attempts.run_benchmark(project, plan_file(project, 1))
    plan = scoring_plan(project, Path(result.session))
    payload = json.loads(plan.read_bytes())
    payload["sessions"][0]["role"] = "formative-pilot"
    plan.write_bytes(json_bytes(payload))
    with pytest.raises(ValueError, match="Evidence role"):
        calculate_scores(project, plan)


def test_export_rubric_detects_an_incorrect_field(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agentsec_evidence.operations.offline import load_existing_run
    from agentsec_evidence.scoring.measurements import finding_fields

    fake_producer(monkeypatch, project)
    result = attempts.run_benchmark(project, plan_file(project, 1))
    execution = next(Path(result.session).glob("attempts/*/execution"))
    existing = load_existing_run(execution, result.cells[0].run_id or "")
    root = execution / "runs" / (result.cells[0].run_id or "")
    sarif = json.loads((root / "exports/results.sarif").read_bytes())["runs"][0]
    sarif["results"][0]["properties"]["agentsecEvidence/jsonPointer"] = "/wrong"
    _, detail = finding_fields(list(existing.findings), sarif)
    assert any(s.endswith(":json-pointer") for s in detail["field_rubric"]["incorrect"])


def test_forged_table_even_with_resealed_manifest_fails(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_producer(monkeypatch, project)
    result = attempts.run_benchmark(project, plan_file(project, 1))
    plan = scoring_plan(project, Path(result.session))
    output = project / "workspace/scored"
    write_scores(project, plan, output)
    target = output / "attempts.csv"
    target.write_bytes(b"not the generated table\n")
    manifest = json.loads((output / "scoring-manifest.json").read_bytes())
    for entry in manifest["entries"]:
        if entry["path"] == target.name:
            entry.update(sha256=sha256_file(target), bytes=target.stat().st_size)
    (output / "scoring-manifest.json").write_bytes(json_bytes(manifest))
    with pytest.raises(ValueError, match="Tables differ"):
        validate_scores(project, output)


@pytest.mark.parametrize(
    "marker", ["scoring-manifest.json", "review-manifest.json", "validation.json"]
)
def test_unselected_protected_destination_is_not_modified(project: Path, marker: str) -> None:
    unrelated = project / "workspace/unselected-evidence"
    unrelated.mkdir()
    (unrelated / marker).write_bytes(b"{}")
    plan = scoring_plan(project, _dummy_session(project))
    before = tree(unrelated)
    with pytest.raises(ValueError, match="finalized evidence"):
        write_scores(project, plan, unrelated / "new-output")
    assert tree(unrelated) == before


def _dummy_session(project: Path) -> Path:
    session = project / "workspace/benchmarks" / ("0" * 64)
    session.mkdir(parents=True)
    for name in ("plan.json", "validation.json"):
        (session / name).write_bytes(b"{}")
    return session


@pytest.mark.parametrize(
    "marker",
    [
        "scoring-manifest.json",
        "review-manifest.json",
        "validation.json",
        "report-manifest.json",
        "bundle-manifest.json",
        "evidence-manifest.json",
    ],
)
def test_plan_helper_refuses_protected_destination_before_reading_session(
    project: Path, monkeypatch: pytest.MonkeyPatch, marker: str
) -> None:
    protected = project / "workspace/protected"
    protected.mkdir()
    (protected / marker).write_bytes(b"{}")
    output = protected / "plan-copy.json"
    before = tree(protected)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "prepare_scoring_plan",
            "--project-root",
            str(project),
            "--session",
            "0" * 64,
            "--rationale",
            "Explicit bounded test selection",
            "--output",
            str(output),
        ],
    )
    script = Path(__file__).resolve().parents[2] / "tools/prepare_scoring_plan.py"
    with pytest.raises(ValueError, match="finalized evidence"):
        runpy.run_path(str(script), run_name="__main__")
    assert tree(protected) == before


def test_plan_helper_writes_new_workspace_plan(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_producer(monkeypatch, project)
    result = attempts.run_benchmark(project, plan_file(project, 1))
    output = project / "workspace/prepared-scoring.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "prepare_scoring_plan",
            "--project-root",
            str(project),
            "--session",
            Path(result.session).name,
            "--rationale",
            "Explicit bounded test selection",
            "--output",
            str(output),
        ],
    )
    script = Path(__file__).resolve().parents[2] / "tools/prepare_scoring_plan.py"
    runpy.run_path(str(script), run_name="__main__")
    plan = ScorePlan.model_validate_json(output.read_bytes())
    assert plan.sessions[0].session == Path(result.session).name
    before = output.read_bytes()
    with pytest.raises(ValueError, match="new and outside"):
        runpy.run_path(str(script), run_name="__main__")
    assert output.read_bytes() == before
