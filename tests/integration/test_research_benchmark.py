"""Ledger/verifier integration with synthetic processes, not native scanner measurements."""

from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path
from typing import Any

import pytest
from test_controlled_research_runner import ROOT, setup_case
from test_research_reporting import matrix, seal

from agentsec_evidence.benchmarks import attempts, research_plan
from agentsec_evidence.benchmarks.attempt_models import ResearchProgress
from agentsec_evidence.benchmarks.models import ResearchBenchmarkPlan, ResearchPreview
from agentsec_evidence.benchmarks.research_evidence import verify_research_attempt
from agentsec_evidence.benchmarks.service import load_plan, plan_bytes, validate_plan
from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.core.io import atomic_write_bytes, json_bytes
from agentsec_evidence.research import controlled


@pytest.fixture
def prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, list[list[str]]]:
    project, rules, _, template, calls, _ = setup_case(tmp_path, monkeypatch, "defaults")
    for name in ("pyproject.toml", "uv.lock"):
        atomic_write_bytes(project / name, (ROOT / name).read_bytes())
    # Keep the real 68-rule shape but substitute inert bytes in this test-only admission.
    profile = json.loads((ROOT / controlled.PROFILE_PATH).read_bytes())
    fake = b"synthetic rule evidence, never executed"
    for rule in profile["rules"]:
        rule["sha256"] = sha256_bytes(fake)
        atomic_write_bytes(rules / rule["source_path"], fake)
    profile["source_license_sha256"] = sha256_file(rules / "LICENSE")
    atomic_write_bytes(project / controlled.PROFILE_PATH, json_bytes(profile))
    monkeypatch.setitem(
        controlled.ADMITTED_PINS,
        controlled.PROFILE_PATH,
        sha256_file(project / controlled.PROFILE_PATH),
    )
    monkeypatch.setattr(research_plan, "ADMITTED_PINS", controlled.ADMITTED_PINS)
    original = vars(controlled)["run_bounded_process"]
    templates = {"defaults": template}

    def capture(argv: list[str], **kwargs: Any) -> Any:
        for i, item in enumerate(argv):
            if i and argv[i - 1] == "--mount" and "target=/output" in item:
                output = Path(item.split(",source=", 1)[1].split(",target=", 1)[0])
                case_id = output.parent.name
                if case_id not in templates:
                    templates[case_id] = matrix(tmp_path / ("native-" + case_id), case_id)
                for name in ("native.json", "native.sarif"):
                    data = (templates[case_id] / output.name / name).read_bytes()
                    atomic_write_bytes(template / output.name / name, data)
        return original(argv, **kwargs)

    monkeypatch.setattr(controlled, "run_bounded_process", capture)
    plan = research_plan.build_research_plan(
        project, plan_id="controlled-test", rule_source="workspace/rules"
    )
    path = project / "workspace/plan.json"
    path.write_bytes(plan_bytes(plan))
    return project, path, calls


def test_validation_is_offline_and_preserves_original_case_units(prepared: Any) -> None:
    project, path, calls = prepared
    plan, dry = load_plan(path), validate_plan(project, path)
    assert isinstance(plan, ResearchBenchmarkPlan) and isinstance(dry, ResearchPreview)
    assert len(plan.pins) == 6 and len(plan.rule_files) == 69 and len(dry.cells) == 15
    assert [c.case_id for c in dry.cells] == [
        c["id"] for c in json.loads((ROOT / controlled.REGISTRY_PATH).read_bytes())["cases"]
    ]
    assert [c.case_id for c in dry.cells if c.internal_repetitions == 2] == ["defaults", "inline"]
    assert not calls and not dry.execution_authorized
    assert not (project / "workspace/benchmarks").exists()


def test_serial_resume_reopens_all_evidence_and_does_not_rescan(prepared: Any) -> None:
    project, path, calls = prepared
    partial = attempts.run_benchmark(project, path, max_new_cells=3)
    assert isinstance(partial, ResearchProgress)
    assert partial.newly_attempted_cells == 3 and not partial.workflow_complete
    complete = attempts.run_benchmark(project, path)
    assert isinstance(complete, ResearchProgress)
    assert complete.workflow_complete and not complete.blocked and not complete.analysis_complete
    assert complete.newly_attempted_cells == 12 and complete.reused_verified_cells == 3
    assert sum(c.scanner_invocations or 0 for c in complete.cells) == 20
    assert sum(c.syntax_invocations or 0 for c in complete.cells) == 9
    assert sum(c.state == "refused" for c in complete.cells) == 7
    assert all(c.finding_records is None for c in complete.cells)
    before = {p: sha256_file(p) for p in Path(complete.session).rglob("*") if p.is_file()}
    count = len(calls)
    reused = attempts.run_benchmark(project, path)
    status = attempts.inspect_benchmark(project, path)
    assert reused.newly_attempted_cells == 0 and reused.reused_verified_cells == 15
    assert status.workflow_complete and len(calls) == count == 29
    assert before == {p: sha256_file(p) for p in before}


@pytest.mark.parametrize(
    "change",
    [
        "order",
        "duplicate",
        "expectation",
        "repeat",
        "split",
        "rule",
        "source",
        "config",
        "environment",
        "family",
    ],
)
def test_changed_admission_refused_before_launch(prepared: Any, change: str) -> None:
    project, path, calls = prepared
    plan = json.loads(path.read_bytes())
    if change == "order":
        plan["cases"].reverse()
    elif change == "duplicate":
        plan["cases"][1] = plan["cases"][0]
    elif change == "expectation":
        plan["cases"][0]["case_sha256"] = "0" * 64
    elif change == "repeat":
        plan["repetitions"] = 2
    elif change == "split":
        plan["split"] = "held-out"
    elif change == "family":
        plan["source_family"] = "public-pilot"
    else:
        target = {
            "rule": project / "workspace/rules/LICENSE",
            "source": project / "src/agentsec_evidence/agents/worker.py",
            "config": project / controlled.EXECUTION_PATH,
            "environment": project / "uv.lock",
        }[change]
        target.write_bytes(target.read_bytes() + b"\n")
    path.write_bytes(json_bytes(plan))
    with pytest.raises(ValueError):
        attempts.run_benchmark(project, path)
    assert not calls and not (project / "workspace/benchmarks").exists()


@pytest.mark.parametrize("failure", ["exception", "interrupt", "cleanup", "timeout"])
def test_failed_attempt_blocks_resume_without_retry(
    prepared: Any, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    project, path, calls = prepared
    original = vars(controlled)["run_bounded_process"]

    def broken(*args: Any, **kwargs: Any) -> Any:
        if failure == "exception":
            raise RuntimeError("private exception text")
        if failure == "interrupt":
            raise KeyboardInterrupt
        result = original(*args, **kwargs)
        return dataclasses.replace(result, timed_out=True) if failure == "timeout" else result

    monkeypatch.setattr(controlled, "run_bounded_process", broken)
    if failure == "cleanup":
        monkeypatch.setattr(controlled, "cleanup_container", lambda **_: False)
    if failure == "interrupt":
        with pytest.raises(KeyboardInterrupt):
            attempts.run_benchmark(project, path)
    else:
        assert attempts.run_benchmark(project, path).blocked
    count = len(calls)
    status = attempts.run_benchmark(project, path)
    assert status.blocked and status.newly_attempted_cells == 0 and len(calls) == count
    finish = next(Path(status.session).glob("attempts/*/finish.json"))
    assert b"private exception text" not in finish.read_bytes()
    assert status.cells[0].state == (
        "interrupted" if failure == "interrupt" else "execution-failed"
    )
    with pytest.raises(ValueError, match="manual retry"):
        assert status.cells[0].attempt_id is not None
        attempts.retry_benchmark(
            project,
            path,
            attempt_id=status.cells[0].attempt_id,
            cause="docker-unavailable-before-launch",
            remediation="docker-command-availability-restored",
        )


def mutate_capture(root: Path, prefix: str, change: str) -> None:
    command = json.loads((root / prefix / "command.json").read_bytes())
    if change == "network":
        command["argv"][command["argv"].index("--network") + 1] = "bridge"
    else:
        index = command["argv"].index("--mount") + 1
        command["argv"][index] = command["argv"][index].replace("source=", "source=unrelated-", 1)
    process = json.loads((root / prefix / "execution.json").read_bytes())
    process["argv"] = command["argv"]
    (root / prefix / "command.json").write_bytes(json_bytes(command))
    (root / prefix / "execution.json").write_bytes(json_bytes(process))


@pytest.mark.parametrize(
    "change",
    [
        "native",
        "mount",
        "network",
        "syntax-mount",
        "cleanup",
        "worker",
        "environment",
        "registry",
        "extra-case",
        "run-id",
    ],
)
def test_resealed_or_changed_evidence_is_not_reusable(prepared: Any, change: str) -> None:
    project, path, calls = prepared
    progress = attempts.run_benchmark(project, path, max_new_cells=1)
    attempt = next(Path(progress.session).glob("attempts/*"))
    root = attempt / "execution/case"
    if change in {"mount", "network", "syntax-mount"}:
        mutate_capture(
            root, "defaults/syntax" if change == "syntax-mount" else "defaults/research-1", change
        )
    elif change == "cleanup":
        (root / "defaults/research-1/cleanup.json").write_bytes(json_bytes({"succeeded": False}))
    elif change == "extra-case":
        atomic_write_bytes(root / "other-case/extra.json", b"{}")
    elif change != "run-id":
        target = {
            "native": root / "defaults/research-1/native.json",
            "worker": root / "worker-source/agentsec_evidence/agents/worker.py",
            "environment": attempt / "execution/environment/uv.lock",
            "registry": root / "cases.json",
        }[change]
        target.write_bytes(target.read_bytes() + b"\n")
    seal(root)
    plan, dry = load_plan(path), validate_plan(project, path)
    assert isinstance(plan, ResearchBenchmarkPlan) and isinstance(dry, ResearchPreview)
    # Recompute the claimed run identity so this tests replay, not just the outer ledger hash.
    from agentsec_evidence.core.identity import semantic_hash

    run_id = (
        "research-"
        + semantic_hash(
            {"manifest": sha256_file(root / "evidence-manifest.json"), "case": "defaults"}
        )[:32]
    )
    if change == "run-id":
        run_id = "research-" + "0" * 32
    with pytest.raises(ValueError):
        verify_research_attempt(project, attempt / "execution", run_id, plan, dry.cells[0])
    before = len(calls)
    with pytest.raises(ValueError):
        attempts.run_benchmark(project, path)
    assert len(calls) == before


def test_hard_linked_rules_are_rejected(prepared: Any) -> None:
    project, path, calls = prepared
    os.link(project / "workspace/rules/LICENSE", project / "license-alias")
    with pytest.raises(ValueError, match="hard-linked"):
        attempts.run_benchmark(project, path)
    assert not calls


def test_writer_lock_prevents_duplicate_dispatch(prepared: Any) -> None:
    import portalocker

    project, path, calls = prepared
    root = project / "workspace/benchmarks"
    root.mkdir()
    with (
        portalocker.Lock(str(root / ".writer.lock"), mode="a+", timeout=0),
        pytest.raises(ValueError, match="writer is active"),
    ):
        attempts.run_benchmark(project, path)
    assert not calls


def test_repinning_changed_expectations_does_not_grant_admission(prepared: Any) -> None:
    project, _, calls = prepared
    target = project / controlled.REGISTRY_PATH
    registry = json.loads(target.read_bytes())
    registry["cases"][0]["gate"] = "syntax-refused"
    target.write_bytes(json_bytes(registry))
    with pytest.raises(ValueError, match="re-pinning"):
        research_plan.build_research_plan(project, plan_id="new-id", rule_source="workspace/rules")
    assert not calls


def test_missing_finish_is_interrupted_not_recovered(prepared: Any) -> None:
    project, path, calls = prepared
    progress = attempts.run_benchmark(project, path, max_new_cells=1)
    finish = next(Path(progress.session).glob("attempts/*/finish.json"))
    finish.unlink()
    count = len(calls)
    status = attempts.run_benchmark(project, path)
    assert status.blocked and status.cells[0].state == "interrupted"
    assert status.cells[0].finding_records is None and len(calls) == count


def test_missing_detector_hits_do_not_fail_execution(
    prepared: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, path, _ = prepared
    original = vars(controlled)["run_bounded_process"]

    def no_hits(argv: list[str], **kwargs: Any) -> Any:
        result = original(argv, **kwargs)
        for i, item in enumerate(argv):
            if i and argv[i - 1] == "--mount" and "target=/output" in item:
                output = Path(item.split(",source=", 1)[1].split(",target=", 1)[0])
                native = json.loads((output / "native.json").read_bytes())
                sarif = json.loads((output / "native.sarif").read_bytes())
                native["results"] = []
                sarif["runs"][0]["results"] = []
                (output / "native.json").write_bytes(json_bytes(native))
                (output / "native.sarif").write_bytes(json_bytes(sarif))
        return result

    monkeypatch.setattr(controlled, "run_bounded_process", no_hits)
    result = attempts.run_benchmark(project, path, max_new_cells=1)
    assert isinstance(result, ResearchProgress) and not result.blocked
    row = result.cells[0]
    assert row.state == "partial-analysis" and row.rows is not None
    assert all(p.finding_records == 0 for p in row.rows)


def test_cli_validation_and_status_launch_nothing(prepared: Any) -> None:
    from typer.testing import CliRunner

    from agentsec_evidence.cli.app import app

    project, path, calls = prepared
    for command in ("validate", "dry-run", "status"):
        result = CliRunner().invoke(
            app, ["benchmark", command, str(path), "--project-root", str(project)]
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)
    assert not calls and not (project / "workspace/benchmarks").exists()


def test_generated_research_schemas_match_models() -> None:
    from agentsec_evidence.benchmarks.attempt_models import ResearchFinish

    for name, model in (
        ("plan", ResearchBenchmarkPlan),
        ("dry-run", ResearchPreview),
        ("attempt-finish", ResearchFinish),
        ("progress", ResearchProgress),
    ):
        assert (
            json.loads((ROOT / f"schemas/benchmark-research-v1/{name}.schema.json").read_bytes())
            == model.model_json_schema()
        )
