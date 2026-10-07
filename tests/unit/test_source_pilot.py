from __future__ import annotations

import dataclasses
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from agentsec_evidence.core.identity import semantic_hash
from agentsec_evidence.execution.process import ProcessCapture
from agentsec_evidence.pilot.inputs import PLAN_PATH, load_plan
from agentsec_evidence.pilot.models import PilotPlan, PilotRow, planned_rows, repeatability
from agentsec_evidence.pilot.runner import (
    invoke,
    ready_capture,
    run_source_pilot,
    save,
    seal_attempt,
    table_bytes,
)
from agentsec_evidence.pilot.validation import read_capture, validate_source_pilot, verify_seal

ROOT = Path(__file__).resolve().parents[2]


def capture(argv: list[str]) -> ProcessCapture:
    now = datetime(2026, 10, 6, tzinfo=UTC)
    return ProcessCapture(tuple(argv), now, now, 10, 0, b"{}", b"", False, False, False, False, 0)


def test_committed_pilot_scope_and_pins() -> None:
    plan = load_plan(ROOT)
    assert len(plan.python_paths) == 26
    assert len(plan.pins) == 9
    assert plan.repetitions == 3
    assert plan.target_execution is False
    assert plan.dockerfile == "present-unsupported-not-run"


@pytest.mark.parametrize(
    "field,value",
    [
        ("repetitions", 4),
        ("revision", "0" * 40),
        ("target_execution", True),
        ("implicit_git_filtering", True),
        ("database_sha256", "0" * 64),
        ("order", ["agent-audit"]),
        ("expected_files", 26),
    ],
)
def test_plan_rejects_unapproved_treatment(field: str, value: Any) -> None:
    data = json.loads((ROOT / PLAN_PATH).read_bytes())
    data[field] = value
    with pytest.raises(ValueError):
        PilotPlan.model_validate(data)


@pytest.mark.parametrize("replacement", ["../escape.py", "A.PY", "/absolute.py"])
def test_plan_rejects_bad_selection(replacement: str) -> None:
    data = json.loads((ROOT / PLAN_PATH).read_bytes())
    data["python_paths"][0] = replacement
    with pytest.raises(ValueError):
        PilotPlan.model_validate(data)


def test_changed_pin_refused(tmp_path: Path) -> None:
    plan = load_plan(ROOT)
    for name in (*plan.pins, PLAN_PATH):
        destination = tmp_path / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
    (tmp_path / "configs/dependency/osv.toml").write_bytes(b"changed")
    with pytest.raises(ValueError, match="configuration changed"):
        load_plan(tmp_path)


@pytest.mark.parametrize(
    "key", ["finding_records", "package_identities", "duration_ns", "exit_code", "semantic_sha256"]
)
def test_unrun_never_becomes_zero_observation(key: str) -> None:
    data = planned_rows()[0].model_dump()
    data[key] = "a" * 64 if key == "semantic_sha256" else 0
    with pytest.raises(ValueError, match="Unexecuted"):
        PilotRow.model_validate(data)


def test_repeatability_and_missing_rows() -> None:
    rows = planned_rows()
    assert len(rows) == 18
    assert all(v is None for v in repeatability(rows).values())
    observed = [
        PilotRow(
            **{
                **r.model_dump(),
                "state": "partial",
                "evidence": ("native.json",),
                "semantic_sha256": semantic_hash(r.stage),
            }
        )
        for r in rows
    ]
    assert all(repeatability(observed).values())
    observed[-1] = observed[-1].model_copy(update={"semantic_sha256": "a" * 64})
    assert repeatability(observed)["osv-sbom"] is False
    with pytest.raises(ValueError, match="missing, duplicated"):
        repeatability(rows[:-1])
    assert b"unknown" in table_bytes(rows)


@pytest.mark.parametrize(
    "field", ["timed_out", "output_limited", "stdout_truncated", "stderr_truncated"]
)
def test_resource_failure_not_success(field: str) -> None:
    change: dict[str, Any] = {field: True}
    assert not ready_capture(dataclasses.replace(capture(["tool"]), **change), True, {0})


def test_exit_and_cleanup_are_separate() -> None:
    assert ready_capture(dataclasses.replace(capture(["tool"]), exit_code=1), True, {0, 1})
    assert not ready_capture(capture(["tool"]), False, {0})
    assert not ready_capture(dataclasses.replace(capture(["tool"]), exit_code=127), True, {0, 1})


def test_native_pair_monitor_and_receipts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def process(argv: list[str], **kwargs: Any) -> ProcessCapture:
        calls.append(kwargs)
        return capture(argv)

    monkeypatch.setattr("agentsec_evidence.pilot.runner.run_bounded_process", process)
    monkeypatch.setattr("agentsec_evidence.pilot.runner.cleanup_container", lambda **kw: True)
    native = tmp_path / "native"
    native.mkdir()
    result, cleaned = invoke(
        ["docker", "scan"],
        native / "capture",
        project=tmp_path,
        docker=Path("docker"),
        name="test",
        environment={},
        native_pair=True,
    )
    assert calls[0]["monitored_files"] == (native / "native.json", native / "native.sarif")
    assert calls[0]["max_generated_bytes"] == 8 * 1024**2
    assert read_capture(native / "capture") == (result, cleaned)
    with pytest.raises(FileExistsError):
        invoke(
            ["docker"],
            native / "capture",
            project=tmp_path,
            docker=Path("docker"),
            name="test",
            environment={},
        )


def test_launch_failure_retains_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: Any, **kwargs: Any) -> Any:
        raise OSError("simulated")

    monkeypatch.setattr("agentsec_evidence.pilot.runner.run_bounded_process", fail)
    monkeypatch.setattr("agentsec_evidence.pilot.runner.cleanup_container", fail)
    with pytest.raises(OSError):
        invoke(
            ["docker"],
            tmp_path / "attempt",
            project=tmp_path,
            docker=Path("docker"),
            name="test",
            environment={},
        )
    assert json.loads((tmp_path / "attempt/cleanup.json").read_bytes()) == {"succeeded": False}
    assert (tmp_path / "attempt/launch-or-capture-failure.json").is_file()


@pytest.mark.parametrize("change", ["modified", "added", "removed"])
def test_seal_tampering(tmp_path: Path, change: str) -> None:
    (tmp_path / "native.json").write_bytes(b"{}")
    seal_attempt(tmp_path)
    assert verify_seal(tmp_path) == 1
    if change == "modified":
        (tmp_path / "native.json").write_bytes(b"changed")
    elif change == "added":
        (tmp_path / "extra").write_bytes(b"extra")
    else:
        (tmp_path / "native.json").unlink()
    with pytest.raises(ValueError, match="seal differs"):
        verify_seal(tmp_path)


def test_only_root_runtime_is_excluded(tmp_path: Path) -> None:
    for relative in ("runtime/scratch", "target/runtime/source.py"):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"content")
    seal_attempt(tmp_path)
    assert verify_seal(tmp_path) == 1
    (tmp_path / "target/runtime/source.py").write_bytes(b"change")
    with pytest.raises(ValueError):
        verify_seal(tmp_path)


def test_preparation_failure_keeps_eighteen_unrun_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "workspace").mkdir()
    shutil.copytree(
        ROOT / "test_cases/pilot/langgraph-cicd", tmp_path / "test_cases/pilot/langgraph-cicd"
    )
    monkeypatch.setattr("agentsec_evidence.pilot.runner.load_plan", lambda _: load_plan(ROOT))
    monkeypatch.setattr("agentsec_evidence.pilot.runner.resolve_docker", lambda _: Path("docker"))

    def fail(*args: Any, **kwargs: Any) -> Any:
        raise ValueError("Controlled preparation refusal")

    monkeypatch.setattr("agentsec_evidence.pilot.runner.prepare_pilot_inputs", fail)
    output = tmp_path / "workspace/attempt"
    with pytest.raises(ValueError, match="preparation refusal"):
        run_source_pilot(
            project=tmp_path,
            cache=tmp_path / "cache",
            rule_source=tmp_path / "rules",
            database=tmp_path / "database/all.zip",
            output=output,
        )
    assert verify_seal(output) >= 2
    report = json.loads((output / "pilot-report.json").read_bytes())
    assert report["instrument_finished"] is False
    assert len(report["rows"]) == 18
    assert all(r["state"] == "not-run" and r["finding_records"] is None for r in report["rows"])
    with pytest.raises(ValueError, match="Only finished"):
        validate_source_pilot(ROOT, output)


def test_forged_process_command_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "agentsec_evidence.pilot.runner.run_bounded_process", lambda argv, **kw: capture(argv)
    )
    monkeypatch.setattr("agentsec_evidence.pilot.runner.cleanup_container", lambda **kw: True)
    root = tmp_path / "capture"
    invoke(
        ["docker", "scan"],
        root,
        project=tmp_path,
        docker=Path("docker"),
        name="test",
        environment={},
    )
    save(root / "command.json", {"argv": ["another"], "target_execution": False})
    with pytest.raises(ValueError, match="Command"):
        read_capture(root)
