from __future__ import annotations

import dataclasses
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from agentsec_evidence.agents.records import AgentInputRequest, verify_input_report
from agentsec_evidence.agents.worker import validate_view
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.core.io import atomic_write_bytes, model_bytes
from agentsec_evidence.execution.process import ProcessCapture
from agentsec_evidence.models.contracts import InventoryEntry
from agentsec_evidence.pilot import qdrant, qdrant_stages
from agentsec_evidence.pilot.inputs import PLAN_PATH, load_plan
from agentsec_evidence.pilot.models import PilotPlan
from agentsec_evidence.pilot.qdrant_inputs import (
    PINS,
    REVISION,
    bind,
    equivalent_python_requests,
    verify_pins,
)
from agentsec_evidence.pilot.qdrant_stages import QdrantRow, planned_rows, repeatability
from agentsec_evidence.pilot.runner import load, ready_capture, save
from agentsec_evidence.pilot.validation import verify_seal

PROJECT = Path(__file__).resolve().parents[2]


def capture(argv: list[str]) -> ProcessCapture:
    now = datetime(2026, 10, 18, tzinfo=UTC)
    return ProcessCapture(tuple(argv), now, now, 10, 0, b"{}", b"", False, False, False, False, 0)


def observed() -> list[QdrantRow]:
    return [
        QdrantRow(
            **{
                **r.model_dump(),
                "state": "partial",
                "duration_ns": 10,
                "exit_code": 0,
                "evidence": "native.json",
                "semantic_sha256": semantic_hash(r.stage),
            }
        )
        for r in planned_rows()
    ]


def test_new_contract_does_not_widen_old_admission() -> None:
    verify_pins(PROJECT)
    assert load_plan(PROJECT).expected_files == 47
    data = load(PROJECT / PLAN_PATH)
    data["revision"] = REVISION
    with pytest.raises(ValueError):
        PilotPlan.model_validate(data)
    assert len(planned_rows()) == 21
    assert {r.stage for r in planned_rows()} >= {"agent-python", "agent-mcp"}
    assert qdrant.report_base()["coverage"]["inventory_files"] == 34
    assert qdrant.report_base()["vulnerability_total"] is None


@pytest.mark.parametrize("pin", list(PINS))
def test_changed_pins_fail_closed(tmp_path: Path, pin: str) -> None:
    for name in PINS:
        destination = tmp_path / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(PROJECT / name, destination)
    (tmp_path / pin).write_bytes(b"changed")
    with pytest.raises(ValueError, match="pin changed"):
        verify_pins(tmp_path)


@pytest.mark.parametrize(
    "field",
    [
        "finding_records",
        "package_identities",
        "duration_ns",
        "exit_code",
        "semantic_sha256",
        "evidence",
    ],
)
def test_unrun_is_unknown_not_zero(field: str) -> None:
    value = "a" * 64 if field == "semantic_sha256" else "native.json" if field == "evidence" else 0
    with pytest.raises(ValueError, match="Unexecuted"):
        QdrantRow.model_validate({**planned_rows()[0].model_dump(), field: value})
    assert b"unknown" in qdrant.table_bytes(planned_rows())


@pytest.mark.parametrize(
    "field,value",
    [
        ("duration_ns", None),
        ("semantic_sha256", None),
        ("exit_code", None),
        ("evidence", None),
        ("evidence", "../outside"),
        ("unit", "package-identities"),
    ],
)
def test_observed_rows_need_bound_evidence(field: str, value: Any) -> None:
    with pytest.raises(ValueError):
        QdrantRow.model_validate({**observed()[0].model_dump(), field: value})


def test_repeatability_preserves_stage_boundaries_and_missing_data() -> None:
    rows = observed()
    assert all(repeatability(rows).values())
    rows[-1] = rows[-1].model_copy(update={"semantic_sha256": "f" * 64})
    assert repeatability(rows)["osv-sbom"] is False
    rows[-1] = rows[-1].model_copy(update={"state": "failed"})
    assert repeatability(rows)["osv-sbom"] is None
    assert all(v is None for v in repeatability(planned_rows()).values())
    for invalid in (rows[:-1], [*rows, rows[0]], list(reversed(rows))):
        with pytest.raises(ValueError):
            repeatability(invalid)


def test_order_equivalence_does_not_rebind_worker_response(tmp_path: Path) -> None:
    entries = []
    for name in ("z.py", "a.py"):
        raw = b"x = 1\n"
        (tmp_path / name).write_bytes(raw)
        entries.append(
            InventoryEntry(
                path=name,
                sha256=sha256_bytes(raw),
                byte_length=len(raw),
                media_type="text/x-python",
            )
        )
    left = AgentInputRequest(
        target_snapshot_id="test-snapshot",
        inventory=entries,
        selected={e.path: "python-source" for e in entries},
    )
    right = left.model_copy(update={"inventory": list(reversed(entries))})
    assert left != right and equivalent_python_requests(left, right)
    raw = model_bytes(left)
    report = validate_view(tmp_path, raw)
    verify_input_report(report, left, raw)
    with pytest.raises(ValueError):
        verify_input_report(report, right, model_bytes(right))
    changed = right.model_copy(update={"target_snapshot_id": "other"})
    assert not equivalent_python_requests(left, changed)
    changed = right.model_copy(update={"inventory": [entries[0]]})
    assert not equivalent_python_requests(left, changed)


def test_replay_bind_is_read_only(tmp_path: Path) -> None:
    path = tmp_path / "result.json"
    bind(path, {"state": "partial"}, write=True)
    before = path.read_bytes()
    bind(path, {"state": "partial"}, write=False)
    with pytest.raises(ValueError, match="derivative differs"):
        bind(path, {"state": "complete"}, write=False)
    assert path.read_bytes() == before


def test_capture_replay_checks_exact_command_without_invoking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    argv = ["docker", "run", "--network", "none"]
    result = capture(argv)
    record = dataclasses.asdict(result)
    del record["stdout"], record["stderr"]
    save(tmp_path / "process.json", record)
    save(tmp_path / "command.json", {"argv": argv, "target_execution": False})
    save(tmp_path / "cleanup.json", {"succeeded": True})
    atomic_write_bytes(tmp_path / "stdout.bin", result.stdout)
    atomic_write_bytes(tmp_path / "stderr.bin", result.stderr)
    monkeypatch.setattr(
        qdrant_stages, "invoke", lambda *a, **kw: pytest.fail("replay executed a tool")
    )
    replayed, clean = qdrant_stages.stage_capture(
        argv, tmp_path, write=False, project=tmp_path, environment={}
    )
    assert clean and replayed == result
    with pytest.raises(ValueError, match="invocation differs"):
        qdrant_stages.stage_capture(
            [*argv, "--privileged"], tmp_path, write=False, project=tmp_path, environment={}
        )


@pytest.mark.parametrize(
    "field", ["timed_out", "output_limited", "stdout_truncated", "stderr_truncated"]
)
def test_failed_capture_is_not_clean(field: str) -> None:
    failed = dataclasses.replace(
        capture(["docker"]),
        timed_out=field == "timed_out",
        output_limited=field == "output_limited",
        stdout_truncated=field == "stdout_truncated",
        stderr_truncated=field == "stderr_truncated",
    )
    assert not ready_capture(failed, True, {0})


def test_preparation_failure_is_sealed_without_scanners(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    parent = project / "workspace"
    parent.mkdir(parents=True)
    cache, rules = tmp_path / "cache", tmp_path / "rules"
    cache.mkdir()
    rules.mkdir()
    database = tmp_path / "database/db.zip"
    database.parent.mkdir()
    database.write_bytes(b"not a database")
    output = parent / "attempt-01"
    monkeypatch.setattr(qdrant, "resolve_docker", lambda _: Path("docker"))
    monkeypatch.setattr(
        qdrant, "run_bounded_process", lambda *a, **kw: pytest.fail("unexpected scanner")
    )
    monkeypatch.setattr(
        qdrant, "prepare_qdrant", lambda *a, **kw: (_ for _ in ()).throw(ValueError("gate refused"))
    )
    with pytest.raises(ValueError, match="gate refused"):
        qdrant.run_qdrant_pilot(
            project=project, cache=cache, rules=rules, database=database, output=output
        )
    report = json.loads((output / qdrant.REPORT).read_bytes())
    assert report["instrument_finished"] is False
    assert all(row["state"] == "not-run" for row in report["rows"])
    assert all(value is None for value in report["repeatability"].values())
    assert verify_seal(output) == 2
    with pytest.raises(ValueError):
        qdrant.run_qdrant_pilot(
            project=project, cache=cache, rules=rules, database=database, output=output
        )


def test_table_separates_units_and_nulls() -> None:
    data = qdrant.table_bytes(observed()).decode()
    assert "agent-python" in data and "agent-mcp" in data
    assert "package-advisory-occurrences" in data and "native-rule-reports" in data
    assert "unknown" in data
