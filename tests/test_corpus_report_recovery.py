"""Authored report/recovery tests; scanner processes are simulated, no public scans."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import portalocker
import pytest
from test_corpus_collection_driver import PROJECT, driver
from test_corpus_collection_driver import cohort as cohort

from agentsec_evidence.corpus.reporting import build_report
from agentsec_evidence.pilot.runner import evidence_records, save
from agentsec_evidence.research.retained import MAX_ENTRY_BYTES, read_retained_research

sys.modules["collect_corpus_core"] = driver
for name in ("corpus_report_v2", "collect_corpus_core_v2"):
    spec = importlib.util.spec_from_file_location(name, PROJECT / "tools" / (name + ".py"))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
reports = sys.modules["corpus_report_v2"]
linked = sys.modules["collect_corpus_core_v2"]


def seal(output: Path, files: dict[str, bytes]) -> None:
    output.mkdir()
    for name, raw in files.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    save(output / "evidence-manifest.json", reports.manifest_for(files))


@pytest.fixture
def finished(tmp_path: Path, cohort: tuple[Path, list[list[str]]]) -> tuple[Path, list[list[str]]]:
    root, commands = cohort
    driver.run_next(tmp_path, root)
    for name in linked.PINS:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((PROJECT / name).read_bytes())
    return root, commands


def test_lossless_report_and_no_new_scans(
    tmp_path: Path, finished: tuple[Path, list[list[str]]]
) -> None:
    root, commands = finished
    before = len(commands)
    attempt = root / "attempts/R03"
    output = tmp_path / "workspace/report-v2"
    result = reports.write_report(tmp_path, attempt, output)
    original = json.loads((root / "reports/R03/report.json").read_bytes())
    assert reports.read_report(output) == original
    assert result["passed"] and result["scanner_invocations"] == 0
    assert len(commands) == before
    assert len(list((output / "observations").glob("*.json"))) == 30
    with pytest.raises(ValueError, match="fresh report"):
        reports.write_report(tmp_path, attempt, output)


@pytest.mark.parametrize("fault", ["extra", "missing", "tampered", "resealed", "link", "index"])
def test_report_corruption_is_refused(
    tmp_path: Path, finished: tuple[Path, list[list[str]]], fault: str
) -> None:
    root, _ = finished
    output = tmp_path / "workspace/report-v2"
    reports.write_report(tmp_path, root / "attempts/R03", output)
    path = output / "observations/0001.json"
    if fault == "extra":
        (output / "extra.txt").write_text("extra")
    elif fault == "missing":
        path.unlink()
    elif fault == "link":
        document = json.loads((output / "report.json").read_bytes())
        document["observation_index"][0]["json"] = "../outside.json"
        save(output / "report.json", document)
    elif fault == "index":
        document = json.loads((output / "report.json").read_bytes())
        document["observation_index"].append(document["observation_index"][0])
        save(output / "report.json", document)
    else:
        path.write_bytes(path.read_bytes() + b" ")
    if fault in {"resealed", "link", "index"}:
        save(output / "evidence-manifest.json", {"files": evidence_records(output)})
    with pytest.raises((ValueError, FileNotFoundError)):
        reports.verify_report(tmp_path, root / "attempts/R03", output)


def test_script_strings_and_source_paths_are_not_active_links(
    tmp_path: Path, finished: tuple[Path, list[list[str]]]
) -> None:
    root, _ = finished
    report = json.loads((root / "reports/R03/report.json").read_bytes())
    key = next(k for k, v in report["observations"].items() if v["kind"] == "custom")
    report["observations"][key]["native"]["authored"] = '<script src="https://bad.test/x"></script>'
    files = reports.package(report)
    pages = [v for k, v in files.items() if k.endswith(".html")]
    assert all(b"<script" not in p for p in pages)
    assert any(b"&lt;script" in p for p in pages)
    assert b'href="observations/0001.html"' in files["report.html"]


def test_large_projection_chunks_without_dropping_data(
    tmp_path: Path, finished: tuple[Path, list[list[str]]]
) -> None:
    root, _ = finished
    report = json.loads((root / "reports/R03/report.json").read_bytes())
    for observation in report["observations"].values():
        observation["authored_padding"] = "x" * 600_000
    assert len(reports.encoded(report)) > MAX_ENTRY_BYTES
    files = reports.package(report)
    assert max(map(len, files.values())) <= MAX_ENTRY_BYTES
    output = tmp_path / "workspace/large-report"
    seal(output, files)
    assert reports.read_report(output) == report
    key = next(iter(report["observations"]))
    report["observations"][key]["authored_padding"] = "x" * (MAX_ENTRY_BYTES + 1)
    with pytest.raises(ValueError):
        reports.package(report)


def test_refused_states_and_unknowns_survive(
    tmp_path: Path, finished: tuple[Path, list[list[str]]]
) -> None:
    root, _ = finished
    report = json.loads((root / "reports/R03/report.json").read_bytes())
    row = report["rows"][0]
    report["observations"].pop(row["key"])
    row.update(state="refused", finding_records=None, reasons=["authored unsupported case"])
    output = tmp_path / "workspace/refused-report"
    seal(output, reports.package(report))
    restored = reports.read_report(output)
    assert restored == report
    assert restored["rows"][0]["finding_records"] is None


def fail_parent(root: Path) -> None:
    path = root / "events/0002.json"
    event = json.loads(path.read_bytes())
    event.update(
        outcome="failed",
        report_manifest_sha256=None,
        error="ValidationError: authored RetainedManifest size failure",
    )
    save(path, event)


@pytest.fixture
def recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    finished: tuple[Path, list[list[str]]],
) -> tuple[Path, Path, list[list[str]]]:
    root, commands = finished
    fail_parent(root)
    # Journal/recovery state-machine tests isolate forensic eligibility, tested separately below.
    monkeypatch.setattr(linked, "diagnose", lambda *args: {"authored_diagnosis": True})
    output = tmp_path / "workspace/linked"
    linked.prepare(tmp_path, root, output, "R03", approved=True)
    return root, output, commands


def test_recovery_retains_failed_parent_without_scanner_retry(
    tmp_path: Path, recovery: tuple[Path, Path, list[list[str]]]
) -> None:
    parent, root, commands = recovery
    old = {p.name: p.read_bytes() for p in (parent / "events").iterdir()}
    count = len(commands)
    state = linked.run_next(tmp_path, root)
    assert state["finished"] and not state["blocked"] and state["events"] == 0
    assert state["parent_remains_failed"] and state["recovery_scanner_invocations"] == 0
    assert state["rows"][0]["state"] == "report-only-recovery"
    assert state["rows"][0]["verified_observed_cells"] == 30
    assert len(commands) == count and driver.status(tmp_path, parent)["blocked"]
    assert old == {p.name: p.read_bytes() for p in (parent / "events").iterdir()}


@pytest.mark.parametrize("fault", ["parent", "harness", "report", "native", "orphan", "journal"])
def test_recovery_binding_changes_block(
    tmp_path: Path, recovery: tuple[Path, Path, list[list[str]]], fault: str
) -> None:
    parent, root, commands = recovery
    count = len(commands)
    if fault == "parent":
        path = parent / "events/0002.json"
    elif fault == "harness":
        path = tmp_path / reports.DRIVER
    elif fault == "report":
        path = root / "reports/R03/observations/0001.html"
    elif fault == "native":
        path = parent / "attempts/R03/evidence-manifest.json"
    elif fault == "orphan":
        (root / "attempts/R03").mkdir()
        path = None
    else:
        driver._append(root, sequence=1, previous_sha256="0" * 64, candidate_id="R03", kind="start")
        path = None
    if path:
        path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError):
        linked.run_next(tmp_path, root)
    assert len(commands) == count


def test_recovery_requires_explicit_approval_and_matching_failure(
    tmp_path: Path, finished: tuple[Path, list[list[str]]]
) -> None:
    root, _ = finished
    output = tmp_path / "workspace/linked"
    with pytest.raises(ValueError, match="approval"):
        linked.prepare(tmp_path, root, output, "R03", approved=False)
    with pytest.raises(ValueError, match="approved report-size failure"):
        linked.prepare(tmp_path, root, output, "R03", approved=True)
    with pytest.raises(ValueError, match="No per-file"):
        linked.diagnose(tmp_path, root, "R03")
    assert not output.exists()


def test_recovery_locks_and_destination_boundaries(
    tmp_path: Path, recovery: tuple[Path, Path, list[list[str]]]
) -> None:
    parent, root, _ = recovery
    with (
        portalocker.Lock(str(parent / ".writer.lock"), mode="a+", timeout=0),
        pytest.raises(portalocker.exceptions.LockException),
    ):
        linked.status(tmp_path, root)
    with pytest.raises(ValueError, match="fresh separate"):
        linked.prepare(tmp_path, parent, root, "R03", approved=True)
    with pytest.raises(ValueError, match="ignored project workspace"):
        linked.status(tmp_path, tmp_path)


def test_forensic_size_recovery_requires_exact_native_reconstruction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    finished: tuple[Path, list[list[str]]],
) -> None:
    root, commands = finished
    count = len(commands)
    report = json.loads((root / "reports/R03/report.json").read_bytes())
    for observation in report["observations"].values():
        observation["authored_padding"] = "x" * 600_000
    refused = root / "reports/R03"
    save(refused / "report.json", report)
    (refused / "report.html").write_bytes(linked.render(report))
    save(refused / "evidence-manifest.json", {"files": evidence_records(refused)})
    monkeypatch.setattr(linked, "build_report", lambda _: report)
    diagnosis = linked.diagnose(tmp_path, root, "R03")
    assert diagnosis["reconstruction_equal"] and not diagnosis["v1_accepted"]
    assert diagnosis["scanner_invocations"] == 0 and len(commands) == count
    with pytest.raises(ValueError):
        read_retained_research(refused)
    report = copy.deepcopy(report)
    report["candidate"]["repository"] = "authored/different"
    with pytest.raises(ValueError, match="native reconstruction"):
        linked.diagnose(tmp_path, root, "R03")


def test_resealed_consistent_derivative_still_requires_native_replay(
    tmp_path: Path, finished: tuple[Path, list[list[str]]]
) -> None:
    root, _ = finished
    report = build_report(driver.verify_core(tmp_path, root / "attempts/R03"))
    report["candidate"]["repository"] = "authored/tampered"
    output = tmp_path / "workspace/false-projection"
    seal(output, reports.package(report))
    assert reports.read_report(output) == report
    with pytest.raises(ValueError, match="native replay"):
        reports.verify_report(tmp_path, root / "attempts/R03", output)


@pytest.mark.parametrize("fault", [None, "scanner", "report", "interrupt"])
def test_linked_scheduler_only_starts_pending_and_records_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str | None
) -> None:
    root = tmp_path / "workspace/linked"
    for folder in ("events", "attempts", "reports"):
        (root / folder).mkdir(parents=True)
    progress = {
        "blocked": False,
        "finished": False,
        "events": 0,
        "journal_head_sha256": "a" * 64,
        "rows": [
            {"candidate_id": "R03", "state": "report-only-recovery"},
            {"candidate_id": "R04", "state": "pending"},
        ],
    }
    monkeypatch.setattr(linked, "_status", lambda *args, **kwargs: progress)
    entry = SimpleNamespace(candidate_id="R04", preparation=str(tmp_path / "workspace/R04"))
    monkeypatch.setattr(
        linked,
        "load",
        lambda *args, **kwargs: (
            SimpleNamespace(parent=str(tmp_path / "workspace/parent")),
            SimpleNamespace(entries=[entry]),
            "a" * 64,
        ),
    )
    launches = []

    def run(project: Path, preparation: Path, admission_path: Path, attempt: Path) -> None:
        launches.append(attempt.name)
        assert preparation == Path(entry.preparation)
        assert admission_path.name == "R04.json"
        attempt.mkdir()
        save(attempt / "evidence-manifest.json", {"authored": True})
        if fault == "scanner":
            raise ValueError("authored scanner failure")
        if fault == "interrupt":
            raise KeyboardInterrupt("authored interruption")

    def write(project: Path, attempt: Path, output: Path) -> dict[str, Any]:
        if fault == "report":
            raise ValueError("authored report failure")
        output.mkdir()
        save(output / "evidence-manifest.json", {"authored": True})
        return {"execution_finished": True}

    monkeypatch.setattr(linked, "run_core", run)
    monkeypatch.setattr(reports, "write_report", write)
    if fault:
        with pytest.raises((ValueError, KeyboardInterrupt)):
            linked.run_next(tmp_path, root)
    else:
        linked.run_next(tmp_path, root)
    assert launches == ["R04"]
    events = [json.loads(p.read_bytes()) for p in sorted((root / "events").iterdir())]
    assert len(events) == 2
    assert events[1]["outcome"] == ("failed" if fault else "completed")
    assert events[1]["error"] is not None if fault else events[1]["error"] is None
    if fault:
        progress["blocked"] = True
        with pytest.raises(ValueError, match="blocks"):
            linked.run_next(tmp_path, root)
        assert launches == ["R04"]


def test_manifest_budget_is_not_raised() -> None:
    with pytest.raises(ValueError):
        reports.manifest_for({"oversized.json": b"x" * (MAX_ENTRY_BYTES + 1)})
    with pytest.raises(ValueError):
        reports.manifest_for({f"part-{i}.json": b"x" * MAX_ENTRY_BYTES for i in range(9)})


@pytest.mark.parametrize("fault", ["oversize", "negative", "boolean", "hash", "extra", "count"])
def test_forensic_manifest_keeps_independent_bounds(fault: str) -> None:
    entries = [
        {"path": name, "bytes": MAX_ENTRY_BYTES + 1, "sha256": "a" * 64}
        for name in ("report.json", "report.html")
    ]
    document: dict[str, Any] = {"files": entries}
    if fault == "oversize":
        entries[0]["bytes"] = linked.DIAGNOSTIC_LIMIT + 1
    elif fault == "negative":
        entries[0]["bytes"] = -1
    elif fault == "boolean":
        entries[0]["bytes"] = True
    elif fault == "hash":
        entries[0]["sha256"] = "not-a-hash"
    elif fault == "extra":
        document["unapproved"] = True
    else:
        entries.append(entries[0])
    with pytest.raises(ValueError):
        linked.DiagnosticManifest.model_validate(document)
