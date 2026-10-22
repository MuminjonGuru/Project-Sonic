"""Authored scheduling/evidence tests; no public target or Docker execution."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import portalocker
import pytest
from test_corpus_core import admission, mock_processes, setup_core

from agentsec_evidence.core.identity import sha256_file
from agentsec_evidence.corpus import contracts, execution
from agentsec_evidence.pilot.runner import evidence_records, save

PROJECT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "corpus_collection_driver", PROJECT / "tools/collect_corpus_core.py"
)
assert spec is not None and spec.loader is not None
driver = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = driver
spec.loader.exec_module(driver)


@pytest.fixture
def cohort(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, list[list[str]]]:
    core, _ = setup_core(tmp_path, monkeypatch)
    target = core.parent / "R03"
    core.rename(target)
    for name in (driver.DRIVER, driver.SPEC):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((PROJECT / name).read_bytes())
    reviews = tmp_path / "workspace/reviews"
    reviews.mkdir()
    admission(target, reviews / "R03.json")
    commands = mock_processes(monkeypatch)
    monkeypatch.setattr(execution, "resolve_docker", lambda _: tmp_path / "docker.exe")
    output = tmp_path / "workspace/collection"
    driver.prepare(tmp_path, target.parent, reviews, output, {})
    return output, commands


def test_complete_and_repeat_status_without_new_launch(
    tmp_path: Path, cohort: tuple[Path, list[list[str]]]
) -> None:
    root, commands = cohort
    assert driver.status(tmp_path, root)["rows"][0]["state"] == "pending"
    assert commands == []
    result = driver.run_next(tmp_path, root)
    assert result["finished"] and not result["blocked"]
    assert result["rows"][0]["verified_observed_cells"] == 30
    count = len(commands)
    assert driver.run_next(tmp_path, root) == result
    assert len(commands) == count
    assert (root / "reports/R03/report.html").is_file()


@pytest.mark.parametrize("kind", ["runtime", "interrupt", "report"])
def test_failed_attempt_is_retained_and_blocks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cohort: tuple[Path, list[list[str]]],
    kind: str,
) -> None:
    root, _ = cohort

    def fail(*args: Any, **kwargs: Any) -> None:
        if kind == "interrupt":
            raise KeyboardInterrupt("authored interruption")
        raise ValueError("authored failure")

    monkeypatch.setattr(driver, "write_report" if kind == "report" else "run_core", fail)
    with pytest.raises((ValueError, KeyboardInterrupt)):
        driver.run_next(tmp_path, root)
    state = driver.status(tmp_path, root)
    assert state["blocked"] and not state["finished"]
    assert state["rows"][0]["state"] == "failed"
    before = {p.name: p.read_bytes() for p in (root / "events").iterdir()}
    with pytest.raises(ValueError, match="blocks"):
        driver.run_next(tmp_path, root)
    assert before == {p.name: p.read_bytes() for p in (root / "events").iterdir()}


def test_start_only_is_never_resumed(tmp_path: Path, cohort: tuple[Path, list[list[str]]]) -> None:
    root, commands = cohort
    state = driver.status(tmp_path, root)
    driver._append(
        root,
        sequence=1,
        previous_sha256=state["journal_head_sha256"],
        candidate_id="R03",
        kind="start",
    )
    assert driver.status(tmp_path, root)["blocked"]
    with pytest.raises(ValueError, match="blocks"):
        driver.run_next(tmp_path, root)
    assert not commands


@pytest.mark.parametrize("name", [driver.DRIVER, driver.SPEC, driver.PROTOCOL])
def test_harness_changes_refuse_before_start(
    tmp_path: Path, cohort: tuple[Path, list[list[str]]], name: str
) -> None:
    root, commands = cohort
    with (tmp_path / name).open("ab") as stream:
        stream.write(b"\n# changed\n")
    with pytest.raises(ValueError, match="harness changed"):
        driver.run_next(tmp_path, root)
    assert not list((root / "events").iterdir()) and not commands


def test_changed_admission_even_resealed_is_refused(
    tmp_path: Path, cohort: tuple[Path, list[list[str]]]
) -> None:
    root, commands = cohort
    path = root / "inputs/admissions/R03.json"
    value = json.loads(path.read_bytes())
    value["reviewer"] = "replacement"
    save(path, value)
    save(root / "inputs/evidence-manifest.json", {"files": evidence_records(root / "inputs")})
    with pytest.raises(ValueError, match="Frozen input changed"):
        driver.run_next(tmp_path, root)
    assert not commands


def test_changed_preparation_is_refused(
    tmp_path: Path, cohort: tuple[Path, list[list[str]]]
) -> None:
    root, commands = cohort
    with (tmp_path / "workspace/R03/plan.json").open("ab") as stream:
        stream.write(b" ")
    with pytest.raises(ValueError, match="entry changed"):
        driver.run_next(tmp_path, root)
    assert not commands


def test_chain_corruption_is_refused(tmp_path: Path, cohort: tuple[Path, list[list[str]]]) -> None:
    root, _ = cohort
    driver._append(root, sequence=1, previous_sha256="0" * 64, candidate_id="R03", kind="start")
    with pytest.raises(ValueError, match="Journal chain"):
        driver.status(tmp_path, root)


def test_orphan_attempt_is_not_adopted(
    tmp_path: Path, cohort: tuple[Path, list[list[str]]]
) -> None:
    root, commands = cohort
    (root / "attempts/R03").mkdir()
    with pytest.raises(ValueError, match="Unscheduled attempt"):
        driver.run_next(tmp_path, root)
    assert not commands


def test_writer_lock_blocks_without_launch(
    tmp_path: Path, cohort: tuple[Path, list[list[str]]]
) -> None:
    root, commands = cohort
    with (
        portalocker.Lock(str(root / ".writer.lock"), mode="a+", timeout=0),
        pytest.raises(portalocker.exceptions.LockException),
    ):
        driver.run_next(tmp_path, root)
    assert not commands


def test_exclusive_events_never_overwrite(
    tmp_path: Path, cohort: tuple[Path, list[list[str]]]
) -> None:
    root, _ = cohort
    fields = dict(sequence=1, previous_sha256="0" * 64, candidate_id="R03", kind="start")
    driver._append(root, **fields)
    before = (root / "events/0001.json").read_bytes()
    with pytest.raises(FileExistsError):
        driver._append(root, **fields)
    assert before == (root / "events/0001.json").read_bytes()


def test_cannot_adopt_new_candidate_as_historical(
    tmp_path: Path, cohort: tuple[Path, list[list[str]]]
) -> None:
    root, _ = cohort
    with pytest.raises(ValueError, match="Only existing formative"):
        driver.prepare(
            tmp_path,
            tmp_path / "workspace",
            tmp_path / "workspace/reviews",
            tmp_path / "workspace/other",
            {"R03": root},
        )


def test_unknown_candidate_and_existing_destination_refused(
    tmp_path: Path, cohort: tuple[Path, list[list[str]]]
) -> None:
    root, _ = cohort
    with pytest.raises(ValueError, match="Unknown reference"):
        driver.prepare(
            tmp_path,
            tmp_path / "workspace",
            tmp_path / "workspace/reviews",
            tmp_path / "workspace/other",
            {"R20": root},
        )
    with pytest.raises(ValueError, match="fresh collection"):
        driver.prepare(tmp_path, tmp_path / "workspace", tmp_path / "workspace/reviews", root, {})


def test_path_traversal_refused(tmp_path: Path) -> None:
    (tmp_path / "workspace").mkdir()
    with pytest.raises(ValueError, match="ignored project workspace"):
        driver.workspace_path(tmp_path, tmp_path / "workspace/../escaped")


def test_finished_report_tampering_refused(
    tmp_path: Path, cohort: tuple[Path, list[list[str]]]
) -> None:
    root, _ = cohort
    driver.run_next(tmp_path, root)
    html = root / "reports/R03/report.html"
    html.write_bytes(html.read_bytes() + b"tampered")
    with pytest.raises(ValueError):
        driver.status(tmp_path, root)


def test_completed_native_manifest_tampering_refused(
    tmp_path: Path, cohort: tuple[Path, list[list[str]]]
) -> None:
    root, _ = cohort
    driver.run_next(tmp_path, root)
    path = root / "attempts/R03/evidence-manifest.json"
    original = sha256_file(path)
    path.write_bytes(path.read_bytes() + b" ")
    assert original != sha256_file(path)
    with pytest.raises(ValueError, match="attempt manifest changed"):
        driver.status(tmp_path, root)


def test_missing_admission_refuses_preparation(
    tmp_path: Path, cohort: tuple[Path, list[list[str]]]
) -> None:
    root, commands = cohort
    with pytest.raises(FileNotFoundError):
        driver.prepare(
            tmp_path,
            tmp_path / "workspace",
            root / "absent",
            tmp_path / "workspace/missing-review",
            {},
        )
    assert not (tmp_path / "workspace/missing-review").exists() and not commands


def test_duplicate_cohort_entry_refused_even_if_resealed(
    tmp_path: Path, cohort: tuple[Path, list[list[str]]]
) -> None:
    root, _ = cohort
    path = root / "inputs/plan.json"
    value = json.loads(path.read_bytes())
    value["entries"].append(value["entries"][0])
    save(path, value)
    save(root / "inputs/evidence-manifest.json", {"files": evidence_records(root / "inputs")})
    with pytest.raises(ValueError, match="cohort membership"):
        driver.status(tmp_path, root)


def test_reference_is_verified_but_never_reexecuted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cohort: tuple[Path, list[list[str]]],
) -> None:
    _, commands = cohort
    preparation = tmp_path / "workspace/R03"
    raw = json.loads((preparation / "plan.json").read_bytes())
    raw["validation"]["preview"]["candidate"]["role"] = "existing-formative-pilot"
    save(preparation / "plan.json", raw)
    model = contracts.CorpusCorePlan.model_validate(raw)
    registry = tmp_path / driver.REGISTRY
    document = json.loads(registry.read_bytes())
    document["candidates"][0]["role"] = "existing-formative-pilot"
    save(registry, document)
    reference = tmp_path / "workspace/reference"
    reference.mkdir()
    (reference / "plan.json").write_bytes((preparation / "plan.json").read_bytes())
    admission(preparation, reference / "admission.json")
    save(reference / "evidence-manifest.json", {"authored": True})
    monkeypatch.setattr(driver, "load_preparation", lambda *args: model)
    monkeypatch.setattr(
        driver,
        "verify_core",
        lambda *args: {
            "execution_finished": True,
            "rows": [{"state": "observed"}] * 30,
        },
    )
    destination = tmp_path / "workspace/reference-cohort"
    driver.prepare(
        tmp_path,
        tmp_path / "workspace",
        tmp_path / "workspace/reviews",
        destination,
        {"R03": reference},
    )
    state = driver.run_next(tmp_path, destination)
    assert state["finished"] and state["events"] == 0
    assert state["rows"][0]["state"] == "existing-reference"
    assert commands == []


def test_status_cannot_write_lock_outside_workspace(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="ignored project workspace"):
        driver.status(tmp_path, tmp_path)
    assert not (tmp_path / ".writer.lock").exists()
