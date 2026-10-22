"""Frozen cohort driver; no retries, target execution or automatic admission decisions."""

from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import portalocker
from pydantic import AwareDatetime, Field, StrictInt

from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.core.io import atomic_write_bytes
from agentsec_evidence.corpus.contracts import (
    CorpusCoreAdmission,
    CorpusCorePlan,
    current_implementation,
    dry_run,
    load_preparation,
    verify_admission,
)
from agentsec_evidence.corpus.execution import run_core, verify_core
from agentsec_evidence.corpus.reporting import verify_report, write_report
from agentsec_evidence.intake.corpus import load_candidates
from agentsec_evidence.intake.corpus_validation import PROTOCOL, REGISTRY
from agentsec_evidence.models.contracts import ContractModel, Sha256
from agentsec_evidence.pilot.runner import evidence_records, save
from agentsec_evidence.research.retained import bounded_file, plain_path, read_retained_research

DRIVER = "tools/collect_corpus_core.py"
SPEC = "docs/corpus-collection-driver.md"


class Entry(ContractModel):
    candidate_id: str = Field(pattern=r"^R[0-9]{2}$")
    preparation: str
    plan_sha256: Sha256
    preparation_manifest_sha256: Sha256
    admission_sha256: Sha256
    forecast_invocations: StrictInt = Field(ge=0)
    existing_attempt: str | None = None
    existing_manifest_sha256: Sha256 | None = None


class CollectionPlan(ContractModel):
    contract: Literal["corpus-collection-plan-v1"] = "corpus-collection-plan-v1"
    root: str
    created_at: AwareDatetime
    entries: tuple[Entry, ...] = Field(min_length=1, max_length=20)
    frozen_pins: dict[str, Sha256]
    treatment: Literal["fixed-python-core;optional-stages-separate"] = (
        "fixed-python-core;optional-stages-separate"
    )


class Event(ContractModel):
    contract: Literal["corpus-collection-event-v1"] = "corpus-collection-event-v1"
    sequence: StrictInt = Field(ge=1, le=40)
    previous_sha256: Sha256
    candidate_id: str = Field(pattern=r"^R[0-9]{2}$")
    at: AwareDatetime
    kind: Literal["start", "finish"]
    outcome: Literal["completed", "failed"] | None = None
    attempt_manifest_sha256: Sha256 | None = None
    report_manifest_sha256: Sha256 | None = None
    error: str | None = None


def workspace_path(project: Path, path: Path) -> Path:
    path = Path(os.path.abspath(path))
    if path == project / "workspace" or not path.is_relative_to(project / "workspace"):
        raise ValueError("Collection paths must remain in the ignored project workspace")
    plain_path(path if path.exists() else path.parent, directory=True)
    return path


def prepare(
    project: Path,
    preparations: Path,
    admissions: Path,
    output: Path,
    references: dict[str, Path],
) -> CollectionPlan:
    project = plain_path(project, directory=True)
    output = workspace_path(project, output)
    if output.exists():
        raise ValueError("Use a fresh collection directory")
    candidates = load_candidates(project / REGISTRY).candidates
    if set(references) - {c.candidate_id for c in candidates}:
        raise ValueError("Unknown reference candidate")
    material = {
        "frozen/" + p: bounded_file(project / p, 1024**2)
        for p in (DRIVER, SPEC, REGISTRY, PROTOCOL)
    }
    entries = []
    for candidate in candidates:
        key = candidate.candidate_id
        preparation = workspace_path(project, preparations / key)
        plan = load_preparation(project, preparation)
        current_implementation(project, plan)
        if plan.validation.preview.candidate != candidate:
            raise ValueError("Candidate differs from registry")
        plan_raw = bounded_file(preparation / "plan.json", 4 * 1024**2)
        reference = references.get(key)
        if reference is not None:
            reference = workspace_path(project, reference)
            if candidate.role != "existing-formative-pilot":
                raise ValueError("Only existing formative pilots may be references")
            replay = verify_core(project, reference)
            if (
                not replay["execution_finished"]
                or bounded_file(reference / "plan.json", 4 * 1024**2) != plan_raw
            ):
                raise ValueError("Reference is incomplete or belongs to another treatment")
            admission_raw = bounded_file(reference / "admission.json", 64 * 1024)
        else:
            admission_raw = bounded_file(admissions / (key + ".json"), 64 * 1024)
        verify_admission(plan, plan_raw, CorpusCoreAdmission.model_validate_json(admission_raw))
        material[f"admissions/{key}.json"] = admission_raw
        entries.append(
            Entry(
                candidate_id=key,
                preparation=str(preparation),
                plan_sha256=sha256_bytes(plan_raw),
                preparation_manifest_sha256=sha256_file(preparation / "evidence-manifest.json"),
                admission_sha256=sha256_bytes(admission_raw),
                forecast_invocations=dry_run(plan)["planned_invocations"],
                existing_attempt=str(reference) if reference else None,
                existing_manifest_sha256=(
                    sha256_file(reference / "evidence-manifest.json") if reference else None
                ),
            )
        )
        print(key + ": admission bound; no launch", flush=True)
    collection = CollectionPlan(
        root=str(output),
        created_at=datetime.now(UTC),
        entries=tuple(entries),
        frozen_pins={p: sha256_bytes(raw) for p, raw in material.items()},
    )
    output.mkdir()
    for name in ("events", "attempts", "reports"):
        (output / name).mkdir()
    for path, raw in material.items():
        atomic_write_bytes(output / "inputs" / path, raw)
    save(output / "inputs/plan.json", collection.model_dump(mode="json"))
    save(output / "inputs/evidence-manifest.json", {"files": evidence_records(output / "inputs")})
    return collection


def load(project: Path, root: Path, *, current: bool = False) -> tuple[CollectionPlan, str]:
    root = workspace_path(project, root)
    retained = read_retained_research(root / "inputs")
    plan = CollectionPlan.model_validate_json(retained.read("plan.json"))
    if plan.root != str(root) or set(retained.files) != {*plan.frozen_pins, "plan.json"}:
        raise ValueError("Collection root or input membership changed")
    registry = load_candidates(root / "inputs/frozen" / REGISTRY)
    if [e.candidate_id for e in plan.entries] != [c.candidate_id for c in registry.candidates]:
        raise ValueError("Collection order or cohort membership differs")
    expected_pins = {"frozen/" + p for p in (DRIVER, SPEC, REGISTRY, PROTOCOL)} | {
        "admissions/" + e.candidate_id + ".json" for e in plan.entries
    }
    if set(plan.frozen_pins) != expected_pins:
        raise ValueError("Frozen input set differs")
    for name, digest in plan.frozen_pins.items():
        if sha256_bytes(retained.read(name)) != digest:
            raise ValueError("Frozen input changed")
        if (
            current
            and name.startswith("frozen/")
            and sha256_file(project / name.removeprefix("frozen/")) != digest
        ):
            raise ValueError("Collection harness changed; do not resume this treatment")
    for entry, candidate in zip(plan.entries, registry.candidates, strict=True):
        preparation = workspace_path(project, Path(entry.preparation))
        raw = bounded_file(preparation / "plan.json", 4 * 1024**2)
        core = CorpusCorePlan.model_validate_json(raw)
        admission_raw = retained.read("admissions/" + entry.candidate_id + ".json")
        if (
            sha256_bytes(raw) != entry.plan_sha256
            or sha256_file(preparation / "evidence-manifest.json")
            != entry.preparation_manifest_sha256
            or sha256_bytes(admission_raw) != entry.admission_sha256
            or core.validation.preview.candidate != candidate
            or dry_run(core)["planned_invocations"] != entry.forecast_invocations
            or bool(entry.existing_attempt) != bool(entry.existing_manifest_sha256)
        ):
            raise ValueError("Bound collection entry changed")
        verify_admission(core, raw, CorpusCoreAdmission.model_validate_json(admission_raw))
        if current:
            current_implementation(project, core)
        if entry.existing_attempt and candidate.role != "existing-formative-pilot":
            raise ValueError("New candidates cannot be historical references")
    return plan, retained.manifest_sha256


def _append(root: Path, **fields: Any) -> None:
    event = Event(at=datetime.now(UTC), **fields)
    path = root / "events" / f"{event.sequence:04d}.json"
    # Exclusive creation and fsync leave a start-only interruption visible, never reusable.
    with path.open("xb") as stream:
        stream.write(event.model_dump_json(indent=2).encode())
        stream.flush()
        os.fsync(stream.fileno())


def _status(project: Path, root: Path, *, current: bool = False) -> dict[str, Any]:
    plan, previous = load(project, root, current=current)
    if {p.name for p in root.iterdir()} - {
        "inputs",
        "events",
        "attempts",
        "reports",
        ".writer.lock",
    }:
        raise ValueError("Unexpected collection member")
    pending = [e for e in plan.entries if e.existing_attempt is None]
    states: dict[str, str] = dict.fromkeys((e.candidate_id for e in pending), "pending")
    finishes: dict[str, Event] = {}
    plain_path(root / "events", directory=True)
    events = sorted((root / "events").iterdir())
    if len(events) > 2 * len(pending):
        raise ValueError("Extra journal events")
    index = 0
    active: str | None = None
    failed = False
    for sequence, path in enumerate(events, 1):
        raw = bounded_file(path, 64 * 1024)
        event = Event.model_validate_json(raw)
        if (
            path.name != f"{sequence:04d}.json"
            or event.sequence != sequence
            or event.previous_sha256 != previous
            or failed
            or index >= len(pending)
            or event.candidate_id != pending[index].candidate_id
        ):
            raise ValueError("Journal chain, order or membership differs")
        previous = sha256_bytes(raw)
        if event.kind == "start":
            if active is not None or any(
                v is not None
                for v in (
                    event.outcome,
                    event.error,
                    event.attempt_manifest_sha256,
                    event.report_manifest_sha256,
                )
            ):
                raise ValueError("Invalid start event")
            active = event.candidate_id
            states[active] = "interrupted-or-running"
        else:
            if active != event.candidate_id or event.outcome is None:
                raise ValueError("Finish without start")
            if event.outcome == "completed" and (
                event.error is not None
                or event.attempt_manifest_sha256 is None
                or event.report_manifest_sha256 is None
            ):
                raise ValueError("Incomplete successful finish")
            if event.outcome == "failed" and not event.error:
                raise ValueError("Failed finish requires explanation")
            states[active] = event.outcome
            finishes[active] = event
            failed = event.outcome == "failed"
            active = None
            index += 1
    started = {k for k, v in states.items() if v != "pending"}
    for folder in ("attempts", "reports"):
        plain_path(root / folder, directory=True)
        if {p.name for p in (root / folder).iterdir()} - started:
            raise ValueError("Unscheduled attempt or report")
    rows = []
    for entry in plan.entries:
        key = entry.candidate_id
        reference = entry.existing_attempt is not None
        state = "existing-reference" if reference else states[key]
        attempt = (
            Path(entry.existing_attempt)
            if entry.existing_attempt is not None
            else root / "attempts" / key
        )
        digest = (
            entry.existing_manifest_sha256
            if reference
            else (finishes[key].attempt_manifest_sha256 if key in finishes else None)
        )
        if digest is not None and sha256_file(attempt / "evidence-manifest.json") != digest:
            raise ValueError("Retained attempt manifest changed")
        count = None
        if state in {"existing-reference", "completed"}:
            workspace_path(project, attempt)
            replay = verify_core(project, attempt)
            if (
                not replay["execution_finished"]
                or sha256_file(attempt / "plan.json") != entry.plan_sha256
                or sha256_file(attempt / "admission.json") != entry.admission_sha256
            ):
                raise ValueError("Attempt is incomplete or differs from admitted treatment")
            count = sum(r["state"] == "observed" for r in replay["rows"])
            if not reference:
                report = root / "reports" / key
                if (
                    sha256_file(report / "evidence-manifest.json")
                    != (finishes[key].report_manifest_sha256)
                    or not verify_report(project, attempt, report)["execution_finished"]
                ):
                    raise ValueError("Completed report differs")
        rows.append(
            {
                "candidate_id": key,
                "state": state,
                "forecast_invocations": entry.forecast_invocations,
                "verified_observed_cells": count,
                "attempt": str(attempt) if state != "pending" else None,
                "error": finishes[key].error if key in finishes else None,
            }
        )
    return {
        "contract": "corpus-collection-status-v1",
        "rows": rows,
        "blocked": failed or active is not None,
        "finished": all(r["state"] in {"existing-reference", "completed"} for r in rows),
        "events": len(events),
        "journal_head_sha256": previous,
        "input_manifest_sha256": sha256_file(root / "inputs/evidence-manifest.json"),
        "scanner_invocations_during_status": 0,
    }


def status(project: Path, root: Path) -> dict[str, Any]:
    project = plain_path(project, directory=True)
    root = workspace_path(project, root)
    lock = root / ".writer.lock"
    if lock.exists():
        plain_path(lock, directory=False)
    with portalocker.Lock(str(lock), mode="a+", timeout=0):
        return _status(project, root)


def run_next(project: Path, root: Path) -> dict[str, Any]:
    project = plain_path(project, directory=True)
    root = workspace_path(project, root)
    lock = root / ".writer.lock"
    if lock.exists():
        plain_path(lock, directory=False)
    with portalocker.Lock(str(lock), mode="a+", timeout=0):
        progress = _status(project, root, current=True)
        if progress["blocked"]:
            raise ValueError("Failed or interrupted collection blocks; no retry or resume")
        if progress["finished"]:
            return progress
        key = next(r["candidate_id"] for r in progress["rows"] if r["state"] == "pending")
        plan, _ = load(project, root, current=True)
        entry = next(e for e in plan.entries if e.candidate_id == key)
        sequence = progress["events"] + 1
        _append(
            root,
            sequence=sequence,
            previous_sha256=progress["journal_head_sha256"],
            candidate_id=key,
            kind="start",
        )
        previous = sha256_file(root / "events" / f"{sequence:04d}.json")
        attempt = root / "attempts" / key
        report = root / "reports" / key
        try:
            run_core(
                project, Path(entry.preparation), root / f"inputs/admissions/{key}.json", attempt
            )
            result = write_report(project, attempt, report)
            if not result["execution_finished"]:
                raise ValueError("Core attempt is incomplete")
        except BaseException as exc:
            manifest = attempt / "evidence-manifest.json"
            _append(
                root,
                sequence=sequence + 1,
                previous_sha256=previous,
                candidate_id=key,
                kind="finish",
                outcome="failed",
                attempt_manifest_sha256=sha256_file(manifest) if manifest.exists() else None,
                error=type(exc).__name__ + ": " + str(exc),
            )
            raise
        _append(
            root,
            sequence=sequence + 1,
            previous_sha256=previous,
            candidate_id=key,
            kind="finish",
            outcome="completed",
            attempt_manifest_sha256=sha256_file(attempt / "evidence-manifest.json"),
            report_manifest_sha256=sha256_file(report / "evidence-manifest.json"),
        )
        return _status(project, root)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "status", "run"))
    parser.add_argument("--project", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--preparations", type=Path)
    parser.add_argument("--admissions", type=Path)
    parser.add_argument("--existing", action="append", default=[])
    parser.add_argument("--count", type=int, default=1, choices=range(1, 21))
    args = parser.parse_args()
    if args.mode == "prepare":
        if args.preparations is None or args.admissions is None:
            parser.error("prepare requires --preparations and --admissions")
        pairs = [v.split("=", 1) for v in args.existing]
        if any(len(p) != 2 for p in pairs) or len({p[0] for p in pairs}) != len(pairs):
            parser.error("existing references require unique ID=path pairs")
        prepare(
            args.project,
            args.preparations,
            args.admissions,
            args.output,
            {key: Path(path) for key, path in pairs},
        )
    if args.mode == "run":
        for _ in range(args.count):
            result = run_next(args.project, args.output)
            print(json.dumps(result, indent=2), flush=True)
            if result["finished"]:
                break
    else:
        print(json.dumps(status(args.project, args.output), indent=2))


if __name__ == "__main__":
    main()
