"""Explicit report-only recovery and linked continuation; no scanner retries."""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import collect_corpus_core as legacy
import corpus_report_v2 as reports
import portalocker
from pydantic import AwareDatetime, Field, StrictInt

from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.core.io import atomic_write_bytes
from agentsec_evidence.corpus.execution import run_core, verify_core
from agentsec_evidence.corpus.reporting import build_report, render
from agentsec_evidence.models.contracts import ContractModel, Sha256
from agentsec_evidence.pilot.runner import evidence_records, save
from agentsec_evidence.research.retained import (
    MAX_ENTRY_BYTES,
    RetainedEntry,
    bounded_file,
    plain_path,
    read_retained_research,
)

DRIVER = "tools/collect_corpus_core_v2.py"
SPEC = reports.SPEC
PINS = (DRIVER, reports.DRIVER, SPEC)
DIAGNOSTIC_LIMIT = 32 * 1024**2
Origin = Literal["existing-reference", "completed-parent", "report-only-recovery"]


class DiagnosticEntry(RetainedEntry):
    bytes: StrictInt = Field(ge=0, le=DIAGNOSTIC_LIMIT)


class DiagnosticManifest(ContractModel):
    # Exactly two known report members: at most 64 MiB, never a valid v1 consumer manifest.
    files: tuple[DiagnosticEntry, ...] = Field(min_length=2, max_length=2)


class Reference(ContractModel):
    candidate_id: str = Field(pattern=r"^R[0-9]{2}$")
    attempt: str
    attempt_manifest_sha256: Sha256
    report_manifest_sha256: Sha256
    origin: Origin


class LinkedPlan(ContractModel):
    contract: Literal["corpus-collection-plan-v2"] = "corpus-collection-plan-v2"
    root: str
    parent: str
    created_at: AwareDatetime
    parent_input_sha256: Sha256
    parent_head_sha256: Sha256
    recovery_candidate: str = Field(pattern=r"^R[0-9]{2}$")
    recovery_authorization: Literal["user-approved-report-only-recovery"]
    recovery_provenance: Literal["user-confirmed-conversation;not-independent-review"] = (
        "user-confirmed-conversation;not-independent-review"
    )
    references: tuple[Reference, ...] = Field(min_length=1, max_length=20)
    frozen_pins: dict[str, Sha256]


def diagnose(project: Path, parent: Path, key: str) -> dict[str, Any]:
    """Forensic-only read: an oversized v1 derivative is never accepted as a v1 report."""
    attempt, output = parent / "attempts" / key, parent / "reports" / key
    replay = verify_core(project, attempt)
    if not replay["execution_finished"]:
        raise ValueError("Recovery requires finished native execution")
    report = build_report(replay)
    plain_path(output, directory=True)
    if {p.name for p in output.iterdir()} != {
        "evidence-manifest.json",
        "report.json",
        "report.html",
    }:
        raise ValueError("Unexpected refused report members")
    manifest_raw = bounded_file(output / "evidence-manifest.json", 1024**2)
    diagnostic = DiagnosticManifest.model_validate(load_agent_json(manifest_raw, max_bytes=1024**2))
    if not any(entry.bytes > MAX_ENTRY_BYTES for entry in diagnostic.files):
        raise ValueError("No per-file report-size violation to recover")
    files = [entry.model_dump(mode="json") for entry in diagnostic.files]
    if {e["path"] for e in files} != {"report.json", "report.html"}:
        raise ValueError("Refused report manifest differs")
    raw = {e["path"]: bounded_file(output / e["path"], DIAGNOSTIC_LIMIT) for e in files}
    for entry in files:
        value = raw[entry["path"]]
        if len(value) != entry["bytes"] or sha256_bytes(value) != entry["sha256"]:
            raise ValueError("Refused report bytes changed")
    if json.loads(raw["report.json"]) != report or raw["report.html"] != render(report):
        raise ValueError("Refused report differs from native reconstruction")
    return {
        "contract": "corpus-report-only-recovery-diagnosis-v1",
        "candidate_id": key,
        "attempt_manifest_sha256": replay["manifest_sha256"],
        "refused_report_manifest_sha256": sha256_bytes(manifest_raw),
        "refused_report_members": files,
        "v1_accepted": False,
        "native_execution_finished": True,
        "reconstruction_equal": True,
        "diagnostic_only_read_limit": DIAGNOSTIC_LIMIT,
        "scanner_invocations": 0,
        "originals_modified": False,
    }


@contextmanager
def lock(root: Path) -> Iterator[None]:
    plain_path(root, directory=True)
    path = root / ".writer.lock"
    if path.exists():
        plain_path(path, directory=False)
    with portalocker.Lock(str(path), mode="a+", timeout=0):
        yield


def parent_state(project: Path, parent: Path, key: str, *, current: bool = False) -> dict[str, Any]:
    state = legacy._status(project, parent, current=current)
    failures = [r for r in state["rows"] if r["state"] == "failed"]
    if (
        len(failures) != 1
        or failures[0]["candidate_id"] != key
        or any(r["state"] == "interrupted-or-running" for r in state["rows"])
        or not state["blocked"]
        or not failures[0]["error"].startswith("ValidationError:")
        or "RetainedManifest" not in failures[0]["error"]
    ):
        raise ValueError("Parent is not the approved report-size failure")
    return state


def prepare(project: Path, parent: Path, output: Path, key: str, *, approved: bool) -> LinkedPlan:
    if not approved:
        raise ValueError("Explicit report-only recovery approval required")
    project = plain_path(project, directory=True)
    parent = legacy.workspace_path(project, parent)
    output = legacy.workspace_path(project, output)
    if output.exists() or output.is_relative_to(parent) or parent.is_relative_to(output):
        raise ValueError("Use a fresh separate linked collection")
    with lock(parent):
        state = parent_state(project, parent, key, current=True)
        source, _ = legacy.load(project, parent, current=True)
        diagnosis = diagnose(project, parent, key)
        material = {"frozen/" + p: bounded_file(project / p, 1024**2) for p in PINS}
        material["recovery.json"] = reports.encoded(diagnosis)
        output.mkdir()
        for name in ("events", "attempts", "reports"):
            (output / name).mkdir()
        references = []
        for row, entry in zip(state["rows"], source.entries, strict=True):
            if row["state"] == "pending":
                continue
            attempt = Path(row["attempt"])
            if (
                sha256_file(attempt / "plan.json") != entry.plan_sha256
                or sha256_file(attempt / "admission.json") != entry.admission_sha256
            ):
                raise ValueError("Recovery/reference differs from admitted treatment")
            report = output / "reports" / entry.candidate_id
            if not reports.write_report(project, attempt, report)["execution_finished"]:
                raise ValueError("Reference report incomplete")
            origin: Origin = (
                "report-only-recovery"
                if row["state"] == "failed"
                else "completed-parent"
                if row["state"] == "completed"
                else "existing-reference"
            )
            references.append(
                Reference(
                    candidate_id=entry.candidate_id,
                    attempt=str(attempt),
                    attempt_manifest_sha256=sha256_file(attempt / "evidence-manifest.json"),
                    report_manifest_sha256=sha256_file(report / "evidence-manifest.json"),
                    origin=origin,
                )
            )
            print(entry.candidate_id + ": report rebuilt from native evidence; no scan", flush=True)
        plan = LinkedPlan(
            root=str(output),
            parent=str(parent),
            created_at=datetime.now(UTC),
            parent_input_sha256=state["input_manifest_sha256"],
            parent_head_sha256=state["journal_head_sha256"],
            recovery_candidate=key,
            recovery_authorization="user-approved-report-only-recovery",
            references=tuple(references),
            frozen_pins={p: sha256_bytes(raw) for p, raw in material.items()},
        )
        for path, raw in material.items():
            atomic_write_bytes(output / "inputs" / path, raw)
        save(output / "inputs/plan.json", plan.model_dump(mode="json"))
        save(
            output / "inputs/evidence-manifest.json", {"files": evidence_records(output / "inputs")}
        )
        return plan


def load(project: Path, root: Path, *, current: bool = False) -> tuple[LinkedPlan, Any, str]:
    retained = read_retained_research(root / "inputs")
    plan = LinkedPlan.model_validate_json(retained.read("plan.json"))
    expected = {"frozen/" + p for p in PINS} | {"recovery.json"}
    if (
        plan.root != str(root)
        or set(plan.frozen_pins) != expected
        or set(retained.files) != expected | {"plan.json"}
    ):
        raise ValueError("Linked plan root or membership differs")
    for name, digest in plan.frozen_pins.items():
        if sha256_bytes(retained.read(name)) != digest:
            raise ValueError("Frozen linked input changed")
        if (
            current
            and name.startswith("frozen/")
            and sha256_file(project / name.removeprefix("frozen/")) != digest
        ):
            raise ValueError("Linked harness changed; use a new plan")
    parent = legacy.workspace_path(project, Path(plan.parent))
    with lock(parent):
        state = parent_state(project, parent, plan.recovery_candidate, current=current)
        if (
            state["input_manifest_sha256"] != plan.parent_input_sha256
            or state["journal_head_sha256"] != plan.parent_head_sha256
        ):
            raise ValueError("Parent journal or inputs changed")
        source, _ = legacy.load(project, parent, current=current)
        diagnosis = diagnose(project, parent, plan.recovery_candidate)
        if reports.encoded(diagnosis) != retained.read("recovery.json"):
            raise ValueError("Recovery evidence changed")
    inherited = [r for r in state["rows"] if r["state"] != "pending"]
    if [r.candidate_id for r in plan.references] != [r["candidate_id"] for r in inherited]:
        raise ValueError("Linked reference membership differs")
    for reference, row in zip(plan.references, inherited, strict=True):
        origin = (
            "report-only-recovery"
            if row["state"] == "failed"
            else "completed-parent"
            if row["state"] == "completed"
            else "existing-reference"
        )
        if reference.attempt != row["attempt"] or reference.origin != origin:
            raise ValueError("Reference provenance differs")
    return plan, source, retained.manifest_sha256


def _status(project: Path, root: Path, *, current: bool = False) -> dict[str, Any]:
    plan, source, previous = load(project, root, current=current)
    if {p.name for p in root.iterdir()} - {
        "inputs",
        "events",
        "attempts",
        "reports",
        ".writer.lock",
    }:
        raise ValueError("Unexpected linked collection member")
    refs = {r.candidate_id: r for r in plan.references}
    pending = [e for e in source.entries if e.candidate_id not in refs]
    states = dict.fromkeys((e.candidate_id for e in pending), "pending")
    finishes = {}
    plain_path(root / "events", directory=True)
    events = sorted((root / "events").iterdir())
    active = None
    failed = False
    index = 0
    for sequence, path in enumerate(events, 1):
        raw = bounded_file(path, 64 * 1024)
        event = legacy.Event.model_validate_json(raw)
        if (
            path.name != f"{sequence:04d}.json"
            or event.sequence != sequence
            or event.previous_sha256 != previous
            or failed
            or index >= len(pending)
            or event.candidate_id != pending[index].candidate_id
        ):
            raise ValueError("Linked journal chain or order differs")
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
                raise ValueError("Invalid linked start")
            active = event.candidate_id
            states[active] = "interrupted-or-running"
        else:
            if active != event.candidate_id or event.outcome is None:
                raise ValueError("Linked finish without start")
            if event.outcome == "completed" and (
                event.error is not None
                or event.attempt_manifest_sha256 is None
                or event.report_manifest_sha256 is None
            ):
                raise ValueError("Incomplete successful linked finish")
            if event.outcome == "failed" and not event.error:
                raise ValueError("Failed linked finish requires explanation")
            states[active] = event.outcome
            finishes[active] = event
            failed = event.outcome == "failed"
            active = None
            index += 1
    started = {k for k, v in states.items() if v != "pending"}
    for folder, allowed in (("attempts", started), ("reports", started | set(refs))):
        plain_path(root / folder, directory=True)
        if {p.name for p in (root / folder).iterdir()} - allowed:
            raise ValueError("Unscheduled linked attempt or report")
    rows = []
    for entry in source.entries:
        key = entry.candidate_id
        reference = refs.get(key)
        finish = finishes.get(key)
        state = reference.origin if reference else states[key]
        attempt = Path(reference.attempt) if reference else root / "attempts" / key
        digest = (
            reference.attempt_manifest_sha256
            if reference
            else finish.attempt_manifest_sha256
            if finish
            else None
        )
        if digest is not None and sha256_file(attempt / "evidence-manifest.json") != digest:
            raise ValueError("Linked native manifest changed")
        count = None
        if reference or state == "completed":
            replay = verify_core(project, attempt)
            report = root / "reports" / key
            if reference is not None:
                report_hash = reference.report_manifest_sha256
            elif finish is not None and finish.report_manifest_sha256 is not None:
                report_hash = finish.report_manifest_sha256
            else:
                raise ValueError("Missing linked finish")
            if (
                not replay["execution_finished"]
                or sha256_file(attempt / "plan.json") != entry.plan_sha256
                or sha256_file(attempt / "admission.json") != entry.admission_sha256
                or sha256_file(report / "evidence-manifest.json") != report_hash
                or not reports.verify_report(project, attempt, report)["execution_finished"]
            ):
                raise ValueError("Linked treatment or report differs")
            count = sum(r["state"] == "observed" for r in replay["rows"])
        rows.append(
            {
                "candidate_id": key,
                "state": state,
                "forecast_invocations": entry.forecast_invocations,
                "verified_observed_cells": count,
                "attempt": str(attempt) if state != "pending" else None,
                "report": str(root / "reports" / key)
                if reference or state == "completed"
                else None,
                "error": finish.error if finish else None,
            }
        )
    return {
        "contract": "corpus-collection-status-v2",
        "rows": rows,
        "blocked": failed or active is not None,
        "finished": all(
            r["state"] not in {"pending", "failed", "interrupted-or-running"} for r in rows
        ),
        "events": len(events),
        "journal_head_sha256": previous,
        "input_manifest_sha256": sha256_file(root / "inputs/evidence-manifest.json"),
        "parent": plan.parent,
        "parent_remains_failed": True,
        "parent_head_sha256": plan.parent_head_sha256,
        "recovery_scanner_invocations": 0,
        "scanner_invocations_during_status": 0,
    }


def status(project: Path, root: Path) -> dict[str, Any]:
    project = plain_path(project, directory=True)
    root = legacy.workspace_path(project, root)
    with lock(root):
        return _status(project, root)


def run_next(project: Path, root: Path) -> dict[str, Any]:
    project = plain_path(project, directory=True)
    root = legacy.workspace_path(project, root)
    with lock(root):
        progress = _status(project, root, current=True)
        if progress["blocked"]:
            raise ValueError("Failed or interrupted linked collection blocks; no retries")
        if progress["finished"]:
            return progress
        plan, source, _ = load(project, root, current=True)
        key = next(r["candidate_id"] for r in progress["rows"] if r["state"] == "pending")
        entry = next(e for e in source.entries if e.candidate_id == key)
        sequence = progress["events"] + 1
        legacy._append(
            root,
            sequence=sequence,
            previous_sha256=progress["journal_head_sha256"],
            candidate_id=key,
            kind="start",
        )
        previous = sha256_file(root / "events" / f"{sequence:04d}.json")
        attempt, report = root / "attempts" / key, root / "reports" / key
        try:
            run_core(
                project,
                Path(entry.preparation),
                Path(plan.parent) / f"inputs/admissions/{key}.json",
                attempt,
            )
            if not reports.write_report(project, attempt, report)["execution_finished"]:
                raise ValueError("Linked attempt is incomplete")
        except BaseException as exc:
            manifest = attempt / "evidence-manifest.json"
            legacy._append(
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
        legacy._append(
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
    parser.add_argument("--parent", type=Path)
    parser.add_argument("--recover")
    parser.add_argument("--approve-report-only-recovery", action="store_true")
    parser.add_argument("--count", type=int, default=1, choices=range(1, 21))
    args = parser.parse_args()
    if args.mode == "prepare":
        if not args.parent or not args.recover or not args.approve_report_only_recovery:
            parser.error("prepare requires parent, recover ID and explicit report-only approval")
        prepare(args.project, args.parent, args.output, args.recover, approved=True)
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
