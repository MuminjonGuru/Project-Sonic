from __future__ import annotations

import shutil
from collections.abc import Iterable
from pathlib import Path
from typing import IO

import portalocker
from pydantic import BaseModel, JsonValue

from agentsec_evidence.core.identity import new_opaque_id, semantic_hash, sha256_file
from agentsec_evidence.core.io import (
    append_model_jsonl,
    atomic_write_bytes,
    atomic_write_jsonl,
    atomic_write_model,
)
from agentsec_evidence.core.paths import normalize_relative_path
from agentsec_evidence.core.time import utc_now
from agentsec_evidence.intake.snapshot import SnapshotResult
from agentsec_evidence.models.contracts import (
    BundleManifest,
    ManifestEntry,
    RunEvent,
    RunRecord,
    RunState,
    Sensitivity,
)

_ALLOWED_TRANSITIONS: dict[RunState, frozenset[RunState]] = {
    RunState.CREATED: frozenset({RunState.READY, RunState.REJECTED}),
    RunState.READY: frozenset({RunState.PLANNED, RunState.REJECTED}),
    RunState.PLANNED: frozenset({RunState.RUNNING, RunState.REJECTED}),
    RunState.RUNNING: frozenset(
        {
            RunState.CAPTURED,
            RunState.TIMED_OUT,
            RunState.CANCELLED,
            RunState.EXECUTION_FAILED,
        }
    ),
    RunState.CAPTURED: frozenset({RunState.PARSING}),
    RunState.PARSING: frozenset({RunState.NORMALIZING, RunState.PARTIAL, RunState.PARSE_FAILED}),
    RunState.NORMALIZING: frozenset({RunState.VALIDATING, RunState.PARTIAL}),
    RunState.VALIDATING: frozenset(
        {RunState.COMPLETE, RunState.PARTIAL, RunState.VALIDATION_FAILED}
    ),
    RunState.COMPLETE: frozenset({RunState.FINALIZED}),
    RunState.PARTIAL: frozenset({RunState.FINALIZED}),
    RunState.TIMED_OUT: frozenset({RunState.FINALIZED}),
    RunState.CANCELLED: frozenset({RunState.FINALIZED}),
    RunState.EXECUTION_FAILED: frozenset({RunState.FINALIZED}),
    RunState.PARSE_FAILED: frozenset({RunState.FINALIZED}),
    RunState.VALIDATION_FAILED: frozenset({RunState.FINALIZED}),
    RunState.REJECTED: frozenset({RunState.FINALIZED}),
    RunState.FINALIZED: frozenset(),
    RunState.ACQUIRING: frozenset(),
}


def _default_sensitivity(relative_path: str) -> Sensitivity:
    if relative_path.startswith(("executions/", "normalized/", "exports/")):
        return Sensitivity.INTERNAL
    return Sensitivity.METADATA_ONLY


class RunBundle:
    def __init__(self, root: Path, run: RunRecord) -> None:
        self.root = root
        self.run = run
        self._lock = portalocker.Lock(str(root / ".write.lock"), mode="a+", timeout=0)
        self._lock_handle: IO[str] | None = self._lock.acquire()
        self._finalized = False

    @classmethod
    def create(
        cls,
        workspace_root: Path,
        *,
        run_label: str,
        profile_id: str,
        config_sha256: str,
        snapshot_result: SnapshotResult,
    ) -> RunBundle:
        run_id = new_opaque_id("run")
        root = workspace_root / "runs" / run_id
        root.mkdir(parents=True, exist_ok=False)
        run = RunRecord(
            run_id=run_id,
            run_label=run_label,
            profile_id=profile_id,
            target_snapshot_id=snapshot_result.snapshot.snapshot_id,
            state=RunState.CREATED,
            created_at=utc_now(),
            config_sha256=config_sha256,
        )
        bundle = cls(root, run)
        atomic_write_model(root / "run.json", run)
        bundle._append_event(None, RunState.CREATED, "run bundle created")
        target_root = root / "target"
        target_root.mkdir(parents=True)
        shutil.copyfile(
            snapshot_result.snapshot_root / "snapshot.json", target_root / "snapshot.json"
        )
        shutil.copyfile(
            snapshot_result.snapshot_root / "inventory.jsonl", target_root / "inventory.jsonl"
        )
        bundle.transition(RunState.READY, "immutable target snapshot linked")
        return bundle

    def __enter__(self) -> RunBundle:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        if not self._finalized:
            self.close()

    def _append_event(
        self, previous_state: RunState | None, next_state: RunState, reason: str
    ) -> None:
        event = RunEvent(
            event_id=new_opaque_id("event"),
            run_id=self.run.run_id,
            occurred_at=utc_now(),
            component="orchestrator",
            previous_state=previous_state,
            next_state=next_state,
            reason=reason,
        )
        append_model_jsonl(self.root / "events.jsonl", event)

    def transition(self, next_state: RunState, reason: str) -> None:
        if self._finalized:
            raise RuntimeError("Finalized bundle cannot transition")
        previous = self.run.state
        if next_state not in _ALLOWED_TRANSITIONS[previous]:
            raise ValueError(f"Invalid run transition: {previous} -> {next_state}")
        self.run.state = next_state
        self._append_event(previous, next_state, reason)
        atomic_write_model(self.root / "run.json", self.run)

    def add_execution_id(self, execution_id: str) -> None:
        if execution_id not in self.run.execution_ids:
            self.run.execution_ids.append(execution_id)
            atomic_write_model(self.root / "run.json", self.run)

    def write_bytes(self, relative_path: str, data: bytes) -> Path:
        if self._finalized:
            raise RuntimeError("Finalized bundle is immutable")
        normalized = normalize_relative_path(relative_path)
        destination = self.root.joinpath(*normalized.split("/"))
        if destination.exists():
            raise FileExistsError(f"Raw product is write-once: {normalized}")
        atomic_write_bytes(destination, data)
        return destination

    def write_model(self, relative_path: str, model: BaseModel) -> Path:
        if self._finalized:
            raise RuntimeError("Finalized bundle is immutable")
        normalized = normalize_relative_path(relative_path)
        destination = self.root.joinpath(*normalized.split("/"))
        atomic_write_model(destination, model)
        return destination

    def write_jsonl(self, relative_path: str, models: Iterable[BaseModel]) -> Path:
        if self._finalized:
            raise RuntimeError("Finalized bundle is immutable")
        normalized = normalize_relative_path(relative_path)
        destination = self.root.joinpath(*normalized.split("/"))
        atomic_write_jsonl(destination, models)
        return destination

    def finalize(self, *, semantic_document: JsonValue) -> BundleManifest:
        if self.run.state not in {
            RunState.COMPLETE,
            RunState.PARTIAL,
            RunState.TIMED_OUT,
            RunState.CANCELLED,
            RunState.EXECUTION_FAILED,
            RunState.PARSE_FAILED,
            RunState.VALIDATION_FAILED,
            RunState.REJECTED,
        }:
            raise ValueError(f"Run cannot be finalized from state {self.run.state}")

        self.run.terminal_state = self.run.state
        self.run.semantic_sha256 = semantic_hash(semantic_document)
        self.run.finalized_at = utc_now()
        self.transition(RunState.FINALIZED, "bundle finalized")

        entries: list[ManifestEntry] = []
        for path in sorted(self.root.rglob("*"), key=lambda item: item.as_posix()):
            if path.name in {".write.lock", "bundle-manifest.json"}:
                continue
            if path.is_symlink():
                raise RuntimeError(f"Symlink in run bundle: {path}")
            if not path.is_file():
                continue
            relative = normalize_relative_path(path.relative_to(self.root).as_posix())
            entries.append(
                ManifestEntry(
                    relative_path=relative,
                    sha256=sha256_file(path),
                    byte_length=path.stat().st_size,
                    sensitivity=_default_sensitivity(relative),
                )
            )

        entry_values: JsonValue = [entry.model_dump(mode="json") for entry in entries]
        entries_sha256 = semantic_hash(entry_values)
        manifest = BundleManifest(
            bundle_id=f"bundle_{entries_sha256}",
            run_id=self.run.run_id,
            created_at=utc_now(),
            entries=entries,
            entries_sha256=entries_sha256,
        )
        atomic_write_model(self.root / "bundle-manifest.json", manifest)
        self._finalized = True
        self.close()
        return manifest

    def close(self) -> None:
        if self._lock_handle is not None:
            self._lock.release()
            self._lock_handle = None
        (self.root / ".write.lock").unlink(missing_ok=True)
