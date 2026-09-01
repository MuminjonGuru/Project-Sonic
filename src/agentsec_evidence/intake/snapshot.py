from __future__ import annotations

import mimetypes
import os
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from agentsec_evidence.core.identity import canonical_json_bytes, semantic_hash, sha256_bytes
from agentsec_evidence.core.io import atomic_write_bytes, atomic_write_model, jsonl_bytes
from agentsec_evidence.core.paths import normalize_relative_path
from agentsec_evidence.core.time import utc_now
from agentsec_evidence.models.contracts import InventoryEntry, TargetSnapshot


class SnapshotError(RuntimeError):
    """Base error for a target that cannot be snapshotted safely."""


class UnsafeTargetError(SnapshotError):
    """The target violates a safety boundary."""


class SnapshotLimitError(SnapshotError):
    """The target exceeds an explicit snapshot limit."""


class SnapshotPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_files: int = Field(default=10_000, gt=0)
    max_total_bytes: int = Field(default=256 * 1024 * 1024, gt=0)
    max_file_bytes: int = Field(default=32 * 1024 * 1024, gt=0)
    excluded_root_names: frozenset[str] = frozenset({".git"})
    reject_symlinks: bool = True


@dataclass(frozen=True)
class SnapshotResult:
    snapshot: TargetSnapshot
    inventory: tuple[InventoryEntry, ...]
    snapshot_root: Path
    content_root: Path


@dataclass(frozen=True)
class _SourceFile:
    source_path: Path
    relative_path: str
    data: bytes
    sha256: str
    media_type: str


def _media_type(path: Path) -> str:
    guessed, _encoding = mimetypes.guess_type(path.name)
    return guessed or "application/octet-stream"


def _collect_files(source: Path, policy: SnapshotPolicy) -> list[_SourceFile]:
    files: list[_SourceFile] = []
    portable_paths: set[str] = set()
    total_bytes = 0

    for root, directory_names, file_names in os.walk(source, topdown=True, followlinks=False):
        root_path = Path(root)
        directory_names.sort()
        file_names.sort()

        retained_directories: list[str] = []
        for directory_name in directory_names:
            directory = root_path / directory_name
            if directory.is_symlink() and policy.reject_symlinks:
                relative = normalize_relative_path(directory.relative_to(source).as_posix())
                raise UnsafeTargetError(f"Symbolic-link directory rejected: {relative}")
            if root_path == source and directory_name in policy.excluded_root_names:
                continue
            retained_directories.append(directory_name)
        directory_names[:] = retained_directories

        for file_name in file_names:
            file_path = root_path / file_name
            relative = normalize_relative_path(file_path.relative_to(source).as_posix())
            portable_key = relative.casefold()
            if portable_key in portable_paths:
                raise UnsafeTargetError(f"Portable path collision rejected: {relative}")
            portable_paths.add(portable_key)
            if file_path.is_symlink() and policy.reject_symlinks:
                raise UnsafeTargetError(f"Symbolic-link file rejected: {relative}")
            if not file_path.is_file():
                raise UnsafeTargetError(f"Non-regular file rejected: {relative}")

            stat = file_path.stat(follow_symlinks=False)
            if stat.st_size > policy.max_file_bytes:
                raise SnapshotLimitError(f"File exceeds byte limit: {relative}")
            if len(files) >= policy.max_files:
                raise SnapshotLimitError("Target exceeds file-count limit")
            total_bytes += stat.st_size
            if total_bytes > policy.max_total_bytes:
                raise SnapshotLimitError("Target exceeds total-byte limit")

            data = file_path.read_bytes()
            if len(data) != stat.st_size:
                raise SnapshotError(f"File changed while reading: {relative}")
            files.append(
                _SourceFile(
                    source_path=file_path,
                    relative_path=relative,
                    data=data,
                    sha256=sha256_bytes(data),
                    media_type=_media_type(file_path),
                )
            )

    return files


def _snapshot_identity(files: list[_SourceFile]) -> str:
    values = [
        {"byte_length": len(file.data), "path": file.relative_path, "sha256": file.sha256}
        for file in files
    ]
    return semantic_hash(cast(JsonValue, values))


def _verify_existing_snapshot(
    *,
    final_root: Path,
    expected: TargetSnapshot,
    inventory: tuple[InventoryEntry, ...],
    inventory_data: bytes,
) -> TargetSnapshot:
    if final_root.is_symlink() or not final_root.is_dir():
        raise SnapshotError("Existing snapshot root is not a regular directory")
    existing = TargetSnapshot.model_validate_json((final_root / "snapshot.json").read_bytes())
    provenance_fields = (
        "target_id",
        "snapshot_id",
        "source_kind",
        "source_label",
        "revision",
        "license_status",
        "content_sha256",
        "inventory_sha256",
        "file_count",
        "total_bytes",
    )
    mismatched = [
        field for field in provenance_fields if getattr(existing, field) != getattr(expected, field)
    ]
    if mismatched:
        raise SnapshotError(
            f"Existing snapshot provenance or identity mismatch: {', '.join(mismatched)}"
        )
    inventory_path = final_root / "inventory.jsonl"
    if inventory_path.read_bytes() != inventory_data:
        raise SnapshotError("Existing snapshot inventory bytes do not match the source")

    content_root = final_root / "content"
    expected_entries = {entry.path: entry for entry in inventory}
    actual_paths: dict[str, Path] = {}
    for path in content_root.rglob("*"):
        relative = normalize_relative_path(path.relative_to(content_root).as_posix())
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            raise SnapshotError(f"Existing snapshot contains an unsafe entry: {relative}")
        if path.is_file():
            actual_paths[relative] = path
    if set(actual_paths) != set(expected_entries):
        raise SnapshotError("Existing snapshot content file set does not match its inventory")
    for relative, path in actual_paths.items():
        entry = expected_entries[relative]
        if (
            path.stat().st_size != entry.byte_length
            or sha256_bytes(path.read_bytes()) != entry.sha256
        ):
            raise SnapshotError(f"Existing snapshot content hash mismatch: {relative}")
    return existing


def create_snapshot(
    source: Path,
    destination_root: Path,
    *,
    source_label: str,
    revision: str,
    source_kind: Literal["project-fixture", "local", "git"] = "project-fixture",
    license_status: Literal["project-authored-private", "identified", "unknown"] = (
        "project-authored-private"
    ),
    policy: SnapshotPolicy | None = None,
) -> SnapshotResult:
    resolved_source = source.resolve(strict=True)
    if not resolved_source.is_dir():
        raise UnsafeTargetError("Snapshot source must be a directory")

    active_policy = policy or SnapshotPolicy()
    files = _collect_files(resolved_source, active_policy)
    content_sha256 = _snapshot_identity(files)
    snapshot_id = f"snapshot_{content_sha256}"
    target_id = f"target_{sha256_bytes(source_label.encode('utf-8'))[:32]}"

    inventory = tuple(
        InventoryEntry(
            path=file.relative_path,
            sha256=file.sha256,
            byte_length=len(file.data),
            media_type=file.media_type,
        )
        for file in files
    )
    inventory_data = jsonl_bytes(inventory)
    inventory_sha256 = sha256_bytes(inventory_data)
    snapshot = TargetSnapshot(
        target_id=target_id,
        snapshot_id=snapshot_id,
        source_kind=source_kind,
        source_label=source_label,
        revision=revision,
        retrieved_at=utc_now(),
        license_status=license_status,
        content_sha256=content_sha256,
        inventory_sha256=inventory_sha256,
        file_count=len(files),
        total_bytes=sum(len(file.data) for file in files),
    )

    destination_root.mkdir(parents=True, exist_ok=True)
    final_root = destination_root / snapshot_id
    if final_root.exists():
        existing_snapshot = _verify_existing_snapshot(
            final_root=final_root,
            expected=snapshot,
            inventory=inventory,
            inventory_data=inventory_data,
        )
        return SnapshotResult(existing_snapshot, inventory, final_root, final_root / "content")

    temporary_root = destination_root / f".{snapshot_id}.{uuid.uuid4().hex}.tmp"
    content_root = temporary_root / "content"
    try:
        for file in files:
            target_path = content_root.joinpath(*file.relative_path.split("/"))
            atomic_write_bytes(target_path, file.data)
            if sha256_bytes(target_path.read_bytes()) != file.sha256:
                raise SnapshotError(f"Copied snapshot hash mismatch: {file.relative_path}")
        atomic_write_bytes(temporary_root / "inventory.jsonl", inventory_data)
        atomic_write_model(temporary_root / "snapshot.json", snapshot)
        os.replace(temporary_root, final_root)
    except BaseException:
        shutil.rmtree(temporary_root, ignore_errors=True)
        raise

    return SnapshotResult(snapshot, inventory, final_root, final_root / "content")


def snapshot_semantic_document(snapshot: TargetSnapshot) -> bytes:
    value = snapshot.model_dump(mode="json", exclude={"retrieved_at"})
    return canonical_json_bytes(value)
