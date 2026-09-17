from __future__ import annotations

import hashlib
import json
import stat
import zipfile
from pathlib import Path

from pydantic import JsonValue

from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.core.paths import normalize_relative_path
from agentsec_evidence.intake.snapshot import SnapshotPolicy


def materialize_pinned_archive(
    *,
    archive: Path,
    git_tree: Path,
    commit_record: Path,
    revision: str,
    destination: Path,
) -> dict[str, JsonValue]:
    """Verify every Git blob before writing a bounded source-only checkout; never execute it."""
    tree = json.loads(git_tree.read_bytes())
    commit = json.loads(commit_record.read_bytes())
    if commit["sha"] != revision or tree["sha"] != commit["commit"]["tree"]["sha"]:
        raise ValueError("Commit/tree identity mismatch")
    if tree.get("truncated"):
        raise ValueError("Truncated Git tree cannot establish a complete source snapshot")
    blobs = {}
    for item in tree["tree"]:
        if item["type"] == "tree":
            continue
        if item["type"] != "blob" or item["mode"] not in {"100644", "100755"}:
            raise ValueError("Symlink, submodule or unsupported Git entry rejected")
        path = normalize_relative_path(item["path"])
        if path in blobs or ":" in path:
            raise ValueError("Duplicate or nonportable Git path")
        blobs[path] = item
    policy = SnapshotPolicy()
    if len(blobs) > policy.max_files:
        raise ValueError("Source exceeds file-count limit")
    if destination.exists():
        raise ValueError("Refusing to overwrite an intake directory")
    files: dict[str, bytes] = {}
    portable: set[str] = set()
    total = 0
    prefix: str | None = None
    with zipfile.ZipFile(archive) as zipped:
        for member in zipped.infolist():
            if member.is_dir():
                continue
            if stat.S_ISLNK(member.external_attr >> 16):
                raise ValueError("Archive symlink rejected")
            parts = member.filename.split("/", 1)
            if len(parts) != 2:
                raise ValueError("Expected one GitHub archive prefix")
            if prefix is None:
                prefix = parts[0]
            if parts[0] != prefix:
                raise ValueError("Multiple archive roots rejected")
            path = normalize_relative_path(parts[1])
            if path not in blobs or path.casefold() in portable:
                raise ValueError("Unexpected or case-colliding archive path")
            portable.add(path.casefold())
            total += member.file_size
            if member.file_size > policy.max_file_bytes or total > policy.max_total_bytes:
                raise ValueError("Archive exceeds snapshot byte limits")
            data = zipped.read(member)
            header = f"blob {len(data)}\0".encode("ascii")
            # SHA-1 is the upstream Git object identity, not our evidence integrity hash.
            digest = hashlib.sha1(header + data, usedforsecurity=False).hexdigest()
            if digest != blobs[path]["sha"] or len(data) != blobs[path]["size"]:
                raise ValueError("Archive content does not match the pinned Git tree")
            files[path] = data
    if set(files) != set(blobs):
        raise ValueError("Archive is missing Git tree files")
    destination.mkdir(parents=True, exist_ok=False)
    entries: list[JsonValue] = []
    for name, data in sorted(files.items()):
        target = destination / name
        if not target.resolve().is_relative_to(destination.resolve()):
            raise ValueError("Intake path escaped its destination")
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as handle:
            handle.write(data)
        entries.append(
            {
                "path": name,
                "sha256": sha256_bytes(data),
                "bytes": len(data),
                "git_blob": blobs[name]["sha"],
            }
        )
    return {
        "revision": revision,
        "tree": tree["sha"],
        "file_count": len(files),
        "total_bytes": total,
        "archive_sha256": sha256_file(archive),
        "files": entries,
        "executed_target_code": False,
    }
