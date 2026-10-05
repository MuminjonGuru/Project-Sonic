from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Literal

from pydantic import Field, JsonValue, StrictInt

from agentsec_evidence.agents.inventory import build_artifact_inventory
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes, sha256_file
from agentsec_evidence.core.io import atomic_write_bytes, atomic_write_model, json_bytes
from agentsec_evidence.core.time import utc_now
from agentsec_evidence.intake.git_verification import (
    MAX_TREE_BYTES,
    GitEvidenceModel,
    GitOid,
    bind_inventory_to_git,
)
from agentsec_evidence.intake.snapshot import create_snapshot
from agentsec_evidence.intake.source_archive import (
    MAX_ARCHIVE_BYTES,
    MAX_COMMIT_RESPONSE_BYTES,
    recover_github_commit,
    verify_source_archive,
)
from agentsec_evidence.intake.views import read_verified_source
from agentsec_evidence.models.contracts import NonEmpty, Sha256


class SourcePreparationSpec(GitEvidenceModel):
    contract: Literal["source-preparation-spec-v1"] = "source-preparation-spec-v1"
    source_label: NonEmpty
    revision: GitOid
    root_tree: GitOid
    archive_sha256: Sha256
    commit_response_sha256: Sha256
    tree_response_sha256: Sha256
    expected_files: StrictInt = Field(ge=1, le=10_000)
    expected_bytes: StrictInt = Field(ge=1, le=256 * 1024 * 1024)
    license_status: Literal["identified", "unknown"]
    split: Literal["pilot-not-held-out"] = "pilot-not-held-out"
    source_scanning_authorization: Literal["not-granted"] = "not-granted"


def _plain(path: Path) -> os.stat_result:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or (
        getattr(metadata, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise ValueError("Evidence paths must not contain links or reparse points")
    return metadata


def _directory(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    for ancestor in (*reversed(absolute.parents), absolute):
        if not stat.S_ISDIR(_plain(ancestor).st_mode):
            raise ValueError("Evidence directory must have plain directory ancestors")
    return absolute


def _read_input(path: Path, *, limit: int) -> bytes:
    _directory(path.parent)
    metadata = _plain(path)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > limit:
        raise ValueError("Input must be a bounded, non-hard-linked regular file")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) != metadata.st_size or len(data) > limit:
        raise ValueError("Input size changed or exceeds limit")
    return data


def prepare_cached_source(
    spec: SourcePreparationSpec, *, cache: Path, output: Path
) -> dict[str, JsonValue]:
    """Prepare cached evidence offline; no fetching, target parsing or scanner permission.

    A new attempt directory is mandatory. Failures retain their inputs and a failed summary;
    earlier receipts and the cached dependency pilot are never changed.
    """
    spec = SourcePreparationSpec.model_validate(spec.model_dump(mode="json"))
    cache = _directory(cache)
    destination = Path(os.path.abspath(output))
    _directory(destination.parent)
    if destination.is_relative_to(cache) or cache.is_relative_to(destination):
        raise ValueError("Preparation output and cache must not overlap")
    destination.mkdir(exist_ok=False)
    summary: dict[str, JsonValue] = {
        "contract": "source-preparation-receipt-v1",
        "prepared_at": utc_now().isoformat(),
        "passed": False,
        "stage": "read-cached-evidence",
        "provenance": "cached-evidence-reverification-not-new-acquisition",
        "split": spec.split,
        "spec_sha256": semantic_hash(spec.model_dump(mode="json")),
        "scanner_invocations": 0,
        "target_code_executed": False,
        "content_parsing": "not-performed",
        "source_scanning_authorization": "not-granted",
        "origin_authentication": "not-established",
        "author_signature_verification": "not-performed",
        "held_out_eligible": False,
    }
    try:
        atomic_write_model(destination / "preparation-spec.json", spec)
        raw: dict[str, bytes] = {}
        for name, limit, expected in (
            ("commit.json", MAX_COMMIT_RESPONSE_BYTES, spec.commit_response_sha256),
            ("tree-exact.json", MAX_TREE_BYTES, spec.tree_response_sha256),
            ("source.zip", MAX_ARCHIVE_BYTES, spec.archive_sha256),
        ):
            data = _read_input(cache / name, limit=limit)
            atomic_write_bytes(destination / "raw" / name, data)
            if sha256_bytes(data) != expected:
                raise ValueError(f"Cached {name} differs from the preparation specification")
            raw[name] = data
        summary["stage"] = "verify-git-objects"
        commit = recover_github_commit(raw["commit.json"], revision=spec.revision)
        atomic_write_bytes(destination / "raw/commit.bin", commit)
        verified = verify_source_archive(
            archive=raw["source.zip"],
            archive_sha256=spec.archive_sha256,
            raw_commit=commit,
            raw_tree=raw["tree-exact.json"],
            revision=spec.revision,
        )
        proof = verified.verification
        if (
            proof.root_tree != spec.root_tree
            or len(proof.files) != spec.expected_files
            or sum(len(data) for data in verified.files.values()) != spec.expected_bytes
        ):
            raise ValueError("Verified inventory differs from the preparation specification")
        atomic_write_model(destination / "git-verification.json", proof)
        summary["stage"] = "materialize-and-replay"
        source = destination / "source"
        source.mkdir()
        for name, data in verified.files.items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(data)
        snapshot = create_snapshot(
            source,
            destination / "snapshots",
            source_label=spec.source_label,
            revision=spec.revision,
            source_kind="git",
            license_status=spec.license_status,
        )
        inventory = build_artifact_inventory(snapshot.snapshot, snapshot.inventory)
        bind_inventory_to_git(inventory, proof)
        for root in (source, snapshot.content_root):
            read_verified_source(
                proof, raw_commit=commit, raw_tree=raw["tree-exact.json"], source_root=root
            )
        atomic_write_model(destination / "artifact-inventory.json", inventory)
        summary.update(
            passed=True,
            stage="complete",
            revision=proof.revision,
            root_tree=proof.root_tree,
            files_verified=len(proof.files),
            verified_bytes=snapshot.snapshot.total_bytes,
            source_content_sha256=snapshot.snapshot.content_sha256,
            git_verification_sha256=semantic_hash(proof.model_dump(mode="json")),
            source_and_snapshot_reverified=True,
        )
    except Exception as error:
        summary["error_type"] = type(error).__name__
        summary["error"] = str(error)
        raise
    finally:
        atomic_write_bytes(destination / "summary.json", json_bytes(summary))
        records: list[JsonValue] = [
            {
                "path": path.relative_to(destination).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for path in sorted(destination.rglob("*"))
            if path.is_file()
        ]
        atomic_write_bytes(destination / "evidence-manifest.json", json_bytes({"files": records}))
    return summary
