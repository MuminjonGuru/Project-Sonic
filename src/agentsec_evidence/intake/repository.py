"""Offline repository preparation and replay; neither operation authorizes a scanner."""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Literal
from zipfile import BadZipFile

from pydantic import AwareDatetime, Field, StrictInt

from agentsec_evidence.agents.inventory import (
    ArtifactInventory,
    FamilyInventory,
    artifact_inventory_semantic_sha256,
    build_artifact_inventory,
)
from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes, sha256_file
from agentsec_evidence.core.io import atomic_write_bytes, atomic_write_model, jsonl_bytes
from agentsec_evidence.core.time import utc_now
from agentsec_evidence.intake.git_verification import (
    MAX_COMMIT_BYTES,
    MAX_TREE_BYTES,
    GitEvidenceModel,
    GitOid,
    GitSourceVerification,
    UnsupportedGitInput,
    bind_inventory_to_git,
)
from agentsec_evidence.intake.snapshot import SnapshotPolicy, create_snapshot
from agentsec_evidence.intake.source_archive import VerifiedArchive, verify_source_archive
from agentsec_evidence.intake.views import read_verified_source
from agentsec_evidence.models.contracts import NonEmpty, Sha256, TargetSnapshot
from agentsec_evidence.research.retained import (
    MAX_ENTRY_BYTES,
    RetainedEntry,
    RetainedManifest,
    bounded_file,
    plain_path,
    read_retained_research,
)

MAX_FILES = 1000
MAX_SOURCE_BYTES = 32 * 1024 * 1024


class RepositoryIntakeSpec(GitEvidenceModel):
    contract: Literal["repository-intake-spec-v1"] = "repository-intake-spec-v1"
    source_label: NonEmpty
    revision: GitOid
    root_tree: GitOid
    archive_sha256: Sha256
    raw_commit_sha256: Sha256
    tree_response_sha256: Sha256
    expected_files: StrictInt = Field(ge=1, le=MAX_FILES)
    expected_bytes: StrictInt = Field(ge=0, le=MAX_SOURCE_BYTES)
    license_status: Literal["identified", "unknown"]
    role: Literal["development", "formative-pilot", "demo"]
    source_scanning_authorization: Literal["not-granted"] = "not-granted"


class RepositoryIntakeReceipt(GitEvidenceModel):
    contract: Literal["repository-intake-receipt-v1"] = "repository-intake-receipt-v1"
    created_at: AwareDatetime
    spec_sha256: Sha256
    state: Literal["prepared", "failed", "unsupported"]
    observed_files: StrictInt | None = Field(default=None, ge=0)
    observed_bytes: StrictInt | None = Field(default=None, ge=0)
    source_content_sha256: Sha256 | None = None
    inventory_semantic_sha256: Sha256 | None = None
    families: tuple[FamilyInventory, ...] = ()
    unclassified_files: StrictInt | None = Field(default=None, ge=0)
    scanner_invocations: Literal[0] = 0
    target_code_executed: Literal[False] = False
    content_parsing: Literal["not-performed"] = "not-performed"
    source_scanning_authorization: Literal["not-granted"] = "not-granted"
    origin_authentication: Literal["not-established"] = "not-established"
    author_signature_verification: Literal["not-performed"] = "not-performed"
    findings: None = None
    error_type: str | None = None
    error: str | None = None


def load_intake_spec(path: Path) -> RepositoryIntakeSpec:
    return RepositoryIntakeSpec.model_validate(
        load_agent_json(bounded_file(path, 128 * 1024), max_bytes=128 * 1024)
    )


def _inputs(spec: RepositoryIntakeSpec) -> tuple[tuple[str, int, str], ...]:
    return (
        ("source.zip", MAX_ENTRY_BYTES, spec.archive_sha256),
        ("commit.bin", MAX_COMMIT_BYTES, spec.raw_commit_sha256),
        ("tree-exact.json", MAX_TREE_BYTES, spec.tree_response_sha256),
    )


def _verified_archive(spec: RepositoryIntakeSpec, raw: dict[str, bytes]) -> VerifiedArchive:
    for name, limit, expected in _inputs(spec):
        if len(raw[name]) > limit or sha256_bytes(raw[name]) != expected:
            raise ValueError("Pinned intake input differs: " + name)
    verified = verify_source_archive(
        archive=raw["source.zip"],
        archive_sha256=spec.archive_sha256,
        raw_commit=raw["commit.bin"],
        raw_tree=raw["tree-exact.json"],
        revision=spec.revision,
    )
    if (
        verified.verification.root_tree != spec.root_tree
        or len(verified.files) != spec.expected_files
        or sum(map(len, verified.files.values())) != spec.expected_bytes
        or any(len(data) > MAX_ENTRY_BYTES for data in verified.files.values())
    ):
        raise ValueError("Verified repository differs from pinned counts or intake byte limits")
    return verified


def _success(
    spec: RepositoryIntakeSpec, inventory: ArtifactInventory, created_at: datetime
) -> RepositoryIntakeReceipt:
    return RepositoryIntakeReceipt(
        created_at=created_at,
        spec_sha256=semantic_hash(spec.model_dump(mode="json")),
        state="prepared",
        observed_files=inventory.snapshot.file_count,
        observed_bytes=inventory.snapshot.total_bytes,
        source_content_sha256=inventory.snapshot.content_sha256,
        inventory_semantic_sha256=artifact_inventory_semantic_sha256(inventory),
        families=inventory.families,
        unclassified_files=sum(not r.recognizer_ids for r in inventory.records),
    )


def _seal(output: Path) -> None:
    entries = tuple(
        RetainedEntry(
            path=path.relative_to(output).as_posix(),
            bytes=path.stat().st_size,
            sha256=sha256_file(path),
        )
        for path in sorted(output.rglob("*"))
        if path.is_file()
    )
    atomic_write_model(output / "evidence-manifest.json", RetainedManifest(files=entries))


def prepare_repository(
    spec: RepositoryIntakeSpec, *, cache: Path, output: Path
) -> RepositoryIntakeReceipt:
    """Verify all pinned Git bytes before materializing; retain failed attempts separately."""
    spec = RepositoryIntakeSpec.model_validate(spec.model_dump(mode="json"))
    cache = plain_path(cache, directory=True)
    output = Path(os.path.abspath(output))
    plain_path(output.parent, directory=True)
    if output.is_relative_to(cache) or cache.is_relative_to(output):
        raise ValueError("Cache and intake output must not overlap")
    output.mkdir(exist_ok=False)
    created_at = utc_now()
    receipt = RepositoryIntakeReceipt(
        created_at=created_at,
        spec_sha256=semantic_hash(spec.model_dump(mode="json")),
        state="failed",
    )
    try:
        atomic_write_model(output / "intake-spec.json", spec)
        raw = {}
        for name, limit, expected in _inputs(spec):
            data = bounded_file(cache / name, limit)
            atomic_write_bytes(output / "raw" / name, data)
            if sha256_bytes(data) != expected:
                raise ValueError("Cached intake input differs: " + name)
            raw[name] = data
        verified = _verified_archive(spec, raw)
        atomic_write_model(output / "git-verification.json", verified.verification)
        source = output / "source"
        source.mkdir()
        for name, data in verified.files.items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(data)
        snapshot = create_snapshot(
            source,
            output / "snapshots",
            source_label=spec.source_label,
            revision=spec.revision,
            source_kind="git",
            license_status=spec.license_status,
            policy=SnapshotPolicy(
                max_files=MAX_FILES,
                max_total_bytes=MAX_SOURCE_BYTES,
                max_file_bytes=MAX_ENTRY_BYTES,
            ),
        )
        inventory = build_artifact_inventory(snapshot.snapshot, snapshot.inventory)
        bind_inventory_to_git(inventory, verified.verification)
        for root in (source, snapshot.content_root):
            read_verified_source(
                verified.verification,
                raw_commit=raw["commit.bin"],
                raw_tree=raw["tree-exact.json"],
                source_root=root,
            )
        atomic_write_model(output / "artifact-inventory.json", inventory)
        receipt = _success(spec, inventory, created_at)
    except (ValueError, OSError, RuntimeError, BadZipFile) as exc:
        receipt = receipt.model_copy(
            update={
                "state": "unsupported" if isinstance(exc, UnsupportedGitInput) else "failed",
                "error_type": type(exc).__name__,
                "error": str(exc),
            }
        )
        raise
    finally:
        atomic_write_model(output / "receipt.json", receipt)
        _seal(output)
    return verify_repository(output, spec=spec)


def verify_repository(root: Path, *, spec: RepositoryIntakeSpec) -> RepositoryIntakeReceipt:
    """Replay retained Git/archive/snapshot evidence against an external spec; read-only."""
    spec = RepositoryIntakeSpec.model_validate(spec.model_dump(mode="json"))
    retained = read_retained_research(root)
    if (retained.root / "runtime").exists():
        raise ValueError("Repository intake has no runtime scratch exception")
    frozen = RepositoryIntakeSpec.model_validate(
        load_agent_json(retained.read("intake-spec.json"), max_bytes=128 * 1024)
    )
    if frozen != spec:
        raise ValueError("Retained intake differs from externally supplied specification")
    receipt = RepositoryIntakeReceipt.model_validate(
        load_agent_json(retained.read("receipt.json"), max_bytes=128 * 1024)
    )
    if receipt.state != "prepared":
        raise ValueError("Failed or unsupported preparation is not a verified repository")
    raw = {name: retained.read("raw/" + name) for name, _, _ in _inputs(spec)}
    verified = _verified_archive(spec, raw)
    proof = GitSourceVerification.model_validate(
        load_agent_json(retained.read("git-verification.json"), max_bytes=MAX_ENTRY_BYTES)
    )
    if proof != verified.verification:
        raise ValueError("Retained Git proof differs from replayed source")
    inventory = ArtifactInventory.model_validate(
        load_agent_json(retained.read("artifact-inventory.json"), max_bytes=MAX_ENTRY_BYTES)
    )
    bind_inventory_to_git(inventory, proof)
    snapshot = inventory.snapshot
    if (
        snapshot.source_label != spec.source_label
        or snapshot.target_id != "target_" + sha256_bytes(spec.source_label.encode("utf-8"))[:32]
        or snapshot.revision != spec.revision
        or snapshot.source_kind != "git"
        or snapshot.license_status != spec.license_status
    ):
        raise ValueError("Snapshot provenance differs from external specification")
    prefix = f"snapshots/{snapshot.snapshot_id}"
    stored = TargetSnapshot.model_validate(
        load_agent_json(retained.read(prefix + "/snapshot.json"), max_bytes=128 * 1024)
    )
    if stored != snapshot or retained.read(prefix + "/inventory.jsonl") != jsonl_bytes(
        [record.source for record in inventory.records]
    ):
        raise ValueError("Snapshot metadata differs from artifact inventory")
    expected = {
        "intake-spec.json",
        "receipt.json",
        "git-verification.json",
        "artifact-inventory.json",
        prefix + "/snapshot.json",
        prefix + "/inventory.jsonl",
    }
    expected.update("raw/" + name for name in raw)
    # Both copies must agree with the Git-verified archive, not just self-authored hashes.
    for content_root in ("source", prefix + "/content"):
        for name, data in verified.files.items():
            key = f"{content_root}/{name}"
            expected.add(key)
            if retained.read(key) != data:
                raise ValueError("Materialized source differs from verified archive: " + key)
    if set(retained.files) != expected:
        raise ValueError("Prepared repository contains unexpected evidence files")
    if receipt != _success(spec, inventory, receipt.created_at):
        raise ValueError("Preparation receipt differs from replayed evidence")
    return receipt
