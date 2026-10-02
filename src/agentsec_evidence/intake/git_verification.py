from __future__ import annotations

import hashlib
import ntpath
import re
from collections import defaultdict
from collections.abc import Mapping
from typing import Annotated, Literal

from pydantic import (
    ConfigDict,
    Field,
    StrictInt,
    StringConstraints,
    field_validator,
    model_validator,
)

from agentsec_evidence.agents.inventory import ArtifactInventory
from agentsec_evidence.agents.validation import canonical_artifact_path, load_agent_json
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.intake.snapshot import SnapshotPolicy
from agentsec_evidence.models.contracts import ContractModel, Sha256

GitOid = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
MAX_TREE_BYTES = 4 * 1024 * 1024
MAX_COMMIT_BYTES = 1024 * 1024
MAX_TREE_ENTRIES = 20_000


class GitVerificationError(ValueError):
    """Pinned evidence is inconsistent; no verified receipt may be produced."""


class UnsupportedGitInput(GitVerificationError):
    """Input is outside the explicitly bounded Git treatment, not a clean result."""


class GitEvidenceModel(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class GitTreeEntry(GitEvidenceModel):
    path: Annotated[str, StringConstraints(min_length=1, max_length=4096)]
    mode: str
    type: str
    sha: GitOid
    size: StrictInt | None = Field(default=None, ge=0)

    @field_validator("path")
    @classmethod
    def portable_path(cls, value: str) -> str:
        canonical_artifact_path(value)
        # Apply Windows device-name rules on Linux too, before any future materialization.
        if ntpath.isreserved(value):
            raise ValueError("Windows-reserved Git path rejected")
        if len(value.split("/")) > 64 or any(p.casefold() == ".git" for p in value.split("/")):
            raise ValueError("Git metadata path or excessive directory depth rejected")
        return value


class VerifiedGitFile(GitEvidenceModel):
    source: GitTreeEntry
    sha256: Sha256

    @model_validator(mode="after")
    def regular_file(self) -> VerifiedGitFile:
        if (
            self.source.type != "blob"
            or self.source.mode not in {"100644", "100755"}
            or self.source.size is None
        ):
            raise ValueError("Verified file must describe a sized regular Git blob")
        return self


class GitSourceVerification(GitEvidenceModel):
    contract: Literal["git-source-verification-v1"] = "git-source-verification-v1"
    revision: GitOid
    root_tree: GitOid
    raw_commit_sha256: Sha256
    tree_response_sha256: Sha256
    files: tuple[VerifiedGitFile, ...] = Field(max_length=10_000)
    verification_scope: Literal["complete-regular-file-git-tree"] = "complete-regular-file-git-tree"
    origin_authentication: Literal["not-established"] = "not-established"
    author_signature_verification: Literal["not-performed"] = "not-performed"
    execution_authorization: Literal["not-granted"] = "not-granted"

    @model_validator(mode="after")
    def file_accounting(self) -> GitSourceVerification:
        paths = [file.source.path for file in self.files]
        if paths != sorted(paths) or len({path.casefold() for path in paths}) != len(paths):
            raise ValueError("Verified file records must be sorted and unique")
        policy = SnapshotPolicy()
        sizes = [file.source.size or 0 for file in self.files]
        if (
            any(size > policy.max_file_bytes for size in sizes)
            or sum(sizes) > policy.max_total_bytes
        ):
            raise ValueError("Verified file records exceed byte limits")
        return self


def git_object_oid(kind: Literal["blob", "tree", "commit"], data: bytes) -> str:
    """Git SHA-1 identity only; evidence integrity is recorded separately using SHA-256."""
    header = f"{kind} {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data, usedforsecurity=False).hexdigest()


def _commit_tree(raw_commit: bytes, revision: str) -> str:
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise UnsupportedGitInput("A full lowercase SHA-1 Git revision is required")
    if len(raw_commit) > MAX_COMMIT_BYTES:
        raise GitVerificationError("Raw commit exceeds byte limit")
    if git_object_oid("commit", raw_commit) != revision:
        raise GitVerificationError("Raw commit does not match pinned revision")
    header, separator, _message = raw_commit.partition(b"\n\n")
    lines = header.split(b"\n")
    if not separator or not re.fullmatch(rb"tree [0-9a-f]{40}", lines[0]):
        raise GitVerificationError("Raw commit must begin with one canonical root tree header")
    if sum(line.startswith(b"tree ") for line in lines) != 1:
        raise GitVerificationError("Ambiguous root tree headers")
    return lines[0][5:].decode("ascii")


def _tree_entries(raw_tree: bytes, expected_root: str) -> tuple[GitTreeEntry, ...]:
    document = load_agent_json(raw_tree, max_bytes=MAX_TREE_BYTES)
    if document.get("truncated") is not False:
        raise GitVerificationError(
            "A complete, explicitly non-truncated recursive tree is required"
        )
    if document.get("sha") != expected_root:
        raise GitVerificationError("Tree response does not match raw commit root")
    items = document.get("tree")
    if not isinstance(items, list) or len(items) > MAX_TREE_ENTRIES:
        raise GitVerificationError("Invalid or excessive Git tree entry list")
    entries: list[GitTreeEntry] = []
    for item in items:
        if not isinstance(item, dict):
            raise GitVerificationError("Invalid Git tree entry")
        # API URLs remain in the hashed original response, not the object encoding.
        entry = GitTreeEntry.model_validate({k: v for k, v in item.items() if k != "url"})
        if (entry.type, entry.mode) not in {
            ("blob", "100644"),
            ("blob", "100755"),
            ("tree", "040000"),
        }:
            raise UnsupportedGitInput("Symlink, submodule or unsupported Git mode/type")
        if (entry.type == "blob" and entry.size is None) or (
            entry.type == "tree" and entry.size is not None
        ):
            raise GitVerificationError("Invalid Git entry size declaration")
        entries.append(entry)
    if len({e.path.casefold() for e in entries}) != len(entries):
        raise GitVerificationError("Duplicate or case-colliding Git tree paths")
    return tuple(entries)


def _verify_trees(entries: tuple[GitTreeEntry, ...], expected_root: str) -> None:
    by_path = {entry.path: entry for entry in entries}
    children: dict[str, list[GitTreeEntry]] = defaultdict(list)
    directories = {"": expected_root}
    for entry in entries:
        parent = entry.path.rpartition("/")[0]
        if parent and (parent not in by_path or by_path[parent].type != "tree"):
            raise GitVerificationError("Missing directory or file/directory conflict in tree")
        children[parent].append(entry)
        if entry.type == "tree":
            directories[entry.path] = entry.sha
    for directory, expected_oid in directories.items():

        def sort_key(entry: GitTreeEntry) -> bytes:
            name = entry.path.rsplit("/", 1)[-1].encode("utf-8")
            return name + (b"/" if entry.type == "tree" else b"")

        # Git sorts directories as if suffixed by '/'; plain full-path sorting
        # gives different identities for prefix-adjacent files and directories.
        content = b"".join(
            (b"40000" if entry.type == "tree" else entry.mode.encode("ascii"))
            + b" "
            + entry.path.rsplit("/", 1)[-1].encode("utf-8")
            + b"\0"
            + bytes.fromhex(entry.sha)
            for entry in sorted(children[directory], key=sort_key)
        )
        if git_object_oid("tree", content) != expected_oid:
            raise GitVerificationError("Reconstructed tree does not match Git object identity")


def verify_git_source(
    *, raw_commit: bytes, raw_tree: bytes, revision: str, files: Mapping[str, bytes]
) -> GitSourceVerification:
    """Verify supplied objects offline; never fetch, materialize or execute target content."""
    root = _commit_tree(raw_commit, revision)
    entries = _tree_entries(raw_tree, root)
    _verify_trees(entries, root)
    blobs = {entry.path: entry for entry in entries if entry.type == "blob"}
    policy = SnapshotPolicy()
    if len(blobs) > policy.max_files or len(files) > policy.max_files:
        raise GitVerificationError("Source file-count limit exceeded")
    if set(files) != set(blobs):
        raise GitVerificationError("Supplied files do not exactly match the pinned Git tree")
    total = 0
    verified: list[VerifiedGitFile] = []
    for path, entry in sorted(blobs.items()):
        data = files[path]
        if not isinstance(data, bytes):
            raise GitVerificationError("Source content must be bytes")
        total += len(data)
        if len(data) > policy.max_file_bytes or total > policy.max_total_bytes:
            raise GitVerificationError("Source byte limit exceeded")
        if len(data) != entry.size or git_object_oid("blob", data) != entry.sha:
            raise GitVerificationError("Source bytes do not match pinned Git blob")
        if data.startswith(
            (
                b"version https://git-lfs.github.com/spec/v1",
                b"version https://hawser.github.com/spec/v1",
            )
        ):
            raise UnsupportedGitInput("Git LFS pointer candidate requires separate support")
        verified.append(VerifiedGitFile(source=entry, sha256=sha256_bytes(data)))
    return GitSourceVerification(
        revision=revision,
        root_tree=root,
        raw_commit_sha256=sha256_bytes(raw_commit),
        tree_response_sha256=sha256_bytes(raw_tree),
        files=tuple(verified),
    )


def bind_inventory_to_git(
    inventory: ArtifactInventory, verification: GitSourceVerification
) -> None:
    """Check the metadata-to-verified-bytes link; loaded receipts still need raw-evidence replay."""
    checked = ArtifactInventory.model_validate(inventory.model_dump(mode="json"))
    proof = GitSourceVerification.model_validate(verification.model_dump(mode="json"))
    if checked.snapshot.source_kind != "git" or checked.snapshot.revision != proof.revision:
        raise GitVerificationError("Snapshot is not bound to the verified Git revision")
    expected = {f.source.path: (f.sha256, f.source.size) for f in proof.files}
    actual = {r.source.path: (r.source.sha256, r.source.byte_length) for r in checked.records}
    if len(expected) != len(proof.files) or expected != actual:
        raise GitVerificationError("Snapshot inventory differs from verified Git content")


def replay_git_verification(
    verification: GitSourceVerification,
    *,
    raw_commit: bytes,
    raw_tree: bytes,
    files: Mapping[str, bytes],
) -> None:
    """Loaded receipts are claims until reproduced against their retained raw evidence."""
    expected = GitSourceVerification.model_validate(verification.model_dump(mode="json"))
    actual = verify_git_source(
        raw_commit=raw_commit, raw_tree=raw_tree, revision=expected.revision, files=files
    )
    if actual != expected:
        raise GitVerificationError("Git verification receipt does not match retained evidence")
