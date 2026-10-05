from __future__ import annotations

import io
import stat
import zipfile
from dataclasses import dataclass

from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.intake.git_verification import (
    MAX_COMMIT_BYTES,
    MAX_TREE_ENTRIES,
    GitSourceVerification,
    GitTreeEntry,
    GitVerificationError,
    UnsupportedGitInput,
    git_object_oid,
    verify_git_source,
)
from agentsec_evidence.intake.snapshot import SnapshotPolicy

MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_COMMIT_RESPONSE_BYTES = 4 * 1024 * 1024


def recover_github_commit(raw_response: bytes, *, revision: str) -> bytes:
    """Recover one supported signed layout, accepting only the exact pinned Git identity.

    The API's verified flag is not trusted. This recovers bytes, not signer authenticity.
    Missing payloads or different header layouts require separately acquired raw objects.
    """
    document = load_agent_json(raw_response, max_bytes=MAX_COMMIT_RESPONSE_BYTES)
    commit = document.get("commit")
    verification = commit.get("verification") if isinstance(commit, dict) else None
    if document.get("sha") != revision or not isinstance(verification, dict):
        raise GitVerificationError("Commit response does not identify the pinned commit")
    payload = verification.get("payload")
    signature = verification.get("signature")
    if not isinstance(payload, str) or not isinstance(signature, str):
        raise UnsupportedGitInput("Exact signed payload and signature are required")
    if (
        not signature.startswith("-----BEGIN PGP SIGNATURE-----\n")
        or not signature.endswith("-----END PGP SIGNATURE-----\n")
        or "\r" in signature
    ):
        raise UnsupportedGitInput("Only the retained LF-terminated PGP layout is supported")
    header, separator, message = payload.encode("utf-8").partition(b"\n\n")
    if not separator or any(line.startswith(b"gpgsig") for line in header.split(b"\n")):
        raise UnsupportedGitInput("Ambiguous signed payload headers")
    # Preserve the final continuation space too: changing even this byte changes the OID.
    raw = header + b"\ngpgsig " + signature.encode().replace(b"\n", b"\n ") + b"\n\n" + message
    if len(raw) > MAX_COMMIT_BYTES or git_object_oid("commit", raw) != revision:
        raise GitVerificationError("Recovered commit bytes do not match the pinned revision")
    return raw


@dataclass(frozen=True)
class VerifiedArchive:
    verification: GitSourceVerification
    files: dict[str, bytes]


def _portable_name(name: str) -> None:
    # Reuse exactly the portable path contract enforced by the Git proof.
    GitTreeEntry(path=name, mode="100644", type="blob", sha="0" * 40, size=0)


def verify_source_archive(
    *, archive: bytes, archive_sha256: str, raw_commit: bytes, raw_tree: bytes, revision: str
) -> VerifiedArchive:
    """Read a bounded one-root ZIP into memory; never extract paths or execute content."""
    if len(archive) > MAX_ARCHIVE_BYTES or sha256_bytes(archive) != archive_sha256:
        raise GitVerificationError("Archive byte limit or expected SHA-256 mismatch")
    policy = SnapshotPolicy()
    files: dict[str, bytes] = {}
    roots: set[str] = set()
    seen: set[str] = set()
    directories: set[str] = set()
    total = 0
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        members = bundle.infolist()
        if len(members) > MAX_TREE_ENTRIES + 1:
            raise GitVerificationError("Archive entry-count limit exceeded")
        for member in members:
            name = member.filename
            if member.orig_filename != name or member.flag_bits & 1:
                raise UnsupportedGitInput("Truncated names or encrypted ZIP members rejected")
            if member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                raise UnsupportedGitInput("Unsupported ZIP compression method")
            directory = member.is_dir()
            portable = name[:-1] if directory else name
            _portable_name(portable)
            if portable.casefold() in seen:
                raise GitVerificationError("Duplicate or case-colliding ZIP members")
            seen.add(portable.casefold())
            root, separator, relative = portable.partition("/")
            roots.add(root)
            if len(roots) != 1 or (not separator and not directory):
                raise GitVerificationError("Archive requires one enclosing directory")
            mode = stat.S_IFMT(member.external_attr >> 16)
            expected_mode = stat.S_IFDIR if directory else stat.S_IFREG
            if mode not in {0, expected_mode} or (member.external_attr & 0x10 and not directory):
                raise UnsupportedGitInput("Link, special entry or conflicting ZIP mode rejected")
            if directory:
                if member.file_size != 0:
                    raise GitVerificationError("Directory member contains data")
                if relative:
                    directories.add(relative)
                continue
            total += member.file_size
            if (
                len(files) >= policy.max_files
                or member.file_size > policy.max_file_bytes
                or total > policy.max_total_bytes
            ):
                raise GitVerificationError("Archive expanded-content limit exceeded")
            with bundle.open(member) as stream:
                data = stream.read(member.file_size + 1)
            if len(data) != member.file_size:
                raise GitVerificationError("Archive size declaration differs from decoded bytes")
            files[relative] = data
    ancestors = {
        "/".join(parts[:index])
        for name in files
        if (parts := name.split("/"))
        for index in range(1, len(parts))
    }
    if not files or not directories.issubset(ancestors):
        raise GitVerificationError("Empty archive or unrelated directory entries rejected")
    proof = verify_git_source(
        raw_commit=raw_commit, raw_tree=raw_tree, revision=revision, files=files
    )
    return VerifiedArchive(proof, files)
