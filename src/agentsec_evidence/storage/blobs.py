from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.core.io import atomic_write_bytes


@dataclass(frozen=True)
class StoredBlob:
    sha256: str
    byte_length: int
    path: Path


class BlobStore:
    """A local content-addressed store keyed by exact-byte SHA-256."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def put(self, data: bytes) -> StoredBlob:
        digest = sha256_bytes(data)
        destination = self.root / "sha256" / digest[:2] / digest
        if destination.exists():
            if not destination.is_file() or destination.is_symlink():
                raise RuntimeError(f"Invalid blob-store entry: {digest}")
            if destination.stat().st_size != len(data) or sha256_file(destination) != digest:
                raise RuntimeError(f"Blob-store integrity failure: {digest}")
            return StoredBlob(digest, len(data), destination)

        atomic_write_bytes(destination, data)
        if sha256_file(destination) != digest:
            destination.unlink(missing_ok=True)
            raise RuntimeError(f"Blob-store write verification failed: {digest}")
        return StoredBlob(digest, len(data), destination)
