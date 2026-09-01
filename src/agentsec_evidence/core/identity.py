from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

from pydantic import JsonValue


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_bytes(value: JsonValue) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def semantic_hash(value: JsonValue) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def new_opaque_id(prefix: str) -> str:
    if not prefix.isidentifier() or not prefix.isascii():
        msg = "ID prefix must be a non-empty ASCII identifier"
        raise ValueError(msg)
    return f"{prefix}_{uuid.uuid4().hex}"
