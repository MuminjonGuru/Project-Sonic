from __future__ import annotations

from pathlib import Path

import pytest

from agentsec_evidence.storage.blobs import BlobStore


def test_blob_store_is_content_addressed_and_detects_corruption(tmp_path: Path) -> None:
    store = BlobStore(tmp_path / "blobs")
    first = store.put(b"exact native bytes")
    second = store.put(b"exact native bytes")

    assert first == second
    assert first.path.read_bytes() == b"exact native bytes"

    first.path.write_bytes(b"corrupt")
    with pytest.raises(RuntimeError, match="integrity failure"):
        store.put(b"exact native bytes")
