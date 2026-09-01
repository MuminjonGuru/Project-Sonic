from __future__ import annotations

import os
from pathlib import Path

import pytest

from agentsec_evidence.intake.snapshot import (
    SnapshotError,
    SnapshotLimitError,
    SnapshotPolicy,
    UnsafeTargetError,
    create_snapshot,
)


def test_snapshot_is_content_addressed_and_byte_exact(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "b.py").write_bytes(b"print('b')\n")
    (source / "a.py").write_bytes(b"print('a')\n")

    first = create_snapshot(
        source,
        tmp_path / "snapshots",
        source_label="fixture:test",
        revision="v1",
    )
    second = create_snapshot(
        source,
        tmp_path / "snapshots",
        source_label="fixture:test",
        revision="v1",
    )

    assert first.snapshot.snapshot_id == second.snapshot.snapshot_id
    assert [entry.path for entry in first.inventory] == ["a.py", "b.py"]
    assert (first.content_root / "a.py").read_bytes() == b"print('a')\n"
    assert first.snapshot.file_count == 2


def test_snapshot_changes_when_content_changes(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    target = source / "sample.py"
    target.write_text("one", encoding="utf-8")
    first = create_snapshot(
        source, tmp_path / "snapshots", source_label="fixture:test", revision="v1"
    )

    target.write_text("two", encoding="utf-8")
    second = create_snapshot(
        source,
        tmp_path / "snapshots",
        source_label="fixture:test",
        revision="v2",
    )

    assert first.snapshot.snapshot_id != second.snapshot.snapshot_id


def test_snapshot_enforces_file_size_limit(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "large.bin").write_bytes(b"1234")

    with pytest.raises(SnapshotLimitError):
        create_snapshot(
            source,
            tmp_path / "snapshots",
            source_label="fixture:test",
            revision="v1",
            policy=SnapshotPolicy(max_file_bytes=3),
        )


def test_snapshot_rejects_symlink_when_supported(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    link = source / "link.txt"
    try:
        os.symlink(outside, link)
    except OSError:
        pytest.skip("Symlink creation is unavailable on this host")

    with pytest.raises(UnsafeTargetError):
        create_snapshot(
            source,
            tmp_path / "snapshots",
            source_label="fixture:test",
            revision="v1",
        )


def test_snapshot_preserves_safe_unicode_name(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    name = "caf\u00e9.py"
    (source / name).write_text("print('unicode')\n", encoding="utf-8")

    result = create_snapshot(
        source,
        tmp_path / "snapshots",
        source_label="fixture:unicode",
        revision="v1",
    )

    assert result.inventory[0].path == name
    assert (result.content_root / name).is_file()


def test_snapshot_rejects_unicode_normalization_collision(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    first = source / "caf\u00e9.py"
    second = source / "cafe\u0301.py"
    first.write_text("first", encoding="utf-8")
    second.write_text("second", encoding="utf-8")
    if len(list(source.iterdir())) != 2:
        pytest.skip("Filesystem normalizes canonically equivalent names")

    with pytest.raises(UnsafeTargetError, match="Portable path collision"):
        create_snapshot(
            source,
            tmp_path / "snapshots",
            source_label="fixture:unicode-collision",
            revision="v1",
        )


def test_existing_snapshot_is_reverified_before_reuse(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "sample.py").write_text("print('source')\n", encoding="utf-8")
    first = create_snapshot(
        source,
        tmp_path / "snapshots",
        source_label="fixture:integrity",
        revision="v1",
    )
    (first.content_root / "sample.py").write_text("tampered\n", encoding="utf-8")

    with pytest.raises(SnapshotError, match="content hash mismatch"):
        create_snapshot(
            source,
            tmp_path / "snapshots",
            source_label="fixture:integrity",
            revision="v1",
        )


def test_snapshot_does_not_silently_reassign_provenance(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "sample.py").write_text("print('source')\n", encoding="utf-8")
    create_snapshot(
        source,
        tmp_path / "snapshots",
        source_label="fixture:first",
        revision="v1",
    )

    with pytest.raises(SnapshotError, match="provenance"):
        create_snapshot(
            source,
            tmp_path / "snapshots",
            source_label="fixture:second",
            revision="v1",
        )
