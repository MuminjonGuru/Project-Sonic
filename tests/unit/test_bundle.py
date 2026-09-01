from __future__ import annotations

from pathlib import Path

import pytest

from agentsec_evidence.core.identity import semantic_hash
from agentsec_evidence.intake.snapshot import create_snapshot
from agentsec_evidence.models.contracts import RunState
from agentsec_evidence.storage.bundle import RunBundle


def test_bundle_finalization_hashes_every_allowlisted_file(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "sample.py").write_text("print('fixture')\n", encoding="utf-8")
    snapshot = create_snapshot(
        source,
        tmp_path / "workspace" / "targets",
        source_label="fixture:bundle",
        revision="v1",
    )

    with RunBundle.create(
        tmp_path / "workspace",
        run_label="bundle-test",
        profile_id="development-static-v1",
        config_sha256=semantic_hash({"profile": "test"}),
        snapshot_result=snapshot,
    ) as bundle:
        bundle.transition(RunState.PLANNED, "test planned")
        bundle.transition(RunState.RUNNING, "test running")
        bundle.write_bytes("executions/test/stdout.bin", b"stdout")
        with pytest.raises(FileExistsError, match="write-once"):
            bundle.write_bytes("executions/test/stdout.bin", b"replacement")
        bundle.transition(RunState.CAPTURED, "captured")
        bundle.transition(RunState.PARSING, "parsing")
        bundle.transition(RunState.NORMALIZING, "normalizing")
        bundle.transition(RunState.VALIDATING, "validating")
        bundle.transition(RunState.COMPLETE, "complete")
        manifest = bundle.finalize(semantic_document={"findings": []})

    assert (bundle.root / "bundle-manifest.json").is_file()
    assert not (bundle.root / ".write.lock").exists()
    assert manifest.entries
    assert manifest.entries == sorted(manifest.entries, key=lambda entry: entry.relative_path)
    with pytest.raises(RuntimeError):
        bundle.write_bytes("late.bin", b"late")
