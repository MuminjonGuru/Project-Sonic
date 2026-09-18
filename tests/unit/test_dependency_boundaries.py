from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from agentsec_evidence.core.identity import sha256_file
from agentsec_evidence.dependencies.pipeline import run_dependency_scan, validate_dependency_bundle
from agentsec_evidence.intake.public_archive import materialize_pinned_archive

ROOT = Path(__file__).resolve().parents[2]


def test_database_failure_retains_a_failed_sealed_bundle(tmp_path: Path) -> None:
    database = tmp_path / "all.zip"
    database.write_bytes(b"not the approved database")
    result = run_dependency_scan(
        project_root=ROOT,
        workspace_root=tmp_path / "workspace",
        source=ROOT / "test_cases/development/dependency-basic/target",
        label="fixture:dependency-basic",
        revision="fixture-v1",
        database=database,
        database_sha256="0" * 64,
    )
    assert result["state"] == "failed"
    bundle = Path(str(result["bundle_root"]))
    assert validate_dependency_bundle(bundle)["passed"]
    assert not (bundle / "native").exists()


def test_public_pilot_without_admission_never_starts(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    with pytest.raises(ValueError, match="admission"):
        run_dependency_scan(
            project_root=ROOT,
            workspace_root=tmp_path / "workspace",
            source=source,
            label="not-admitted",
            revision="unknown",
            database=tmp_path / "all.zip",
            database_sha256="0" * 64,
            split="pilot",
        )
    assert not (tmp_path / "workspace").exists()


@pytest.mark.parametrize("fault", [None, "tamper", "truncated", "symlink", "traversal"])
def test_public_archive_is_fully_verified_before_materialization(
    tmp_path: Path, fault: str | None
) -> None:
    content = b"version=1\n"
    name = "../uv.lock" if fault == "traversal" else "uv.lock"
    digest = hashlib.sha1(b"blob 10\0" + content, usedforsecurity=False).hexdigest()
    tree = {
        "sha": "tree-identity",
        "truncated": fault == "truncated",
        "tree": [
            {
                "path": name,
                "type": "blob",
                "mode": "120000" if fault == "symlink" else "100644",
                "sha": digest,
                "size": len(content),
            }
        ],
    }
    commit = {"sha": "commit-identity", "commit": {"tree": {"sha": "tree-identity"}}}
    tree_path, commit_path = tmp_path / "tree.json", tmp_path / "commit.json"
    tree_path.write_text(json.dumps(tree), encoding="utf-8")
    commit_path.write_text(json.dumps(commit), encoding="utf-8")
    archive = tmp_path / "source.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("root/" + name, b"changed" if fault == "tamper" else content)
    destination = tmp_path / "source"
    kwargs = dict(
        archive=archive,
        git_tree=tree_path,
        commit_record=commit_path,
        revision="commit-identity",
        destination=destination,
    )
    if fault:
        with pytest.raises(ValueError):
            materialize_pinned_archive(**kwargs)  # type: ignore[arg-type]
        assert not destination.exists()
    else:
        result = materialize_pinned_archive(**kwargs)  # type: ignore[arg-type]
        assert result["file_count"] == 1 and result["archive_sha256"] == sha256_file(archive)
        assert (destination / "uv.lock").read_bytes() == content
