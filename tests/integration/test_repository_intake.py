from __future__ import annotations

import io
import json
import socket
import subprocess
import zipfile
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from agentsec_evidence.cli.app import app
from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.core.io import atomic_write_model, json_bytes
from agentsec_evidence.intake.repository import (
    RepositoryIntakeSpec,
    load_intake_spec,
    prepare_repository,
    verify_repository,
)
from agentsec_evidence.research.retained import RetainedEntry, RetainedManifest

PROJECT = Path(__file__).resolve().parents[2]


@pytest.fixture
def cached(tmp_path: Path) -> tuple[Path, RepositoryIntakeSpec]:
    case = json.loads((PROJECT / "test_cases/development/pinned-git/case.json").read_bytes())
    cache = tmp_path / "cache"
    cache.mkdir()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        for file in case["files"]:
            bundle.writestr("authored/" + file["path"], file["text"].encode())
    (cache / "source.zip").write_bytes(buffer.getvalue())
    (cache / "commit.bin").write_bytes(case["raw_commit"].encode())
    (cache / "tree-exact.json").write_bytes(json_bytes(case["tree"]))
    spec = RepositoryIntakeSpec(
        source_label="existing-authored-git-fixture",
        revision=case["revision"],
        root_tree=case["tree"]["sha"],
        archive_sha256=sha256_file(cache / "source.zip"),
        raw_commit_sha256=sha256_file(cache / "commit.bin"),
        tree_response_sha256=sha256_file(cache / "tree-exact.json"),
        expected_files=len(case["files"]),
        expected_bytes=sum(len(f["text"].encode()) for f in case["files"]),
        license_status="unknown",
        role="development",
    )
    return cache, spec


def reseal(root: Path) -> None:
    entries = tuple(
        RetainedEntry(
            path=p.relative_to(root).as_posix(), bytes=p.stat().st_size, sha256=sha256_file(p)
        )
        for p in sorted(root.rglob("*"))
        if p.is_file() and p.name != "evidence-manifest.json"
    )
    atomic_write_model(root / "evidence-manifest.json", RetainedManifest(files=entries))


def hashes(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): sha256_file(p) for p in root.rglob("*") if p.is_file()}


def test_unsigned_raw_git_prepares_all_files_without_execution(
    cached: tuple[Path, RepositoryIntakeSpec], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("Offline intake attempted a process or network operation")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    cache, spec = cached
    before = hashes(cache)
    output = tmp_path / "prepared"
    receipt = prepare_repository(spec, cache=cache, output=output)
    assert receipt.state == "prepared" and receipt.observed_files == 21
    assert receipt.scanner_invocations == 0 and receipt.findings is None
    assert receipt.source_scanning_authorization == "not-granted"
    assert receipt.content_parsing == "not-performed"
    assert (output / "source/.agent-audit.yaml").is_file()
    assert hashes(cache) == before
    snapshot = hashes(output)
    assert verify_repository(output, spec=spec) == receipt
    assert hashes(output) == snapshot
    unknown = [f for f in receipt.families if f.recognition_support == "no-recognizer"]
    assert unknown and all(f.candidate_file_count is None for f in unknown)
    for file, value in (("spec", spec), ("receipt", receipt)):
        schema = json.loads(
            (PROJECT / f"schemas/repository-intake-v1/{file}.schema.json").read_bytes()
        )
        Draft202012Validator(schema).validate(value.model_dump(mode="json"))


def test_repeated_preparation_preserves_semantics_and_refuses_overwrite(
    cached: tuple[Path, RepositoryIntakeSpec], tmp_path: Path
) -> None:
    cache, spec = cached
    first = prepare_repository(spec, cache=cache, output=tmp_path / "a")
    second = prepare_repository(spec, cache=cache, output=tmp_path / "b")
    assert first.model_dump(exclude={"created_at"}) == second.model_dump(exclude={"created_at"})
    before = hashes(tmp_path / "a")
    with pytest.raises(FileExistsError):
        prepare_repository(spec, cache=cache, output=tmp_path / "a")
    assert hashes(tmp_path / "a") == before


@pytest.mark.parametrize("mode", ["120000", "160000"])
def test_unsupported_git_entries_are_retained_not_clean(
    cached: tuple[Path, RepositoryIntakeSpec], tmp_path: Path, mode: str
) -> None:
    cache, spec = cached
    tree = json.loads((cache / "tree-exact.json").read_bytes())
    tree["tree"][0]["mode"] = mode
    if mode == "160000":
        tree["tree"][0]["type"] = "commit"
    (cache / "tree-exact.json").write_bytes(json_bytes(tree))
    spec = spec.model_copy(update={"tree_response_sha256": sha256_file(cache / "tree-exact.json")})
    output = tmp_path / "unsupported"
    with pytest.raises(ValueError, match="Symlink, submodule"):
        prepare_repository(spec, cache=cache, output=output)
    receipt = json.loads((output / "receipt.json").read_bytes())
    assert receipt["state"] == "unsupported" and receipt["observed_files"] is None
    assert receipt["scanner_invocations"] == 0 and not (output / "source").exists()
    with pytest.raises(ValueError, match="not a verified"):
        verify_repository(output, spec=spec)


@pytest.mark.parametrize("change", ["missing", "hash", "count", "bytes", "root", "bad-zip"])
def test_preparation_failures_are_retained(
    cached: tuple[Path, RepositoryIntakeSpec], tmp_path: Path, change: str
) -> None:
    cache, spec = cached
    if change == "missing":
        (cache / "commit.bin").unlink()
    elif change == "hash":
        (cache / "commit.bin").write_bytes(b"changed")
    elif change == "bad-zip":
        (cache / "source.zip").write_bytes(b"not-zip")
        spec = spec.model_copy(update={"archive_sha256": sha256_bytes(b"not-zip")})
    else:
        key = {"count": "expected_files", "bytes": "expected_bytes", "root": "root_tree"}[change]
        spec = spec.model_copy(update={key: "0" * 40 if change == "root" else 1})
    with pytest.raises((ValueError, OSError, zipfile.BadZipFile)):
        prepare_repository(spec, cache=cache, output=tmp_path / "failed")
    receipt = json.loads((tmp_path / "failed/receipt.json").read_bytes())
    assert receipt["state"] == "failed" and receipt["findings"] is None
    assert receipt["observed_files"] is None and receipt["error_type"]
    assert (tmp_path / "failed/evidence-manifest.json").is_file()


@pytest.mark.parametrize(
    "change",
    [
        "source",
        "snapshot-content",
        "raw",
        "proof",
        "receipt",
        "inventory",
        "snapshot-metadata",
        "external-spec",
        "extra-file",
        "runtime-dir",
        "failed-receipt",
    ],
)
def test_replay_rejects_resealed_tampering(
    cached: tuple[Path, RepositoryIntakeSpec], tmp_path: Path, change: str
) -> None:
    cache, spec = cached
    root = tmp_path / "prepared"
    prepare_repository(spec, cache=cache, output=root)
    snapshot = next((root / "snapshots").iterdir())
    if change in {"source", "snapshot-content"}:
        base = root / "source" if change == "source" else snapshot / "content"
        next(p for p in base.rglob("*") if p.is_file()).write_bytes(b"changed")
    elif change == "raw":
        (root / "raw/commit.bin").write_bytes(b"changed")
    elif change == "extra-file":
        (root / "extra.txt").write_text("not allowed")
    elif change == "runtime-dir":
        (root / "runtime").mkdir()
    elif change == "external-spec":
        spec = spec.model_copy(update={"role": "demo"})
    else:
        target, key, value = {
            "proof": (root / "git-verification.json", "root_tree", "0" * 40),
            "receipt": (root / "receipt.json", "observed_files", 0),
            "failed-receipt": (root / "receipt.json", "state", "failed"),
            "inventory": (root / "artifact-inventory.json", "scan_authorization", "granted"),
            "snapshot-metadata": (snapshot / "snapshot.json", "source_label", "other"),
        }[change]
        document = json.loads(target.read_bytes())
        document[key] = value
        target.write_bytes(json_bytes(document))
    reseal(root)
    with pytest.raises(ValueError):
        verify_repository(root, spec=spec)


@pytest.mark.parametrize(
    "kind", ["source_label", "role", "authorization", "too-many", "too-large", "duplicate"]
)
def test_spec_validation(
    cached: tuple[Path, RepositoryIntakeSpec], tmp_path: Path, kind: str
) -> None:
    _, spec = cached
    document = spec.model_dump(mode="json")
    if kind == "duplicate":
        raw = json_bytes(document).rstrip()[:-1] + b',"role":"demo"}'
    else:
        key, value = {
            "source_label": ("source_label", ""),
            "role": ("role", "held-out"),
            "authorization": ("source_scanning_authorization", "granted"),
            "too-many": ("expected_files", 1001),
            "too-large": ("expected_bytes", 32 * 1024**2 + 1),
        }[kind]
        document[key] = value
        raw = json_bytes(document)
    path = tmp_path / "spec.json"
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        load_intake_spec(path)


def test_cli_prepares_replays_and_reports_failure(
    cached: tuple[Path, RepositoryIntakeSpec], tmp_path: Path
) -> None:
    cache, spec = cached
    spec_path = tmp_path / "spec.json"
    atomic_write_model(spec_path, spec)
    root = tmp_path / "cli"
    runner = CliRunner()
    args = [
        "target",
        "prepare-git",
        "--spec",
        str(spec_path),
        "--cache",
        str(cache),
        "--output",
        str(root),
    ]
    result = runner.invoke(app, [*args, "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["state"] == "prepared"
    verified = runner.invoke(
        app, ["target", "verify-git", str(root), "--spec", str(spec_path), "--json"]
    )
    assert verified.exit_code == 0 and json.loads(verified.stdout)["scanner_invocations"] == 0
    assert runner.invoke(app, args).exit_code == 5
    display = runner.invoke(app, ["target", "verify-git", str(root), "--spec", str(spec_path)])
    assert display.exit_code == 0 and "not established" in display.stdout
    (root / "raw/commit.bin").write_bytes(b"changed")
    failed = runner.invoke(
        app, ["target", "verify-git", str(root), "--spec", str(spec_path), "--json"]
    )
    assert failed.exit_code == 5 and "error:" in failed.output


def test_overlap_and_linked_inputs_refused(
    cached: tuple[Path, RepositoryIntakeSpec], tmp_path: Path
) -> None:
    cache, spec = cached
    with pytest.raises(ValueError, match="overlap"):
        prepare_repository(spec, cache=cache, output=cache / "new")
    import os

    original = cache / "commit.bin"
    copy = tmp_path / "linked"
    os.link(original, copy)
    with pytest.raises(ValueError, match="non-hard-linked"):
        prepare_repository(spec, cache=cache, output=tmp_path / "linked-input")
