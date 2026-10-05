from __future__ import annotations

import io
import json
import os
import stat
import struct
import zipfile
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from agentsec_evidence.agents.inventory import ArtifactInventory
from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.intake import source_archive
from agentsec_evidence.intake.git_verification import (
    GitSourceVerification,
    bind_inventory_to_git,
    git_object_oid,
)
from agentsec_evidence.intake.snapshot import SnapshotPolicy
from agentsec_evidence.intake.source_archive import recover_github_commit, verify_source_archive
from agentsec_evidence.intake.source_preparation import SourcePreparationSpec, prepare_cached_source
from agentsec_evidence.intake.views import read_verified_source

ROOT = Path(__file__).resolve().parents[2]
CASE = ROOT / "test_cases/development/pinned-git/case.json"


def zip_bytes(entries: Sequence[tuple[str | zipfile.ZipInfo, bytes]]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as bundle:
        for name, data in entries:
            bundle.writestr(name, data)
    return stream.getvalue()


@pytest.fixture
def cached_case(tmp_path: Path) -> tuple[Path, SourcePreparationSpec, dict[str, Any]]:
    case = json.loads(CASE.read_bytes())
    files = {file["path"]: file["text"].encode() for file in case["files"]}
    signature = (
        "-----BEGIN PGP SIGNATURE-----\n"
        "authored-test-placeholder-not-a-valid-signature\n"
        "-----END PGP SIGNATURE-----\n"
    )
    header, message = case["raw_commit"].split("\n\n", 1)
    signed = (header + "\ngpgsig " + "\n ".join(signature.split("\n")) + "\n\n" + message).encode()
    revision = git_object_oid("commit", signed)
    response: dict[str, Any] = {
        "sha": revision,
        "commit": {"verification": {"payload": case["raw_commit"], "signature": signature}},
    }
    archive = zip_bytes([("fixture/", b""), *[("fixture/" + p, d) for p, d in files.items()]])
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "source.zip").write_bytes(archive)
    (cache / "commit.json").write_bytes(json_bytes(response))
    (cache / "tree-exact.json").write_bytes(json_bytes(case["tree"]))
    spec = SourcePreparationSpec(
        source_label="authored-preparation-test",
        revision=revision,
        root_tree=case["tree"]["sha"],
        archive_sha256=sha256_file(cache / "source.zip"),
        commit_response_sha256=sha256_file(cache / "commit.json"),
        tree_response_sha256=sha256_file(cache / "tree-exact.json"),
        expected_files=len(files),
        expected_bytes=sum(len(data) for data in files.values()),
        license_status="unknown",
    )
    return (
        cache,
        spec,
        {
            "archive": archive,
            "archive_sha256": spec.archive_sha256,
            "raw_commit": signed,
            "raw_tree": json_bytes(case["tree"]),
            "revision": revision,
        },
    )


def test_recovery_is_exact_bytes_not_a_signature_claim(cached_case: Any) -> None:
    cache, spec, arguments = cached_case
    response = json.loads((cache / "commit.json").read_bytes())
    for verified in (False, True):
        response["commit"]["verification"]["verified"] = verified
        assert (
            recover_github_commit(json_bytes(response), revision=spec.revision)
            == arguments["raw_commit"]
        )
    proof = verify_source_archive(**arguments).verification
    assert proof.author_signature_verification == "not-performed"
    assert proof.origin_authentication == "not-established"
    assert proof.execution_authorization == "not-granted"


@pytest.mark.parametrize(
    "change", ["sha", "no-commit", "null-payload", "null-signature", "layout", "crlf", "message"]
)
def test_recovery_rejects_unsupported_or_changed_evidence(cached_case: Any, change: str) -> None:
    cache, spec, _ = cached_case
    response = json.loads((cache / "commit.json").read_bytes())
    verification = response["commit"]["verification"]
    if change == "sha":
        response["sha"] = "0" * 40
    elif change == "no-commit":
        response["commit"] = None
    elif change.startswith("null-"):
        verification[change.removeprefix("null-")] = None
    elif change == "layout":
        verification["payload"] = "gpgsig already-there\n" + verification["payload"]
    elif change == "crlf":
        verification["signature"] = verification["signature"].replace("\n", "\r\n")
    else:
        verification["payload"] += "changed"
    with pytest.raises(ValueError):
        recover_github_commit(json_bytes(response), revision=spec.revision)


@pytest.mark.parametrize("data", [b"{}", b"[]", b'{"sha":1,"sha":2}', b"not-json"])
def test_recovery_rejects_malformed_response(data: bytes) -> None:
    with pytest.raises(ValueError):
        recover_github_commit(data, revision="0" * 40)


@pytest.mark.parametrize(
    "name",
    [
        "../outside",
        "fixture/../outside",
        "/absolute",
        "C:/absolute",
        "fixture\\escape",
        "fixture/NUL",
        "fixture/a:stream",
        "fixture/.git/config",
        "fixture/a\x00hidden",
        "fixture/file.",
        "fixture//file",
        "file-at-root",
    ],
)
def test_unsafe_archive_names_rejected(cached_case: Any, name: str) -> None:
    _, _, arguments = cached_case
    archive = zip_bytes([(name, b"data")])
    # ZipInfo strips NUL during creation; mutate encoded names to exercise read-time truncation.
    if "\x00" in name:
        archive = zip_bytes([("fixture/aXhidden", b"data")]).replace(b"aXhidden", b"a\0hidden")
    with pytest.raises(ValueError):
        verify_source_archive(
            **{**arguments, "archive": archive, "archive_sha256": sha256_bytes(archive)}
        )


@pytest.mark.parametrize(
    "kind", ["duplicate", "case", "two-roots", "empty-dir", "empty", "missing"]
)
def test_archive_membership_refusals(cached_case: Any, kind: str) -> None:
    _, _, arguments = cached_case
    entries = {
        "duplicate": [("fixture/a", b"1"), ("fixture/a", b"2")],
        "case": [("fixture/a", b"1"), ("fixture/A", b"2")],
        "two-roots": [("fixture/a", b"1"), ("other/b", b"2")],
        "empty-dir": [("fixture/a", b"1"), ("fixture/unused/", b"")],
        "empty": [("fixture/", b"")],
        "missing": [("fixture/a", b"1")],
    }[kind]
    if kind == "duplicate":
        with pytest.warns(UserWarning, match="Duplicate"):
            archive = zip_bytes(entries)
    else:
        archive = zip_bytes(entries)
    with pytest.raises(ValueError):
        verify_source_archive(
            **{**arguments, "archive": archive, "archive_sha256": sha256_bytes(archive)}
        )


@pytest.mark.parametrize("mode", [stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFDIR])
def test_special_zip_members_rejected(cached_case: Any, mode: int) -> None:
    _, _, arguments = cached_case
    info = zipfile.ZipInfo("fixture/a")
    info.create_system = 3
    info.external_attr = (mode | 0o644) << 16
    archive = zip_bytes([(info, b"some-target")])
    with pytest.raises(ValueError, match="Link, special"):
        verify_source_archive(
            **{**arguments, "archive": archive, "archive_sha256": sha256_bytes(archive)}
        )


@pytest.mark.parametrize("change", ["encrypted", "crc", "compression", "directory-data"])
def test_zip_format_errors_are_not_clean(cached_case: Any, change: str) -> None:
    _, _, arguments = cached_case
    if change == "directory-data":
        archive = zip_bytes([("fixture/", b"unexpected")])
    else:
        data = bytearray(zip_bytes([("fixture/file", b"unique-payload")]))
        if change == "encrypted":
            struct.pack_into("<H", data, 6, 1)
            struct.pack_into("<H", data, data.index(b"PK\x01\x02") + 8, 1)
        elif change == "compression":
            struct.pack_into("<H", data, data.index(b"PK\x01\x02") + 10, 99)
        else:
            data[data.index(b"unique-payload")] = ord("X")
        archive = bytes(data)
    with pytest.raises((ValueError, zipfile.BadZipFile)):
        verify_source_archive(
            **{**arguments, "archive": archive, "archive_sha256": sha256_bytes(archive)}
        )


@pytest.mark.parametrize("limit", ["compressed", "entries", "files", "file-bytes", "total-bytes"])
def test_archive_budgets(cached_case: Any, monkeypatch: pytest.MonkeyPatch, limit: str) -> None:
    _, _, arguments = cached_case
    if limit == "compressed":
        monkeypatch.setattr(source_archive, "MAX_ARCHIVE_BYTES", 1)
    elif limit == "entries":
        monkeypatch.setattr(source_archive, "MAX_TREE_ENTRIES", 1)
    else:
        policy = SnapshotPolicy.model_validate(
            {
                {
                    "files": "max_files",
                    "file-bytes": "max_file_bytes",
                    "total-bytes": "max_total_bytes",
                }[limit]: 1
            }
        )
        monkeypatch.setattr(source_archive, "SnapshotPolicy", lambda: policy)
    with pytest.raises(ValueError, match="limit"):
        verify_source_archive(**arguments)


def test_preparation_replays_repeats_and_does_not_overwrite(
    cached_case: Any, tmp_path: Path
) -> None:
    cache, spec, _ = cached_case
    before = {p: sha256_file(p) for p in cache.iterdir()}
    first = tmp_path / "first"
    summary = prepare_cached_source(spec, cache=cache, output=first)
    repeat = prepare_cached_source(spec, cache=cache, output=tmp_path / "second")
    assert {k: v for k, v in summary.items() if k != "prepared_at"} == {
        k: v for k, v in repeat.items() if k != "prepared_at"
    }
    assert summary["files_verified"] == spec.expected_files == 21
    assert summary["scanner_invocations"] == 0 and summary["held_out_eligible"] is False
    assert summary["content_parsing"] == "not-performed"
    proof = GitSourceVerification.model_validate_json(
        (first / "git-verification.json").read_bytes()
    )
    inventory = ArtifactInventory.model_validate_json(
        (first / "artifact-inventory.json").read_bytes()
    )
    bind_inventory_to_git(inventory, proof)
    assert inventory.snapshot.license_status == "unknown"
    for record in json.loads((first / "evidence-manifest.json").read_bytes())["files"]:
        assert sha256_file(first / record["path"]) == record["sha256"]
    retained = {p: sha256_file(p) for p in first.rglob("*") if p.is_file()}
    with pytest.raises(FileExistsError):
        prepare_cached_source(spec, cache=cache, output=first)
    assert retained == {p: sha256_file(p) for p in first.rglob("*") if p.is_file()}
    assert before == {p: sha256_file(p) for p in cache.iterdir()}
    next((first / "source").rglob("*.py")).write_bytes(b"changed")
    with pytest.raises(ValueError, match="changed"):
        read_verified_source(
            proof,
            raw_commit=(first / "raw/commit.bin").read_bytes(),
            raw_tree=(first / "raw/tree-exact.json").read_bytes(),
            source_root=first / "source",
        )


@pytest.mark.parametrize(
    "field",
    [
        "archive_sha256",
        "commit_response_sha256",
        "tree_response_sha256",
        "root_tree",
        "expected_files",
        "expected_bytes",
    ],
)
def test_failed_attempts_keep_receipts(cached_case: Any, tmp_path: Path, field: str) -> None:
    cache, spec, _ = cached_case
    value = spec.model_dump(mode="json")
    value[field] = (
        1 if field.startswith("expected_") else "0" * (40 if field == "root_tree" else 64)
    )
    changed = SourcePreparationSpec.model_validate(value)
    output = tmp_path / "failure"
    with pytest.raises(ValueError):
        prepare_cached_source(changed, cache=cache, output=output)
    summary = json.loads((output / "summary.json").read_bytes())
    assert summary["passed"] is False and summary["stage"] != "complete"
    assert summary["scanner_invocations"] == 0
    assert (output / "evidence-manifest.json").is_file()
    assert not (output / "source").exists()


def test_cache_output_overlap_and_hardlink_refused(cached_case: Any, tmp_path: Path) -> None:
    cache, spec, _ = cached_case
    with pytest.raises(ValueError, match="overlap"):
        prepare_cached_source(spec, cache=cache, output=cache / "output")
    os.link(cache / "commit.json", tmp_path / "hardlink")
    with pytest.raises(ValueError, match="hard-linked"):
        prepare_cached_source(spec, cache=cache, output=tmp_path / "hardlink-attempt")


@pytest.mark.parametrize("kind", ["symlink", "reparse"])
def test_preparation_rejects_linked_ancestors(
    cached_case: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    cache, spec, _ = cached_case
    original = Path.lstat

    def linked(path: Path) -> Any:
        if path == cache:
            return SimpleNamespace(
                st_mode=stat.S_IFLNK if kind == "symlink" else stat.S_IFDIR,
                st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT if kind == "reparse" else 0,
            )
        return original(path)

    monkeypatch.setattr(Path, "lstat", linked)
    with pytest.raises(ValueError, match="links or reparse"):
        prepare_cached_source(spec, cache=cache, output=tmp_path / "refused")
    assert not (tmp_path / "refused").exists()
