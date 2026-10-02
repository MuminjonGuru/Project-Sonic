from __future__ import annotations

import io
import json
import shutil
import tarfile
from pathlib import Path

import pytest

from agentsec_evidence.agents import image_transfer as transfer
from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.core.io import model_bytes
from agentsec_evidence.core.time import utc_now

PROJECT = Path(__file__).resolve().parents[2]


def make_archive(path: Path, fault: str = "") -> tuple[str, str]:
    blobs = [
        json.dumps({"os": "linux", "architecture": "amd64", "role": role}).encode()
        for role in ("scanner", "validator")
    ]
    if fault == "platform":
        blobs[0] = b'{"os":"linux","architecture":"arm64"}'
    ids = tuple("sha256:" + sha256_bytes(blob) for blob in blobs)
    assert len(ids) == 2
    manifests: list[dict[str, object]] = [
        {"Config": f"blobs/sha256/{sha256_bytes(blob)}", "RepoTags": None, "Layers": []}
        for blob in blobs
    ]
    if fault == "tags":
        manifests[0]["RepoTags"] = ["must-not-retag:latest"]
    if fault == "extra-image":
        manifests.append(manifests[0])
    if fault == "missing-config":
        manifests[0]["Config"] = "missing.json"
    with tarfile.open(path, "w") as archive:

        def add(name: str, raw: bytes) -> None:
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))

        if fault != "missing-manifest":
            add("manifest.json", json.dumps(manifests).encode())
        for blob in blobs:
            add(f"blobs/sha256/{sha256_bytes(blob)}", blob)
        if fault == "duplicate":
            add("manifest.json", b"[]")
        if fault in ("../outside", "/absolute", "C:/absolute", "bad\\name"):
            add(fault, b"bad")
        if fault == "link":
            link = tarfile.TarInfo("link")
            link.type = tarfile.SYMTYPE
            link.linkname = "../outside"
            archive.addfile(link)
    return ids[0], ids[1]


def make_bundle(root: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[transfer.ImageBundle, str]:
    root.mkdir()
    pins = make_archive(root / "images.tar")
    monkeypatch.setattr(transfer, "_pins", lambda _: (pins, "a" * 64))
    manifest = transfer.ImageBundle(
        created_at=utc_now(),
        image_ids=pins,
        tool_config_sha256="a" * 64,
        archive_sha256=sha256_file(root / "images.tar"),
        archive_bytes=(root / "images.tar").stat().st_size,
    )
    raw = model_bytes(manifest)
    (root / "manifest.json").write_bytes(raw)
    return manifest, sha256_bytes(raw)


def test_verify_bundle_needs_no_docker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "bundle"
    manifest, digest = make_bundle(root, monkeypatch)
    assert transfer.verify_bundle(root, digest, PROJECT) == manifest


@pytest.mark.parametrize(
    "fault",
    [
        "tags",
        "extra-image",
        "missing-config",
        "missing-manifest",
        "duplicate",
        "link",
        "../outside",
        "/absolute",
        "C:/absolute",
        "bad\\name",
        "platform",
    ],
)
def test_archive_refuses_unsafe_or_different_images(tmp_path: Path, fault: str) -> None:
    path = tmp_path / "images.tar"
    pins = make_archive(path, fault)
    with pytest.raises(ValueError):
        transfer.verify_image_archive(path, pins)


def test_archive_checks_config_content_hash(tmp_path: Path) -> None:
    path = tmp_path / "images.tar"
    pins = make_archive(path)
    with pytest.raises(ValueError, match="IDs differ"):
        transfer.verify_image_archive(path, (pins[0], "sha256:" + "f" * 64))


@pytest.mark.parametrize("fault", ["digest", "archive", "config", "pins", "length", "unknown"])
def test_reject_before_docker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    root = tmp_path / "bundle"
    manifest, digest = make_bundle(root, monkeypatch)
    calls = []
    monkeypatch.setattr(transfer, "_DockerTransfer", lambda _: calls.append("docker"))
    if fault == "digest":
        digest = "b" * 64
    elif fault == "archive":
        raw = (root / "images.tar").read_bytes()
        (root / "images.tar").write_bytes(b"x" + raw[1:])
    elif fault == "config":
        monkeypatch.setattr(transfer, "_pins", lambda _: (manifest.image_ids, "b" * 64))
    elif fault == "pins":
        monkeypatch.setattr(transfer, "_pins", lambda _: (("wrong", "wrong"), "a" * 64))
    else:
        value = json.loads((root / "manifest.json").read_bytes())
        value["archive_bytes" if fault == "length" else "unknown"] = 10
        raw = json.dumps(value).encode()
        (root / "manifest.json").write_bytes(raw)
        digest = sha256_bytes(raw)
    output = tmp_path / "import"
    with pytest.raises(ValueError):
        transfer.import_images(PROJECT, root, digest, output)
    assert not calls
    assert json.loads((output / "status.json").read_bytes())["passed"] is False


def test_manifest_rejects_duplicate_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "bundle"
    _, _digest = make_bundle(root, monkeypatch)
    raw = (root / "manifest.json").read_bytes().rstrip()[:-1] + b',"platform":"linux/amd64"}'
    (root / "manifest.json").write_bytes(raw)
    with pytest.raises(ValueError, match="Duplicate"):
        transfer.verify_bundle(root, sha256_bytes(raw), PROJECT)


def test_admitted_pins_come_from_existing_strict_contract() -> None:
    pins, digest = transfer._pins(PROJECT)
    assert all(item.startswith("sha256:") for item in pins)
    assert digest == sha256_file(PROJECT / "configs/tools/agent-audit.toml")


def test_no_overwrite(tmp_path: Path) -> None:
    with pytest.raises(FileExistsError):
        transfer.export_images(PROJECT, tmp_path)
    with pytest.raises(FileExistsError):
        transfer.import_images(PROJECT, tmp_path, "a" * 64, tmp_path)


@pytest.mark.parametrize("fault", ["ids", "platform", "count"])
def test_inspect_must_match_both_pins(fault: str) -> None:
    pins = ("sha256:" + "a" * 64, "sha256:" + "b" * 64)
    records = [{"Id": pin, "Os": "linux", "Architecture": "amd64"} for pin in pins]
    transfer.verify_inspection(json.dumps(records).encode(), pins)
    if fault == "ids":
        records[1]["Id"] = pins[0]
    elif fault == "platform":
        records[0]["Os"] = "windows"
    else:
        records.pop()
    with pytest.raises(ValueError):
        transfer.verify_inspection(json.dumps(records).encode(), pins)


def test_transfer_calls_only_save_load_and_inspect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.tar"
    pins = make_archive(source)
    monkeypatch.setattr(transfer, "_pins", lambda _: (pins, "a" * 64))
    calls: list[list[str]] = []

    class FakeDocker:
        def __init__(self, output: Path) -> None:
            self.output = output

        def run(self, label: str, arguments: list[str], generated: Path | None = None) -> bytes:
            calls.append(arguments)
            if arguments[0] == "inspect":
                return json.dumps(
                    [{"Id": pin, "Os": "linux", "Architecture": "amd64"} for pin in pins]
                ).encode()
            if arguments[0] == "save":
                assert arguments[1:3] == ["--output", str(generated)]
                assert arguments[3:] == list(pins)
                assert generated is not None
                shutil.copyfile(source, generated)
            else:
                assert arguments == ["load", "--input", str(self.output / "images.tar")]
            return b""

    monkeypatch.setattr(transfer, "_DockerTransfer", FakeDocker)
    bundle = tmp_path / "export"
    digest = transfer.export_images(PROJECT, bundle)
    transfer.import_images(PROJECT, bundle, digest, tmp_path / "import")
    assert [call[0] for call in calls] == ["inspect", "save", "load", "inspect"]
    assert json.loads((tmp_path / "import/status.json").read_bytes())["passed"] is True


def test_failed_export_retains_failure_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable(_: Path) -> None:
        raise RuntimeError("Docker unavailable")

    monkeypatch.setattr(transfer, "_DockerTransfer", unavailable)
    with pytest.raises(RuntimeError, match="unavailable"):
        transfer.export_images(PROJECT, tmp_path / "export")
    status = json.loads((tmp_path / "export/status.json").read_bytes())
    assert status == {"passed": False, "error": "Docker unavailable"}


@pytest.mark.parametrize("fault", ["", "digest", "size", "platform", "extra", "tags", "binding"])
def test_oci_index_identity_chain(tmp_path: Path, fault: str) -> None:
    path = tmp_path / "images.tar"
    config_ids = make_archive(path)
    with tarfile.open(path, "r:") as archive:
        content = {}
        for member in archive:
            handle = archive.extractfile(member)
            assert handle is not None
            with handle:
                content[member.name] = handle.read()

    def blob(value: object) -> dict[str, object]:
        raw = json.dumps(value).encode()
        digest = sha256_bytes(raw)
        content["blobs/sha256/" + digest] = raw
        return {"digest": "sha256:" + digest, "size": len(raw)}

    roots = []
    for config_id in config_ids:
        raw = content["blobs/sha256/" + config_id.removeprefix("sha256:")]
        runtime = blob({"config": {"digest": config_id, "size": len(raw)}, "layers": []})
        runtime["platform"] = {"os": "linux", "architecture": "amd64"}
        attestation = blob({"config": {}, "layers": []})
        attestation["platform"] = {"os": "unknown", "architecture": "unknown"}
        attestation["annotations"] = {
            "vnd.docker.reference.type": "attestation-manifest",
            "vnd.docker.reference.digest": runtime["digest"] if fault != "binding" else "wrong",
        }
        if fault == "platform":
            runtime["platform"] = {"os": "linux", "architecture": "arm64"}
        root = blob({"manifests": [runtime, attestation]})
        if fault == "size":
            root["size"] = 1
        if fault == "tags":
            root["annotations"] = {"org.opencontainers.image.ref.name": "latest"}
        roots.append(root)
    pins = (str(roots[0]["digest"]), str(roots[1]["digest"]))
    if fault == "digest":
        content["blobs/sha256/" + pins[0].removeprefix("sha256:")] = b"{}"
    if fault == "extra":
        roots.append(roots[0])
    content["index.json"] = json.dumps({"schemaVersion": 2, "manifests": roots}).encode()
    with tarfile.open(path, "w") as archive:
        for name, raw in content.items():
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
    if fault:
        with pytest.raises(ValueError):
            transfer.verify_image_archive(path, pins)
    else:
        transfer.verify_image_archive(path, pins)


def test_import_retains_exact_manifest_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "bundle"
    manifest, _ = make_bundle(bundle, monkeypatch)
    raw = b"  " + model_bytes(manifest)
    (bundle / "manifest.json").write_bytes(raw)

    class FakeDocker:
        def __init__(self, output: Path) -> None:
            pass

        def run(self, label: str, arguments: list[str]) -> bytes:
            return json.dumps(
                [{"Id": pin, "Os": "linux", "Architecture": "amd64"} for pin in manifest.image_ids]
            ).encode()

    monkeypatch.setattr(transfer, "_DockerTransfer", FakeDocker)
    transfer.import_images(PROJECT, bundle, sha256_bytes(raw), tmp_path / "import")
    assert (tmp_path / "import/manifest.json").read_bytes() == raw
