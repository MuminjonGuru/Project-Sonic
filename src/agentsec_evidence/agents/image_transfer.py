"""Private transfer of the exact admitted images, not a source-build or admission mechanism."""

from __future__ import annotations

import dataclasses
import json
import re
import shutil
import tarfile
from collections.abc import Callable
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import Field

from agentsec_evidence.agents.execution import AgentAuditToolConfig
from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.core.io import atomic_write_bytes, model_bytes
from agentsec_evidence.core.time import utc_now
from agentsec_evidence.execution.config import Sha256Text, StrictConfigModel, load_toml_config
from agentsec_evidence.execution.process import run_bounded_process
from agentsec_evidence.orchestration.shared import minimal_environment, resolve_docker

MAX_ARCHIVE_BYTES = 4 * 1024**3
MAX_JSON_BYTES = 1024**2


class ImageBundle(StrictConfigModel):
    contract: Literal["agent-image-transfer-v1"] = "agent-image-transfer-v1"
    created_at: datetime
    platform: Literal["linux/amd64"] = "linux/amd64"
    tool_config_sha256: Sha256Text
    image_ids: tuple[str, str]
    archive: Literal["images.tar"] = "images.tar"
    archive_sha256: Sha256Text
    archive_bytes: int = Field(strict=True, gt=0, le=MAX_ARCHIVE_BYTES)
    scope: Literal["private-recovery-not-public-distribution"] = (
        "private-recovery-not-public-distribution"
    )


def _json(raw: bytes) -> object:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("JSON exceeds transfer metadata limit")
    return json.loads(raw, object_pairs_hook=unique)


def _regular(path: Path) -> None:
    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise ValueError(f"Expected a regular, non-linked file: {path}")


def _pins(project_root: Path) -> tuple[tuple[str, str], str]:
    config = load_toml_config(project_root / "configs/tools/agent-audit.toml", AgentAuditToolConfig)
    return (config.value.image, config.value.validator_image), config.sha256


def _oci_configs(read: Callable[[str], bytes], image_ids: tuple[str, str]) -> list[str]:
    def descriptor(value: object) -> dict[str, object]:
        if not isinstance(value, dict):
            raise ValueError("Invalid OCI descriptor")
        digest = value.get("digest")
        if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("Invalid OCI digest")
        raw = read("blobs/sha256/" + digest.removeprefix("sha256:"))
        if len(raw) != value.get("size") or "sha256:" + sha256_bytes(raw) != digest:
            raise ValueError("OCI descriptor checksum or size mismatch")
        parsed = _json(raw)
        if not isinstance(parsed, dict):
            raise ValueError("Invalid OCI document")
        return parsed

    index = _json(read("index.json"))
    if not isinstance(index, dict) or index.get("schemaVersion") != 2:
        raise ValueError("Invalid OCI root index")
    roots = index.get("manifests")
    if not isinstance(roots, list) or len(roots) != 2:
        raise ValueError("OCI root index must identify two admitted images")
    root_ids = []
    configs = []
    for root in roots:
        image = descriptor(root)
        if root.get("annotations"):
            raise ValueError("Named OCI references are not accepted in an image-ID export")
        root_ids.append(root["digest"])
        children = image.get("manifests")
        if not isinstance(children, list) or not 1 <= len(children) <= 2:
            raise ValueError("Unsupported OCI index shape")
        runtimes = []
        attestations = []
        for child in children:
            document = descriptor(child)
            platform = child.get("platform")
            if platform == {"os": "linux", "architecture": "amd64"}:
                runtime_config = document.get("config")
                descriptor(runtime_config)
                assert isinstance(runtime_config, dict)
                configs.append(str(runtime_config["digest"]))
                runtimes.append(child["digest"])
            elif platform == {"os": "unknown", "architecture": "unknown"}:
                annotations = child.get("annotations", {})
                if annotations.get("vnd.docker.reference.type") != "attestation-manifest":
                    raise ValueError("Unsupported non-runtime OCI descriptor")
                attestations.append(annotations.get("vnd.docker.reference.digest"))
            else:
                raise ValueError("Unexpected executable platform in OCI index")
        if len(runtimes) != 1 or any(item != runtimes[0] for item in attestations):
            raise ValueError("OCI index must bind one runtime and its optional attestation")
    if sorted(root_ids) != sorted(image_ids):
        raise ValueError("OCI index IDs differ from the admitted pins")
    return configs


def verify_image_archive(path: Path, image_ids: tuple[str, str]) -> None:
    """Inspect outer archive metadata without extracting layers or executing image content."""
    _regular(path)
    if not 0 < path.stat().st_size <= MAX_ARCHIVE_BYTES:
        raise ValueError("Image archive exceeds transfer size limit or is empty")
    with tarfile.open(path, mode="r:") as archive:
        entries: dict[str, tarfile.TarInfo] = {}
        for entry in archive:
            name = PurePosixPath(entry.name)
            if (
                len(entries) >= 4096
                or name.is_absolute()
                or ".." in name.parts
                or "\\" in entry.name
                or ":" in entry.name
                or entry.name in entries
                or not (entry.isfile() or entry.isdir())
            ):
                raise ValueError("Unsafe, duplicate or excessive archive members")
            entries[entry.name] = entry

        def read(name: str) -> bytes:
            entry = entries.get(name)
            if entry is None or not entry.isfile() or entry.size > MAX_JSON_BYTES:
                raise ValueError("Missing or oversized image metadata")
            handle = archive.extractfile(entry)
            assert handle is not None
            with handle:
                return handle.read(MAX_JSON_BYTES + 1)

        manifests = _json(read("manifest.json"))
        if not isinstance(manifests, list) or len(manifests) != len(image_ids):
            raise ValueError("Archive must contain exactly the two admitted images")
        found = []
        for item in manifests:
            if not isinstance(item, dict) or not isinstance(item.get("Config"), str):
                raise ValueError("Invalid Docker save manifest")
            if item.get("RepoTags") not in (None, []):
                raise ValueError("Tagged images are not accepted; export by exact image ID")
            raw = read(item["Config"])
            found.append("sha256:" + sha256_bytes(raw))
            config = _json(raw)
            if (
                not isinstance(config, dict)
                or config.get("os") != "linux"
                or config.get("architecture") != "amd64"
            ):
                raise ValueError("Only the admitted linux/amd64 images are supported")
        # containerd-backed Docker may identify an attested OCI index, not its config blob.
        expected_configs = _oci_configs(read, image_ids) if "index.json" in entries else image_ids
        if sorted(found) != sorted(expected_configs):
            raise ValueError("Archive image configuration IDs differ from the admitted pins")


def verify_bundle(bundle: Path, manifest_sha256: str, project_root: Path) -> ImageBundle:
    if not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256):
        raise ValueError("A trusted lowercase SHA-256 manifest digest is required")
    if bundle.is_symlink() or bundle.is_junction() or not bundle.is_dir():
        raise ValueError("Bundle must be a non-linked directory")
    manifest_path = bundle / "manifest.json"
    _regular(manifest_path)
    if manifest_path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError("Transfer manifest is too large")
    raw = manifest_path.read_bytes()
    if sha256_bytes(raw) != manifest_sha256:
        raise ValueError("Transfer manifest checksum differs from the trusted digest")
    manifest = ImageBundle.model_validate(_json(raw))
    pins, config_hash = _pins(project_root)
    if manifest.image_ids != pins or manifest.tool_config_sha256 != config_hash:
        raise ValueError("Transfer manifest differs from the checkout's admitted treatment")
    path = bundle / manifest.archive
    _regular(path)
    if (
        path.stat().st_size != manifest.archive_bytes
        or sha256_file(path) != manifest.archive_sha256
    ):
        raise ValueError("Image archive checksum or size mismatch")
    verify_image_archive(path, pins)
    return manifest


def verify_inspection(raw: bytes, pins: tuple[str, str]) -> None:
    records = _json(raw)
    if not isinstance(records, list) or len(records) != len(pins):
        raise ValueError("Docker did not inspect both admitted images")
    found = []
    for record in records:
        if (
            not isinstance(record, dict)
            or record.get("Os") != "linux"
            or record.get("Architecture") != "amd64"
        ):
            raise ValueError("Docker image platform mismatch")
        found.append(record.get("Id"))
    if set(found) != set(pins):
        raise ValueError("Docker image IDs differ from admitted pins")


def _record(path: Path, value: object) -> None:
    atomic_write_bytes(path, (json.dumps(value, indent=2, default=str) + "\n").encode())


class _DockerTransfer:
    def __init__(self, output: Path) -> None:
        docker = resolve_docker(None)
        if docker is None:
            raise RuntimeError("Docker CLI is unavailable")
        self.docker = docker
        self.output = output
        self.environment = minimal_environment(output / "runtime")

    def run(self, label: str, arguments: list[str], generated: Path | None = None) -> bytes:
        capture = run_bounded_process(
            [str(self.docker), "image", *arguments],
            cwd=self.output,
            environment=self.environment,
            timeout_seconds=600,
            max_stdout_bytes=MAX_JSON_BYTES,
            max_stderr_bytes=MAX_JSON_BYTES,
            monitored_files=() if generated is None else (generated,),
            max_generated_bytes=None if generated is None else MAX_ARCHIVE_BYTES,
        )
        atomic_write_bytes(self.output / "logs" / f"{label}.stdout.bin", capture.stdout)
        atomic_write_bytes(self.output / "logs" / f"{label}.stderr.bin", capture.stderr)
        metadata = dataclasses.asdict(capture)
        del metadata["stdout"], metadata["stderr"]
        _record(self.output / "logs" / f"{label}.json", metadata)
        if capture.exit_code != 0 or capture.timed_out or capture.output_limited:
            raise RuntimeError(f"Docker {label} failed; retained logs under {self.output}")
        return capture.stdout


def export_images(project_root: Path, output: Path) -> str:
    output = output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    try:
        pins, config_hash = _pins(project_root)
        docker = _DockerTransfer(output)
        verify_inspection(docker.run("inspect-before", ["inspect", *pins]), pins)
        archive = output / "images.tar"
        docker.run("save", ["save", "--output", str(archive), *pins], generated=archive)
        verify_image_archive(archive, pins)
        manifest = ImageBundle(
            created_at=utc_now(),
            tool_config_sha256=config_hash,
            image_ids=pins,
            archive_sha256=sha256_file(archive),
            archive_bytes=archive.stat().st_size,
        )
        raw = model_bytes(manifest)
        atomic_write_bytes(output / "manifest.json", raw)
        digest = sha256_bytes(raw)
        verify_bundle(output, digest, project_root)
        _record(output / "status.json", {"passed": True, "manifest_sha256": digest})
        return digest
    except Exception as exc:
        _record(output / "status.json", {"passed": False, "error": str(exc)})
        raise


def import_images(project_root: Path, bundle: Path, manifest_sha256: str, output: Path) -> None:
    output = output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    try:
        manifest = verify_bundle(bundle, manifest_sha256, project_root)
        # Load a verified private copy, never an archive changing in a shared incoming folder.
        archive = output / "images.tar"
        shutil.copyfile(bundle / manifest.archive, archive)
        if archive.stat().st_size != manifest.archive_bytes or (
            sha256_file(archive) != manifest.archive_sha256
        ):
            raise ValueError("Archive changed while staging import")
        raw_manifest = (bundle / "manifest.json").read_bytes()
        if sha256_bytes(raw_manifest) != manifest_sha256:
            raise ValueError("Manifest changed while staging import")
        atomic_write_bytes(output / "manifest.json", raw_manifest)
        docker = _DockerTransfer(output)
        docker.run("load", ["load", "--input", str(archive)])
        verify_inspection(
            docker.run("inspect-after", ["inspect", *manifest.image_ids]), manifest.image_ids
        )
        _record(
            output / "status.json",
            {
                "passed": True,
                "manifest_sha256": manifest_sha256,
                "image_ids": manifest.image_ids,
                "scope": "load-and-identity-verification-not-source-rebuild-or-scan",
            },
        )
    except Exception as exc:
        _record(output / "status.json", {"passed": False, "error": str(exc)})
        raise
