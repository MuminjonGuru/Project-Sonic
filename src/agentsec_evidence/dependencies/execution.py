from __future__ import annotations

import json
from pathlib import Path

from agentsec_evidence.execution.docker import _mount

SYFT_IMAGE = "anchore/syft@sha256:500e2d872ac019436926e8322b4fc1f39441d94d21f6f4046c6ff29b30e8cb02"
OSV_IMAGE = (
    "ghcr.io/google/osv-scanner@sha256:"
    "afd838850ac1a0fcc15ff4a041dc9ba11123c3f0d2666217a5f0fcf9222b55fa"
)


def build_dependency_argv(
    *,
    docker: Path,
    name: str,
    producer: str,
    input_file: Path,
    output: Path,
    config: Path,
    database: Path | None = None,
    adjacent_config: Path | None = None,
) -> list[str]:
    # Explicit config and offline, non-resolving OSV keep both comparison paths controlled.
    # Exclude source-dependent call analysis from this inventory-and-matching experiment.
    if (
        producer not in {"syft", "osv"}
        or not name.startswith("sonic-dep-")
        or not name.replace("-", "").isalnum()
    ):
        raise ValueError("Invalid dependency producer/container name")
    input_name = "uv.lock" if producer == "syft" or input_file.name == "uv.lock" else "bom.cdx.json"
    argv = [
        str(docker),
        "run",
        "--rm",
        "--pull",
        "never",
        "--name",
        name,
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "65534:65534",
        "--cpus",
        "2",
        "--memory",
        "2g",
        "--pids-limit",
        "256",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=256m",
        "--env",
        "HOME=/tmp",
        "--mount",
        _mount(input_file, f"/src/{input_name}", read_only=True),
        "--mount",
        _mount(output, "/output", read_only=False),
    ]
    if adjacent_config:
        argv.extend(["--mount", _mount(adjacent_config, "/src/osv-scanner.toml", read_only=True)])
    if producer == "syft":
        argv.extend(
            [
                "--mount",
                _mount(config, "/config.yaml", read_only=True),
                SYFT_IMAGE,
                "scan",
                "dir:/src",
                "--config",
                "/config.yaml",
                "--output",
                "syft-json=/output/syft.json",
                "--output",
                "cyclonedx-json@1.6=/output/bom.cdx.json",
            ]
        )
    else:
        if database is None:
            raise ValueError("OSV requires an explicit frozen database")
        argv.extend(
            [
                "--env",
                "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/database",
                "--mount",
                _mount(database, "/database/osv-scalibr/PyPI/all.zip", read_only=True),
                "--mount",
                _mount(config, "/config.toml", read_only=True),
                OSV_IMAGE,
                "scan",
                "source",
                "--lockfile",
                f"/src/{input_name}",
                "--config",
                "/config.toml",
                "--offline",
                "--no-call-analysis=all",
                "--no-resolve",
                "--all-packages",
                "--format=json",
                "--output-file",
                "/output/osv.json",
            ]
        )
    return argv


def verify_tool_record(path: Path) -> None:
    record = json.loads(path.read_bytes())
    if record["syft"]["image"] != SYFT_IMAGE or record["osv"]["image"] != OSV_IMAGE:
        raise ValueError("Tool manifest does not match this adapter version")
    if record["cyclonedx_version"] != "1.6":
        raise ValueError("Unsupported CycloneDX treatment")
