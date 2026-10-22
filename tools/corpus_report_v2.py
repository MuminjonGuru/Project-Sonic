"""Offline, cell-chunked corpus reports with unchanged retained-file budgets."""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Any, cast

from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.core.io import atomic_write_bytes
from agentsec_evidence.corpus.execution import verify_core
from agentsec_evidence.corpus.reporting import build_report, render
from agentsec_evidence.pilot.runner import save
from agentsec_evidence.reporting.html_styles import STYLES
from agentsec_evidence.research.retained import (
    RetainedManifest,
    plain_path,
    read_retained_research,
)

DRIVER = "tools/corpus_report_v2.py"
SPEC = "docs/corpus-report-recovery.md"


def encoded(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, allow_nan=False, indent=2, sort_keys=True) + "\n"
    ).encode()


def detail_page(key: str, observation: dict[str, Any]) -> bytes:
    # Escape native evidence as text; filenames and navigation are generated, never source paths.
    detail = {k: v for k, v in observation.items() if k != "semantic"}
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'; "
        "base-uri 'none'; form-action 'none'\">"
        "<title>Retained observation</title><style>"
        + STYLES
        + "main{max-width:1200px;margin:auto;padding:1rem}h1{font-size:1.4rem;"
        "overflow-wrap:anywhere}</style></head><body><main>"
        '<a href="../report.html">Back to repository summary</a><h1>'
        + html.escape(key)
        + "</h1><p>Internal, unredacted static evidence. "
        "Not a confirmed vulnerability. The paired JSON preserves the semantic projection too.</p>"
        "<pre>" + html.escape(encoded(detail).decode()) + "</pre></main></body></html>"
    ).encode()


def package(report: dict[str, Any]) -> dict[str, bytes]:
    """Lossless v1 JSON reconstruction through bounded, indexed observation documents."""
    if report.get("contract") != "corpus-core-report-v1":
        raise ValueError("Expected native-replayed v1 report projection")
    observations = report["observations"]
    keys = [row["key"] for row in report["rows"] if row["state"] == "observed"]
    if len(set(keys)) != len(keys) or set(keys) != set(observations):
        raise ValueError("Observation and observed-row membership differs")
    files: dict[str, bytes] = {}
    index = []
    links = []
    for number, key in enumerate(keys, 1):
        path = f"observations/{number:04d}.json"
        page = f"observations/{number:04d}.html"
        raw = encoded(
            {"contract": "corpus-core-observation-v2", "key": key, "observation": observations[key]}
        )
        files[path] = raw
        files[page] = detail_page(key, observations[key])
        index.append(
            {
                "key": key,
                "json": path,
                "html": page,
                "json_sha256": sha256_bytes(raw),
                "json_bytes": len(raw),
                "html_sha256": sha256_bytes(files[page]),
            }
        )
        links.append(
            '<li><a href="'
            + page
            + '">'
            + html.escape(key)
            + '</a> (<a href="'
            + path
            + '">JSON</a>)</li>'
        )
    summary = {k: v for k, v in report.items() if k != "observations"}
    summary.update(
        contract="corpus-core-report-v2",
        observation_index=index,
        reconstruction_contract="corpus-core-report-v1",
    )
    files["report.json"] = encoded(summary)
    # Reuse the established summary renderer without embedding unbounded evidence in its page.
    overview = render({**report, "observations": {}}).decode()
    marker = "<h2>Evidence records</h2>"
    if overview.count(marker) != 1:
        raise ValueError("Summary renderer evidence section changed")
    overview = overview.replace(
        marker,
        marker + "<p>Version 2: one document per observed cell. "
        "All repetitions retained; no records dropped.</p><ul>" + "".join(links) + "</ul>",
    )
    files["report.html"] = overview.encode()
    manifest_for(files)  # Refuse before writing if a cell or the whole package exceeds its budget.
    return files


def manifest_for(files: dict[str, bytes]) -> dict[str, Any]:
    manifest = {
        "files": [
            {"path": path, "bytes": len(raw), "sha256": sha256_bytes(raw)}
            for path, raw in sorted(files.items())
        ]
    }
    RetainedManifest.model_validate(manifest)
    return manifest


def write_report(project: Path, source: Path, output: Path) -> dict[str, Any]:
    output = output.absolute()
    plain_path(output.parent, directory=True)
    if output.exists():
        raise ValueError("Use a fresh report directory")
    files = package(build_report(verify_core(project, source)))
    output.mkdir()
    for name, raw in files.items():
        atomic_write_bytes(output / name, raw)
    save(output / "evidence-manifest.json", manifest_for(files))
    return verify_report(project, source, output)


def read_report(output: Path) -> dict[str, Any]:
    """Reconstruct the lossless v1 projection; this alone is not native attestation."""
    retained = read_retained_research(output)
    report = json.loads(retained.read("report.json"))
    if (
        report.pop("contract", None) != "corpus-core-report-v2"
        or report.pop("reconstruction_contract", None) != "corpus-core-report-v1"
    ):
        raise ValueError("Wrong chunked report contract")
    index = report.pop("observation_index")
    observations = {}
    for entry in index:
        raw = retained.read(entry["json"])
        value = json.loads(raw)
        if (
            entry["key"] in observations
            or value.get("key") != entry["key"]
            or value.get("contract") != "corpus-core-observation-v2"
            or sha256_bytes(raw) != entry["json_sha256"]
            or len(raw) != entry["json_bytes"]
        ):
            raise ValueError("Observation index binding differs")
        observations[entry["key"]] = value["observation"]
    report.update(contract="corpus-core-report-v1", observations=observations)
    if retained.files != package(report):
        raise ValueError("Chunked report membership or projection differs")
    return cast(dict[str, Any], report)


def verify_report(project: Path, source: Path, output: Path) -> dict[str, Any]:
    report = read_report(output)
    if report != build_report(verify_core(project, source)):
        raise ValueError("Chunked report differs from native replay")
    return {
        "contract": "corpus-core-report-verification-v2",
        "passed": True,
        "execution_finished": report["execution_finished"],
        "source_manifest_sha256": report["source_manifest_sha256"],
        "scanner_invocations": 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("write", "verify"))
    parser.add_argument("--project", type=Path, default=Path.cwd())
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    operation = write_report if args.mode == "write" else verify_report
    print(json.dumps(operation(args.project, args.source, args.output), indent=2))


if __name__ == "__main__":
    main()
