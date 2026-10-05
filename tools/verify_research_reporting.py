"""Replay a retained controlled research matrix into common reports without running tools."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from agentsec_evidence.core.identity import semantic_hash, sha256_file
from agentsec_evidence.core.io import atomic_write_bytes
from agentsec_evidence.reporting.service import validate_common_report, write_common_report
from agentsec_evidence.research.retained import read_retained_research

ROOT = Path(__file__).resolve().parents[1]


def save(path: Path, value: Any) -> None:
    atomic_write_bytes(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def checksum(root: Path) -> str:
    return semantic_hash(
        {
            p.relative_to(root).as_posix(): sha256_file(p)
            for p in sorted(root.rglob("*"))
            if p.is_file()
        }
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--legacy-bundle", type=Path, action="append", default=[])
    args = parser.parse_args()
    output = args.output.resolve()
    if output == ROOT / "workspace" or not output.is_relative_to(ROOT / "workspace"):
        raise ValueError("Verification output must be a new ignored workspace child")
    output.mkdir(parents=True, exist_ok=False)
    retained = read_retained_research(args.matrix)
    registry = json.loads(retained.read("cases.json"))
    sources = [retained.root / case["id"] for case in registry["cases"]]
    legacy = [p.resolve(strict=True) for p in args.legacy_bundle]
    before = {str(p): checksum(p) for p in legacy}
    rows = []
    for source in sources:
        destination = output / source.name
        report = write_common_report(project_root=ROOT, bundles=[source], output=destination)
        row = {
            "case": source.name,
            "source_state": report.sources[0].state,
            "contract": report.contract,
            "sarif_runs": report.sarif_runs,
            "validation": validate_common_report(ROOT, destination),
        }
        rows.append(row)
        save(output / "progress.json", rows)
        print(source.name, report.sources[0].state, report.sarif_runs, "SARIF runs", flush=True)
    bundles = [*sources, *legacy]
    combined = write_common_report(project_root=ROOT, bundles=bundles, output=output / "combined")
    validate_common_report(ROOT, output / "combined")
    write_common_report(project_root=ROOT, bundles=bundles, output=output / "repeat")
    equal = (output / "combined/results.sarif").read_bytes() == (
        output / "repeat/results.sarif"
    ).read_bytes()
    after = read_retained_research(retained.root)
    unchanged = retained.manifest_sha256 == after.manifest_sha256 and retained.files == after.files
    unchanged = unchanged and before == {str(p): checksum(p) for p in legacy}
    if not equal or not unchanged:
        raise RuntimeError("Evidence changed or repeated export differs")
    save(
        output / "summary.json",
        {
            "passed": True,
            "research_cases": len(sources),
            "legacy_sources": len(legacy),
            "source_kinds": sorted({s.kind for s in combined.sources}),
            "combined_sources": len(combined.sources),
            "combined_sarif_runs": combined.sarif_runs,
            "source_bytes_unchanged": unchanged,
            "repeated_sarif_identical": equal,
            "scanner_invocations": 0,
            "target_execution": False,
            "limitations": [
                "Different controlled targets and legacy pilots remain labelled separately",
                "This is reporting integration, not a same-repository experiment",
            ],
        },
    )
    save(
        output / "evidence-manifest.json",
        {
            "files": [
                {
                    "path": p.relative_to(output).as_posix(),
                    "bytes": p.stat().st_size,
                    "sha256": sha256_file(p),
                }
                for p in sorted(output.rglob("*"))
                if p.is_file()
            ]
        },
    )
    print("Offline research reporting verification complete", flush=True)


if __name__ == "__main__":
    main()
