"""Offline regression over retained engineering evidence; never invokes a scanner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import cast

from pydantic import JsonValue

from agentsec_evidence.core.identity import semantic_hash, sha256_file
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.reporting.service import validate_common_report, write_common_report


def bundle_hash(root: Path) -> str:
    return semantic_hash(
        {
            path.relative_to(root).as_posix(): sha256_file(path)
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-directory", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.report_directory.resolve()
    if not output.is_relative_to(root / "workspace"):
        raise ValueError("Verification must stay in the development workspace")
    output.mkdir(parents=True, exist_ok=False)
    matrix = json.loads(
        (root / "workspace/dependency-oracle-audit-2026-09-18/results.json").read_bytes()
    )
    pilot = json.loads(
        (root / "workspace/dependency-final-public-pilot-2026-09-18/results.json").read_bytes()
    )
    static = json.loads(
        (root / "workspace/dependency-static-regression-2026-09-18/results.json").read_bytes()
    )
    inputs = (
        [Path(item["bundle"]) for item in matrix]
        + [Path(item["bundle_root"]) for item in pilot]
        + [Path(item["result"]["run_root"]) for item in static]
    )
    before = {path.name: bundle_hash(path) for path in inputs}
    (output / "source-checksums-before.json").write_bytes(json_bytes(cast(JsonValue, before)))
    results: list[JsonValue] = []
    for index, source in enumerate(inputs):
        destination = output / "reports" / source.name
        report = write_common_report(project_root=root, bundles=[source], output=destination)
        validation = validate_common_report(root, destination)
        results.append(
            {
                "run_id": source.name,
                "state": report.sources[0].state,
                "sarif_runs": report.sarif_runs,
                "validation": validation,
                "output": str(destination),
            }
        )
        (output / "results.json").write_bytes(json_bytes(results))
        print(
            f"{index + 1}/{len(inputs)}: {source.name}; {report.sources[0].state}; valid",
            flush=True,
        )
    combined_sources = [
        inputs[0],
        inputs[len(matrix)],
        Path(static[0]["result"]["run_root"]),
        Path(static[1]["result"]["run_root"]),
    ]
    combined = write_common_report(
        project_root=root, bundles=combined_sources, output=output / "combined"
    )
    validate_common_report(root, output / "combined")
    write_common_report(
        project_root=root, bundles=combined_sources, output=output / "combined-repeat"
    )
    repeated = (output / "combined/results.sarif").read_bytes() == (
        output / "combined-repeat/results.sarif"
    ).read_bytes()
    after = {path.name: bundle_hash(path) for path in inputs}
    (output / "source-checksums-after.json").write_bytes(json_bytes(cast(JsonValue, after)))
    passed = (
        before == after and repeated and len(combined.sources) == 4 and combined.sarif_runs == 6
    )
    (output / "summary.json").write_bytes(
        json_bytes(
            {
                "passed": passed,
                "source_bundles": len(inputs),
                "source_bytes_unchanged": before == after,
                "combined_sources": len(combined.sources),
                "combined_sarif_runs": combined.sarif_runs,
                "repeat_sarif_identical": repeated,
                "scanners_invoked": 0,
                "limitation": (
                    "Different targets and paired paths remain separate; "
                    "this is not a new experiment."
                ),
            }
        )
    )
    if not passed:
        raise SystemExit("Common reporting verification failed")


if __name__ == "__main__":
    main()
