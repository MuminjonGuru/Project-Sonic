"""Build/replay a completed public-pilot report offline; never launch scanners or targets."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from agentsec_evidence.core.identity import sha256_file
from agentsec_evidence.core.io import atomic_write_bytes, json_bytes
from agentsec_evidence.reporting.models import PublicPilotSource
from agentsec_evidence.reporting.service import (
    require_new_derivative,
    validate_common_report,
    write_common_report,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pilot", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    output = require_new_derivative(args.output, [args.pilot])
    output.mkdir(parents=True, exist_ok=False)
    prior = sha256_file(args.pilot / "evidence-manifest.json")
    first = write_common_report(project_root=project, bundles=[args.pilot], output=output / "first")
    print("First public report retained", flush=True)
    second = write_common_report(
        project_root=project, bundles=[args.pilot], output=output / "repeat"
    )
    if first.model_dump(exclude={"generated_at"}) != second.model_dump(exclude={"generated_at"}):
        raise ValueError("Repeated common-report projections differ")
    if (output / "first/results.sarif").read_bytes() != (
        output / "repeat/results.sarif"
    ).read_bytes():
        raise ValueError("Repeated SARIF bytes differ")
    source = first.sources[0]
    if not isinstance(source, PublicPilotSource):
        raise ValueError("Expected one public pilot source")
    print("Repeated report/SARIF projections agree", flush=True)
    checks = []
    for mutation in ("message", "missing-run", "held-out-label", "finding-count"):
        root = output / ("negative-" + mutation)
        shutil.copytree(output / "first", root)
        sarif = json.loads((root / "results.sarif").read_bytes())
        report = json.loads((root / "report.json").read_bytes())
        if mutation == "message":
            result = next(result for run in sarif["runs"] for result in run["results"])
            result["message"]["text"] = "Deliberately changed negative-check copy"
        elif mutation == "missing-run":
            sarif["runs"].pop()
        elif mutation == "held-out-label":
            report["sources"][0]["summary"]["evidence_role"] = "held-out"
        else:
            report["sources"][0]["summary"]["rows"][2]["finding_records"] += 1
        atomic_write_bytes(root / "results.sarif", json_bytes(sarif))
        atomic_write_bytes(root / "report.json", json_bytes(report))
        manifest = json.loads((root / "report-manifest.json").read_bytes())
        for entry in manifest["entries"]:
            path = root / entry["path"]
            entry.update(sha256=sha256_file(path), bytes=path.stat().st_size)
        atomic_write_bytes(root / "report-manifest.json", json_bytes(manifest))
        try:
            validate_common_report(project, root)
        except ValueError as exc:
            checks.append({"case": mutation, "rejected": True, "reason": str(exc)[:600]})
        else:
            raise ValueError("Corrupted report was accepted: " + mutation)
    if prior != sha256_file(args.pilot / "evidence-manifest.json"):
        raise ValueError("Original pilot seal changed")
    receipt = {
        "passed": True,
        "contract": first.contract,
        "pilot_manifest_sha256": prior,
        "stage_rows": len(source.summary.rows),
        "sarif_runs": first.sarif_runs,
        "agent_records_per_repetition": [len(r.agent_findings) for r in source.summary.repetitions],
        "vulnerability_total": None,
        "negative_checks": checks,
        "repeat_excludes_only": ["generated_at"],
        "sarif_bytes_repeat": True,
        "scanner_or_target_execution": False,
        "limitations": "Local consistency replay, not external attestation or accuracy evidence",
    }
    atomic_write_bytes(output / "verification.json", json_bytes(receipt))
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
