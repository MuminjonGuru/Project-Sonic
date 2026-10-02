"""Generate and verify one authored inventory example, without scanning target code."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentsec_evidence.agents.inventory import (
    ArtifactInventory,
    artifact_inventory_semantic_sha256,
    build_artifact_inventory,
)
from agentsec_evidence.agents.validation import canonical_artifact_path
from agentsec_evidence.core.identity import sha256_file
from agentsec_evidence.core.io import (
    atomic_write_bytes,
    atomic_write_model,
    json_bytes,
    model_bytes,
)
from agentsec_evidence.intake.snapshot import create_snapshot

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "test_cases/development/artifact-inventory/case.json"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New, unused evidence directory")
    output = parser.parse_args().output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    case = json.loads(CASE.read_bytes())
    source = output / "authored-source"
    for entry in case["files"]:
        path = canonical_artifact_path(entry["path"])
        atomic_write_bytes(source / path, entry["text"].encode("utf-8"))
    snapshot = create_snapshot(
        source,
        output / "snapshots",
        source_label=case["case_id"],
        revision="authored-artifact-inventory-v1",
    )
    report = build_artifact_inventory(snapshot.snapshot, snapshot.inventory)
    atomic_write_model(output / "inventory.json", report)
    repeat = build_artifact_inventory(snapshot.snapshot, snapshot.inventory)
    atomic_write_model(output / "inventory-repeat.json", repeat)
    if model_bytes(report) != model_bytes(repeat):
        raise RuntimeError("Same-input inventory repetition changed")
    restored = ArtifactInventory.model_validate_json((output / "inventory.json").read_bytes())
    expected = {e["path"]: tuple(e["expected_recognizers"]) for e in case["files"]}
    if {r.source.path: r.recognizer_ids for r in restored.records} != expected:
        raise RuntimeError("Authored path expectations did not match")
    if {f.family: f.candidate_file_count for f in restored.families} != case[
        "expected_family_counts"
    ]:
        raise RuntimeError("Authored family expectations did not match")
    unclassified = sum(not r.recognizer_ids for r in report.records)
    if unclassified != case["expected_unclassified_files"]:
        raise RuntimeError("Authored unclassified count did not match")
    summary = {
        "passed": True,
        "evidence_type": "authored-engineering-case-not-a-repository-scan",
        "case_sha256": sha256_file(CASE),
        "catalog_sha256": report.catalog_sha256,
        "semantic_sha256": artifact_inventory_semantic_sha256(report),
        "files_retained": len(report.records),
        "files_with_candidates": len(report.records) - unclassified,
        "unclassified_files": unclassified,
        "family_counts": {f.family: f.candidate_file_count for f in report.families},
        "repeat_bytes_equal": True,
        "security_analysis": "not-run",
        "finding_count": None,
        "independent_expected_outcome_review": "not-performed",
    }
    atomic_write_bytes(output / "summary.json", json_bytes(summary))
    records = [
        {
            "path": path.relative_to(output).as_posix(),
            "byte_length": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in sorted(output.rglob("*"))
        if path.is_file()
    ]
    atomic_write_bytes(output / "evidence-manifest.json", json_bytes({"files": records}))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
