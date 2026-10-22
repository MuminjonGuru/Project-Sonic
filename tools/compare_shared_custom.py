"""Create a local comparison from two sealed authored shared-worker attempts."""

from __future__ import annotations

import argparse
import csv
import io
import json
from pathlib import Path
from typing import Any

from agentsec_evidence.core.identity import sha256_file
from agentsec_evidence.core.io import atomic_write_bytes
from agentsec_evidence.custom_rules.shared_execution import verify_shared
from agentsec_evidence.custom_rules.shared_inputs import SharedPlan
from agentsec_evidence.pilot.runner import evidence_records, save
from agentsec_evidence.research.retained import bounded_file, plain_path


def compare_plans(left: SharedPlan, right: SharedPlan) -> None:
    exclude = {"max_files", "repetitions", "requests"}
    if left.model_dump(exclude=exclude) != right.model_dump(exclude=exclude):
        raise ValueError("Only batching and repetition counts may differ")
    if left.requests == right.requests:
        raise ValueError("A partition comparison needs different input partitions")
    if left.repetitions < 2:
        raise ValueError("The left attempt must also establish fresh-run repeatability")


def compare(left: Path, right: Path, output: Path) -> dict[str, Any]:
    left, right = plain_path(left, directory=True), plain_path(right, directory=True)
    output = output.absolute()
    plain_path(output.parent, directory=True)
    if output.exists() or any(output.is_relative_to(p) for p in (left, right)):
        raise ValueError("Derivative needs a fresh directory outside sealed attempts")
    summaries = [verify_shared(left), verify_shared(right)]
    plans = [
        SharedPlan.model_validate_json(bounded_file(p / "plan.json", 4 * 1024**2))
        for p in (left, right)
    ]
    compare_plans(*plans)
    if (
        not all(s["origin_assertions_passed"] for s in summaries)
        or not summaries[0]["repeatability_passed"]
    ):
        raise ValueError("Origin expectations or fresh-run repeatability failed")
    rows = []
    for a, b in zip(summaries[0]["families"], summaries[1]["families"], strict=True):
        if a["family"] != b["family"]:
            raise ValueError("Family order differs")
        rows.append(
            {
                **{
                    k: a[k]
                    for k in (
                        "family",
                        "files",
                        "analyzed",
                        "incomplete",
                        "finding_records",
                        "inventory_records",
                        "limitation_records",
                        "origin_cases",
                        "semantic_sha256",
                    )
                },
                "repeatability": a["repeatability"],
                "partition_equivalent": a["semantic_sha256"] == b["semantic_sha256"],
            }
        )
    result = {
        "contract": "shared-custom-partition-comparison-v1",
        "evidence_role": "authored-development-not-held-out",
        "evidence_manifests": [s["evidence_manifest_sha256"] for s in summaries],
        "snapshot_id": plans[0].snapshot_id,
        "implementation_pins_equal": True,
        "origin_assertions_passed": True,
        "fresh_repeatability_passed": True,
        "partition_equivalent": all(r["partition_equivalent"] for r in rows),
        "worker_invocations": sum(s["worker_invocations"] for s in summaries),
        "batch_limits": [p.max_files for p in plans],
        "repetitions": [p.repetitions for p in plans],
        "overlap_pairs": len(summaries[0]["overlap_candidates"]),
        "overlap_files": len({r["path"] for r in summaries[0]["overlap_candidates"]}),
        "families": rows,
        "unique_vulnerabilities": None,
        "comparison_helper_sha256": sha256_file(Path(__file__)),
        "limitations": summaries[0]["limitations"],
    }
    output.mkdir()
    save(output / "comparison.json", result)
    for label, summary in zip(("left", "right"), summaries, strict=True):
        save(output / (label + "-validation.json"), summary)
    table = io.StringIO(newline="")
    writer = csv.DictWriter(table, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    atomic_write_bytes(output / "families.csv", table.getvalue().encode())
    save(output / "checksums.json", {"files": evidence_records(output)})
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--left", required=True, type=Path)
    parser.add_argument("--right", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = compare(args.left, args.right, args.output)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["partition_equivalent"] else 1)


if __name__ == "__main__":
    main()
