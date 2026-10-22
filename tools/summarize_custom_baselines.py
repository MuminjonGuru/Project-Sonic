"""Create an evidence-linked authored comparison, not an accuracy leaderboard."""

from __future__ import annotations

import argparse
import csv
import io
import json
from pathlib import Path
from typing import Any

from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.core.io import atomic_write_bytes
from agentsec_evidence.custom_rules.baseline_execution import verify_baselines
from agentsec_evidence.custom_rules.baseline_inputs import ROLES
from agentsec_evidence.custom_rules.shared_inputs import read_registry
from agentsec_evidence.pilot.runner import save
from agentsec_evidence.reporting.custom_contracts import FAMILIES
from agentsec_evidence.research.retained import plain_path, read_retained_research


def build_comparison(
    validation: dict[str, Any], reference: dict[str, Any], sources: dict[str, bytes]
) -> dict[str, Any]:
    if validation.get("passed") is not True or set(reference["observations"]) != set(sources):
        raise ValueError("Comparison requires verified complete source accounting")
    first = {(r["group"], r["role"]): r for r in validation["rows"] if r["repetition"] == 1}
    exclusions = {r["path"]: r for r in validation["excluded"]}
    rows = []
    for path, raw in sorted(sources.items()):
        group = path.split("/")[0]
        baselines: dict[str, Any] = {}
        for role in ROLES:
            stage = first[(group, role)]
            evidence = {
                "attempt_manifest_sha256": validation["manifest_sha256"],
                "stage_path": stage["key"],
            }
            if path in exclusions:
                baselines[role] = {
                    "state": "input-excluded",
                    "findings": None,
                    "reason": exclusions[path],
                    "evidence": evidence,
                }
            elif stage["state"] != "observed":
                baselines[role] = {
                    "state": stage["state"],
                    "findings": None,
                    "reasons": stage["reasons"],
                    "evidence": evidence,
                }
            else:
                observation = validation["observations"][stage["key"]]
                if path not in observation["files"]:
                    raise ValueError("Eligible file absent from observation accounting")
                baselines[role] = {**observation["files"][path], "evidence": evidence}
        rows.append(
            {
                "path": path,
                "sha256": sha256_bytes(raw),
                "source": raw.decode("utf-8"),
                "custom": reference["observations"][path],
                "baselines": baselines,
                "cross_tool_equivalence": "unreviewed",
                "vulnerability_truth": "not-established",
            }
        )
    return {
        "contract": "authored-cross-tool-observations-v1",
        "split": "development-only",
        "custom_manifest_sha256": reference["original_manifest_sha256"],
        "baseline_manifest_sha256": validation["manifest_sha256"],
        "rows": rows,
        "limitations": validation["limitations"],
        "source_note": "Authored development snippets, not public repository source.",
        "accuracy_metrics": None,
    }


def table_bytes(comparison: dict[str, Any]) -> bytes:
    families = [f.key for f in FAMILIES]
    columns = ["path", "source_sha256", *families]
    columns += [field for role in ROLES for field in (role + "_state", role + "_reports")]
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    for row in comparison["rows"]:
        value = {"path": row["path"], "source_sha256": row["sha256"]}
        for family in families:
            findings = row["custom"][family]["findings"]
            value[family] = str(len(findings)) if findings is not None else "unknown"
        for role, observation in row["baselines"].items():
            value[role + "_state"] = observation["state"]
            findings = observation["findings"]
            value[role + "_reports"] = str(len(findings)) if findings is not None else "unknown"
        writer.writerow(value)
    return buffer.getvalue().encode()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attempt", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    output = args.output.absolute()
    if output.exists() or not output.is_relative_to(project / "outputs"):
        raise ValueError("Choose a new ignored outputs child")
    plain_path(output.parent, directory=True)
    validation = verify_baselines(args.attempt)
    retained = read_retained_research(args.attempt)
    reference = json.loads(retained.read("custom-reference.json"))
    sources = {
        f"{family.key}/{case.id}.py": case.source.encode()
        for family in FAMILIES
        for case in read_registry(retained.read("registries/" + family.registry), family.key).cases
    }
    comparison = build_comparison(validation, reference, sources)
    output.mkdir()
    save(output / "validation.json", validation)
    save(output / "per-file.json", comparison)
    atomic_write_bytes(output / "per-file.csv", table_bytes(comparison))
    save(
        output / "checksums.json",
        {
            "files": [
                {"path": p.name, "sha256": sha256_bytes(p.read_bytes())}
                for p in sorted(output.iterdir())
            ],
            "scope": "Derived comparison only; original attempts remain separately sealed",
        },
    )
    print(json.dumps({"output": str(output), "source_files": len(sources)}, indent=2))


if __name__ == "__main__":
    main()
