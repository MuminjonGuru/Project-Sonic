"""Versioned offline correction of review/level pairs without rewriting source evidence."""

from __future__ import annotations

import argparse
import copy
import json
import re
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft7Validator, FormatChecker
from referencing import Registry

from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.core.io import atomic_write_bytes
from agentsec_evidence.research.retained import MAX_ENTRY_BYTES, bounded_file, plain_path

CONTRACT = "sarif-review-level-projection-v1"
SCHEMA_SHA256 = "ad6db49878699b091f3eeb765b6e29e92a34bad4da88664d000c923b549c3a25"
META = "agentsecEvidence/reviewLevelProjection"
PRIOR = "agentsecEvidence/priorSarifReviewLevel"
MEMBERS = {"source.sarif", "results.sarif", "correction.json", "README.md"}
LIMITATIONS = [
    "Schema and selected kind/level/rank constraints only; not complete SARIF conformance.",
    "Original result kinds, claims, priorities and policy are not adjudicated or approved.",
    "The previous SARIF level is not necessarily the scanner's native severity.",
    "No scanner execution, original-producer replay, source-code validation or consumer upload.",
    "References are preserved, not dereferenced or rebased; external evidence remains external.",
    "Internal/unredacted; source copies may contain sensitive evidence and need sharing review.",
]


def need(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def encoded(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, allow_nan=False, indent=2, sort_keys=True) + "\n"
    ).encode()


def document(raw: bytes) -> dict[str, Any]:
    return cast(dict[str, Any], load_agent_json(raw, max_bytes=MAX_ENTRY_BYTES))


def validator(schema_path: Path) -> Draft7Validator:
    raw = bounded_file(schema_path, MAX_ENTRY_BYTES)
    need(sha256_bytes(raw) == SCHEMA_SHA256, "Pinned SARIF schema hash differs")
    return Draft7Validator(document(raw), format_checker=FormatChecker(), registry=Registry())


def project(raw: bytes, expected_sha256: str, schema_path: Path) -> dict[str, bytes]:
    need(bool(re.fullmatch(r"[0-9a-f]{64}", expected_sha256)), "Expected a lowercase SHA-256")
    need(sha256_bytes(raw) == expected_sha256, "Source SARIF hash differs from external binding")
    source = document(raw)
    check = validator(schema_path)
    check.validate(source)
    need(
        META not in source.get("properties", {}), "Already projected or reserved metadata collision"
    )
    corrected = copy.deepcopy(source)
    changes = []
    record_count = 0
    review_count = 0
    for ri, run in enumerate(corrected["runs"]):
        for fi, result in enumerate(run.get("results", [])):
            record_count += 1
            kind = result.get("kind", "fail")
            level = result.get("level", "none")
            need(PRIOR not in result.get("properties", {}), "Reserved result property collision")
            if kind != "fail":
                need("rank" not in result, "Non-fail rank is outside this correction contract")
                need(kind == "review" or level == "none", "Non-review kind/level mismatch refused")
            if kind != "review":
                continue
            review_count += 1
            if level == "none":
                continue
            pointer = f"/runs/{ri}/results/{fi}"
            changes.append(
                {
                    "pointer": pointer,
                    "rule_id": result.get("ruleId"),
                    "previous_level": level,
                    "new_level": "none",
                    "source_result_sha256": sha256_bytes(
                        encoded(source["runs"][ri]["results"][fi])
                    ),
                    "properties_were_present": "properties" in result,
                }
            )
            result["level"] = "none"
            result.setdefault("properties", {})[PRIOR] = {
                "value": level,
                "source_sha256": expected_sha256,
                "source_pointer": pointer + "/level",
                "meaning": "Previous export level, not inferred native severity or calibrated risk",
            }

    binding = {
        "contract": CONTRACT,
        "source_sha256": expected_sha256,
        "source_member": "source.sarif",
        "schema_sha256": SCHEMA_SHA256,
        "changed_results": len(changes),
        "human_acceptance": False,
    }
    corrected.setdefault("properties", {})[META] = binding
    check.validate(corrected)

    # Reversing only the declared edits must recover every original JSON value.
    restored = copy.deepcopy(corrected)
    del restored["properties"][META]
    if "properties" not in source:
        del restored["properties"]
    for change in changes:
        _, _, rindex, _, findex = change["pointer"].split("/")
        result = restored["runs"][int(rindex)]["results"][int(findex)]
        result["level"] = change["previous_level"]
        del result["properties"][PRIOR]
        if not change["properties_were_present"]:
            del result["properties"]
    need(restored == source, "Undeclared semantic change in projection")
    ledger = {
        **binding,
        "source_bytes": len(raw),
        "runs": len(source["runs"]),
        "result_records": record_count,
        "review_records": review_count,
        "unchanged_records": record_count - len(changes),
        "changes": changes,
        "reversible_json_projection": True,
        "native_replayed": False,
        "scanner_invocations": 0,
        "limitations": LIMITATIONS,
    }
    readme = f"""# Corrected SARIF Review Levels

Contract: `{CONTRACT}`. Source SHA-256: `{expected_sha256}`.

- [Corrected export](results.sarif): {len(changes)} review levels changed to none.
- [Original bytes](source.sarif): retained exactly; not the corrected delivery export.
- [Correction ledger](correction.json): pointers and previous levels for every edit.
- [Checksums](evidence-manifest.json): package consistency, not independent attestation.

The export retains {record_count} result records in {len(source["runs"])} runs.
No records, locations, priorities, policy fields or claims were removed or merged.
Previous export levels are preserved separately and are not assumed to be native severity.
Existing fail kinds remain as recorded; this correction does not approve those claims.
Schema and selected prose checks are not full conformance or tested consumer compatibility.
References are unchanged and may require external evidence; no links are followed.
The original report and HTML are not replaced. No scan or native replay took place.
This package is internal/unredacted and is not automatically safe to distribute.
"""
    files = {
        "source.sarif": raw,
        "results.sarif": encoded(corrected),
        "correction.json": encoded(ledger),
        "README.md": readme.encode(),
    }
    need(
        all(len(data) <= MAX_ENTRY_BYTES for data in files.values()),
        "Projection exceeds file budget",
    )
    return files


def write(source: Path, expected_sha256: str, output: Path, schema_path: Path) -> dict[str, Any]:
    source = plain_path(source, directory=False)
    output = output.absolute()
    output = plain_path(output.parent, directory=True) / output.name
    need(not output.exists() and not output.is_symlink(), "Fresh output folder required")
    need(
        not output.is_relative_to(source.parent),
        "Output must be outside the source evidence folder",
    )
    raw = bounded_file(source, MAX_ENTRY_BYTES)
    files = project(raw, expected_sha256, schema_path)
    # The new folder is created only after input, schema, size and preservation checks.
    output.mkdir()
    for name, data in files.items():
        atomic_write_bytes(output / name, data)
    manifest = {
        "contract": CONTRACT,
        "source_sha256": expected_sha256,
        "files": {
            name: {"bytes": len(data), "sha256": sha256_bytes(data)}
            for name, data in sorted(files.items())
        },
    }
    atomic_write_bytes(output / "evidence-manifest.json", encoded(manifest))
    return verify(output, expected_sha256, schema_path)


def verify(output: Path, expected_sha256: str, schema_path: Path) -> dict[str, Any]:
    output = plain_path(output, directory=True)
    need(
        {p.name for p in output.iterdir()} == MEMBERS | {"evidence-manifest.json"},
        "Package membership differs",
    )
    manifest = document(bounded_file(output / "evidence-manifest.json", MAX_ENTRY_BYTES))
    contents = {name: bounded_file(output / name, MAX_ENTRY_BYTES) for name in MEMBERS}
    expected_manifest = {
        "contract": CONTRACT,
        "source_sha256": expected_sha256,
        "files": {
            name: {"bytes": len(data), "sha256": sha256_bytes(data)}
            for name, data in sorted(contents.items())
        },
    }
    need(manifest == expected_manifest, "Package manifest differs")
    expected_files = project(contents["source.sarif"], expected_sha256, schema_path)
    need(contents == expected_files, "Package differs from the source-bound projection")
    ledger = document(contents["correction.json"])
    return {
        "contract": CONTRACT,
        "passed": True,
        "source_sha256": expected_sha256,
        "manifest_sha256": sha256_bytes(
            bounded_file(output / "evidence-manifest.json", MAX_ENTRY_BYTES)
        ),
        "result_records": ledger["result_records"],
        "changed_results": ledger["changed_results"],
        "native_replayed": False,
        "scanner_invocations": 0,
        "human_acceptance": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("write", "verify"))
    parser.add_argument("--source", type=Path)
    parser.add_argument(
        "--source-sha256",
        required=True,
        help="Trusted original SARIF hash, not a package assertion",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--schema",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "schemas/vendor/oasis/sarif-schema-2.1.0.json",
    )
    args = parser.parse_args()
    if args.mode == "write":
        if args.source is None:
            parser.error("write requires --source")
        result = write(args.source, args.source_sha256, args.output, args.schema)
    else:
        if args.source is not None:
            parser.error("verify uses the source copy and external hash; omit --source")
        result = verify(args.output, args.source_sha256, args.schema)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
