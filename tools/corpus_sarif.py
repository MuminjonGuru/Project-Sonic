"""Loss-explicit, offline SARIF over frozen corpus derivatives and draft reviews."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import quote

from corpus_report_v2 import encoded, manifest_for, read_report
from corpus_review_report import inputs as review_inputs
from corpus_review_report import json_object, need
from jsonschema import Draft7Validator, FormatChecker
from referencing import Registry

from agentsec_evidence.agents.validation import canonical_artifact_path
from agentsec_evidence.core.identity import canonical_json_bytes, sha256_bytes
from agentsec_evidence.core.io import atomic_write_bytes
from agentsec_evidence.exports.sarif import SARIF_SCHEMA_URI
from agentsec_evidence.pilot.runner import save
from agentsec_evidence.reporting.custom_contracts import FAMILIES
from agentsec_evidence.research.retained import (
    MAX_ENTRY_BYTES,
    bounded_file,
    plain_path,
    read_retained_research,
)

CONTRACT = "corpus-core-sarif-v1"
SCHEMA_SHA256 = "ad6db49878699b091f3eeb765b6e29e92a34bad4da88664d000c923b549c3a25"
PREFIX = "agentsecEvidence/"
CUSTOM = {f.key for f in FAMILIES}
BASELINES = {"semgrep-research", "semgrep-policy", "agent-audit-python"}
UNOBSERVED = {
    "unsupported-size",
    "input-refused",
    "policy-refused",
    "no-input",
    "failed",
    "not-run",
}
COMMON_LOSSES = [
    "Standard SARIF regions contain lines only; native coordinates remain in properties.",
    "Severity is not calibrated: all unaccepted claims use kind=review and level=none.",
    "Full native records, inventory detail and diagnostics remain in bound source reports.",
    "Policy is retained in properties; no SARIF suppression request or approval is invented.",
    "No code flows, fixes, vulnerability equivalence, runtime reachability or safety verdict.",
    "Generic consumers may ignore evidence properties, draft reviews and incomplete states.",
]


def props(**values: Any) -> dict[str, Any]:
    return {PREFIX + k: v for k, v in values.items()}


def digest(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def location(path: str, span: dict[str, Any]) -> dict[str, Any]:
    canonical_artifact_path(path)
    start, end = span.get("start_line"), span.get("end_line")
    need(type(start) is int and start >= 1, "Missing or invalid start line")
    end = start if end is None else end
    need(type(end) is int and end >= start, "Invalid end line")
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": quote(path, safe="/"), "uriBaseId": "SRCROOT"},
            "region": {"startLine": start, "endLine": end},
        }
    }


def claim_rows(obs: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Extract observed records without counting inventory as detection or inferring metadata."""
    out = []
    kind = obs["kind"]
    if kind == "custom":
        native = obs["native"]
        rules = {r["rule_id"]: r for r in native["rules"]}
        need(len(rules) == len(native["rules"]), "Duplicate native rule IDs")
        for fi, file in enumerate(native["files"]):
            for ri, record in enumerate(file["findings"] or []):
                rid = record["rule"]["rule_id"] if "rule" in record else record["rule_id"]
                rule = rules[rid]
                need(
                    rule.get("status", "active-condition") == "active-condition", "Not a condition"
                )
                out.append(
                    {
                        "rule_id": rid,
                        "message": rule["title"],
                        "path": file["path"],
                        "span": record["location"],
                        "source_sha256": file["source_sha256"],
                        "native_id": {
                            "record_id": record["record_id"],
                            "blob_sha256": obs["native_sha256"],
                        },
                        "native_pointer": f"/files/{fi}/findings/{ri}",
                        "native_message_kind": "catalog-title-not-inferred-description",
                        "native_priority": record.get(
                            "priority", record.get("rule", {}).get("severity")
                        ),
                        "native_confidence": None,
                        "native_policy": {"policy": native["policy"]},
                        "native_record_sha256": digest(record),
                        "native_rule": rule,
                    }
                )
        info = {
            "tool_name": native["producer"],
            "tool_version": native["version"],
            "analysis_state": native["execution_state"],
            "inventory_records_not_exported_as_results": sum(
                len(f["inventory"]) for f in native["files"]
            ),
            "limitation_records_externalized": sum(
                len(f["limitations_observed"]) for f in native["files"]
            ),
            "file_states": [
                {"path": f["path"], "state": f["state"], "reason": f["reason"]}
                for f in native["files"]
            ],
            "deferred_rule_ids": [
                r["rule_id"] for r in native["rules"] if r.get("status") == "deferred"
            ],
            "native_report_sha256": obs["native_sha256"],
            "policy": native["policy"],
        }
    elif kind == "semgrep":
        evidence = obs["evidence"]
        for record in evidence["findings"]:
            a = record["anchor"]
            out.append(
                {
                    "rule_id": a["rule_id"],
                    "message": record["message"],
                    "path": a["path"],
                    "span": a,
                    "native_id": {
                        "json_pointer": record["json_pointer"],
                        "blob_sha256": evidence["native_json_sha256"],
                    },
                    "native_pointer": record["json_pointer"],
                    "native_sarif_pointer": record["sarif_pointer"],
                    "native_sarif_sha256": evidence["native_sarif_sha256"],
                    "native_message_kind": "retained-reconciled-message",
                    "native_priority": None,
                    "native_confidence": None,
                    "native_policy": {
                        "view": evidence["role"],
                        "native_suppressions": record["native_suppressions"],
                    },
                    "native_record_sha256": digest(record),
                    "native_rule": None,
                }
            )
        info = {
            "tool_name": "Semgrep",
            "tool_version": None,
            "analysis_state": obs["assessment"]["analysis_state"],
            "inventory_records_not_exported_as_results": None,
            "limitation_records_externalized": None,
            "file_states": evidence["files"],
            "deferred_rule_ids": None,
            "native_report_sha256": evidence["native_json_sha256"],
            "native_sarif_sha256": evidence["native_sarif_sha256"],
            "profile_sha256": evidence["profile_sha256"],
            "native_execution_successful": evidence["native_execution_successful"],
            "native_errors": evidence["native_errors"],
            "native_skipped_rules": evidence["native_skipped_rules"],
            "policy": evidence["role"],
            "additional_loss": (
                "Tool version, native severity, rule help and flows are absent "
                "from this derivative; not inferred."
            ),
        }
    elif kind == "agent-audit":
        versions = {f["producer"]["tool_version"] for f in obs["findings"]}
        need(len(versions) <= 1, "Mixed Agent Audit versions in one cell")
        for record in obs["findings"]:
            need(
                len(record["locations"]) == len(record["evidence"]) == 1,
                "Multiple locations require a new mapping",
            )
            loc, evidence = record["locations"][0], record["evidence"][0]
            native = record["native_extension"]["agent_audit"]
            out.append(
                {
                    "rule_id": record["rule"]["native_id"],
                    "message": record["message"]["title"],
                    "path": loc["artifact_path"],
                    "span": loc,
                    "native_id": {
                        "json_pointer": evidence["json_pointer"],
                        "blob_sha256": evidence["blob_sha256"],
                    },
                    "native_pointer": evidence["json_pointer"],
                    "native_message_kind": "retained-title-description-externalized",
                    "native_priority": record["severity"]["native_label"],
                    "native_confidence": record["confidence"]["native_label"],
                    "native_policy": {
                        k: native.get(k)
                        for k in (
                            "tier",
                            "suppressed",
                            "suppressed_by",
                            "suppressed_reason",
                            "needs_review",
                        )
                    },
                    "native_record_sha256": digest(record),
                    "native_rule": record["rule"],
                    "native_location": {
                        k: native["location"].get(k)
                        for k in ("start_line", "end_line", "start_column", "end_column")
                    },
                }
            )
        info = {
            "tool_name": "Agent Audit",
            "tool_version": next(iter(versions), None),
            "analysis_state": obs["analysis_completeness"],
            "inventory_records_not_exported_as_results": None,
            "limitation_records_externalized": None,
            "file_states": None,
            "deferred_rule_ids": None,
            "native_report_sha256": obs["native_sha256"],
            "native_scanned_files": obs["native_scanned_files"],
            "per_file_completion": obs["per_file_completion"],
            "policy": "native-tier-and-explicit-suppression-are-distinct",
            "additional_loss": (
                "Descriptions, snippets, remediation and unknown fields remain in source evidence. "
                "Version is absent for an empty cell."
            ),
        }
    else:
        raise ValueError("Unknown corpus observation kind")
    need(len(out) == obs["finding_records"], "Observed count differs")
    return out, info


def review_key(candidate: str, cell: str, native_id: dict[str, Any]) -> str:
    return digest({"candidate": candidate, "cell": cell, "native_id": native_id})


def review_index(projection: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result = {}
    for row in projection["rows"]:
        need(
            row["review_status"] == "ai-proposed-student-review-pending"
            and row["human_decision"] is None
            and row["independent_review"] is None,
            "Only pending review proposals are admitted",
        )
        frozen = row["frozen_record"]
        identity = frozen["identity"]
        key = review_key(
            identity["candidate_id"], frozen["evidence_key"], identity["native_record_identity"]
        )
        need(key not in result, "Duplicate review binding")
        result[key] = row
    return result


def build_repository(
    report: dict[str, Any], manifest_sha: str, reviews: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    candidate = report["candidate"]
    cid, revision = candidate["candidate_id"], candidate["revision"]
    need(re.fullmatch(r"R[0-9]{2}", cid) is not None, "Invalid candidate ID")
    need(re.fullmatch(r"[0-9a-f]{40}", revision) is not None, "Invalid revision")
    need(
        re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", candidate["repository"]) is not None,
        "Invalid repository",
    )
    selected = {f["source"]["path"]: f["source"] for f in report["selected_inputs"]}
    need(len(selected) == len(report["selected_inputs"]), "Duplicate selected paths")
    rows, observations = report["rows"], report["observations"]
    need(len({r["key"] for r in rows}) == len(rows), "Duplicate execution cells")
    need(
        {r["key"] for r in rows if r["state"] == "observed"} == set(observations),
        "Observation membership differs",
    )
    runs, ledger, attached = [], [], []
    for row in rows:
        key, producer = row["key"], row["producer"]
        need(producer in CUSTOM | BASELINES, "Unknown producer")
        need(type(row["repetition"]) is int and 1 <= row["repetition"] <= 3, "Invalid repetition")
        common = props(
            candidate=candidate,
            cell=key,
            repetition=row["repetition"],
            batch=row["batch"],
            producer=producer,
            executionState=row["state"],
            reasons=row["reasons"],
            reportManifestSha256=manifest_sha,
            sourceManifestSha256=report["source_manifest_sha256"],
            sourceContentSha256=report["source_content_sha256"],
            selectionSha256=report["selection_sha256"],
            analysisCompleteness="not-established",
            humanAcceptance=False,
            optionalStages="not-admitted-in-core",
            inventoryIsFinding=False,
        )
        run: dict[str, Any] = {
            "tool": {"driver": {"name": producer}},
            "automationDetails": {"id": f"{cid}/{revision}/{key}/"},
            "columnKind": "unicodeCodePoints",
            "originalUriBaseIds": {
                "SRCROOT": {"uri": f"https://github.com/{candidate['repository']}/blob/{revision}/"}
            },
            "versionControlProvenance": [
                {
                    "repositoryUri": "https://github.com/" + candidate["repository"],
                    "revisionId": revision,
                }
            ],
            "properties": common,
        }
        cell = {
            "cell": key,
            "producer": producer,
            "repetition": row["repetition"],
            "batch": row["batch"],
            "state": row["state"],
            "observed_results": None,
            "exported_results": None,
            "reasons": row["reasons"],
            "inventory_records_not_exported_as_results": None,
            "limitation_records_externalized": None,
            "draft_review_links": 0,
        }
        if row["state"] != "observed":
            need(
                row["state"] in UNOBSERVED and row["finding_records"] is None,
                "Unobserved results cannot be clean counts",
            )
            # The pinned schema rejects null results. Keep unrun cells in the ledger,
            # not fabricated SARIF runs with empty successful-looking result arrays.
            ledger.append(cell)
            continue
        obs = observations[key]
        need(
            obs["kind"]
            == (
                "custom"
                if producer in CUSTOM
                else "agent-audit"
                if producer == "agent-audit-python"
                else "semgrep"
            ),
            "Producer kind differs",
        )
        claims, info = claim_rows(obs)
        need(len(claims) == row["finding_records"], "Row count differs")
        descriptors = sorted({c["rule_id"] for c in claims})
        driver = {"name": info["tool_name"], "rules": [{"id": rid} for rid in descriptors]}
        if info["tool_version"] is not None:
            driver["version"] = info["tool_version"]
        run["tool"]["driver"] = driver
        run["properties"].update(
            props(
                coverage=info,
                exportLosses=COMMON_LOSSES,
                toolVersionAvailable=info["tool_version"] is not None,
                invocationMapping="omitted-no-inferred-process-status",
            )
        )
        results = []
        native_keys = set()
        for claim in claims:
            need(claim["path"] in selected, "Foreign finding path")
            if "source_sha256" in claim:
                need(
                    claim["source_sha256"] == selected[claim["path"]]["sha256"],
                    "Source hash differs",
                )
            native_id = claim["native_id"]
            native_key = digest(
                {"identity": native_id, "sarif_pointer": claim.get("native_sarif_pointer")}
            )
            need(native_key not in native_keys, "Duplicate native observation identity")
            native_keys.add(native_key)
            rkey = review_key(cid, key, native_id)
            review = reviews.get(rkey)
            if review is not None:
                identity = review["frozen_record"]["identity"]
                need(
                    (
                        identity["revision"],
                        identity["producer"],
                        identity["source_path"],
                        identity["rule_id"],
                        identity["location"],
                    )
                    == (revision, producer, claim["path"], claim["rule_id"], claim["span"]),
                    "Draft review source differs",
                )
                attached.append(review["review_id"])
            reference = (
                None
                if review is None
                else {
                    "review_id": review["review_id"],
                    "status": review["review_status"],
                    "authorship": review["authorship"],
                    "proposal": review["proposal"]["proposed_outcome"],
                    "human_decision": None,
                    "independent_review": None,
                    "path": "../inputs/reviews.json",
                    "record_identity_sha256": review["frozen_record"]["identity_sha256"],
                }
            )
            unique = digest({"repository": candidate, "cell": key, "claim": claim})
            results.append(
                {
                    "ruleId": claim["rule_id"],
                    "ruleIndex": descriptors.index(claim["rule_id"]),
                    "kind": "review",
                    "level": "none",
                    "message": {"text": claim["message"]},
                    "locations": [location(claim["path"], claim["span"])],
                    "partialFingerprints": {"agentsecEvidence/corpusObservation/v1": unique},
                    "properties": props(
                        nativeReference=native_id,
                        nativePointer=claim["native_pointer"],
                        sourceSha256=selected[claim["path"]]["sha256"],
                        nativeCoordinates=claim.get("native_location", claim["span"]),
                        nativePriority=claim["native_priority"],
                        nativeConfidence=claim["native_confidence"],
                        priorityAndConfidence="native-not-calibrated",
                        nativePolicy=claim["native_policy"],
                        nativeRecordSha256=claim["native_record_sha256"],
                        nativeRule=claim["native_rule"],
                        nativeSarifSha256=claim.get("native_sarif_sha256"),
                        nativeSarifPointer=claim.get("native_sarif_pointer"),
                        messageOrigin=claim["native_message_kind"],
                        review=reference,
                        verificationState="unaccepted-static-observation",
                        sourceReportCell=key,
                    ),
                }
            )
        need(
            len(
                {r["partialFingerprints"]["agentsecEvidence/corpusObservation/v1"] for r in results}
            )
            == len(results),
            "Duplicate observation identities",
        )
        run["results"] = results
        cell.update(
            observed_results=len(claims),
            exported_results=len(results),
            inventory_records_not_exported_as_results=info[
                "inventory_records_not_exported_as_results"
            ],
            limitation_records_externalized=info["limitation_records_externalized"],
            draft_review_links=sum(r["properties"][PREFIX + "review"] is not None for r in results),
            additional_loss=info.get("additional_loss"),
        )
        runs.append(run)
        ledger.append(cell)
    log = {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": runs,
        "properties": props(
            unobservedCells=[c for c in ledger if c["state"] != "observed"],
            omittedRuns="Unobserved cells remain null in accounting, never empty clean scans.",
        ),
    }
    return log, {
        "contract": CONTRACT,
        "candidate": candidate,
        "source_report_manifest_sha256": manifest_sha,
        "cells": ledger,
        "draft_review_ids": attached,
        "projection_losses": COMMON_LOSSES,
        "exported_observations_all_repetitions_and_views": sum(
            c["exported_results"] or 0 for c in ledger
        ),
        "native_replay": False,
        "invocations_omitted": (
            "Full process records are external; coverage/state remain in properties and ledger."
        ),
        "source_reports_required": True,
        "unique_vulnerabilities": None,
    }


def validate_log(log: dict[str, Any], schema: dict[str, Any]) -> None:
    # No remote schema retrieval; prose constraints below are not enforced by the JSON schema.
    Draft7Validator(schema, format_checker=FormatChecker(), registry=Registry()).validate(log)
    for run in log["runs"]:
        need(run["columnKind"] == "unicodeCodePoints", "Explicit column convention required")
        state = run["properties"][PREFIX + "executionState"]
        need(
            state == "observed" and isinstance(run["results"], list),
            "Only observed runs are exported",
        )
        need("invocations" not in run, "Cannot infer invocations from derivative status")
        for r in run["results"] or []:
            need(
                r["kind"] == "review" and r["level"] == "none", "Unaccepted claims need review/none"
            )
            need("suppressions" not in r, "Native policy is not platform approval")
            need(
                run["tool"]["driver"]["rules"][r["ruleIndex"]]["id"] == r["ruleId"],
                "Rule index differs",
            )
            region = r["locations"][0]["physicalLocation"]["region"]
            need(set(region) == {"startLine", "endLine"}, "Only line coordinates are admitted")


def package(
    projection: dict[str, Any],
    exports: dict[str, bytes],
    reports_root: Path,
    schema: dict[str, Any],
) -> dict[str, bytes]:
    reviews = review_index(projection)
    files = {"inputs/reviews.json": exports["inputs/reviews.json"]}
    index, attached = [], []
    for cid, manifest in projection["report_manifests"].items():
        need(re.fullmatch(r"R[0-9]{2}", cid) is not None, "Invalid repository key")
        need(
            sha256_bytes(
                bounded_file(reports_root / cid / "evidence-manifest.json", MAX_ENTRY_BYTES)
            )
            == manifest,
            "Report changed during export",
        )
        report = read_report(reports_root / cid)
        need(report["candidate"]["candidate_id"] == cid, "Report candidate differs")
        log, accounting = build_repository(report, manifest, reviews)
        validate_log(log, schema)
        files[f"{cid}/results.sarif"] = encoded(log)
        files[f"{cid}/accounting.json"] = encoded(accounting)
        attached.extend(accounting["draft_review_ids"])
        index.append(
            {
                "candidate": report["candidate"],
                "sarif": f"{cid}/results.sarif",
                "accounting": f"{cid}/accounting.json",
                "source_manifest_sha256": manifest,
                "cells": len(accounting["cells"]),
                "cell_states": dict(Counter(c["state"] for c in accounting["cells"])),
                "exported_observations_all_repetitions_and_views": accounting[
                    "exported_observations_all_repetitions_and_views"
                ],
            }
        )
    need(
        sorted(attached) == sorted(r["review_id"] for r in projection["rows"]),
        "Draft review linkage incomplete or duplicated",
    )
    files["index.json"] = encoded(
        {
            "contract": CONTRACT,
            "repositories": index,
            "review_source_sha256": projection["review_source_sha256"],
            "protocol_sha256": projection["protocol_sha256"],
            "schema_sha256": SCHEMA_SHA256,
            "schema_semantic_sha256": digest(schema),
            "draft_reviews_linked": len(attached),
            "native_replay": False,
            "scanner_invocations": 0,
            "distribution": "internal-unredacted",
            "unique_vulnerabilities": None,
            "limitations": COMMON_LOSSES,
        }
    )
    lines = [
        "# Corpus SARIF Exports",
        "",
        "Internal, unredacted derivative. No new scans or human approvals.",
        "",
        "Separate runs preserve tools, repetitions, policy views and custom batches.",
        "Review/none is deliberate: native priority stays in properties, not calibrated severity.",
        "Unobserved cells stay null in accounting and are not exported as SARIF runs.",
        "Inventory is not findings; SARIF-only viewers may not display coverage omissions.",
        "",
        "| Repository ID | SARIF | Accounting |",
        "|---|---|---|",
    ]
    lines.extend(
        f"| {e['candidate']['candidate_id']} | [{e['sarif']}]({e['sarif']}) | "
        f"[{e['accounting']}]({e['accounting']}) |"
        for e in index
    )
    lines.extend(
        [
            "",
            f"{len(attached)} draft reviews link only to their original first-repeat records.",
            "No review propagates to repeats, policy counterparts or positional overlaps.",
            "Byte-identical reviews are in inputs/reviews.json; original reports remain required.",
            "Schema/mapping checks do not test GitHub/IDE upload or consumer compatibility.",
            "",
            "## Projection Limits",
            "",
            *["- " + loss for loss in COMMON_LOSSES],
            "",
            "Semgrep severity, version and full rule metadata are absent and are not invented.",
            "Descriptions, snippets, remediation, inventory and native bytes remain external.",
            "Legacy exports are unchanged. The new mapping implements review/none explicitly.",
            "",
        ]
    )
    files["README.md"] = "\n".join(lines).encode()
    manifest_for(files)
    return files


def execute(
    mode: str,
    review: Path,
    queue: Path,
    reports: Path,
    sources: Path,
    protocol: Path,
    output: Path,
    schema: Path,
) -> dict[str, Any]:
    projection, exports = review_inputs(review, queue, reports, sources, protocol)
    schema_raw = bounded_file(schema, MAX_ENTRY_BYTES)
    need(sha256_bytes(schema_raw) == SCHEMA_SHA256, "SARIF schema differs from pinned vendor bytes")
    expected = package(projection, exports, reports, json_object(schema_raw))
    output = output.absolute()
    for root in (review, queue, reports, sources):
        base = plain_path(root, directory=True)
        need(
            not output.is_relative_to(base) and not base.is_relative_to(output),
            "Output overlaps evidence",
        )
    if mode == "write":
        plain_path(output.parent, directory=True)
        need(not output.exists(), "Use a fresh export directory")
        output.mkdir()
        for name, raw in expected.items():
            atomic_write_bytes(output / name, raw)
        save(output / "evidence-manifest.json", manifest_for(expected))
    need(
        read_retained_research(output).files == expected,
        "SARIF package differs from bound projection",
    )
    return {
        "contract": CONTRACT,
        "passed": True,
        "repositories": len(projection["report_manifests"]),
        "draft_reviews_linked": len(projection["rows"]),
        "files": len(expected),
        "scanner_invocations": 0,
        "native_replay": False,
        "human_acceptance": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("write", "verify"))
    for name in ("review", "queue", "reports", "sources", "protocol", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument(
        "--schema", type=Path, default=Path("schemas/vendor/oasis/sarif-schema-2.1.0.json")
    )
    print(encoded(execute(**vars(parser.parse_args()))).decode())


if __name__ == "__main__":
    main()
