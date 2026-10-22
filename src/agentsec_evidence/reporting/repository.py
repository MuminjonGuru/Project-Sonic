"""Offline repository/custom report. The original common-report v1-v5 contracts stay intact."""

# Long template lines keep escaped HTML markup together.
# ruff: noqa: E501

from __future__ import annotations

import argparse
import copy
import html
import json
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote

from agentsec_evidence.agents.inventory import ArtifactInventory
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes, sha256_file
from agentsec_evidence.core.io import atomic_write_bytes
from agentsec_evidence.custom_rules.repository_contracts import (
    RepositoryCustomPlan,
    current_native,
    validate_plan,
)
from agentsec_evidence.custom_rules.repository_execution import schedule, verify_repository_custom
from agentsec_evidence.exports.sarif import SARIF_SCHEMA_URI
from agentsec_evidence.pilot.runner import load, save
from agentsec_evidence.reporting.custom_contracts import FAMILIES
from agentsec_evidence.reporting.dependency import dependency_sarif, load_dependency_run
from agentsec_evidence.reporting.html_styles import STYLES
from agentsec_evidence.reporting.pilot import load_pilot_source
from agentsec_evidence.reporting.semgrep_export import semgrep_sarif_run
from agentsec_evidence.research.execution import ResearchExecutionAssessment
from agentsec_evidence.research.models import SemgrepDualView
from agentsec_evidence.research.retained import bounded_file, plain_path, read_retained_research

LIMITATIONS = [
    "Formative engineering pilots, not held-out evaluation or independently reviewed labels.",
    "Counts are per-tool records, not unique or confirmed vulnerabilities. Repetitions are not new samples.",
    "Custom checks are file-local static conditions. Inventory and deferred IDs are not detection coverage.",
    "No target execution, installation, runtime exploitability or effective permissions were tested.",
    "Custom policy is research-only. Semgrep retains research/policy views with implicit Git filtering disabled.",
    "Baseline evidence is a separately timed attempt, not a single simultaneous scan or a fair speed comparison.",
    "Zero custom findings does not mean safe; unsupported constructs and unknown analysis remain visible.",
    "Dockerfile/skills remain unsupported. Broad prompt, memory and delegation security are not established.",
    "Tool annotation treatment 1.1.0 uses Python 3.13 semantics; target runtime and later introspection are unknown.",
    "Internal/unredacted derivative. No native reports or source files are copied into this portable folder.",
    "SHA-256 binds recorded bytes, not independent attestation. Sharing still requires a separate review.",
]

REPORT_STYLES = (
    STYLES
    + """
table { min-width:860px; }
th { white-space:nowrap; }
td:first-child { min-width:165px; }
.table-wrap:focus-visible { outline:2px solid #086d69; outline-offset:2px; }
"""
)


def qdrant_sarif(root: Path, report: dict[str, Any]) -> dict[str, Any]:
    """Only called after full Qdrant replay; keep Python, MCP and dependency paths separate."""
    retained = read_retained_research(root, manifest_contract="source-pilot-evidence-v1")
    runs: list[dict[str, Any]] = []
    for rep in range(1, 4):
        prefix = f"repetition-{rep}"
        dual = SemgrepDualView.model_validate_json(retained.read(prefix + "/dual-view.json"))
        for stage, evidence in (
            ("semgrep-research", dual.research),
            ("semgrep-policy", dual.repository_policy),
        ):
            if evidence is None:
                raise ValueError("Qdrant report requires both retained views")
            path = prefix + "/" + stage
            row = next(r for r in report["rows"] if r["repetition"] == rep and r["stage"] == stage)
            native_path = path + "/native.sarif"
            runs.append(
                semgrep_sarif_run(
                    evidence=evidence,
                    execution=ResearchExecutionAssessment.model_validate_json(
                        retained.read(path + "/assessment.json")
                    ),
                    native=json.loads(retained.read(native_path))["runs"][0],
                    native_json_path=path + "/native.json",
                    native_sarif_path=native_path,
                    target_sha256=report["content_sha256"],
                    exit_code=row["exit_code"],
                    properties={"repetition": rep, "stage": stage, "policy": evidence.role},
                )
            )
        for stage in ("agent-python", "agent-mcp"):
            path = prefix + "/" + stage + "/results.sarif"
            run = copy.deepcopy(json.loads(retained.read(path))["runs"][0])
            run.setdefault("properties", {}).update(
                {
                    "repetition": rep,
                    "stage": stage,
                    "retainedSarifPath": path,
                    "retainedSarifSha256": sha256_bytes(retained.read(path)),
                    "perFileCompletion": "not-observable",
                }
            )
            runs.append(run)
        row = next(
            r for r in report["rows"] if r["repetition"] == rep and r["stage"] == "osv-direct"
        )
        bundle = root / Path(row["evidence"]).parent
        document = dependency_sarif(load_dependency_run(bundle))
        for run in cast(list[dict[str, Any]], document["runs"]):
            run.setdefault("properties", {}).update(
                {
                    "repetition": rep,
                    "stage": run["properties"]["agentsecEvidence/comparisonPath"],
                    "dependencyManifestPath": row["evidence"],
                    "dependencyManifestSha256": sha256_file(root / row["evidence"]),
                }
            )
            runs.append(run)
    for run in runs:
        run.setdefault("properties", {}).update(
            {
                "sourceManifestSha256": retained.manifest_sha256,
                "repository": report["repository"],
                "revision": report["revision"],
                "evidenceRole": "formative-pilot-not-held-out",
                "uniqueVulnerabilities": None,
            }
        )
    return {"version": "2.1.0", "$schema": SARIF_SCHEMA_URI, "runs": runs}


def custom_runs(rows: list[dict[str, Any]], manifest: str) -> list[dict[str, Any]]:
    runs = []
    for row in rows:
        native = row["native"]
        rules = [
            {**r, **({"status": "active-condition"} if row["family"] == "tool-execution" else {})}
            for r in native["rules"]
        ]
        active = {r["rule_id"]: r for r in rules if r["status"] == "active-condition"}
        results = []
        for file in native["files"]:
            for finding in file["findings"] or []:
                rule = finding.get("rule") or active[finding["rule_id"]]
                span = finding["location"]
                results.append(
                    {
                        "ruleId": rule["rule_id"],
                        "level": "warning",
                        "message": {"text": rule["title"] + " (unreviewed static condition)"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": quote(file["path"], safe="/")},
                                    "region": {
                                        "startLine": span["start_line"],
                                        "endLine": span["end_line"],
                                    },
                                }
                            }
                        ],
                        "partialFingerprints": {"nativeRecordId": finding["record_id"]},
                        "properties": {
                            "nativePriority": rule.get("severity", rule.get("priority")),
                            "priorityInterpretation": "uncalibrated priority",
                            "nativeUtf8ByteRange": span,
                            "sourceSha256": file["source_sha256"],
                            "nativeReportSha256": row["native_sha256"],
                            "exportLosses": ["source-expression", "SARIF-columns"],
                            "suppressionApplication": "not-applied",
                            "reviewGrouping": "not-performed",
                        },
                    }
                )
        runs.append(
            {
                "tool": {
                    "driver": {
                        "name": native["producer"],
                        "version": native["version"],
                        "rules": [
                            {"id": r["rule_id"], "shortDescription": {"text": r["title"]}}
                            for r in active.values()
                        ],
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": native["execution_state"] == "complete",
                        "toolExecutionNotifications": [
                            {
                                "level": "warning",
                                "message": {"text": f["path"] + ": " + f["reason"]},
                            }
                            for f in native["files"]
                            if f["state"] != "analyzed"
                        ],
                    }
                ],
                "properties": {
                    "sourceManifestSha256": manifest,
                    "repetition": row["repetition"],
                    "batch": row["batch"],
                    "family": row["family"],
                    "nativeReportPath": row["key"] + "/stdout.bin",
                    "nativeReportSha256": row["native_sha256"],
                    "analysisCompleteness": "not-established",
                    "policy": native["policy"],
                    "uniqueVulnerabilities": None,
                    "exportBoundary": "Conditions only; inventory, deferred rules and limitations remain in report.json",
                },
            }
        )
    return runs


def table(headings: list[str], rows: list[list[Any]]) -> str:
    def cell(value: Any) -> str:
        return html.escape("unknown / not applicable" if value is None else str(value))

    return (
        '<div class="table-wrap" tabindex="0" role="region" '
        'aria-label="Scrollable evidence table"><table><thead><tr>'
        + "".join("<th scope=col>" + cell(h) + "</th>" for h in headings)
        + "</tr></thead><tbody>"
        + "".join(
            "<tr>" + "".join("<td>" + cell(v) + "</td>" for v in row) + "</tr>" for row in rows
        )
        + "</tbody></table></div>"
    )


def render(report: dict[str, Any]) -> bytes:
    e = html.escape
    plan = report["custom"]["plan"]
    base = report["custom"]["baseline_report"]
    family_table = table(
        [
            "Family",
            "Selected",
            "Analyzed",
            "Incomplete",
            "Conditions",
            "Inventory",
            "Limits",
            "Repeated semantics",
        ],
        [
            [
                f[k]
                for k in (
                    "family",
                    "selected_files",
                    "analyzed_files",
                    "incomplete_files",
                    "condition_records",
                    "inventory_records",
                    "limitation_records",
                    "repeatability",
                )
            ]
            for f in report["custom"]["families"]
        ],
    )
    baseline_table = table(
        ["Repetition", "Stage", "Status", "Reports", "Packages", "Unit", "Seconds"],
        [
            [
                r.get("repetition"),
                r.get("stage"),
                r.get("state"),
                r.get("finding_records"),
                r.get("package_identities"),
                r.get("unit", "see native stage contract"),
                round(r["duration_ns"] / 1e9, 3) if r.get("duration_ns") is not None else None,
            ]
            for r in base["rows"]
        ],
    )
    observations = []
    for row in report["custom"]["rows"]:
        if row["repetition"] != 1:
            continue
        for file in row["native"]["files"]:
            for finding in file["findings"] or []:
                rule = finding.get("rule") or next(
                    r for r in row["native"]["rules"] if r["rule_id"] == finding["rule_id"]
                )
                observations.append(
                    '<article class="finding"><h3>'
                    + e(rule["rule_id"] + " - " + rule["title"])
                    + "</h3><p><code>"
                    + e(file["path"])
                    + "</code> : "
                    + str(finding["location"]["start_line"])
                    + "</p><p>"
                    + e(
                        rule.get(
                            "boundary", "Static syntax evidence; runtime impact is not established."
                        )
                    )
                    + "</p><p>"
                    + e(
                        rule.get(
                            "remediation",
                            "Review the cited source and its callers; runtime impact is not established.",
                        )
                    )
                    + '</p><p class="muted">Unreviewed static condition. Native record: <code>'
                    + e(finding["record_id"])
                    + "</code></p></article>"
                )
    detail_rows = []
    for row in report["custom"]["rows"]:
        if row["repetition"] == 1:
            for file in row["native"]["files"]:
                if file["state"] != "analyzed" or file["inventory"] or file["limitations_observed"]:
                    detail_rows.append(  # noqa: PERF401 - conditional, multi-field HTML record
                        "<details><summary>"
                        + e(row["family"] + " / " + file["path"] + " / " + file["state"])
                        + '</summary><div class="detail-body"><pre>'
                        + e(
                            json.dumps(
                                {
                                    k: file[k]
                                    for k in ("reason", "inventory", "limitations_observed")
                                },
                                indent=2,
                                sort_keys=True,
                            )
                        )
                        + "</pre></div></details>"
                    )
    baseline_findings = []
    for run in report["baseline_sarif"]["runs"]:
        props = run.get("properties", {})
        rep = props.get("repetition", props.get("agentsecEvidence/repetition"))
        if rep != 1:
            continue
        name = run["tool"]["driver"]["name"]
        entries = []
        for result in run.get("results", []):
            locs = result.get("locations", [])
            location = json.dumps(locs, ensure_ascii=True, sort_keys=True)
            entries.append(
                [
                    result.get("ruleId"),
                    result["message"].get("text", ""),
                    location,
                    json.dumps(result.get("suppressions", []), sort_keys=True),
                ]
            )
        baseline_findings.append(
            "<details><summary>"
            + e(name)
            + " / first repetition / "
            + str(len(entries))
            + ' records</summary><div class="detail-body">'
            + table(
                ["Rule / advisory", "Native/exported claim", "Location", "Suppression"], entries
            )
            + "</div></details>"
        )
    limits = "".join("<li>" + e(x) + "</li>" for x in report["limitations"])
    inventory = report["custom"].get("artifact_inventory")
    inventory_table = (
        table(
            ["Artifact family", "Filename candidates", "Recognition", "Interpretation"],
            [
                [
                    f[k]
                    for k in (
                        "family",
                        "candidate_file_count",
                        "recognition_support",
                        "interpretation",
                    )
                ]
                for f in inventory["families"]
            ],
        )
        if inventory
        else "<p>Parent inventory unavailable.</p>"
    )
    document = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Repository security evidence - {e(plan["target"])}</title><style>{REPORT_STYLES}</style></head>
<body><a class="skip" href="#main">Skip to evidence</a><header><p>FORMATIVE REPOSITORY PILOT / INTERNAL</p>
<h1>{e(plan["repository"].removeprefix("https://github.com/"))}</h1><p>Static conditions, component matches and explicit analysis limits</p>
<p>Revision <code>{e(plan["revision"])}</code></p></header>
<div class="layout"><nav aria-label="Sections"><a href="#overview">Overview</a><a href="#custom">Custom families</a>
<a href="#baseline">Baselines</a><a href="#findings">Conditions</a><a href="#coverage">Coverage details</a>
<a href="#limits">Limitations</a><a href="#evidence">Evidence</a></nav><main id="main">
<section id="overview"><h2>Verified inputs, bounded analysis</h2>
<p>{len(plan["inventory"])} pinned Python files; {plan["repetitions"]} custom repetitions. All seven families received the same selected bytes.</p>
<p class="notice">Not a security certification. Conditions, inventory, package-advisory matches and unsupported analysis are different units. No overall risk score or vulnerability total is assigned.</p>
<p>Original reports and all repeated records are retained. The summaries below use one repetition; baseline and custom attempt timings remain separate.</p></section>
<section id="custom"><h2>Custom-family results</h2>{family_table}<p>Analyzed means bounded checks completed, not complete security coverage. Inventory-only families do not detect vulnerabilities.</p></section>
<section id="baseline"><h2>Baseline execution and component matching</h2>{baseline_table}
<p>Both OSV paths and both Semgrep views remain separate. Package presence does not establish matching completion, reachability or exploitability.</p>
{"".join(baseline_findings)}</section>
<section id="findings"><h2>Custom conditions for review</h2>{"".join(observations) or "<p>No custom condition records in the first repetition. Review coverage and limitations before interpreting this result.</p>"}</section>
<section id="coverage"><h2>Inventory and analysis limitations</h2>{inventory_table}
<p>Filename candidates are not parsed detections. No candidate recognized is not proof of absence. Actual tool selection and unsupported areas remain separate.</p>
{"".join(detail_rows) or "<p>No per-file observations retained.</p>"}</section>
<section id="limits"><h2>Interpretation boundaries</h2><ul>{limits}</ul></section>
<section id="evidence"><h2>Evidence bindings</h2><p><a href="report.json">Structured report</a> | <a href="results.sarif">SARIF conditions and baseline exports</a> | <a href="manifest.json">Checksums</a></p>
<dl class="metadata"><dt>Custom evidence seal</dt><dd><code>{e(report["custom"]["evidence_manifest_sha256"])}</code></dd>
<dt>Baseline evidence seal</dt><dd><code>{e(plan["baseline_manifest_sha256"])}</code></dd>
<dt>Repository content</dt><dd><code>{e(plan["content_sha256"])}</code></dd></dl>
<p>The portable package validates its derivatives. Full native replay requires the retained source attempts and frozen database.</p></section>
</main></div><footer>Offline evidence report. No scripts, external resources, target execution or automatic issue merging.</footer></body></html>"""
    return document.encode()


def export_report(project: Path, root: Path, database: Path, output: Path) -> dict[str, Any]:
    verification = verify_repository_custom(project, root, database)
    plan = RepositoryCustomPlan.model_validate(verification["plan"])
    if plan.target == "langgraph-cicd":
        _, baseline_document = load_pilot_source(project, Path(plan.baseline_root))
        baseline_sarif = cast(dict[str, Any], baseline_document)
    else:
        baseline_sarif = qdrant_sarif(Path(plan.baseline_root), verification["baseline_report"])
    report = {
        "contract": "repository-evidence-report-v1",
        "custom": verification,
        "baseline_sarif": baseline_sarif,
        "limitations": LIMITATIONS,
        "sensitivity": "internal-unredacted-not-release-cleared",
    }
    sarif = {
        "version": "2.1.0",
        "$schema": SARIF_SCHEMA_URI,
        "runs": baseline_sarif["runs"]
        + custom_runs(verification["rows"], verification["evidence_manifest_sha256"]),
    }
    output = output.absolute()
    plain_path(output.parent, directory=True)
    if (
        output.exists()
        or output.is_relative_to(root)
        or output.is_relative_to(Path(plan.baseline_root))
    ):
        raise ValueError("Use a new derivative folder outside source evidence")
    output.mkdir()
    save(output / "report.json", report)
    save(output / "results.sarif", sarif)
    atomic_write_bytes(output / "report.html", render(report))
    save(
        output / "manifest.json",
        {
            "contract": "repository-evidence-package-v1",
            "source_manifest_sha256": verification["evidence_manifest_sha256"],
            "files": {
                p.name: {"sha256": sha256_file(p), "bytes": p.stat().st_size}
                for p in sorted(output.iterdir())
            },
        },
    )
    return verify_report(output)


def verify_report(root: Path) -> dict[str, Any]:
    root = plain_path(root, directory=True)
    manifest = load(root / "manifest.json")
    if manifest.get("contract") != "repository-evidence-package-v1" or set(manifest["files"]) != {
        "report.json",
        "results.sarif",
        "report.html",
    }:
        raise ValueError("Unsupported report package or membership")
    if {p.name for p in root.iterdir()} != {*manifest["files"], "manifest.json"}:
        raise ValueError("Unexpected report package content")
    contents = {name: bounded_file(root / name, 32 * 1024**2) for name in manifest["files"]}
    if any(
        manifest["files"][name] != {"sha256": sha256_bytes(raw), "bytes": len(raw)}
        for name, raw in contents.items()
    ):
        raise ValueError("Report package checksum differs")
    report = json.loads(contents["report.json"])
    if (
        report.get("contract") != "repository-evidence-report-v1"
        or report["limitations"] != LIMITATIONS
    ):
        raise ValueError("Report contract or limitations differ")
    if manifest["source_manifest_sha256"] != report["custom"]["evidence_manifest_sha256"]:
        raise ValueError("Source evidence binding differs")
    validate_custom_projection(report["custom"])
    expected = {
        "version": "2.1.0",
        "$schema": SARIF_SCHEMA_URI,
        "runs": report["baseline_sarif"]["runs"]
        + custom_runs(report["custom"]["rows"], report["custom"]["evidence_manifest_sha256"]),
    }
    if json.loads(contents["results.sarif"]) != expected or contents["report.html"] != render(
        report
    ):
        raise ValueError("Report projections differ")
    return {
        "contract": "repository-evidence-package-verification-v1",
        "passed": True,
        "native_replayed": False,
        "meaning": "Derivative consistency, not native replay or independent attestation",
        "manifest_sha256": sha256_file(root / "manifest.json"),
    }


def validate_custom_projection(custom: dict[str, Any]) -> None:
    """Recheck embedded native bytes and first-repeat tables, without claiming raw replay."""
    plan = RepositoryCustomPlan.model_validate(custom["plan"])
    validate_plan(plan)
    if "artifact_inventory" in custom:
        inventory = ArtifactInventory.model_validate(custom["artifact_inventory"])
        if inventory.snapshot.content_sha256 != plan.content_sha256:
            raise ValueError("Artifact inventory belongs to a different repository snapshot")
    baseline_raw = custom["baseline_report_json"].encode()
    if sha256_bytes(baseline_raw) != plan.baseline_report_sha256:
        raise ValueError("Embedded baseline report hash differs")
    if custom["baseline_report"] != {
        **json.loads(baseline_raw),
        "retained_manifest_sha256": plan.baseline_manifest_sha256,
    }:
        raise ValueError("Baseline table differs from embedded source report")
    rows = custom["rows"]
    planned = schedule(plan)
    if len(rows) != len(planned):
        raise ValueError("Embedded native schedule differs")
    grouped: dict[tuple[str, int], list[Any]] = {}
    for row, expected in zip(rows, planned, strict=True):
        if any(row[k] != expected[k] for k in ("key", "family", "repetition", "batch")):
            raise ValueError("Embedded native schedule differs")
        raw = row["native_json"].encode()
        if sha256_bytes(raw) != row["native_sha256"]:
            raise ValueError("Embedded native hash differs")
        family = next(f for f in FAMILIES if f.key == row["family"])
        native = current_native(
            raw,
            plan.requests[row["batch"]].model_dump_json().encode(),
            family,
            row["native_exit_code"],
        )
        if (
            native.model_dump(mode="json") != row["native"]
            or row["state"] != "validated"
            or row["native_state"] != native.execution_state
            or row["finding_records"] != sum(len(f.findings or []) for f in native.files)
        ):
            raise ValueError("Embedded native projection differs")
        grouped.setdefault((family.key, row["repetition"]), []).extend(native.files)
    expected_summaries = []
    for family in FAMILIES:
        hashes = []
        for rep in range(1, plan.repetitions + 1):
            files = sorted(grouped[family.key, rep], key=lambda f: f.path)
            if [f.path for f in files] != [e.path for e in plan.inventory]:
                raise ValueError("Embedded partition membership differs")
            hashes.append(semantic_hash([f.model_dump(mode="json") for f in files]))
        first = grouped[family.key, 1]
        expected_summaries.append(
            {
                "family": family.key,
                "selected_files": len(first),
                "analyzed_files": sum(f.state == "analyzed" for f in first),
                "incomplete_files": sum(f.state != "analyzed" for f in first),
                "condition_records": sum(len(f.findings or []) for f in first),
                "inventory_records": sum(len(f.inventory) for f in first),
                "limitation_records": sum(len(f.limitations_observed) for f in first),
                "repeatability": "not-assessed"
                if len(hashes) == 1
                else "equal"
                if len(set(hashes)) == 1
                else "different",
                "semantic_sha256": hashes,
            }
        )
    if custom["families"] != expected_summaries or custom["unique_vulnerabilities"] is not None:
        raise ValueError("Custom summary differs from embedded native evidence")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("build", "verify"))
    parser.add_argument("--project", type=Path, default=Path.cwd())
    parser.add_argument("--input", type=Path)
    parser.add_argument("--database", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "build":
        if args.input is None or args.database is None:
            parser.error("build requires --input and --database")
        result = export_report(args.project, args.input, args.database, args.output)
    else:
        result = verify_report(args.output)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
