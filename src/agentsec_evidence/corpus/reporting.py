"""Offline core JSON/HTML derivatives; no scanner launches or implicit evidence exports."""

# Keep escaped HTML templates and reader-facing limitations together.
# ruff: noqa: E501

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Any, cast

from pydantic import JsonValue

from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.core.io import atomic_write_bytes
from agentsec_evidence.corpus.contracts import ROLES, CorpusCorePlan
from agentsec_evidence.corpus.execution import verify_core
from agentsec_evidence.pilot.runner import evidence_records, save
from agentsec_evidence.reporting.custom_contracts import FAMILIES
from agentsec_evidence.reporting.html_styles import STYLES
from agentsec_evidence.reporting.repository import table
from agentsec_evidence.research.retained import plain_path, read_retained_research

LIMITATIONS = [
    "Purposively selected descriptive evidence, not a held-out accuracy benchmark.",
    "Static conditions and native reports are not confirmed or unique vulnerabilities.",
    "The two earlier pilots remain previously inspected; repeats are not independent samples.",
    "Custom families use bounded file-local partitions; baselines use the complete eligible selection.",
    "Inventory-only orchestration and agent-to-agent families are not vulnerability detectors.",
    "Agent Audit does not establish per-file completion; reported scanner totals are not coverage proof.",
    "Custom suppressions are not applied; Semgrep research/policy views both disable Git ignore filtering.",
    "Dependencies, MCP JSON and IaC are not run in this core attempt; older pilot results are not pooled here.",
    "No target execution, model calls, runtime exploitability, effective permissions or safety verdict.",
    "Unknown, refused and failed analysis is not a zero-finding result. Partial custom counts are observed records only.",
    "Internal/unredacted report. Native files and source bytes are not copied or linked to local paths.",
    "Hashes bind retained bytes, not independent attestation or review of security relevance.",
    "Core SARIF export is not provided by this increment; original native evidence remains retained.",
]


def summary(
    plan: CorpusCorePlan, rows: list[dict[str, Any]], observations: dict[str, Any]
) -> list[dict[str, Any]]:
    result = []
    paths = [e.source.path for e in plan.validation.preview.selection]
    for producer in (*[f.key for f in FAMILIES], *ROLES):
        repetitions = []
        for rep in range(1, 4):
            cells = [r for r in rows if r["producer"] == producer and r["repetition"] == rep]
            observed = [r for r in cells if r["state"] == "observed"]
            complete = bool(cells) and len(cells) == len(observed)
            values = [observations[r["key"]] for r in observed]
            files = sorted(
                (f for v in values if v["kind"] == "custom" for f in v["native"]["files"]),
                key=lambda f: f["path"],
            )
            if len({f["path"] for f in files}) != len(files) or any(
                f["path"] not in paths for f in files
            ):
                raise ValueError("Duplicate or foreign custom input")
            is_custom = producer in {f.key for f in FAMILIES}
            omitted = [p for p in paths if p not in {f["path"] for f in files}] if is_custom else []
            semantic = [v["semantic"] for v in values]
            repetitions.append(
                {
                    "repetition": rep,
                    "state": "observed"
                    if complete
                    else "failed"
                    if any(r["state"] == "failed" for r in cells)
                    else "not-run"
                    if any(r["state"] == "not-run" for r in cells)
                    else cells[0]["state"],
                    "selected_files": len(paths),
                    "observed_cells": len(observed),
                    "planned_cells": len(cells),
                    "finding_records": sum(r["finding_records"] for r in observed)
                    if complete
                    else None,
                    "observed_records_before_failure": sum(r["finding_records"] for r in observed)
                    if observed and not complete
                    else None,
                    "analyzed_files": sum(f["state"] == "analyzed" for f in files)
                    if is_custom and complete
                    else None,
                    "incomplete_files": sum(f["state"] != "analyzed" for f in files) + len(omitted)
                    if is_custom and complete
                    else None,
                    "omitted_paths": omitted if is_custom else None,
                    "inventory_records": sum(len(f["inventory"]) for f in files)
                    if is_custom and complete
                    else None,
                    "limitation_records": sum(len(f["limitations_observed"]) for f in files)
                    if is_custom and complete
                    else None,
                    "duration_ns": sum(r["duration_ns"] for r in observed) if complete else None,
                    "semantic_sha256": semantic_hash(cast(JsonValue, semantic))
                    if complete
                    else None,
                    "reasons": sorted({reason for r in cells for reason in r["reasons"]}),
                }
            )
        hashes = [r["semantic_sha256"] for r in repetitions]
        result.append(
            {
                "producer": producer,
                "repetitions": repetitions,
                "repeatability": "not-assessed"
                if None in hashes
                else "equal"
                if len(set(hashes)) == 1
                else "different",
            }
        )
    return result


def build_report(replay: dict[str, Any]) -> dict[str, Any]:
    plan = CorpusCorePlan.model_validate(replay["plan"])
    preview = plan.validation.preview
    return {
        "contract": "corpus-core-report-v1",
        "candidate": preview.candidate.model_dump(mode="json"),
        "source_content_sha256": preview.source_content_sha256,
        "selection_sha256": preview.selection_sha256,
        "source_manifest_sha256": replay["manifest_sha256"],
        "validation_manifest_sha256": plan.validation_manifest_sha256,
        "artifact_inventory_sha256": preview.artifact_inventory_sha256,
        "selected_inputs": [e.model_dump(mode="json") for e in preview.selection],
        "core_input_gates": [s.model_dump(mode="json") for s in plan.assessment.stages],
        "full_inventory_files": preview.full_inventory_files,
        "optional_candidates": preview.model_dump(mode="json")["optional_artifact_candidates"],
        "optional_execution": "not-admitted-in-core",
        "execution_finished": replay["execution_finished"],
        "error": replay["error"],
        "attempt_duration_ns": replay["duration_ns"],
        "summary": summary(plan, replay["rows"], replay["observations"]),
        "rows": replay["rows"],
        "observations": replay["observations"],
        "unique_vulnerabilities": None,
        "limitations": LIMITATIONS,
        "distribution": "internal-unredacted-separate-sharing-review-required",
    }


def render(report: dict[str, Any]) -> bytes:
    e = html.escape
    candidate = report["candidate"]
    rows = [
        [
            s["producer"],
            r["repetition"],
            r["state"],
            r["selected_files"],
            r["analyzed_files"],
            r["incomplete_files"],
            r["finding_records"],
            r["inventory_records"],
            s["repeatability"],
        ]
        for s in report["summary"]
        for r in s["repetitions"]
    ]
    tables = table(
        [
            "Producer",
            "Repeat",
            "State",
            "Selected",
            "Analyzed",
            "Incomplete",
            "Reports",
            "Inventory",
            "Repeatability",
        ],
        rows,
    )
    details = []
    for row in report["rows"]:
        observation = report["observations"].get(row["key"])
        if observation is None:
            continue
        # Native messages and evidence are data, never active HTML or automatic local links.
        detail = {k: v for k, v in observation.items() if k != "semantic"}
        details.append(
            "<details><summary>"
            + e(row["key"])
            + '</summary><div class="detail-body"><pre>'
            + e(json.dumps(detail, ensure_ascii=True, indent=2, sort_keys=True))
            + "</pre></div></details>"
        )
    limitation_html = "".join("<li>" + e(x) + "</li>" for x in report["limitations"])
    status = (
        "Finished at the declared scope"
        if report["execution_finished"]
        else "Incomplete attempt: do not interpret as a clean scan"
    )
    error = "<pre>" + e(json.dumps(report["error"], indent=2)) + "</pre>" if report["error"] else ""
    text = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Core security evidence: {e(candidate["repository"])}</title>
<style>{STYLES}main{{max-width:1500px;margin:auto}}table{{min-width:1050px}}th{{white-space:nowrap}}</style></head>
<body><a class="skip" href="#main">Skip to evidence</a><header><p>Descriptive repository analysis | Internal</p>
<h1>{e(candidate["repository"])}</h1><p>{e(candidate["revision"])}</p><p>{e(status)}</p></header>
<main id="main"><section><h2>Scope and outcome</h2><p>{len(report["selected_inputs"])} selected Python files from {report["full_inventory_files"]} inventoried repository files.</p>
<p>{e(candidate["role"])}. No target code was executed.</p><div class="notice">Reports are static observations, not confirmed vulnerabilities. Unsupported and unrun counts remain unknown.</div>{error}
<dl class="metadata"><dt>Evidence manifest</dt><dd>{e(report["source_manifest_sha256"])}</dd><dt>Selection hash</dt><dd>{e(report["selection_sha256"])}</dd><dt>Measured attempt time</dt><dd>{report["attempt_duration_ns"] / 1e9:.3f} seconds, excluding preparation and report replay</dd></dl></section>
<section><h2>Producer results and coverage</h2>{tables}<p>Baseline per-file analysis completeness is not established. Inventory counts are not finding counts.</p></section>
<section><h2>Evidence records</h2>{"".join(details)}</section><section><h2>Optional stages</h2><p>Not run in this core treatment. Artifact presence does not establish scanner applicability.</p><pre>{e(json.dumps(report["optional_candidates"], indent=2, sort_keys=True))}</pre></section>
<section><h2>Limits and interpretation</h2><ul>{limitation_html}</ul></section></main></body></html>"""
    return text.encode("utf-8")


def write_report(project: Path, source: Path, output: Path) -> dict[str, Any]:
    output = output.absolute()
    plain_path(output.parent, directory=True)
    if output.exists():
        raise ValueError("Use a new report directory; never overwrite a derivative")
    report = build_report(verify_core(project, source))
    output.mkdir()
    save(output / "report.json", report)
    atomic_write_bytes(output / "report.html", render(report))
    save(output / "evidence-manifest.json", {"files": evidence_records(output)})
    return verify_report(project, source, output)


def verify_report(project: Path, source: Path, output: Path) -> dict[str, Any]:
    retained = read_retained_research(output)
    if set(retained.files) != {"report.json", "report.html"}:
        raise ValueError("Unexpected report export or package member")
    report = build_report(verify_core(project, source))
    if json.loads(retained.read("report.json")) != report or retained.read("report.html") != render(
        report
    ):
        raise ValueError("Report differs from replayed native evidence")
    return {
        "contract": "corpus-core-report-verification-v1",
        "passed": True,
        "source_manifest_sha256": report["source_manifest_sha256"],
        "report_html_sha256": sha256_bytes(retained.read("report.html")),
        "execution_finished": report["execution_finished"],
        "scanner_invocations": 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("write", "verify"))
    parser.add_argument("--project", type=Path, default=Path.cwd())
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = (
        write_report(args.project, args.source, args.output)
        if args.mode == "write"
        else verify_report(args.project, args.source, args.output)
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
