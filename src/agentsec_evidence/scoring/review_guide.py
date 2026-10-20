"""Evidence navigation and review actions, never security verdicts or new measurements."""

from __future__ import annotations

import html
import os
import unicodedata
from pathlib import Path
from urllib.parse import quote

from pydantic import JsonValue

from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.reporting.service import require_new_derivative
from agentsec_evidence.research.retained import bounded_file, plain_path
from agentsec_evidence.scoring.models import (
    MeasurementRow,
    Metric,
    Reference,
    ScorePlan,
    ScoreReport,
)
from agentsec_evidence.scoring.service import MAX_BYTES, validate_scores

TOPICS = {
    "coverage": (
        "Coverage needs interpretation",
        "Check selected, excluded, skipped and unreported paths before interpreting alert counts. "
        "A reported path does not establish completed analysis.",
    ),
    "exports": (
        "Export omissions or mismatches",
        "Inspect the field-level observations and original normalized/native records. "
        "Distinguish intentionally unrepresented fields from missing or incorrectly mapped fields.",
    ),
    "packages": (
        "Dependency handoff differences",
        "Locate missing/added identities and source qualifiers at the named handoff. "
        "Check whether a copied-SBOM mutation was intentional before attributing a tool defect. "
        "Do not add losses across paths or repetitions.",
    ),
    "matching": (
        "Matching limits",
        "Check unresolved versions and unsupported package evidence. Zero exact matches is not "
        "proof of completed vulnerability matching or safety.",
    ),
    "claims": (
        "Scanner claims need contextual review",
        "Inspect the original rule, location, evidence and report-bound review. Native severity, "
        "confidence and remediation are scanner claims, not endorsed conclusions. "
        "Do not merge different risks merely because they share a line.",
    ),
    "agreement": (
        "Development expectations or repetitions disagree",
        "Inspect the denominator and exact treatment before investigating the discrepancy. "
        "Retain the failed comparison; do not tune held-out cases or replace historical results.",
    ),
}


def _text(value: object) -> str:
    # Render data as literal text, including Markdown links, images and HTML-like payloads.
    escaped = html.escape(str(value).replace("\r", " ").replace("\n", " "), quote=True)
    return "".join(
        f"U+{ord(c):04X}"
        if unicodedata.category(c) in {"Cc", "Cf"}
        else f"&#{ord(c)};"
        if c in "\\`*_{}[]()|#!"
        else c
        for c in escaped
    )


def _link(label: str, path: Path, output: Path) -> str:
    relative = Path(os.path.relpath(path, output)).as_posix()
    return f"[{_text(label)}](<{quote(relative, safe='/.-_')}>)"


def _value(metric: Metric) -> str:
    if metric.status != "measured":
        return metric.status
    if metric.denominator is not None:
        return f"{metric.numerator}/{metric.denominator}"
    return str(metric.numerator)


def _positive(row: MeasurementRow, names: set[str]) -> bool:
    return any(
        m.name in names and m.status == "measured" and (m.numerator or 0) > 0 for m in row.metrics
    )


def _shortfall(row: MeasurementRow, names: set[str]) -> bool:
    return any(
        m.name in names
        and m.status == "measured"
        and m.numerator is not None
        and m.denominator is not None
        and m.numerator < m.denominator
        for m in row.metrics
    )


def review_topics(row: MeasurementRow) -> tuple[str, ...]:
    selected = []
    if _shortfall(row, {"reported-path-coverage"}) or any(
        m.name == "analysis-completion" and m.status == "unknown" for m in row.metrics
    ):
        selected.append("coverage")
    if _positive(row, {"unrepresented-export-fields", "incorrect-or-missing-export-fields"}):
        selected.append("exports")
    if (
        _shortfall(row, {"package-projection-retention"})
        or _positive(row, {"source-qualifier-losses"})
        or any(
            isinstance(row.observations.get(k), list) and row.observations[k]
            for k in ("missing", "added", "missing_identifiers")
        )
    ):
        selected.append("packages")
    if _positive(row, {"unsupported-package-observations"}) or any(
        m.name == "matching-completion" and m.status == "unknown" for m in row.metrics
    ):
        selected.append("matching")
    if _positive(row, {"native-rule-reports", "reported-package-advisory-pairs"}):
        selected.append("claims")
    if _shortfall(
        row,
        {
            "finite-inventory-recall",
            "finite-match-precision",
            "finite-match-recall",
            "finite-rule-path-agreement",
            "semantic-agreement-to-first",
        },
    ):
        selected.append("agreement")
    return tuple(selected)


def render_review_guide(
    report: ScoreReport, plan: ScorePlan, *, project: Path, bundle: Path, output: Path
) -> dict[str, bytes]:
    topics: dict[str, list[int]] = {key: [] for key in TOPICS}
    for index, row in enumerate(report.rows):
        for key in review_topics(row):
            topics[key].append(index)
    lines = [
        "# Results Review Guide",
        "",
        "An evidence-navigation aid, not a security verdict, risk ranking or new experiment.",
        "Integrity validation covers the scoring derivative. Native sources were not replayed "
        "by this guide; stored evidence hashes are references, not fresh verification "
        "or attestation.",
        "Internal only: not redacted or cleared for release. No scanner messages or code snippets "
        "are copied into this guide; source links may still expose sensitive evidence.",
        "",
        "## Scope",
        "",
        f"Selection: {_text(plan.selection_rationale)}",
        "",
        f"Selected sessions: {len(plan.sessions)}. Measurement rows: {len(report.rows)}. "
        f"Attempt/cell rows: {len(report.attempts)}. These are not independent research samples.",
        "Source artifacts: "
        + ", ".join(
            _link(name, bundle / name, output)
            for name in ("plan.json", "scores.json", "SUMMARY.md", "TABLES.md", "attempts.csv")
        )
        + ".",
        "",
        "Exclusions: "
        + ("; ".join(_text(x) for x in plan.exclusions) or "None listed in this selection."),
        "",
        "## Review Actions",
        "",
        "Counts below are measurement rows requiring interpretation, not findings or unique "
        "issues. One row can appear in several topics; never sum these counts.",
        "",
        "| Topic | Rows | Next action |",
        "|---|---:|---|",
    ]
    for key, (title, action) in TOPICS.items():
        lines.append(f"| [{title}](DETAILS.md#{key}) | {len(topics[key])} | {action} |")
    lines += [
        "",
        "A zero topic count means no trigger in the selected measurements, not absence of risk.",
        "",
        "## Execution and Review Boundaries",
        "",
        "| Recorded state | Attempt/cell rows |",
        "|---|---:|",
    ]
    for state in sorted({str(a.get("state", "unknown")) for a in report.attempts}):
        total = sum(str(a.get("state", "unknown")) == state for a in report.attempts)
        lines.append(f"| {_text(state)} | {total} |")
    lines += [
        "",
        "Inspect failed, refused, unsupported and unattempted rows in attempts.csv. "
        "Do not retry automatically or read workflow status as complete security analysis.",
        "Original attempts remain visible after recovery; "
        "this table is not a count of current failures.",
        "",
        "### Finding review",
        "",
    ]
    if not report.reviews:
        lines.append("No review sidecar selected. Review status is unavailable, not accepted.")
    for index, review in enumerate(report.reviews):
        lines.append(
            f"- Review {index + 1}: {_text(review.get('pending_finding_occurrences', 'unknown'))} "
            f"pending occurrences; {_text(review.get('human_decision_occurrences', 'unknown'))} "
            "recorded human decisions. These are not independent accuracy labels. "
            f"{_text(review.get('scope', 'Scope unknown'))}"
        )
    lines += [
        "",
        "## Acceptance Checklist",
        "",
        "- Can you identify the selected case, session, stage/view and repetition?",
        "- Can you distinguish a scanner claim from a reviewed conclusion?",
        "- Can you locate the original evidence and explain coverage or handoff limitations?",
        "- Can you distinguish a refusal/failure/unknown result from no reported findings?",
        "- Is the next review action clear without inventing a remediation or an overall score?",
        "",
        "Student acceptance is not recorded by generating this document. "
        "Human review time and productivity improvement remain unmeasured.",
        "",
    ]
    details = [
        "# Review Evidence Index",
        "",
        "All matching rows and repetitions are retained. Topic membership is navigation only, "
        "not deduplication, severity or adjudication. JSON pointers are printed separately because "
        "file viewers do not consistently navigate JSON fragments.",
        "",
    ]
    for key, (title, _) in TOPICS.items():
        details += [f'<a id="{key}"></a>', f"## {title}", ""]
        if not topics[key]:
            details += ["No selected measurement row triggers this topic.", ""]
        for index in topics[key]:
            row = report.rows[index]
            details += [
                f"### {_text(row.case_id)} / {_text(row.stage)} / repetition {row.repetition}",
                "",
                f"Role: {row.evidence_role}; state: {_text(row.state)}; "
                f"analysis: {row.analysis_completeness}.",
                f"Session: `{row.session}`; attempt: {_text(row.attempt_id)}; row: `{row.row_id}`.",
                _link("Scoring record", bundle / "scores.json", output)
                + f"; pointer `/rows/{index}`.",
                "",
                "| Metric | Result | Unit | Excluded | Unknown | Limitation |",
                "|---|---|---|---:|---|---|",
            ]
            for metric in row.metrics:
                unknown = metric.unknown if metric.unknown is not None else "unknown"
                details.append(
                    f"| {_text(metric.name)} | {_value(metric)} | {_text(metric.unit)} | "
                    f"{metric.excluded} | {unknown} "
                    f"| {_text(metric.limitation)} |"
                )
            for ref in row.references:
                details.append(
                    "- "
                    + _link(ref.path, project / ref.path, output)
                    + f"; SHA-256 `{ref.sha256}`; pointer: {_text(ref.pointer or '(whole file)')}."
                )
            details.append("")
    details += ["## Original Review Records", ""]
    for review in report.reviews:
        raw_refs = review.get("references")
        if isinstance(raw_refs, list):
            for raw in raw_refs:
                ref = Reference.model_validate(raw)
                details.append(
                    "- "
                    + _link(ref.path, project / ref.path, output)
                    + f"; SHA-256 `{ref.sha256}`."
                )
    return {
        "REVIEW.md": ("\n".join(lines) + "\n").encode(),
        "DETAILS.md": ("\n".join(details) + "\n").encode(),
    }


def write_review_guide(project: Path, bundle: Path, output: Path) -> dict[str, JsonValue]:
    project = plain_path(project, directory=True)
    bundle = plain_path(bundle, directory=True)
    parent = plain_path(output.parent, directory=True)
    if not bundle.is_relative_to(project) or not parent.is_relative_to(project / "outputs"):
        raise ValueError("Use a project scoring bundle and a new directory under existing outputs")
    destination = require_new_derivative(parent / output.name, [bundle])
    for directory in (parent, *parent.parents):
        if any(
            (directory / name).exists()
            for name in (
                "scoring-manifest.json",
                "review-manifest.json",
                "review-guide-manifest.json",
                "validation.json",
            )
        ):
            raise ValueError("Review guide cannot modify finalized evidence")
    validate_scores(project, bundle)
    before: dict[str, JsonValue] = {
        p.name: sha256_bytes(bounded_file(p, MAX_BYTES)) for p in bundle.iterdir()
    }
    report = ScoreReport.model_validate_json(bounded_file(bundle / "scores.json", MAX_BYTES))
    plan = ScorePlan.model_validate_json(bounded_file(bundle / "plan.json", MAX_BYTES))
    rendered = render_review_guide(report, plan, project=project, bundle=bundle, output=destination)
    if before != {p.name: sha256_bytes(bounded_file(p, MAX_BYTES)) for p in bundle.iterdir()}:
        raise ValueError("Scoring bundle changed during review generation")
    receipt: dict[str, JsonValue] = {
        "contract": "evidence-review-guide-v1",
        "source_bundle": bundle.relative_to(project).as_posix(),
        "source_files": before,
        "renderer_sha256": sha256_file(Path(__file__)),
        "validation_scope": "scoring-derivative-integrity-only",
        "native_sources_replayed": False,
        "student_acceptance": "pending",
        "new_scanner_invocations": 0,
        "files": {name: sha256_bytes(raw) for name, raw in rendered.items()},
    }
    destination.mkdir(exist_ok=False)
    for name, raw in {**rendered, "review-guide-manifest.json": json_bytes(receipt)}.items():
        with (destination / name).open("xb") as stream:
            stream.write(raw)
    return receipt
