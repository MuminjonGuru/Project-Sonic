"""Separate benchmark presentation; no pooled security verdict or new measurement."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping, Sequence

from agentsec_evidence.reporting.html import MAX_HTML_BYTES, _details, _metadata, _table, _text
from agentsec_evidence.reporting.html_styles import STYLES
from agentsec_evidence.scoring.models import MeasurementRow, Metric, ScorePlan, ScoreReport
from agentsec_evidence.scoring.review_guide import TOPICS, review_topics

SCORE_STYLES = (
    STYLES
    + """
table { min-width:720px; }
#pilot table { min-width:1000px; }
.measurement table { min-width:900px; }
.table-wrap { overscroll-behavior-inline:contain; }
@media print { table,#pilot table,.measurement table { min-width:0; } }
"""
)

PILOT_SNAPSHOT_METRICS = {
    "reported-path-coverage",
    "normalized-to-sarif-field-retention",
    "native-rule-reports",
    "native-aggregate-files",
    "package-projection-retention",
    "source-qualifier-losses",
    "reported-package-advisory-pairs",
}


def _result(metric: Metric) -> str:
    if metric.status != "measured":
        return metric.status
    if metric.denominator is not None:
        return f"{metric.numerator}/{metric.denominator}"
    return str(metric.numerator)


def _measurement(index: int, row: MeasurementRow) -> str:
    repeat = f"repetition {row.repetition}" if row.repetition else "shared or summary row (0)"
    output = (
        f'<details class="measurement" id="row-{index}"><summary>'
        + _text(f"{row.case_id} | {row.stage} | {repeat} | {row.state}")
        + '</summary><div class="detail-body">'
    )
    output += _metadata(
        (
            ("Scoring pointer", f"/rows/{index}"),
            ("Evidence role", row.evidence_role),
            ("Session", row.session),
            ("Attempt", row.attempt_id),
            ("Row identity", row.row_id),
            ("Analysis completeness", row.analysis_completeness),
        )
    )
    output += _table(
        ("Metric", "Status / result", "Unit", "Numerator", "Denominator", "Excluded", "Unknown"),
        (
            (
                m.name,
                f"{m.status}: {_result(m)}" if m.status == "measured" else m.status,
                m.unit,
                m.numerator if m.numerator is not None else "Unknown",
                m.denominator
                if m.denominator is not None
                else "Count (no ratio)"
                if m.status == "measured"
                else "Not specified",
                m.excluded,
                m.unknown if m.unknown is not None else "Unknown",
            )
            for m in row.metrics
        ),
        "Exact retained measurements; empty and unknown denominators are not zero results",
    )
    output += _table(
        ("Metric", "Eligibility", "Limitation", "Version"),
        ((m.name, m.eligibility, m.limitation, m.version) for m in row.metrics),
        "Measurement scope and limits",
    )
    output += _details("Recorded observations", row.observations)
    output += _table(
        ("Source artifact (not copied)", "SHA-256", "JSON pointer"),
        ((r.path, r.sha256, r.pointer or "Whole file") for r in row.references),
        "Retained source references; not reopened by this presentation",
    )
    return output + "</div></details>"


def render_score_html(
    report: ScoreReport,
    plan: ScorePlan,
    *,
    input_files: Sequence[tuple[str, int, str]],
    exports: Mapping[str, str],
) -> bytes:
    digest = base64.b64encode(hashlib.sha256(SCORE_STYLES.encode()).digest()).decode("ascii")
    csp = f"default-src 'none'; style-src 'sha256-{digest}'; base-uri 'none'; form-action 'none'"
    output = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<meta http-equiv="Content-Security-Policy" content="{_text(csp)}">'
        '<meta name="referrer" content="no-referrer">'
        "<title>Benchmark Evidence Report</title>"
        f"<style>{SCORE_STYLES}</style></head><body>"
        '<a class="skip" href="#overview">Skip to report</a>'
        '<header><div class="eyebrow">DEVELOPMENT AND FORMATIVE EVIDENCE</div>'
        "<h1>Benchmark Evidence Report</h1><p>Coverage, evidence preservation and repeatability</p>"
        "<p>Internal, unredacted. Not a repository security verdict "
        "or final evaluation.</p></header>"
        '<div class="layout"><nav aria-label="Report sections">'
        '<a href="#overview">Scope and selection</a><a href="#pilot">Pilot observations</a>'
        '<a href="#actions">Review actions</a>'
        '<a href="#sessions">Sessions and measurements</a>'
        '<a href="#attempts">Attempt history</a><a href="#reviews">Finding reviews</a>'
        '<a href="#evidence">Evidence and exports</a></nav><main>'
        '<section id="overview"><h2>What this report establishes</h2>'
        "<p>The scoring bundle and its generated tables were validated. Native sources, "
        "ledger histories and review sidecars were not reopened. This is a presentation of "
        "retained measurements, not a new scan or an independent assessment.</p>"
    )
    output += _metadata(
        (
            ("Selection rationale", plan.selection_rationale),
            ("Selected sessions", len(plan.sessions)),
            ("Measurement rows", len(report.rows)),
            ("Attempt/cell records", len(report.attempts)),
            ("Scoring contract", report.contract),
            ("Scoring plan SHA-256", report.plan_sha256),
        )
    )
    output += (
        '<p class="notice">Sessions, stages, views, attempts and repetitions are not independent '
        "research samples. Development and formative-pilot evidence are kept separate. "
        "No pooled vulnerability total, public detection accuracy or human productivity "
        "improvement is established.</p><h3>Selection exclusions</h3><ul>"
        + "".join(f"<li>{_text(x)}</li>" for x in plan.exclusions)
        + ("" if plan.exclusions else "<li>None recorded in this selection.</li>")
        + "</ul><h3>Evidence limitations</h3><ul>"
        + "".join(f"<li>{_text(x)}</li>" for x in report.limitations)
        + "</ul><p>Case IDs are retained labels, not independent case-family counts. "
        "Shared origins and controlled mutations require the original protocol; this scoring "
        "contract does not supply a complete family mapping. "
        "No family relationship is inferred.</p>"
        '</section><section id="pilot"><h2>Formative-pilot observations</h2>'
        "<p>First repetition only, separately identified by session and case. These are retained "
        "coverage, report-count and handoff measurements, not vulnerability truth. All other "
        "repetitions, timing, failed attempts and limitations remain in the session records.</p>"
    )
    pilot_rows = [
        r for r in report.rows if r.evidence_role == "formative-pilot" and r.repetition == 1
    ]
    if not pilot_rows:
        output += "<p>No first-repetition formative-pilot measurements in this selection.</p>"
    for i, session in enumerate(plan.sessions):
        selected_rows = [r for r in pilot_rows if r.session == session.session]
        if not selected_rows:
            continue
        output += (
            f'<h3>Session {i + 1}</h3><p><a href="#session-{i}">Complete session records</a></p>'
        )
        output += _table(
            ("Case", "Stage / view", "Metric", "Result", "Unit", "Limitation"),
            (
                (r.case_id, r.stage, m.name, _result(m), m.unit, m.limitation)
                for r in selected_rows
                for m in r.metrics
                if m.name in PILOT_SNAPSHOT_METRICS
            ),
            "Formative evidence, repetition 1; paths and measurements are not additive",
        )
    output += (
        '</section><section id="actions"><h2>Evidence review actions</h2>'
        "<p>Topic membership identifies measurement rows needing interpretation, not unique "
        "issues or severity. A row may occur in multiple topics; counts must not be summed. "
        "Zero topic rows is not evidence of absence of risk.</p>"
    )
    for key, (title, action) in TOPICS.items():
        selected = [(i, row) for i, row in enumerate(report.rows) if key in review_topics(row)]
        output += f"<h3>{_text(title)}: {len(selected)} measurement rows</h3><p>{_text(action)}</p>"
        output += '<details><summary>Source rows</summary><div class="detail-body"><ul>'
        for index, row in selected:
            session_number = next(
                n + 1 for n, s in enumerate(plan.sessions) if s.session == row.session
            )
            output += (
                f'<li><a href="#row-{index}">'
                + _text(
                    f"Session {session_number} / {row.case_id} / {row.stage} / "
                    f"repetition {row.repetition} / {row.state}"
                )
                + "</a></li>"
            )
        output += "" if selected else "<li>No selected row triggers this topic.</li>"
        output += "</ul></div></details>"
    output += '</section><section id="sessions"><h2>Sessions and measurements</h2>'
    output += (
        "<p>Session order follows the frozen selection. Every stage and repetition is retained. "
        "Repetition 0 denotes shared accounting or a summary, not an additional execution. "
        "Unknown, "
        "undefined, not-applicable and measured zero remain distinct.</p><ol>"
    )
    for i, session in enumerate(plan.sessions):
        rows = [r for r in report.rows if r.session == session.session]
        attempts = [a for a in report.attempts if a.get("session") == session.session]
        output += (
            f'<li><a href="#session-{i}">Session {i + 1}: {_text(session.role)}</a>'
            f" | {len(rows)} measurement rows | {len(attempts)} attempt/cell records</li>"
        )
    output += "</ol></section>"
    for i, session in enumerate(plan.sessions):
        output += f'<section id="session-{i}"><h2>Session {i + 1}: {_text(session.role)}</h2>'
        output += _metadata(
            (
                ("Session identity", session.session),
                ("Original plan SHA-256", session.plan_sha256),
                ("Original validation SHA-256", session.validation_sha256),
            )
        )
        indexed_rows = [(n, r) for n, r in enumerate(report.rows) if r.session == session.session]
        if not indexed_rows:
            output += "<p>No measurement rows recorded for this selected session.</p>"
        for n, row in indexed_rows:
            output += _measurement(n, row)
        output += "</section>"
    output += '<section id="attempts"><h2>Attempt history and unattempted cells</h2>'
    output += (
        "<p>Original failures remain visible after recovery. These counts describe retained "
        "records, not current failures or independent experiments. Workflow completion does "
        "not establish complete security analysis. "
        "Missing values are not successful zero results.</p>"
    )
    states = sorted({str(a.get("state", "unknown")) for a in report.attempts})
    output += _table(
        ("Recorded state", "Attempt/cell records"),
        (
            (state, sum(str(a.get("state", "unknown")) == state for a in report.attempts))
            for state in states
        ),
        "Historical record counts (including retries and unattempted cells)",
    )
    for i, attempt in enumerate(report.attempts):
        output += (
            f'<details class="attempt"><summary>{i + 1}. '
            + _text(
                f"{attempt.get('case_id')} | {attempt.get('state')} | "
                f"repetition {attempt.get('repetition')}"
            )
            + '</summary><div class="detail-body">'
        )
        output += _metadata(
            (key.replace("_", " "), attempt.get(key))
            for key in (
                "session",
                "evidence_role",
                "plan_id",
                "case_id",
                "attempt_id",
                "cell_id",
                "ordinal",
                "repetition",
                "state",
                "scanner_invocations",
                "finding_records",
                "duration_ns",
                "error_kind",
            )
        )
        output += _details(f"Exact attempt/cell record /attempts/{i}", attempt) + "</div></details>"
    output += '</section><section id="reviews"><h2>Finding review provenance</h2>'
    output += (
        "<p>These are retained review summaries bound to their original reports. AI proposals "
        "are not human acceptance or independent accuracy labels. Declared identities are not "
        "authenticated; decisions do not transfer automatically to repetitions or new scans.</p>"
    )
    if not report.reviews:
        output += (
            "<p>No review sidecar was selected. Review status is unavailable, not accepted.</p>"
        )
    for i, review in enumerate(report.reviews):
        output += f"<h3>Review {i + 1}</h3>" + _metadata(
            (key.replace("_", " "), review.get(key))
            for key in (
                "pending_finding_occurrences",
                "human_decision_occurrences",
                "annotation_count",
                "identity_assurance",
                "scope",
                "report_manifest_sha256",
                "review_sha256",
            )
        )
        output += _details(f"Retained review summary /reviews/{i}", review)
    output += '</section><section id="evidence"><h2>Evidence and selected exports</h2>'
    output += _table(("Input file", "Bytes", "SHA-256"), input_files, "Validated scoring inputs")
    output += _details(
        "Historical scoring implementation references (not reopened)",
        [r.model_dump(mode="json") for r in report.analysis_sources],
    )
    output += '<ul><li><a href="html-manifest.json" download>HTML checksum manifest</a></li>'
    for key, name in exports.items():
        output += (
            f'<li><a href="evidence/{name}" download>{_text(key)}: {_text(name)}</a> '
            "(internal, unredacted)</li>"
        )
    output += (
        "</ul><p>Only explicitly selected scoring exports are copied. Original source paths "
        "and JSON pointers are text references, not executable links. Hashes establish "
        "recorded consistency, not independent attestation. No automatic redaction or "
        "public-release clearance is claimed.</p></section></main></div>"
        "<footer>agentsec-evidence | Offline benchmark presentation v1 | "
        "No scanners, target execution or network requests.</footer></body></html>"
    )
    raw = output.encode("utf-8")
    if len(raw) > MAX_HTML_BYTES:
        raise ValueError("Rendered benchmark exceeds byte budget; no rows were silently omitted")
    return raw
