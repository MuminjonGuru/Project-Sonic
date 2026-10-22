"""Offline HTML companion for proposed corpus reviews, never a scanner or approval service."""

# Keep self-contained HTML/CSS and report paragraphs intact; executable logic is formatted.
# ruff: noqa: E501

from __future__ import annotations

import argparse
import html
import re
from collections import Counter
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote

from corpus_report_v2 import encoded, manifest_for, read_report
from corpus_review_sampling import records, select
from pydantic import Field, StrictInt

from agentsec_evidence.agents.validation import canonical_artifact_path, load_agent_json
from agentsec_evidence.core.identity import canonical_json_bytes, sha256_bytes
from agentsec_evidence.core.io import atomic_write_bytes
from agentsec_evidence.models.contracts import Sha256
from agentsec_evidence.pilot.runner import save
from agentsec_evidence.reporting.html_styles import STYLES
from agentsec_evidence.research.models import ResearchModel
from agentsec_evidence.research.retained import (
    MAX_ENTRY_BYTES,
    RetainedManifest,
    bounded_file,
    plain_path,
    read_retained_research,
)

CONTRACT = "corpus-review-html-v1"
AUTHORSHIP = "AI-drafted source-context assessment; student review pending; no independent reviewer"
OUTCOMES = (
    "supported-static-condition",
    "claim-not-substantiated-as-worded",
    "inventory-only",
    "unresolved",
)
RELEVANCE = (
    "existing-control",
    "test-only",
    "trust-boundary-review",
    "routine-functionality",
    "identifier-only",
    "inventory-only",
)
REVIEW_FILES = {
    "reviews.json",
    "metrics.json",
    "README.md",
    "REVIEW.md",
    "CASE_STUDIES.md",
    "SOURCES.md",
    "verification.json",
}
QUEUE_FILES = {"queue.json", "population.json", "README.md"}


class Proposal(ResearchModel):
    proposed_outcome: Literal[
        "supported-static-condition",
        "claim-not-substantiated-as-worded",
        "inventory-only",
        "unresolved",
    ]
    contextual_relevance: Literal[
        "existing-control",
        "test-only",
        "trust-boundary-review",
        "routine-functionality",
        "identifier-only",
        "inventory-only",
    ]
    assessment: str = Field(min_length=1, max_length=16384)
    observed_controls: str = Field(min_length=1, max_length=16384)
    uncertainty: str = Field(min_length=1, max_length=16384)
    suggested_action: str = Field(min_length=1, max_length=16384)
    supplementary_ranges: tuple[tuple[str, StrictInt, StrictInt], ...] = Field(max_length=32)


class Citation(ResearchModel):
    candidate_id: str = Field(pattern=r"^R[0-9]{2}$")
    repository: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    path: str = Field(min_length=1, max_length=4096)
    source_sha256: Sha256
    start_line: StrictInt = Field(ge=1)
    end_line: StrictInt = Field(ge=1)
    excerpt: str = Field(max_length=1024 * 1024)
    url: str = Field(max_length=8192)


class ReviewRow(ResearchModel):
    review_id: str = Field(pattern=r"^Q[0-9]{2}$")
    frozen_record: dict[str, Any]
    proposal: Proposal
    citations: tuple[Citation, ...] = Field(min_length=1, max_length=33)
    overlap: dict[str, Any]
    policy_context: dict[str, Any]
    review_status: Literal["ai-proposed-student-review-pending"]
    authorship: Literal[
        "AI-drafted source-context assessment; student review pending; no independent reviewer"
    ]
    human_decision: None
    independent_review: None
    external_context_ids: tuple[str, ...] = Field(max_length=32)


def need(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def json_object(raw: bytes) -> dict[str, Any]:
    return load_agent_json(raw, max_bytes=MAX_ENTRY_BYTES)


def checksum_bundle(root: Path, names: set[str]) -> tuple[dict[str, bytes], str]:
    root = plain_path(root, directory=True)
    raw = bounded_file(root / "checksums.json", MAX_ENTRY_BYTES)
    value = json_object(raw)
    need(set(value) in ({"files"}, {"algorithm", "files"}), "Unknown checksum contract")
    need(value.get("algorithm", "sha256") == "sha256", "Wrong checksum algorithm")
    manifest = RetainedManifest.model_validate({"files": value["files"]})
    need({e.path for e in manifest.files} == names, "Input manifest membership differs")
    need({p.name for p in root.iterdir()} == names | {"checksums.json"}, "Unexpected input member")
    files = {}
    for entry in manifest.files:
        data = bounded_file(root / entry.path, entry.bytes)
        need(
            len(data) == entry.bytes and sha256_bytes(data) == entry.sha256,
            "Input checksum differs",
        )
        files[entry.path] = data
    return files, sha256_bytes(raw)


def line_bounds(record: dict[str, Any]) -> tuple[int, int]:
    location = record["identity"]["location"]
    start = location.get("start_line") or location.get("line")
    end = location.get("end_line") or start
    need(type(start) is int and type(end) is int and 1 <= start <= end, "Invalid finding location")
    return start, end


def overlaps(record: dict[str, Any], population: list[dict[str, Any]]) -> list[dict[str, Any]]:
    identity = record["identity"]
    start, end = line_bounds(record)
    result = []
    for other in population:
        oid = other["identity"]
        if (oid["candidate_id"], oid["source_path"]) != (
            identity["candidate_id"],
            identity["source_path"],
        ):
            continue
        if other["identity_sha256"] == record["identity_sha256"]:
            continue
        lo, hi = line_bounds(other)
        if max(start, lo) <= min(end, hi):
            result.append(
                {
                    "identity_sha256": other["identity_sha256"],
                    "producer": oid["producer"],
                    "rule_id": oid["rule_id"],
                    "location": oid["location"],
                }
            )
    return result


def policy_fields(record: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    producer = record["identity"]["producer"]
    if producer == "agent-audit-python":
        native = record["claim_record"]["native_extension"]["agent_audit"]
        return {
            "kind": "native-agent-audit",
            **{
                k: native.get(k)
                for k in (
                    "tier",
                    "confidence",
                    "suppressed",
                    "suppressed_by",
                    "suppressed_reason",
                    "needs_review",
                )
            },
        }
    if producer == "semgrep-research":
        evidence = report["observations"]["runs/r01/semgrep-policy"]["evidence"]
        return {
            "kind": "paired-semgrep-policy",
            "native_json_sha256": evidence["native_json_sha256"],
            "matching_anchor_records": [
                r for r in evidence["findings"] if r["anchor"] == record["claim_record"]["anchor"]
            ],
            "file_status": [
                r for r in evidence["files"] if r["path"] == record["identity"]["source_path"]
            ],
        }
    return {"kind": "custom-research-only"}


def verify_citations(row: ReviewRow, report: dict[str, Any], sources: Path) -> None:
    identity = row.frozen_record["identity"]
    candidate = report["candidate"]
    selected = {s["source"]["path"]: s["source"] for s in report["selected_inputs"]}
    start, end = line_bounds(row.frozen_record)
    first = row.citations[0]
    need(
        first.path == identity["source_path"]
        and first.start_line <= start <= end <= first.end_line,
        "Primary citation misses finding",
    )
    need(len(row.citations) == len(row.proposal.supplementary_ranges) + 1, "Citation count differs")
    need(
        [(c.path, c.start_line, c.end_line) for c in row.citations[1:]]
        == list(row.proposal.supplementary_ranges),
        "Supplementary ranges differ",
    )
    for c in row.citations:
        canonical_artifact_path(c.path)
        need(
            (c.candidate_id, c.repository, c.revision)
            == (candidate["candidate_id"], candidate["repository"], candidate["revision"]),
            "Citation repository binding differs",
        )
        need(
            c.path in selected and c.source_sha256 == selected[c.path]["sha256"],
            "Citation input binding differs",
        )
        raw = bounded_file(sources / c.candidate_id / "prepared/source" / c.path, MAX_ENTRY_BYTES)
        need(sha256_bytes(raw) == c.source_sha256, "Cited source bytes differ")
        lines = raw.decode("utf-8-sig").splitlines()
        need(c.start_line <= c.end_line <= len(lines), "Citation range exceeds source")
        need(c.excerpt == "\n".join(lines[c.start_line - 1 : c.end_line]), "Cited excerpt differs")
        url = f"https://github.com/{c.repository}/blob/{c.revision}/{quote(c.path, safe='/')}#L{c.start_line}-L{c.end_line}"
        need(c.url == url, "Citation link differs from pinned source")


def derive_counts(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "review_proposals": len(rows),
        "student_accepted": 0,
        "independently_reviewed": 0,
        "proposed_outcomes": dict(Counter(r["proposal"]["proposed_outcome"] for r in rows)),
        "contextual_relevance": dict(Counter(r["proposal"]["contextual_relevance"] for r in rows)),
        "producers": dict(Counter(r["frozen_record"]["identity"]["producer"] for r in rows)),
        "frozen_path_roles": dict(Counter(r["frozen_record"]["path_role"] for r in rows)),
        "reviewed_repositories": len(
            {r["frozen_record"]["identity"]["candidate_id"] for r in rows}
        ),
        "agent_audit_native_tiers": dict(
            Counter(
                r["policy_context"]["tier"]
                for r in rows
                if r["policy_context"]["kind"] == "native-agent-audit"
            )
        ),
        "semgrep_policy_matching_selected_anchors": sum(
            len(r["policy_context"]["matching_anchor_records"])
            for r in rows
            if r["policy_context"]["kind"] == "paired-semgrep-policy"
        ),
        "records_with_overlap_candidates": sum(bool(r["overlap"]["candidates"]) for r in rows),
        "unique_vulnerabilities": None,
        "precision": None,
        "recall": None,
    }


def bind_reviews(
    document: dict[str, Any],
    queue: dict[str, Any],
    reports: dict[str, dict[str, Any]],
    sources: Path,
) -> dict[str, Any]:
    """Validate evidence references, not the correctness or acceptance of reviewer reasoning."""
    need(document.get("contract") == "corpus-source-context-review-v1", "Wrong review contract")
    need(document.get("authorship") == AUTHORSHIP, "Wrong review provenance")
    need(queue.get("contract") == "local-descriptive-review-queue-v1", "Wrong queue contract")
    population = [record for report in reports.values() for record in records(report)]
    frozen = select(population)
    need(queue["records"] == frozen, "Queue selection differs from frozen sampling protocol")
    need(0 < len(document["rows"]) == len(frozen) <= 80, "Review sample membership differs")
    for number, (raw, expected) in enumerate(zip(document["rows"], frozen, strict=True), 1):
        row = ReviewRow.model_validate(raw)
        need(row.review_id == f"Q{number:02}", "Review order differs")
        need(row.frozen_record == expected, "Original record differs from retained evidence")
        need(
            expected["identity_sha256"] == sha256_bytes(canonical_json_bytes(expected["identity"])),
            "Finding identity differs",
        )
        report = reports[expected["identity"]["candidate_id"]]
        verify_citations(row, report, sources)
        policy = {k: v for k, v in row.policy_context.items() if k != "interpretation"}
        need(policy == policy_fields(expected, report), "Native policy fields differ")
        need(
            set(row.overlap)
            == {"candidates", "relation", "rationale", "merge_applied", "suppression_applied"},
            "Unknown overlap fields",
        )
        need(
            row.overlap["merge_applied"] is False and row.overlap["suppression_applied"] is False,
            "Review cannot merge or suppress",
        )
        need(
            row.overlap["candidates"] == overlaps(expected, population), "Overlap candidates differ"
        )
    counts = derive_counts(document["rows"])
    counts["population_records"] = len(population)
    for key, value in counts.items():
        need(document["metrics"].get(key) == value, "Review metrics differ: " + key)
    return counts


def inputs(
    review: Path, queue_root: Path, reports_root: Path, sources: Path, protocol: Path
) -> tuple[dict[str, Any], dict[str, bytes]]:
    review_files, review_hash = checksum_bundle(review, REVIEW_FILES)
    queue_files, queue_hash = checksum_bundle(queue_root, QUEUE_FILES)
    document = json_object(review_files["reviews.json"])
    queue = json_object(queue_files["queue.json"])
    report_root = plain_path(reports_root, directory=True)
    sources = plain_path(sources, directory=True)
    bindings = document["frozen_inputs"]
    for name in ("queue", "population"):
        need(
            bindings[f"{name}_sha256"] == sha256_bytes(queue_files[f"{name}.json"]),
            "Frozen input binding differs",
        )
    protocol_hash = sha256_bytes(bounded_file(protocol, MAX_ENTRY_BYTES))
    need(
        bindings["protocol_sha256"] == queue["protocol_sha256"] == protocol_hash,
        "Protocol binding differs",
    )
    for name in ("status", "results"):
        need(
            sha256_bytes(bounded_file(report_root / f"{name}.json", MAX_ENTRY_BYTES))
            == queue[f"source_{name}_sha256"],
            "Collection binding differs",
        )
    reports = {}
    for key, digest in queue["source_manifests"].items():
        need(re.fullmatch(r"R[0-9]{2}", key) is not None, "Invalid candidate key")
        need(
            sha256_bytes(
                bounded_file(report_root / key / "evidence-manifest.json", MAX_ENTRY_BYTES)
            )
            == digest,
            "Report manifest binding differs",
        )
        reports[key] = read_report(report_root / key)
        need(reports[key]["candidate"]["candidate_id"] == key, "Candidate identity differs")
    population = [r for report in reports.values() for r in records(report)]
    need(
        json_object(queue_files["population.json"])["records"] == population,
        "Population differs from reports",
    )
    counts = bind_reviews(document, queue, reports, sources)
    need(json_object(review_files["metrics.json"]) == document["metrics"], "Metrics export differs")
    projection = {
        "contract": CONTRACT,
        "authorship": AUTHORSHIP,
        "distribution": "internal-unredacted",
        "review_source_sha256": sha256_bytes(review_files["reviews.json"]),
        "queue_source_sha256": sha256_bytes(queue_files["queue.json"]),
        "review_checksum_manifest_sha256": review_hash,
        "queue_checksum_manifest_sha256": queue_hash,
        "protocol_sha256": protocol_hash,
        "report_manifests": queue["source_manifests"],
        "metrics": counts,
        "rows": document["rows"],
        "repositories": [
            {
                "candidate": r["candidate"],
                "selected_python_files": len(r["selected_inputs"]),
                "core_input_gates": r["core_input_gates"],
                "review_proposals": sum(
                    x["frozen_record"]["identity"]["candidate_id"] == key for x in document["rows"]
                ),
            }
            for key, r in reports.items()
        ],
        "verification": {
            "report_derivatives": "reconstructed",
            "source_citations": "rehashed-and-excerpts-checked",
            "native_replay": "not-performed",
            "scanner_invocations": 0,
            "target_execution": False,
            "human_approval": "not-recorded",
            "independent_review": "not-recorded",
        },
    }
    return projection, {
        "inputs/reviews.json": review_files["reviews.json"],
        "inputs/queue.json": queue_files["queue.json"],
    }


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def page(title: str, content: str, *, detail: bool = False) -> bytes:
    nav = (
        '<a href="../report.html">All reviews</a>'
        if detail
        else '<a href="#reviews">Review register</a><a href="#scope">Repository scope</a><a href="#evidence">Evidence</a>'
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        "style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
        '<meta name="referrer" content="no-referrer"><title>'
        + esc(title)
        + "</title><style>"
        + STYLES
        + "main{max-width:1260px;margin:auto}nav{display:flex;gap:20px;flex-wrap:wrap;border-right:0;border-bottom:1px solid var(--line);padding:12px 5%}nav a{display:inline-block}.small{font-size:13px}.numbers{display:flex;gap:36px;flex-wrap:wrap;padding:16px 0}.numbers strong{display:block;font-size:24px}.source{white-space:pre-wrap}header h1{font-size:28px}</style></head><body>"
        '<a class="skip" href="#main">Skip to content</a><header><div class="eyebrow">STATIC EVIDENCE / CONTEXT REVIEW</div><h1>'
        + esc(title)
        + "</h1><p>Internal, unredacted. AI-drafted assessments; student review pending. No independent approval.</p></header><nav>"
        + nav
        + '</nav><main id="main">'
        + content
        + "</main><footer>Source-level observations are not confirmed vulnerabilities. No findings were removed, merged or suppressed by this review.</footer></body></html>"
    ).encode()


def table(headers: list[str], rows: list[list[str]]) -> str:
    return (
        '<div class="table-wrap"><table><thead><tr>'
        + "".join('<th scope="col">' + esc(h) + "</th>" for h in headers)
        + "</tr></thead><tbody>"
        + "".join("<tr>" + "".join("<td>" + c + "</td>" for c in row) + "</tr>" for row in rows)
        + "</tbody></table></div>"
    )


def native_policy(row: dict[str, Any]) -> str:
    policy = row["policy_context"]
    if policy["kind"] == "native-agent-audit":
        return f"Tier {policy['tier']}; explicit suppressed={policy['suppressed']}; native confidence={policy['confidence']} (uncalibrated)"
    if policy["kind"] == "paired-semgrep-policy":
        states = ", ".join(f["state"] for f in policy["file_status"]) or "unknown"
        return f"Policy-view matching anchors: {len(policy['matching_anchor_records'])}; file: {states}"
    return "Research-only custom observation; no suppression treatment"


def overview(report: dict[str, Any]) -> bytes:
    counts = report["metrics"]
    body = (
        '<section><h2>Review status</h2><div class="numbers">'
        + "".join(
            f"<div><strong>{esc(counts[k])}</strong>{esc(label)}</div>"
            for k, label in (
                ("review_proposals", "draft assessments"),
                ("reviewed_repositories", "repositories in sample"),
                ("student_accepted", "student accepted"),
                ("independently_reviewed", "independently reviewed"),
            )
        )
        + "</div>"
    )
    body += '<p class="notice">The sample evaluates exact claim wording. Supported syntax can still be routine or test-only. These counts are not precision, confirmed vulnerabilities or a ranking of scanners.</p>'
    body += table(
        ["Proposed outcome", "Records"],
        [[esc(k), esc(counts["proposed_outcomes"].get(k, 0))] for k in OUTCOMES],
    )
    body += "<p>Native actionability tier and explicit suppression are different fields. SUPPRESSED-tier observations remain evidence, not ordinary presented alerts. An absent policy-view finding is not proof of safety.</p></section>"
    body += '<section id="reviews"><h2>Review register</h2>'
    rows = []
    for row in report["rows"]:
        identity, proposal = row["frozen_record"]["identity"], row["proposal"]
        rows.append(
            [
                f'<a href="reviews/{row["review_id"]}.html">{row["review_id"]}</a>',
                esc(identity["candidate_id"]) + "<br>" + esc(identity["source_path"]),
                esc(identity["producer"]) + "<br>" + esc(identity["rule_id"]),
                esc(proposal["proposed_outcome"])
                + '<br><span class="muted">'
                + esc(proposal["contextual_relevance"])
                + "</span>",
                esc(native_policy(row)),
            ]
        )
    body += (
        table(
            ["Review", "Source", "Producer / rule", "Draft assessment", "Native policy context"],
            rows,
        )
        + "</section>"
    )
    body += '<section id="scope"><h2>Repository scope</h2><p>Zero sampled reviews does not mean zero findings or complete review. Input eligibility is not analysis completeness. Unsupported baselines remain outside paired comparisons; optional dependency, MCP JSON and IaC stages are not part of this Python-core table.</p>'
    rows = []
    for r in report["repositories"]:
        c = r["candidate"]
        gates = "<br>".join(
            esc(g["stage"])
            + ": "
            + esc(g["state"])
            + ("; " + esc("; ".join(g["reasons"])) if g["reasons"] else "")
            for g in r["core_input_gates"]
        )
        rows.append(
            [
                esc(c["candidate_id"]) + "<br>" + esc(c["repository"]),
                "<code>" + esc(c["revision"]) + "</code><br>" + esc(c["role"]),
                esc(r["selected_python_files"]),
                esc(r["review_proposals"]),
                gates,
            ]
        )
    body += (
        table(
            [
                "Repository",
                "Pinned revision / role",
                "Python files",
                "Draft reviews",
                "Input gates",
            ],
            rows,
        )
        + "</section>"
    )
    body += '<section id="evidence"><h2>Evidence and limits</h2><p>All source citations were rehashed against pinned selected inputs. The report derivatives and frozen sample were reconstructed; native scanner execution was not replayed. Source interpretation and overlap grouping remain reviewer proposals.</p><ul><li><a href="inputs/reviews.json">Original review JSON</a> (byte-identical)</li><li><a href="inputs/queue.json">Frozen pending queue</a> (byte-identical)</li><li><a href="report.json">Companion data and bindings</a></li><li><a href="evidence-manifest.json">SHA-256 manifest</a></li></ul><p>This portable companion contains selected findings and source excerpts, not the complete native report collection. No external resource loads or scanner launches occur. Redistribution requires a separate review.</p></section>'
    return page("Corpus review companion", body)


def detail(row: dict[str, Any]) -> bytes:
    identity, proposal = row["frozen_record"]["identity"], row["proposal"]
    body = "<section><h2>" + esc(identity["rule_id"]) + '</h2><dl class="metadata">'
    for label, value in (
        ("Repository", row["citations"][0]["repository"]),
        ("Revision", identity["revision"]),
        ("Source", identity["source_path"]),
        ("Frozen path role", row["frozen_record"]["path_role"]),
        ("Proposed outcome", proposal["proposed_outcome"]),
        ("Context", proposal["contextual_relevance"]),
        ("Review state", "AI proposal; student review pending"),
        ("Finding identity", row["frozen_record"]["identity_sha256"]),
        ("Native evidence", row["frozen_record"]["evidence_key"]),
    ):
        body += "<dt>" + esc(label) + "</dt><dd>" + esc(value) + "</dd>"
    body += '</dl><p class="notice">This assessment does not change the original scanner finding, establish exploitability or record human approval.</p></section>'
    body += "<section><h2>Contextual assessment</h2>"
    for label, key in (
        ("Observed condition", "assessment"),
        ("Existing controls and context", "observed_controls"),
        ("What remains unknown", "uncertainty"),
        ("Suggested verification", "suggested_action"),
    ):
        body += "<h3>" + esc(label) + '</h3><p class="source">' + esc(proposal[key]) + "</p>"
    body += (
        "</section><section><h2>Native policy and overlap</h2><p>"
        + esc(native_policy(row))
        + "</p><pre>"
        + esc(encoded(row["policy_context"]).decode())
        + "</pre><p>"
        + esc(row["overlap"]["rationale"])
        + "</p><pre>"
        + esc(encoded(row["overlap"]).decode())
        + "</pre></section>"
    )
    body += "<section><h2>Source evidence</h2>"
    for c in row["citations"]:
        body += (
            "<h3>"
            + esc(c["path"])
            + '</h3><p><a rel="noreferrer noopener" href="'
            + esc(c["url"])
            + '">Pinned source, lines '
            + esc(c["start_line"])
            + "-"
            + esc(c["end_line"])
            + '</a></p><p class="small">SHA-256: <code>'
            + esc(c["source_sha256"])
            + "</code></p><pre>"
            + esc(
                "\n".join(
                    f"{n}: {line}"
                    for n, line in enumerate(c["excerpt"].splitlines(), c["start_line"])
                )
            )
            + "</pre>"
        )
    body += (
        "</section><section><h2>Unchanged finding snapshot</h2><p>The JSON below preserves the selected original claim, including native severity and confidence where provided. It is a projection of retained evidence, not the full native file.</p><pre>"
        + esc(encoded(row["frozen_record"]).decode())
        + '</pre><p><a href="'
        + row["review_id"]
        + '.json">This review record as JSON</a></p></section>'
    )
    return page(row["review_id"] + " / " + identity["candidate_id"], body, detail=True)


def package(report: dict[str, Any], exports: dict[str, bytes]) -> dict[str, bytes]:
    files = {**exports, "report.json": encoded(report), "report.html": overview(report)}
    for row in report["rows"]:
        # IDs passed strict validation; no source path becomes a local output path.
        files[f"reviews/{row['review_id']}.html"] = detail(row)
        files[f"reviews/{row['review_id']}.json"] = encoded(row)
    manifest_for(files)
    return files


def execute(
    mode: str, review: Path, queue: Path, reports: Path, sources: Path, protocol: Path, output: Path
) -> dict[str, Any]:
    projection, exports = inputs(review, queue, reports, sources, protocol)
    expected = package(projection, exports)
    output = output.absolute()
    for root in (review, queue, reports, sources):
        base = plain_path(root, directory=True)
        need(
            not output.is_relative_to(base) and not base.is_relative_to(output),
            "Output overlaps source evidence",
        )
    if mode == "write":
        plain_path(output.parent, directory=True)
        need(not output.exists(), "Use a fresh companion directory")
        output.mkdir()
        for name, raw in expected.items():
            atomic_write_bytes(output / name, raw)
        save(output / "evidence-manifest.json", manifest_for(expected))
    need(
        read_retained_research(output).files == expected,
        "Companion differs from bound input projection",
    )
    return {
        "contract": CONTRACT,
        "passed": True,
        "review_proposals": len(projection["rows"]),
        "files": len(expected),
        "scanner_invocations": 0,
        "fresh_native_replay": False,
        "human_approval": False,
        "independent_attestation": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("write", "verify"))
    for name in ("review", "queue", "reports", "sources", "protocol", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    print(encoded(execute(**vars(args))).decode())


if __name__ == "__main__":
    main()
