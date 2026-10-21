"""Write-once, reproducible offline tables over pinned governed sessions."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from agentsec_evidence.benchmarks.attempts import replay_retained_history
from agentsec_evidence.benchmarks.dependency_plan import ADMITTED_PINS, ORACLE
from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.reporting.service import require_new_derivative
from agentsec_evidence.research.retained import bounded_file, plain_path
from agentsec_evidence.reviews.service import validate_review
from agentsec_evidence.scoring.calculations import count, ratio
from agentsec_evidence.scoring.measurements import Context, dependency_rows, source_rows
from agentsec_evidence.scoring.models import Reference, ScoreManifest, ScorePlan, ScoreReport

MAX_BYTES = 32 * 1024**2
FILES = {"plan.json", "scores.json", "measurements.csv", "attempts.csv", "TABLES.md", "SUMMARY.md"}


def _json(path: Path) -> Any:
    return json.loads(bounded_file(path, MAX_BYTES))


def _ref(project: Path, path: Path, pointer: str = "") -> Reference:
    plain_path(path, directory=False)
    return Reference(
        path=path.relative_to(project).as_posix(), sha256=sha256_file(path), pointer=pointer
    )


def calculate_scores(project: Path, plan_path: Path) -> ScoreReport:
    project = plain_path(project, directory=True)
    raw = bounded_file(plan_path, MAX_BYTES)
    plan = ScorePlan.model_validate_json(raw)
    source_refs = tuple(_ref(project, p) for p in sorted((project / "src").rglob("*.py")))
    rows = []
    attempts: list[dict[str, Any]] = []
    review_results: list[dict[str, Any]] = []
    for request in plan.sessions:
        session = project / "workspace/benchmarks" / request.session
        frozen, preview, history = replay_retained_history(
            project,
            session,
            plan_sha256=request.plan_sha256,
            validation_sha256=request.validation_sha256,
        )
        pilot = frozen.contract == "benchmark-public-pilot-plan-v1"
        if (request.role == "formative-pilot") != pilot:
            raise ValueError("Evidence role differs from the frozen treatment")
        refs = (_ref(project, session / "plan.json"), _ref(project, session / "validation.json"))
        semantic_groups: dict[str, list[tuple[Context, str | None]]] = {}
        for ordinal, row in enumerate(history.attempts, 1):
            folder = session / "attempts" / f"{ordinal:04d}_{row.attempt_id}"
            start = _json(folder / "start.json")
            finish_path = folder / "finish.json"
            finish = _json(finish_path) if finish_path.exists() else None
            evidence = finish.get("evidence") if finish else None
            rowrefs = (
                *refs,
                _ref(project, folder / "start.json"),
                *((_ref(project, finish_path),) if finish else ()),
            )
            ctx = Context(
                project,
                request.session,
                row.case_id,
                request.role,
                str(row.attempt_id),
                row.repetition,
                rowrefs,
            )
            item = row.model_dump(mode="json")
            item.update(
                {
                    "session": request.session,
                    "plan_id": frozen.plan_id,
                    "evidence_role": request.role,
                    "ordinal": ordinal,
                    "retry": start.get("retry"),
                    "duration_ns": finish.get("duration_ns") if finish else None,
                    "error_kind": finish.get("error_kind") if finish else None,
                    "references": [r.model_dump(mode="json") for r in rowrefs],
                }
            )
            attempts.append(item)
            rows.append(
                ctx.row(
                    "attempt-ledger",
                    row.state,
                    [
                        count(
                            "scanner-invocations",
                            row.scanner_invocations,
                            "process-invocations",
                            "Null means unverified; validation workers are separate.",
                        ),
                        count(
                            "attempt-wall-time",
                            item["duration_ns"],
                            "nanoseconds",
                            "Historical measured duration, not analyst time or a "
                            "controlled performance comparison.",
                        ),
                        count(
                            "human-review-time",
                            None,
                            "nanoseconds",
                            "Not measured retrospectively.",
                        ),
                    ],
                    {
                        "retry": start.get("retry"),
                        "verified_terminal_attempt": row.verified_terminal_attempt,
                        "error_kind": item["error_kind"],
                    },
                    (),
                    analysis="not-run"
                    if row.scanner_invocations == 0
                    else "incomplete"
                    if row.state
                    in {"interrupted", "execution-failed", "unsupported", "partial-analysis"}
                    else "not-established",
                )
            )
            semantic_groups.setdefault(row.case_id, []).append(
                (ctx, evidence.get("semantic_sha256") if evidence else None)
            )
            if not evidence:
                continue
            execution = folder / "execution"
            if pilot:
                rows.extend(source_rows(ctx, execution / "pilot"))
            elif frozen.contract == "benchmark-research-plan-v1":
                rows.extend(source_rows(ctx, execution / "case" / row.case_id))
            elif frozen.contract.startswith("benchmark-dependency"):
                dep_root = execution / "dependency-runs" / evidence["run_id"]
                if (dep_root / "manifest.json").is_file():
                    oracle = None
                    if (
                        row.case_id == "dev-dependency-basic-v1"
                        and frozen.contract == "benchmark-dependency-plan-v1"
                    ):
                        oracle = project / ORACLE
                        if sha256_file(oracle) != ADMITTED_PINS[ORACLE]:
                            raise ValueError("Approved finite oracle changed")
                    rows.extend(dependency_rows(ctx, dep_root, row.repetition, oracle=oracle))
            else:
                root = execution / "runs" / evidence["run_id"]
                if (root / "bundle-manifest.json").is_file():
                    cell = next(c for c in preview.cells if c.cell_id == row.cell_id)
                    expectation = getattr(cell, "expectation", None)
                    rows.extend(
                        source_rows(
                            ctx,
                            root,
                            expectation=expectation.model_dump(mode="json")
                            if expectation
                            else None,
                        )
                    )
        for case, observations in semantic_groups.items():
            if pilot:
                continue
            hashes = [digest for _, digest in observations]
            repetitions = [ctx.repetition for ctx, _ in observations]
            comparable = (
                len(hashes) >= 2
                and len(set(repetitions)) == len(repetitions)
                and all(h is not None for h in hashes)
            )
            context = observations[0][0]
            rows.append(
                context.row(
                    "case-repeatability",
                    "observed" if comparable else "not-comparable",
                    [
                        ratio(
                            "semantic-agreement-to-first",
                            sum(h == hashes[0] for h in hashes[1:]) if comparable else None,
                            len(hashes) - 1,
                            unit="within-treatment-repeat-comparisons",
                            eligibility=(
                                "Distinct planned repetitions; recovery attempts are not repeats"
                            ),
                            unknown=0 if comparable else None,
                            limitation=(
                                "One source family, not independent samples. "
                                "Missing semantics and retries remain "
                                "unscored."
                            ),
                        )
                    ],
                    {"semantic_hashes": hashes, "case": case, "planned_repetitions": repetitions},
                    tuple(ref for c, _ in observations[1:] for ref in c.references),
                    repetition=0,
                )
            )
        attempted = {r.cell_id for r in history.rows}
        attempts.extend(
            {
                "session": request.session,
                "plan_id": frozen.plan_id,
                "evidence_role": request.role,
                "case_id": cell.case_id,
                "repetition": cell.repetition,
                "state": "not-attempted",
                "attempt_id": None,
                "finding_records": None,
                "scanner_invocations": None,
                "references": [r.model_dump(mode="json") for r in refs],
            }
            for cell in preview.cells
            if cell.cell_id not in attempted
        )
    for review_input in plan.reviews:
        report = plain_path(project / review_input.report, directory=True)
        review = plain_path(project / review_input.review, directory=True)
        previous = (
            plain_path(project / review_input.previous, directory=True)
            if review_input.previous
            else None
        )
        if (
            sha256_file(report / "report-manifest.json") != review_input.report_manifest_sha256
            or sha256_file(review / "review-manifest.json") != review_input.review_manifest_sha256
        ):
            raise ValueError("Pinned review/report manifest changed")
        result = validate_review(
            project=project, report_root=report, root=review, previous=previous
        )
        review_results.append(
            {
                **result,
                "report": review_input.report,
                "review": review_input.review,
                "scope": (
                    "Exact historical report occurrences only; no automatic transfer "
                    "to repeated scans or accuracy labels"
                ),
                "references": [
                    _ref(project, p).model_dump(mode="json")
                    for p in (
                        report / "report-manifest.json",
                        review / "review-manifest.json",
                        review / "review.json",
                    )
                ],
            }
        )
    all_refs = {ref.path: ref for row in rows for ref in row.references}
    for ref in (*source_refs, *all_refs.values()):
        if sha256_file(project / ref.path) != ref.sha256:
            raise ValueError("Scoring source changed during calculation")
    if bounded_file(plan_path, MAX_BYTES) != raw:
        raise ValueError("Scoring plan changed during calculation")
    return ScoreReport(
        plan_sha256=sha256_bytes(raw),
        analysis_sources=source_refs,
        rows=tuple(rows),
        attempts=tuple(attempts),
        reviews=tuple(review_results),
        limitations=(
            "Retained evidence replay; no scanners, target code, Docker API or "
            "network launched by scoring.",
            "Hashes verify recorded consistency, not independent attestation or academic approval.",
            "Development and one formative public pilot are not held-out evaluation "
            "or population estimates.",
            "No pooled vulnerability total, public accuracy, risk score or inferred "
            "analyst productivity.",
            "Field retention measures the explicit normalized-to-export rubric, not "
            "all native semantics or claim correctness.",
            "Known missing native confidence/description/remediation exports remain "
            "available in original normalized/native evidence.",
            "Dependency identity projection excludes source qualifiers, occurrences "
            "and relationship fidelity; these limits remain explicit.",
            "Review sidecars remain tied to their original report; AI proposals are "
            "not independent labels.",
            "Original-path historical replay does not authorize execution with "
            "changed implementation or claim independent-machine reproduction.",
        ),
    )


def _csv(headers: list[str], records: list[dict[str, Any]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=headers, lineterminator="\n", extrasaction="ignore")
    writer.writeheader()
    for record in records:
        safe = {}
        for key in headers:
            value = record.get(key)
            text = (
                ""
                if value is None
                else json.dumps(value, sort_keys=True, ensure_ascii=True)
                if isinstance(value, (dict, list, tuple))
                else str(value)
            )
            # CSV is a display derivative; prevent formula execution in spreadsheet viewers.
            safe[key] = "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text
        writer.writerow(safe)
    return stream.getvalue().encode("utf-8")


def _md(value: object) -> str:
    return (
        str(value)
        .replace("|", "\\|")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", " ")
        .replace("\r", " ")
    )


def render_tables(report: ScoreReport) -> bytes:
    lines = [
        "# Offline Evidence-Quality Tables",
        "",
        "Retained development/formative evidence. No new scans; no public accuracy "
        "or overall safety score.",
        "",
        "## Attempt Ledger",
        "",
        "| Plan | Case | Repeat | State | Scanner invocations |",
        "|---|---|---:|---|---:|",
    ]
    lines.extend(
        "| "
        + " | ".join(
            _md(a.get(k) if a.get(k) is not None else "unknown")
            for k in ("plan_id", "case_id", "repetition", "state", "scanner_invocations")
        )
        + " |"
        for a in report.attempts
    )
    lines += [
        "",
        "## Measurements",
        "",
        "Every row links to the exact retained evidence; complete machine-readable "
        "details are in scores.json and measurements.csv.",
        "",
    ]
    for row in report.rows:
        lines += [
            f"### {_md(row.case_id)} / {_md(row.stage)} / repetition {row.repetition}",
            "",
            f"State: {_md(row.state)}. Analysis completeness: {row.analysis_completeness}. "
            f"Role: {row.evidence_role}.",
            "",
            "| Metric | Result | Unit | Limitation |",
            "|---|---|---|---|",
        ]
        for m in row.metrics:
            value = (
                f"{m.numerator}/{m.denominator}"
                if m.denominator is not None and m.numerator is not None
                else str(m.numerator)
                if m.status == "measured"
                else m.status
            )
            lines.append(f"| {_md(m.name)} | {value} | {_md(m.unit)} | {_md(m.limitation)} |")
        for ref in row.references:
            lines.append(
                f"- Evidence: `{ref.path}{'#' + ref.pointer if ref.pointer else ''}`; "
                f"SHA-256 `{ref.sha256}`."
            )
    lines += ["", "## Review Status", ""]
    for review in report.reviews:
        lines.append(
            f"- {review['pending_finding_occurrences']} pending proposals; "
            f"{review['human_decision_occurrences']} recorded human decisions. "
            f"{_md(review['scope'])}."
        )
    lines += ["", "## Limits", "", *(f"- {line}" for line in report.limitations)]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _outputs(report: ScoreReport, raw_plan: bytes) -> dict[str, bytes]:
    records: list[dict[str, Any]] = []
    for row in report.rows:
        base = row.model_dump(mode="json", exclude={"metrics", "observations"})
        records.extend({**base, **metric.model_dump(mode="json")} for metric in row.metrics)
    return {
        "plan.json": raw_plan,
        "scores.json": json_bytes(report.model_dump(mode="json")),
        "measurements.csv": _csv(
            [
                "session",
                "case_id",
                "evidence_role",
                "attempt_id",
                "repetition",
                "stage",
                "state",
                "analysis_completeness",
                "name",
                "status",
                "numerator",
                "denominator",
                "value",
                "unit",
                "eligibility",
                "excluded",
                "unknown",
                "version",
                "limitation",
                "references",
            ],
            records,
        ),
        "attempts.csv": _csv(
            [
                "session",
                "plan_id",
                "evidence_role",
                "case_id",
                "repetition",
                "ordinal",
                "attempt_id",
                "state",
                "verified_terminal_attempt",
                "scanner_invocations",
                "duration_ns",
                "error_kind",
                "retry",
                "references",
            ],
            list(report.attempts),
        ),
        "TABLES.md": render_tables(report),
        "SUMMARY.md": render_summary(report),
    }


def render_summary(report: ScoreReport) -> bytes:
    """A readable entry point; full rows retain every repetition, denominator and pointer."""
    lines = [
        "# Evidence-Quality Review",
        "",
        "Offline replay of selected retained development sessions and one formative public pilot.",
        "This is not a new scan, final evaluation, vulnerability count or independent review.",
        "",
        "Full evidence: [tables](TABLES.md), [JSON](scores.json), "
        "[measurements](measurements.csv), [all attempts](attempts.csv).",
        "",
        "## Public Pilot: First Repetition",
        "",
        "The other repetitions remain separate in the full tables. "
        "Reported coverage is not proof of completed security analysis.",
        "",
        "| Stage | Measurement | Result | Meaning |",
        "|---|---|---|---|",
    ]
    chosen = {
        "reported-path-coverage",
        "native-rule-reports",
        "native-aggregate-files",
        "normalized-to-sarif-field-retention",
        "reported-package-advisory-pairs",
        "package-projection-retention",
        "source-qualifier-losses",
    }
    for row in report.rows:
        if row.evidence_role != "formative-pilot" or row.repetition != 1:
            continue
        for m in row.metrics:
            if m.name not in chosen or m.status == "not-applicable":
                continue
            value = f"{m.numerator}/{m.denominator}" if m.denominator else str(m.numerator)
            lines.append(f"| {_md(row.stage)} | {_md(m.name)} | {value} | {_md(m.limitation)} |")
    lines += ["", "## Repeatability", ""]
    for row in report.rows:
        if row.evidence_role == "formative-pilot" and row.stage.startswith("repeatability-"):
            m = row.metrics[0]
            lines.append(
                f"- {row.stage}: {m.numerator}/{m.denominator} comparisons agree. "
                "One repository, not independent samples."
            )
    lines += ["", "## Development Checks and Failures", ""]
    for state in sorted({str(a["state"]) for a in report.attempts}):
        total = sum(a["state"] == state for a in report.attempts)
        lines.append(
            f"- {state}: {total} attempt/cell rows. "
            "Terminal workflow state does not establish complete security analysis."
        )
    selected = {"finite-match-precision", "finite-match-recall", "finite-rule-path-agreement"}
    lines += ["", "| Case | Stage | Repeat | Check | Result |", "|---|---|---:|---|---|"]
    for row in report.rows:
        for m in row.metrics:
            if m.name in selected:
                value = f"{m.numerator}/{m.denominator}" if m.status == "measured" else m.status
                lines.append(
                    f"| {_md(row.case_id)} | {_md(row.stage)} | {row.repetition} "
                    f"| {m.name} | {value} |"
                )
    lines += [
        "",
        "These are finite authored engineering expectations, not independently "
        "reviewed public vulnerability labels. Refusals, missing data and errors are unscored.",
        "",
        "## Limits and Review",
        "",
    ]
    for review in report.reviews:
        lines.append(
            f"- {review['pending_finding_occurrences']} pending finding occurrences; "
            f"{review['human_decision_occurrences']} recorded human decisions. "
            "Review remains bound to its original report, not transferred to new runs."
        )
    lines += [
        "- Unknown-version native advisories are not exact package-version matches.",
        "- Original native and normalized records remain available despite export omissions.",
        "- Relationship/occurrence fidelity and per-package matching completion remain unproven.",
        "- Human preparation/review time and productivity improvement are not measured.",
        "- The next decision is usefulness/refinement review, not a new scanner or a safety score.",
    ]
    return ("\n".join(lines) + "\n").encode()


def write_scores(project: Path, plan_path: Path, output: Path) -> ScoreReport:
    raw = bounded_file(plan_path, MAX_BYTES)
    plan = ScorePlan.model_validate_json(raw)
    protected = [project / "workspace/benchmarks" / s.session for s in plan.sessions]
    protected.extend(
        project / path for r in plan.reviews for path in (r.report, r.review, r.previous) if path
    )
    destination = require_new_derivative(output, protected)
    for parent in (destination, *destination.parents):
        if parent.exists():
            plain_path(parent, directory=True)
        if any(
            (parent / name).exists()
            for name in ("scoring-manifest.json", "review-manifest.json", "validation.json")
        ):
            raise ValueError("Scoring output cannot modify finalized evidence or sessions")
    report = calculate_scores(project, plan_path)
    if report.plan_sha256 != sha256_bytes(raw):
        raise ValueError("Scoring plan changed before publication")
    files = _outputs(report, raw)
    destination.mkdir(parents=True, exist_ok=False)
    for name, data in files.items():
        with (destination / name).open("xb") as handle:
            handle.write(data)
    manifest: Any = {
        "contract": "evidence-scoring-manifest-v1",
        "entries": [
            {"path": name, "sha256": sha256_bytes(data), "bytes": len(data)}
            for name, data in sorted(files.items())
        ],
    }
    with (destination / "scoring-manifest.json").open("xb") as handle:
        handle.write(json_bytes(ScoreManifest.model_validate(manifest).model_dump(mode="json")))
    validate_scores(project, destination)
    return report


def validate_scores(project: Path, root: Path, *, replay: bool = False) -> dict[str, Any]:
    root = plain_path(root, directory=True)
    manifest = ScoreManifest.model_validate(_json(root / "scoring-manifest.json")).model_dump(
        mode="json"
    )
    if manifest.get("contract") != "evidence-scoring-manifest-v1" or {
        p.name for p in root.iterdir()
    } != FILES | {"scoring-manifest.json"}:
        raise ValueError("Invalid scoring bundle entries")
    entries = manifest["entries"]
    if len(entries) != len(FILES) or {e["path"] for e in entries} != FILES:
        raise ValueError("Invalid scoring manifest paths")
    content = {}
    for entry in entries:
        raw = bounded_file(root / entry["path"], MAX_BYTES)
        if sha256_bytes(raw) != entry["sha256"] or len(raw) != entry["bytes"]:
            raise ValueError("Scoring derivative integrity failure")
        content[entry["path"]] = raw
    report = ScoreReport.model_validate_json(content["scores.json"])
    ScorePlan.model_validate_json(content["plan.json"])
    if report.plan_sha256 != sha256_bytes(content["plan.json"]) or content != _outputs(
        report, content["plan.json"]
    ):
        raise ValueError("Tables differ from the canonical scoring payload")
    if replay and calculate_scores(project, root / "plan.json") != report:
        raise ValueError(
            "Offline score replay differs; source/analysis changes require a new derivative"
        )
    return {
        "passed": True,
        "contract": report.contract,
        "rows": len(report.rows),
        "attempt_rows": len(report.attempts),
        "native_sources_replayed": replay,
        "vulnerability_total": None,
    }
