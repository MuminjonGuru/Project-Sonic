"""Script-free offline HTML derived from validated common reports, not new scans."""

from __future__ import annotations

import base64
import hashlib
import html
import json
import unicodedata
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Literal, cast

from pydantic import Field, JsonValue, StrictInt, model_validator

from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.dependencies.models import DependencyModel
from agentsec_evidence.models.contracts import Finding, Sha256
from agentsec_evidence.reporting.html_styles import STYLES
from agentsec_evidence.reporting.models import (
    AgentSource,
    DependencySource,
    DependencySummary,
    PublicPilotSource,
    ResearchSource,
)
from agentsec_evidence.reporting.presentation import (
    PresentationInputs,
    read_presentation_inputs,
    verify_presentation_inputs_unchanged,
)
from agentsec_evidence.reporting.service import require_new_derivative
from agentsec_evidence.research.models import SemgrepPassEvidence
from agentsec_evidence.research.retained import bounded_file, plain_path
from agentsec_evidence.reviews.models import ReviewAnnotation

MAX_HTML_BYTES = 32 * 1024**2
MAX_MANIFEST_BYTES = 1024**2
EXPORTS = {
    "report-json": ("report", "report.json"),
    "sarif": ("report", "results.sarif"),
    "review-json": ("review", "review.json"),
}
OUTPUT_NAMES = {"report.html", *("evidence/" + name for _, name in EXPORTS.values())}
PROTECTED_MARKERS = (
    "bundle-manifest.json",
    "manifest.json",
    "evidence-manifest.json",
    "report-manifest.json",
    "review-manifest.json",
    "scoring-manifest.json",
    "review-guide-manifest.json",
    "html-manifest.json",
    "validation.json",
    "start.json",
    "finish.json",
)


class HtmlFile(DependencyModel):
    path: Literal[
        "report.html", "evidence/report.json", "evidence/results.sarif", "evidence/review.json"
    ]
    sha256: Sha256
    bytes: StrictInt = Field(ge=1, le=64 * 1024**2)


class HtmlInput(DependencyModel):
    group: Literal["report", "review"]
    name: Literal[
        "report.json",
        "results.sarif",
        "report-manifest.json",
        "review.json",
        "review-manifest.json",
    ]
    sha256: Sha256
    bytes: StrictInt = Field(ge=1, le=64 * 1024**2)


class HtmlManifest(DependencyModel):
    contract: Literal["offline-html-report-v1"] = "offline-html-report-v1"
    sensitivity: Literal["internal-not-release-cleared"] = "internal-not-release-cleared"
    evidence_mode: Literal["retained-report-no-new-scan"] = "retained-report-no-new-scan"
    validation_scope: Literal["common-report-derivative-and-optional-review-bindings"] = (
        "common-report-derivative-and-optional-review-bindings"
    )
    original_sources_revalidated: Literal[False] = False
    report_manifest_sha256: Sha256
    review_provided: bool
    input_files: tuple[HtmlInput, ...] = Field(min_length=3, max_length=5)
    renderer_sources: dict[str, Sha256]
    entries: tuple[HtmlFile, ...] = Field(min_length=1, max_length=4)

    @model_validator(mode="after")
    def accounting(self) -> HtmlManifest:
        expected = {("report", n) for n in ("report.json", "results.sarif", "report-manifest.json")}
        if self.review_provided:
            expected |= {("review", n) for n in ("review.json", "review-manifest.json")}
        if (
            len(self.input_files) != len(expected)
            or {(i.group, i.name) for i in self.input_files} != expected
        ):
            raise ValueError("HTML input accounting differs")
        manifest = next(i for i in self.input_files if i.name == "report-manifest.json")
        paths = [e.path for e in self.entries]
        if (
            manifest.sha256 != self.report_manifest_sha256
            or len(paths) != len(set(paths))
            or "report.html" not in paths
            or paths != sorted(paths)
        ):
            raise ValueError("HTML manifest accounting differs")
        if set(self.renderer_sources) != {"html.py", "html_styles.py", "presentation.py"}:
            raise ValueError("HTML renderer identity is incomplete")
        for entry in self.entries:
            if entry.path == "report.html":
                if entry.bytes > MAX_HTML_BYTES:
                    raise ValueError("HTML report exceeds byte budget")
                continue
            original = next(
                (i for i in self.input_files if i.name == entry.path.split("/")[1]), None
            )
            if original is None or (original.sha256, original.bytes) != (entry.sha256, entry.bytes):
                raise ValueError("Selected export differs from its retained input")
        return self


def _text(value: object) -> str:
    text = "Not recorded" if value is None else str(value)
    # Make invisible controls visible without interpreting scanner text as markup or URLs.
    text = "".join(
        f"\\u{ord(c):04x}"
        if unicodedata.category(c) in {"Cc", "Cf", "Cs"} and c not in "\n\t"
        else c
        for c in text
    )
    return html.escape(text, quote=True)


def _object(value: JsonValue) -> dict[str, JsonValue]:
    return value if isinstance(value, dict) else {}


def _array(value: JsonValue) -> list[JsonValue]:
    return value if isinstance(value, list) else []


def _table(headers: Sequence[str], rows: Iterable[Sequence[object]], caption: str) -> str:
    return (
        '<div class="table-wrap"><table><caption>'
        + _text(caption)
        + "</caption><thead><tr>"
        + "".join('<th scope="col">' + _text(h) + "</th>" for h in headers)
        + "</tr></thead><tbody>"
        + "".join(
            "<tr>" + "".join("<td>" + _text(v) + "</td>" for v in row) + "</tr>" for row in rows
        )
        + "</tbody></table></div>"
    )


def _details(label: str, value: object) -> str:
    return (
        "<details><summary>"
        + _text(label)
        + '</summary><div class="detail-body"><pre>'
        + _text(json.dumps(value, indent=2, ensure_ascii=True, sort_keys=True))
        + "</pre></div></details>"
    )


def _metadata(items: Iterable[tuple[str, object]]) -> str:
    return (
        '<dl class="metadata">'
        + "".join("<dt>" + _text(k) + "</dt><dd>" + _text(v) + "</dd>" for k, v in items)
        + "</dl>"
    )


def _seconds(value: int | None) -> str:
    return "Not recorded" if value is None else f"{value / 1_000_000_000:.3f} s"


def _coverage(view: SemgrepPassEvidence) -> str:
    reported = sum(f.state in {"reported", "reported-with-native-issue"} for f in view.files)
    total = len(view.files)
    if not total:
        return '<p class="muted">No selected paths; reported-path ratio is undefined.</p>'
    return (
        f'<div class="coverage"><span>{_text(view.role)}</span>'
        f'<progress value="{reported}" max="{total}" '
        f'aria-label="Reported paths: {_text(view.role)}">'
        f"{reported}/{total}</progress><span>{reported}/{total}</span></div>"
    )


def _dependency(summary: DependencySummary) -> str:
    output = _metadata(
        (
            ("Eligible package name/version identities", summary.eligible_unique_packages),
            ("Local packages counted separately", summary.separate_local_packages),
            ("Frozen database SHA-256", summary.database_sha256),
        )
    )
    output += _table(
        (
            "Stage",
            "State",
            "Identified packages",
            "Eligible packages",
            "Package-advisory pairs",
            "Match occurrences",
        ),
        (
            (
                s.stage,
                s.state,
                s.identified_unique_packages,
                s.eligible_reported_packages,
                s.reported_package_advisory_matches,
                s.reported_match_occurrences,
            )
            for s in summary.stages
        ),
        "Dependency observations; paths are not additive",
    )
    output += _table(
        ("Handoff", "Comparable", "Name/version retention", "Missing", "Added", "Qualifier losses"),
        (
            (
                f"{c.left} -> {c.right}",
                c.comparable,
                f"{c.package_projection_retention.numerator}/{c.package_projection_retention.denominator}"
                if c.package_projection_retention
                and c.package_projection_retention.value is not None
                else "Undefined / not assessed",
                len(c.missing),
                len(c.added),
                len(c.source_qualifier_losses),
            )
            for c in summary.comparisons
        ),
        "Evidence handoffs; identity counts do not prove relationship preservation",
    )
    output += (
        '<p class="muted">Per-package matching completion is not observable. '
        "Zero matches are not proof of safety.</p>"
    )
    output += _details(
        "Exact dependency comparisons, timings and limitations", summary.model_dump(mode="json")
    )
    return output


def _source_sections(inputs: PresentationInputs) -> str:
    output = ""
    for index, source in enumerate(inputs.report.sources):
        output += f'<section id="source-{index}"><h2>{_text(source.label)}</h2>'
        output += _metadata(
            (
                ("Source type", source.kind),
                ("Recorded state", source.state),
                ("Revision", source.revision),
                ("Source run ID", source.run_id),
                ("Source manifest SHA-256", source.source_manifest_sha256),
            )
        )
        if isinstance(source, PublicPilotSource):
            summary = source.summary
            output += "<h3>Scope and tool execution</h3>"
            output += _metadata(
                (
                    ("Evidence role", summary.evidence_role),
                    ("Git-verified inventory files", len(summary.inventory.records)),
                    ("Selected Python files", len(summary.plan.python_paths)),
                    ("Dockerfile", summary.plan.dockerfile),
                    ("Analysis completeness", summary.analysis_completeness),
                )
            )
            output += _table(
                ("Artifact surface", "Recorded state", "Files", "Evidence pointer"),
                (
                    (c.get("surface"), c.get("state"), c.get("files"), c.get("evidence"))
                    for c in summary.retained_coverage
                ),
                "Artifact coverage: inventory is not detection coverage",
            )
            output += _table(
                ("Repeat", "Tool / treatment", "State", "Records", "Unit", "Packages", "Duration"),
                (
                    (
                        r.repetition,
                        r.stage,
                        r.state,
                        r.finding_records,
                        r.unit,
                        r.package_identities,
                        _seconds(r.duration_ns),
                    )
                    for r in summary.rows
                ),
                "Recorded stage results; repeated observations are not independent cases",
            )
            for rep in summary.repetitions:
                output += f"<h3>Repetition {rep.repetition}: coverage and dependency evidence</h3>"
                output += _coverage(rep.semgrep.research)
                if rep.semgrep.repository_policy is not None:
                    output += _coverage(rep.semgrep.repository_policy)
                output += (
                    '<p class="muted">Bars show native reported paths, not completed analysis '
                    f"by every rule. Agent Audit reports {rep.agent_native_scanned_files} files "
                    "in aggregate; per-file completion is unknown.</p>"
                )
                output += _dependency(rep.dependency)
            output += _details(
                "Semantic repeatability and timing",
                {
                    "repeatability": summary.repeatability,
                    "repetition_wall_ns": summary.repetition_wall_ns,
                    "attempt_wall_ns": summary.attempt_wall_ns,
                    "manual_recovery_actions_during_attempt": (
                        summary.manual_recovery_actions_during_attempt
                    ),
                    "manual_preparation_and_adjudication_time_ns": None,
                },
            )
        elif isinstance(source, DependencySource):
            output += _dependency(source.summary)
        elif isinstance(source, ResearchSource):
            output += _metadata(
                (
                    ("Evidence role", source.summary.evidence_role),
                    ("Selected files", source.summary.selected_file_count),
                    ("Syntax state", source.summary.syntax_state),
                )
            )
            output += _table(
                ("View / repeat", "Execution outcome", "Records", "Duration"),
                (
                    (
                        p.key,
                        p.execution.model_dump(mode="json"),
                        p.native_finding_records,
                        _seconds(p.duration_ns),
                    )
                    for p in source.summary.passes
                ),
                "Controlled research observations; no unrun count is inferred",
            )
            for p in source.summary.passes:
                output += f"<h3>{_text(p.key)}</h3>" + _coverage(p.evidence)
        else:
            output += _metadata(
                (
                    ("Execution outcome", source.summary.execution_outcome),
                    ("Stored normalized records", source.summary.normalized_finding_count),
                    ("Recorded failures", source.summary.normalized_failure_count),
                    ("Duration", _seconds(source.summary.duration_ns)),
                )
            )
            if isinstance(source, AgentSource):
                output += _metadata(
                    (
                        ("Scanner launched", source.agent_details.scanner_launched),
                        ("Native findings", source.agent_details.native_result_count),
                        ("Native aggregate files", source.agent_details.native_scanned_files),
                        ("Per-file completion", source.agent_details.per_file_completion),
                    )
                )
            output += _table(
                ("Property", "Applicability", "Support", "Execution", "Observation"),
                (
                    (c.property_id, c.applicability, c.adapter_support, c.execution, c.observation)
                    for c in source.coverage
                ),
                "Declared coverage records, not all possible agent properties",
            )
            if source.failures:
                output += _details(
                    "Recorded failures", [f.model_dump(mode="json") for f in source.failures]
                )
        output += (
            _details(
                "Complete retained source record, including limitations and references",
                source.model_dump(mode="json"),
            )
            + "</section>"
        )
    return output


def _native_finding(
    inputs: PresentationInputs, run: dict[str, JsonValue], result: dict[str, JsonValue]
) -> Finding | None:
    props, fingerprints = _object(run.get("properties")), _object(result.get("partialFingerprints"))
    for source in inputs.report.sources:
        if isinstance(source, PublicPilotSource) and source.run_id == props.get(
            "agentsecEvidence/sourceRunId"
        ):
            for rep in source.summary.repetitions:
                if rep.agent_run_id == props.get(
                    "agentsecEvidence/nativeRunId"
                ) and rep.agent_execution_id == props.get("agentsecEvidence/nativeExecutionId"):
                    matches = [
                        f
                        for f in rep.agent_findings
                        if f.fingerprints.record_v1 == fingerprints.get("agentsecEvidenceRecord/v1")
                    ]
                    # An ambiguous fingerprint is not permission to attach another record's review.
                    return matches[0] if len(matches) == 1 else None
    return None


def _locations(result: dict[str, JsonValue]) -> str:
    rows: list[Sequence[object]] = []
    for item in _array(result.get("locations")):
        location = _object(item)
        physical = _object(location.get("physicalLocation"))
        artifact = _object(physical.get("artifactLocation"))
        region = _object(physical.get("region"))
        if physical:
            rows.append((artifact.get("uri"), region.get("startLine"), region.get("endLine")))
        for logical in _array(location.get("logicalLocations")):
            identity = _object(logical)
            rows.append((identity.get("fullyQualifiedName", identity.get("name")), None, None))
    if not rows:
        return '<p class="muted">No source or logical location in this export.</p>'
    return _table(("Artifact / package", "Start line", "End line"), rows, "Reported locations")


def _findings(inputs: PresentationInputs) -> str:
    output = '<section id="findings"><h2>Scanner reports and contextual review</h2>'
    output += (
        "<p>Each tool, policy view and repetition remains separate. A scanner report is not "
        "a confirmed vulnerability. Native severity and confidence are tool assertions.</p>"
    )
    latest: dict[tuple[str, str, str, str], ReviewAnnotation] = {}
    if inputs.review is not None:
        latest = {a.subject.key: a for a in inputs.review.annotations}
    for index, item in enumerate(_array(inputs.sarif.get("runs"))):
        run = _object(item)
        driver = _object(_object(run.get("tool")).get("driver"))
        props = _object(run.get("properties"))
        results = _array(run.get("results"))
        version = driver.get("semanticVersion", driver.get("version"))
        output += f'<h3 id="tool-run-{index}">{_text(driver.get("name"))} / {_text(version)}</h3>'
        output += _metadata(
            (
                ("Source run", props.get("agentsecEvidence/sourceRunId")),
                (
                    "Treatment",
                    props.get(
                        "agentsecEvidence/pilotStage",
                        props.get(
                            "agentsecEvidence/comparisonPath",
                            props.get("agentsecEvidence/researchPass"),
                        ),
                    ),
                ),
                ("Repetition", props.get("agentsecEvidence/repetition")),
                ("Retained SARIF result records", len(results)),
            )
        )
        output += _details(
            "Tool, rule, invocation and provenance metadata",
            {k: v for k, v in run.items() if k != "results"},
        )
        if not results:
            output += (
                '<p class="notice">No result records in this export. Consult execution '
                "and coverage states before interpretation; this is not a safety verdict.</p>"
            )
        for number, raw_result in enumerate(results, 1):
            result = _object(raw_result)
            native = _native_finding(inputs, run, result)
            result_props = _object(result.get("properties"))
            output += f'<article class="finding"><h4>{number}. {_text(result.get("ruleId"))}</h4>'
            message = _object(result.get("message"))
            output += "<p>" + _text(message.get("text", message.get("markdown"))) + "</p>"
            output += _locations(result)
            output += _metadata(
                (
                    (
                        "Native severity",
                        native.severity.native_label
                        if native
                        else result_props.get("agentsecEvidence/nativeSeverity"),
                    ),
                    ("Exported SARIF level", result.get("level")),
                    ("Native confidence", native.confidence.native_label if native else None),
                    (
                        "Suppression evidence",
                        "Present; not approval"
                        if result.get("suppressions")
                        else "No marker in this export",
                    ),
                    (
                        "Native evidence SHA-256",
                        result_props.get(
                            "agentsecEvidence/nativeJsonSha256",
                            result_props.get("agentsecEvidence/sourceBlobSha256"),
                        ),
                    ),
                    ("Native JSON pointer", result_props.get("agentsecEvidence/jsonPointer")),
                )
            )
            if native is not None:
                output += _details(
                    "Original normalized finding: description, advice and evidence",
                    native.model_dump(mode="json"),
                )
                key = (
                    str(props.get("agentsecEvidence/sourceRunId")),
                    native.run_id,
                    native.execution_id,
                    native.record_id,
                )
                annotation = latest.get(key)
                if annotation is not None:
                    output += _metadata(
                        (
                            ("Review decision", annotation.decision),
                            ("Working conclusion", annotation.conclusion),
                            ("Reviewer role", annotation.reviewer.role),
                            ("Review rationale", annotation.rationale),
                            ("Uncertainty", annotation.uncertainty),
                        )
                    )
                else:
                    output += (
                        '<p class="muted">No supplied contextual review '
                        "for this finding occurrence.</p>"
                    )
            output += (
                _details("Exact SARIF result, locations and evidence pointers", result)
                + "</article>"
            )
    output += "<h3>Review provenance</h3>"
    if inputs.review is None:
        output += (
            "<p>No review sidecar supplied. This does not establish that no review exists "
            "or that findings were accepted.</p>"
        )
    else:
        output += _metadata(
            (
                ("Review history entries", len(inputs.review.annotations)),
                ("Latest finding-occurrence assessments", len(latest)),
                ("Latest AI proposals", sum(a.decision == "proposed" for a in latest.values())),
                (
                    "Latest non-proposal decisions",
                    sum(a.decision != "proposed" for a in latest.values()),
                ),
            )
        )
        output += _details("Review validation and declared authorship", inputs.review_validation)
        output += _details(
            "Complete review history; proposals are not independent labels",
            inputs.review.model_dump(mode="json"),
        )
    return output + "</section>"


def render_html(inputs: PresentationInputs, exports: Sequence[str] = ()) -> bytes:
    digest = base64.b64encode(hashlib.sha256(STYLES.encode()).digest()).decode("ascii")
    csp = f"default-src 'none'; style-src 'sha256-{digest}'; base-uri 'none'; form-action 'none'"
    output = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<meta http-equiv="Content-Security-Policy" content="{html.escape(csp, quote=True)}">'
        '<meta name="referrer" content="no-referrer"><title>Security Evidence Report</title>'
        f'<style>{STYLES}</style></head><body><a class="skip" href="#overview">Skip to report</a>'
        '<header><div class="eyebrow">STATIC ANALYSIS / RETAINED EVIDENCE</div>'
        "<h1>Security Evidence Report</h1><p>"
        + _text(" | ".join(s.label for s in inputs.report.sources))
        + "</p><p>Internal report. Sensitive-content and sharing review required.</p></header>"
        '<div class="layout"><nav aria-label="Report sections"><a href="#overview">Overview</a>'
    )
    output += "".join(
        f'<a href="#source-{i}">Source {i + 1}: {_text(s.label)}</a>'
        for i, s in enumerate(inputs.report.sources)
    )
    output += (
        '<a href="#findings">Scanner reports</a><a href="#evidence">Evidence and exports</a>'
        '</nav><main><section id="overview"><h2>What this report establishes</h2>'
        "<p>The saved report and any supplied review bindings were validated. "
        "Original scan bundles were not reopened. This is an offline view of retained results, "
        "not a fresh scan or independent security assessment.</p>"
    )
    output += _metadata(
        (
            ("Report contract", inputs.report.contract),
            ("Source report generated at", inputs.report.generated_at.isoformat()),
            ("Source bundles", len(inputs.report.sources)),
            ("SARIF tool runs", inputs.report.sarif_runs),
            (
                "Overall vulnerability total",
                "Not defined: units, paths and repetitions are not additive",
            ),
        )
    )
    output += (
        '<p class="notice">Partial, failed, refused, unsupported and unknown analysis must '
        "not be interpreted as clean. Unsupported properties remain outside the "
        "demonstrated coverage.</p>"
    )
    output += _details("Report limitations", inputs.report.limitations) + "</section>"
    output += _source_sections(inputs) + _findings(inputs)
    output += '<section id="evidence"><h2>Evidence and exports</h2>'
    output += (
        "<p>Evidence identifiers and pointers are retained as text, not followed as filesystem "
        "paths or external links. Original native files are not copied automatically. "
        "Fields absent from an export remain absent; the source records above preserve "
        "additional information where available.</p>"
    )
    output += _table(
        ("Group", "Input file", "Bytes", "SHA-256"),
        ((f.group, f.path.name, len(f.data), f.sha256) for f in inputs.files),
        "Validated presentation inputs",
    )
    output += '<ul><li><a href="html-manifest.json" download>Report checksum manifest</a></li>'
    for key in exports:
        _, name = EXPORTS[key]
        output += (
            f'<li><a href="evidence/{name}" download>{_text(key)}: {_text(name)}</a> '
            "(internal, unredacted)</li>"
        )
    output += (
        "</ul><p>Hashes establish recorded consistency, not independent attestation. "
        "No automatic redaction or public-release clearance is claimed.</p></section></main></div>"
        "<footer>agentsec-evidence | Offline HTML report v1 | No target code, scanners or "
        "network requests are executed by this report.</footer></body></html>"
    )
    raw = output.encode("utf-8")
    if len(raw) > MAX_HTML_BYTES:
        raise ValueError("Rendered report exceeds byte budget; no findings were silently truncated")
    return raw


def write_html_report(
    *,
    project: Path,
    report_root: Path,
    output: Path,
    review_root: Path | None = None,
    exports: Sequence[str] = (),
) -> HtmlManifest:
    selected = tuple(sorted(exports))
    if len(set(selected)) != len(selected) or not set(selected).issubset(EXPORTS):
        raise ValueError("Unknown or duplicate selected export")
    if "review-json" in selected and review_root is None:
        raise ValueError("A review export requires a supplied review sidecar")
    project = plain_path(project, directory=True)
    parent = plain_path(output.parent, directory=True)
    if not parent.is_relative_to(project / "outputs"):
        raise ValueError("Use a new report directory under existing project outputs")
    for ancestor in (parent, *parent.parents):
        if any((ancestor / marker).exists() for marker in PROTECTED_MARKERS):
            raise ValueError("HTML output cannot modify finalized evidence")
    roots = [report_root, *([review_root] if review_root is not None else [])]
    destination = require_new_derivative(parent / output.name, roots)
    inputs = read_presentation_inputs(project, report_root, review_root=review_root)
    payload = {"report.html": render_html(inputs, selected)}
    for key in selected:
        group, name = EXPORTS[key]
        payload["evidence/" + name] = inputs.file(group, name).data
    manifest = HtmlManifest(
        report_manifest_sha256=inputs.report_manifest_sha256,
        review_provided=inputs.review is not None,
        input_files=tuple(HtmlInput.model_validate(f.reference()) for f in inputs.files),
        renderer_sources={
            name: sha256_file(Path(__file__).with_name(name))
            for name in ("html.py", "html_styles.py", "presentation.py")
        },
        entries=tuple(
            HtmlFile(
                path=cast(
                    Literal[
                        "report.html",
                        "evidence/report.json",
                        "evidence/results.sarif",
                        "evidence/review.json",
                    ],
                    name,
                ),
                sha256=sha256_bytes(raw),
                bytes=len(raw),
            )
            for name, raw in sorted(payload.items())
        ),
    )
    verify_presentation_inputs_unchanged(inputs)
    destination.mkdir(exist_ok=False)
    # Publish the manifest last: an interrupted write cannot appear as a validated bundle.
    for name, raw in payload.items():
        path = destination / name
        path.parent.mkdir(exist_ok=True)
        with path.open("xb") as stream:
            stream.write(raw)
    with (destination / "html-manifest.json").open("xb") as stream:
        stream.write(json_bytes(manifest.model_dump(mode="json")))
    validate_html_report(destination)
    return manifest


def validate_html_report(root: Path) -> dict[str, JsonValue]:
    root = plain_path(root, directory=True)
    manifest = HtmlManifest.model_validate(
        load_agent_json(
            bounded_file(root / "html-manifest.json", MAX_MANIFEST_BYTES),
            max_bytes=MAX_MANIFEST_BYTES,
        )
    )
    expected = {e.path for e in manifest.entries} | {"html-manifest.json"}
    actual: set[str] = set()
    for path in root.iterdir():
        if path.name == "evidence":
            plain_path(path, directory=True)
            if not any(p.startswith("evidence/") for p in expected):
                raise ValueError("Unexpected HTML evidence directory")
            for child in path.iterdir():
                plain_path(child, directory=False)
                actual.add("evidence/" + child.name)
        else:
            plain_path(path, directory=False)
            actual.add(path.name)
    if actual != expected:
        raise ValueError("HTML report file set differs from manifest")
    for entry in manifest.entries:
        raw = bounded_file(root / entry.path, entry.bytes)
        if len(raw) != entry.bytes or sha256_bytes(raw) != entry.sha256:
            raise ValueError("HTML report integrity failure")
    return {
        "passed": True,
        "contract": manifest.contract,
        "files": len(manifest.entries),
        "validation_scope": "html-package-integrity-only",
        "original_sources_revalidated": False,
        "sensitivity": manifest.sensitivity,
    }
