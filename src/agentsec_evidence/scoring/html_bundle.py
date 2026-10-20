"""Bounded, portable HTML derivatives of an existing scoring bundle."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Self, cast

from pydantic import Field, JsonValue, StrictInt, model_validator

from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.dependencies.models import DependencyModel
from agentsec_evidence.models.contracts import Sha256
from agentsec_evidence.reporting.html import MAX_HTML_BYTES, MAX_MANIFEST_BYTES, PROTECTED_MARKERS
from agentsec_evidence.reporting.service import require_new_derivative
from agentsec_evidence.research.retained import bounded_file, plain_path
from agentsec_evidence.scoring.html import render_score_html
from agentsec_evidence.scoring.models import ScorePlan, ScoreReport
from agentsec_evidence.scoring.service import FILES, MAX_BYTES, validate_scores

INPUT_NAMES = FILES | {"scoring-manifest.json"}
EXPORTS = {
    "scores-json": "scores.json",
    "plan-json": "plan.json",
    "measurements-csv": "measurements.csv",
    "attempts-csv": "attempts.csv",
}
RENDERER_SOURCES = (
    "scoring/html.py",
    "scoring/html_bundle.py",
    "scoring/review_guide.py",
    "reporting/html.py",
    "reporting/html_styles.py",
)
InputName = Literal[
    "plan.json",
    "scores.json",
    "measurements.csv",
    "attempts.csv",
    "TABLES.md",
    "SUMMARY.md",
    "scoring-manifest.json",
]
OutputName = Literal[
    "report.html",
    "evidence/plan.json",
    "evidence/scores.json",
    "evidence/measurements.csv",
    "evidence/attempts.csv",
]


class ScoringHtmlInput(DependencyModel):
    name: InputName
    sha256: Sha256
    bytes: StrictInt = Field(ge=1, le=MAX_BYTES)


class ScoringHtmlFile(DependencyModel):
    path: OutputName
    sha256: Sha256
    bytes: StrictInt = Field(ge=1, le=MAX_BYTES)


class ScoringHtmlManifest(DependencyModel):
    contract: Literal["offline-scoring-html-v1"] = "offline-scoring-html-v1"
    sensitivity: Literal["internal-not-release-cleared"] = "internal-not-release-cleared"
    evidence_mode: Literal["retained-scoring-no-new-scan"] = "retained-scoring-no-new-scan"
    validation_scope: Literal["scoring-derivative-and-table-consistency"] = (
        "scoring-derivative-and-table-consistency"
    )
    native_sources_replayed: Literal[False] = False
    scoring_manifest_sha256: Sha256
    input_files: tuple[ScoringHtmlInput, ...] = Field(min_length=7, max_length=7)
    renderer_sources: dict[str, Sha256]
    entries: tuple[ScoringHtmlFile, ...] = Field(min_length=1, max_length=5)

    @model_validator(mode="after")
    def accounting(self) -> Self:
        names = [f.name for f in self.input_files]
        paths = [f.path for f in self.entries]
        if set(names) != INPUT_NAMES or names != sorted(names):
            raise ValueError("Scoring HTML input accounting differs")
        if set(self.renderer_sources) != set(RENDERER_SOURCES):
            raise ValueError("Scoring HTML renderer identity is incomplete")
        source = {f.name: f for f in self.input_files}
        if source["scoring-manifest.json"].sha256 != self.scoring_manifest_sha256:
            raise ValueError("Scoring HTML source manifest differs")
        if paths != sorted(set(paths)) or "report.html" not in paths:
            raise ValueError("Scoring HTML output accounting differs")
        for entry in self.entries:
            if entry.path == "report.html":
                if entry.bytes > MAX_HTML_BYTES:
                    raise ValueError("Scoring HTML exceeds byte budget")
            else:
                original = source[cast(InputName, entry.path.split("/")[1])]
                if (original.sha256, original.bytes) != (entry.sha256, entry.bytes):
                    raise ValueError("Scoring HTML selected export differs from original")
        return self


@dataclass(frozen=True)
class ScoringPresentation:
    root: Path
    files: dict[str, bytes]
    plan: ScorePlan
    report: ScoreReport


def _snapshot(root: Path) -> dict[str, bytes]:
    if {p.name for p in root.iterdir()} != INPUT_NAMES:
        raise ValueError("Scoring presentation requires the exact seven-file scoring bundle")
    files = {}
    total = 0
    for name in sorted(INPUT_NAMES):
        raw = bounded_file(
            root / name, MAX_MANIFEST_BYTES if name == "scoring-manifest.json" else MAX_BYTES
        )
        total += len(raw)
        if total > 128 * 1024**2:
            raise ValueError("Scoring presentation input budget exceeded")
        if name.endswith(".json"):
            load_agent_json(raw, max_bytes=MAX_BYTES)
        files[name] = raw
    return files


def verify_scoring_inputs_unchanged(inputs: ScoringPresentation) -> None:
    if _snapshot(inputs.root) != inputs.files:
        raise ValueError("Scoring bundle changed during HTML generation")


def read_scoring_inputs(project: Path, root: Path) -> ScoringPresentation:
    root = plain_path(root, directory=True)
    files = _snapshot(root)
    validate_scores(project, root, replay=False)
    report = ScoreReport.model_validate_json(files["scores.json"])
    plan = ScorePlan.model_validate_json(files["plan.json"])
    sessions = {s.session: s.role for s in plan.sessions}
    for row in report.rows:
        if sessions.get(row.session) != row.evidence_role:
            raise ValueError("Scoring row is outside its selected session or evidence role")
    for attempt in report.attempts:
        session = attempt.get("session")
        if not isinstance(session, str) or sessions.get(session) != attempt.get("evidence_role"):
            raise ValueError("Scoring attempt is outside its selected session or evidence role")
    inputs = ScoringPresentation(root=root, files=files, report=report, plan=plan)
    verify_scoring_inputs_unchanged(inputs)
    return inputs


def write_scoring_html(
    project: Path, bundle: Path, output: Path, *, exports: Sequence[str] = ()
) -> ScoringHtmlManifest:
    selected = tuple(sorted(exports))
    if len(set(selected)) != len(selected) or not set(selected).issubset(EXPORTS):
        raise ValueError("Unknown or duplicate scoring HTML export")
    project = plain_path(project, directory=True)
    parent = plain_path(output.parent, directory=True)
    if not parent.is_relative_to(project / "outputs"):
        raise ValueError("Use a new report directory under existing project outputs")
    for ancestor in (parent, *parent.parents):
        if any((ancestor / marker).exists() for marker in PROTECTED_MARKERS):
            raise ValueError("Scoring HTML output cannot modify finalized evidence")
    destination = require_new_derivative(parent / output.name, [bundle])
    inputs = read_scoring_inputs(project, bundle)
    source_files = tuple(
        ScoringHtmlInput(name=cast(InputName, name), sha256=sha256_bytes(raw), bytes=len(raw))
        for name, raw in sorted(inputs.files.items())
    )
    payload = {
        "report.html": render_score_html(
            inputs.report,
            inputs.plan,
            input_files=[(f.name, f.bytes, f.sha256) for f in source_files],
            exports={key: EXPORTS[key] for key in selected},
        )
    }
    for key in selected:
        name = EXPORTS[key]
        payload["evidence/" + name] = inputs.files[name]
    package = Path(__file__).resolve().parents[1]
    manifest = ScoringHtmlManifest(
        scoring_manifest_sha256=sha256_bytes(inputs.files["scoring-manifest.json"]),
        input_files=source_files,
        renderer_sources={name: sha256_file(package / name) for name in RENDERER_SOURCES},
        entries=tuple(
            ScoringHtmlFile(path=cast(OutputName, name), sha256=sha256_bytes(raw), bytes=len(raw))
            for name, raw in sorted(payload.items())
        ),
    )
    verify_scoring_inputs_unchanged(inputs)
    destination.mkdir(exist_ok=False)
    for name, raw in payload.items():
        path = destination / name
        path.parent.mkdir(exist_ok=True)
        with path.open("xb") as stream:
            stream.write(raw)
    # The manifest is last; interrupted output must not look like a completed package.
    with (destination / "html-manifest.json").open("xb") as stream:
        stream.write(json_bytes(manifest.model_dump(mode="json")))
    validate_scoring_html(destination)
    return manifest


def validate_scoring_html(root: Path) -> dict[str, JsonValue]:
    root = plain_path(root, directory=True)
    manifest = ScoringHtmlManifest.model_validate(
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
                raise ValueError("Unexpected scoring HTML evidence directory")
            for child in path.iterdir():
                plain_path(child, directory=False)
                actual.add("evidence/" + child.name)
        else:
            plain_path(path, directory=False)
            actual.add(path.name)
    if actual != expected:
        raise ValueError("Scoring HTML file set differs from manifest")
    for entry in manifest.entries:
        raw = bounded_file(root / entry.path, entry.bytes)
        if len(raw) != entry.bytes or sha256_bytes(raw) != entry.sha256:
            raise ValueError("Scoring HTML integrity failure")
    return {
        "passed": True,
        "contract": manifest.contract,
        "files": len(manifest.entries),
        "validation_scope": "html-package-integrity-only",
        "native_sources_replayed": False,
        "sensitivity": manifest.sensitivity,
    }
