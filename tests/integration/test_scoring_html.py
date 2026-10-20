from __future__ import annotations

import json
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from test_html_reporting import Page, tree
from typer.testing import CliRunner

from agentsec_evidence.cli.app import app
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.reporting.html import PROTECTED_MARKERS
from agentsec_evidence.scoring import html as renderer
from agentsec_evidence.scoring import html_bundle as bundle
from agentsec_evidence.scoring import service
from agentsec_evidence.scoring.calculations import count, ratio
from agentsec_evidence.scoring.models import (
    MeasurementRow,
    Metric,
    Reference,
    ScoreManifest,
    ScorePlan,
    ScoreReport,
    SessionInput,
)

ROOT = Path(__file__).resolve().parents[2]


def save(root: Path, plan: ScorePlan, report: ScoreReport) -> None:
    files = service._outputs(report, json_bytes(plan.model_dump(mode="json")))
    root.mkdir(exist_ok=True)
    for name, raw in files.items():
        (root / name).write_bytes(raw)
    manifest = ScoreManifest.model_validate(
        {
            "entries": [
                {"path": n, "bytes": len(raw), "sha256": sha256_bytes(raw)}
                for n, raw in sorted(files.items())
            ]
        }
    )
    (root / "scoring-manifest.json").write_bytes(json_bytes(manifest.model_dump(mode="json")))


@pytest.fixture
def source(tmp_path: Path) -> tuple[Path, Path]:
    project = tmp_path / "project"
    (project / "outputs").mkdir(parents=True)
    shutil.copyfile(ROOT / "pyproject.toml", project / "pyproject.toml")
    plan = ScorePlan(
        sessions=(
            SessionInput(
                session="b" * 64,
                plan_sha256="c" * 64,
                validation_sha256="d" * 64,
                role="development",
            ),
            SessionInput(
                session="e" * 64,
                plan_sha256="f" * 64,
                validation_sha256="a" * 64,
                role="formative-pilot",
            ),
        ),
        selection_rationale="Synthetic presentation tests, not observed research results",
        exclusions=("Held-out cases",),
    )
    metrics = (
        count("native-rule-reports", 0, "native-rule-reports", "Not a safety verdict"),
        ratio(
            "reported-path-coverage",
            12,
            26,
            unit="selected-paths",
            eligibility="This view only",
            limitation="Not completed analysis",
        ),
        ratio(
            "empty-ratio",
            0,
            0,
            unit="fields",
            eligibility="Empty scope",
            limitation="Undefined, not perfect",
        ),
        count("matching-completion", None, "packages", "Not observed"),
        Metric(
            name="unsupported",
            status="not-applicable",
            numerator=None,
            denominator=None,
            value=None,
            unit="files",
            eligibility="Unsupported input",
            excluded=1,
            unknown=None,
            limitation="Not clean",
        ),
    )
    reference = Reference(
        path="workspace/missing-native.json", sha256="1" * 64, pointer="/results/0"
    )
    report = ScoreReport(
        plan_sha256=sha256_bytes(json_bytes(plan.model_dump(mode="json"))),
        analysis_sources=(reference,),
        rows=tuple(
            MeasurementRow(
                row_id=str(i + 1) * 64,
                session=s.session,
                case_id="shared-case",
                evidence_role=s.role,
                attempt_id=f"attempt-{i}",
                repetition=i,
                stage="research" if i == 0 else "policy",
                state="refused" if i == 0 else "partial-analysis",
                analysis_completeness="incomplete",
                metrics=metrics,
                observations={"missing": ["a package"]},
                references=(reference,),
            )
            for i, s in enumerate(plan.sessions)
        ),
        attempts=tuple(
            {
                "session": plan.sessions[0].session,
                "evidence_role": "development",
                "case_id": "shared-case",
                "attempt_id": f"attempt-{i}",
                "repetition": 1,
                "state": state,
                "references": [reference.model_dump(mode="json")],
            }
            for i, state in enumerate(("execution-failed", "not-attempted", "partial-analysis"))
        ),
        reviews=(
            {
                "pending_finding_occurrences": 1,
                "human_decision_occurrences": 0,
                "scope": "Original report only",
                "latest": [{"decision": "proposed", "reviewer_role": "ai-assistant"}],
            },
        ),
        limitations=("Not independent labels",),
    )
    root = project / "scores"
    save(root, plan, report)
    return project, root


def rewrite(root: Path, change: Any) -> None:
    plan = ScorePlan.model_validate_json((root / "plan.json").read_bytes())
    raw = json.loads((root / "scores.json").read_bytes())
    change(raw)
    save(root, plan, ScoreReport.model_validate(raw))


def test_roundtrip_offline_preservation_relocation_and_cli(
    source: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    project, root = source
    before = tree(root)

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("Presentation attempted execution, network or native replay")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(service, "calculate_scores", forbidden)
    exports = tuple(bundle.EXPORTS)
    first = project / "outputs/one"
    manifest = bundle.write_scoring_html(project, root, first, exports=exports)
    bundle.write_scoring_html(project, root, project / "outputs/two", exports=exports[::-1])
    assert tree(first) == tree(project / "outputs/two")
    assert tree(root) == before
    assert manifest.native_sources_replayed is False
    assert len(manifest.input_files) == 7 and len(manifest.entries) == 5
    for name in bundle.EXPORTS.values():
        assert (first / "evidence" / name).read_bytes() == before[name]
    relocated = tmp_path / "relocated"
    shutil.copytree(first, relocated)
    assert bundle.validate_scoring_html(relocated)["passed"] is True
    cli = CliRunner().invoke(
        app,
        [
            "score",
            "html",
            str(root),
            "--output",
            str(project / "outputs/cli"),
            "--project-root",
            str(project),
        ],
    )
    assert cli.exit_code == 0, cli.output
    assert set(tree(project / "outputs/cli")) == {"report.html", "html-manifest.json"}
    check = CliRunner().invoke(app, ["score", "validate-html", str(relocated)])
    assert check.exit_code == 0 and json.loads(check.output)["native_sources_replayed"] is False
    with pytest.raises(ValueError):
        bundle.write_scoring_html(project, root, first)


def test_complete_semantics_and_safe_owned_links(source: tuple[Path, Path]) -> None:
    project, root = source
    output = project / "outputs/view"
    bundle.write_scoring_html(project, root, output)
    raw = (output / "report.html").read_text(encoding="utf-8")
    page = Page(raw)
    assert sum(tag == "details" and a.get("class") == "measurement" for tag, a in page.tags) == 2
    assert sum(tag == "details" and a.get("class") == "attempt" for tag, a in page.tags) == 3
    for expected in (
        "development",
        "formative-pilot",
        "shared or summary row (0)",
        "measured: 0",
        "12/26",
        "undefined",
        "unknown",
        "not-applicable",
        "execution-failed",
        "not-attempted",
        "refused",
        "partial-analysis",
        "This view only",
        "Not completed analysis",
        "Original report only",
        "ai-assistant",
        "proposed",
        "Unknown",
        "Held-out cases",
        "No pooled vulnerability total",
        "shared accounting or a summary",
        "missing-native.json",
    ):
        assert expected in raw
    assert "cross-repeat summary (0)" not in raw
    ids = [a["id"] for _, a in page.tags if "id" in a]
    assert len(ids) == len(set(ids))
    for tag, attrs in page.tags:
        assert tag not in {"script", "iframe", "img", "object", "embed", "form", "link"}
        assert not any(k.startswith("on") for k in attrs)
        if tag == "a":
            link = attrs.get("href") or ""
            assert link[1:] in ids if link.startswith("#") else (output / link).is_file()
    schema = json.loads(
        (ROOT / "schemas/offline-scoring-html-v1/manifest.schema.json").read_bytes()
    )
    Draft202012Validator(schema).validate(json.loads((output / "html-manifest.json").read_bytes()))
    assert schema == bundle.ScoringHtmlManifest.model_json_schema()


def test_untrusted_data_is_literal(source: tuple[Path, Path]) -> None:
    project, root = source
    attack = '</summary><script>alert(1)</script><img src="https://invalid/x">\u202e'

    def change(raw: Any) -> None:
        raw["rows"][0]["case_id"] = attack
        raw["rows"][0]["observations"] = {"payload": attack}
        raw["rows"][0]["metrics"][0]["limitation"] = attack
        raw["attempts"][0]["state"] = attack
        raw["reviews"][0]["scope"] = attack

    rewrite(root, change)
    output = project / "outputs/safe"
    bundle.write_scoring_html(project, root, output)
    text = (output / "report.html").read_text(encoding="utf-8")
    assert "&lt;script&gt;" in text and "\\u202e" in text and "\u202e" not in text
    assert not any(tag in {"script", "img"} for tag, _ in Page(text).tags)


@pytest.mark.parametrize("name", sorted(bundle.INPUT_NAMES))
def test_corrupt_source_refused(source: tuple[Path, Path], name: str) -> None:
    project, root = source
    (root / name).write_bytes((root / name).read_bytes() + b" ")
    if name == "scoring-manifest.json":
        (root / name).write_bytes(b"{}")
    with pytest.raises(ValueError):
        bundle.write_scoring_html(project, root, project / "outputs/rejected")
    assert not (project / "outputs/rejected").exists()


@pytest.mark.parametrize("change", ["row-session", "row-role", "attempt-session", "attempt-role"])
def test_selection_binding_refused(source: tuple[Path, Path], change: str) -> None:
    project, root = source

    def mutate(raw: Any) -> None:
        row = raw["rows"][0] if change.startswith("row") else raw["attempts"][0]
        row["session" if change.endswith("session") else "evidence_role"] = (
            "9" * 64 if change.endswith("session") else "formative-pilot"
        )

    rewrite(root, mutate)
    with pytest.raises(ValueError, match="session or evidence role"):
        bundle.write_scoring_html(project, root, project / "outputs/rejected")


@pytest.mark.parametrize(
    "payload", [b'{"contract":1,"contract":2}', b'{"x":NaN}', b'{"x":1e999}', b'{"x":']
)
def test_strict_json_before_legacy_validation(source: tuple[Path, Path], payload: bytes) -> None:
    project, root = source
    (root / "scores.json").write_bytes(payload)
    with pytest.raises(ValueError):
        bundle.write_scoring_html(project, root, project / "outputs/rejected")


@pytest.mark.parametrize("marker", PROTECTED_MARKERS)
def test_finalized_destinations_protected(source: tuple[Path, Path], marker: str) -> None:
    project, root = source
    protected = project / "outputs/protected"
    protected.mkdir()
    (protected / marker).write_bytes(b"{}")
    with pytest.raises(ValueError, match="finalized"):
        bundle.write_scoring_html(project, root, protected / "new")
    assert set(tree(protected)) == {marker}


@pytest.mark.parametrize("exports", [("unknown",), ("scores-json", "scores-json")])
def test_bad_export_selection(source: tuple[Path, Path], exports: tuple[str, ...]) -> None:
    project, root = source
    with pytest.raises(ValueError, match="export"):
        bundle.write_scoring_html(project, root, project / "outputs/rejected", exports=exports)


def test_output_boundaries_and_extra_source(source: tuple[Path, Path]) -> None:
    project, root = source
    with pytest.raises(ValueError, match="existing project outputs"):
        bundle.write_scoring_html(project, root, project / "elsewhere")
    (root / "extra").write_bytes(b"unexpected")
    with pytest.raises(ValueError, match="seven-file"):
        bundle.write_scoring_html(project, root, project / "outputs/rejected")


def test_source_race_and_render_budget(
    source: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    project, root = source
    original = renderer.render_score_html

    def changed(*args: Any, **kwargs: Any) -> bytes:
        raw = original(*args, **kwargs)
        (root / "SUMMARY.md").write_bytes(b"changed")
        return raw

    monkeypatch.setattr(bundle, "render_score_html", changed)
    with pytest.raises(ValueError, match="changed during"):
        bundle.write_scoring_html(project, root, project / "outputs/race")
    assert not (project / "outputs/race").exists()
    monkeypatch.setattr(renderer, "MAX_HTML_BYTES", 10)
    plan = ScorePlan.model_validate_json((root / "plan.json").read_bytes())
    report = ScoreReport.model_validate_json((root / "scores.json").read_bytes())
    with pytest.raises(ValueError, match="no rows were silently omitted"):
        renderer.render_score_html(report, plan, input_files=[], exports={})


@pytest.mark.parametrize("target", ["report.html", "html-manifest.json", "extra", "empty-evidence"])
def test_portable_tampering_refused(source: tuple[Path, Path], target: str) -> None:
    project, root = source
    output = project / "outputs/view"
    bundle.write_scoring_html(project, root, output)
    if target == "empty-evidence":
        (output / "evidence").mkdir()
    else:
        (output / target).write_bytes(b"tampered")
    with pytest.raises(ValueError):
        bundle.validate_scoring_html(output)
    result = CliRunner().invoke(app, ["score", "validate-html", str(output)])
    assert result.exit_code == 5


@pytest.mark.parametrize("change", ["input", "export", "renderer", "manifest", "duplicate", "path"])
def test_manifest_accounting(source: tuple[Path, Path], change: str) -> None:
    project, root = source
    output = project / "outputs/view"
    manifest = bundle.write_scoring_html(
        project, root, output, exports=("scores-json",)
    ).model_dump(mode="json")
    if change == "input":
        manifest["input_files"][0]["name"] = "scores.json"
    elif change == "export":
        manifest["entries"][0]["sha256"] = "0" * 64
    elif change == "renderer":
        manifest["renderer_sources"].pop("scoring/html.py")
    elif change == "manifest":
        manifest["scoring_manifest_sha256"] = "0" * 64
    elif change == "duplicate":
        manifest["entries"].append(manifest["entries"][0])
    else:
        manifest["entries"][0]["path"] = "../outside"
    with pytest.raises(ValueError):
        bundle.ScoringHtmlManifest.model_validate(manifest)


def test_hardlinks_not_read_as_plain_files(source: tuple[Path, Path]) -> None:
    project, root = source
    extra = project / "copy.json"
    extra.hardlink_to(root / "scores.json")
    with pytest.raises(ValueError):
        bundle.write_scoring_html(project, root, project / "outputs/rejected")
