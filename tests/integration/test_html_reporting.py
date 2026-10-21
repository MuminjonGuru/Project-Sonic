from __future__ import annotations

import hashlib
import json
import shutil
import socket
import subprocess
from collections.abc import Sequence
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from pydantic import JsonValue
from test_common_reporting import dependency_bundle
from test_public_pilot_reporting import review_inputs as review_inputs
from test_public_pilot_reporting import synthetic_projection
from test_research_reporting import matrix
from typer.testing import CliRunner

from agentsec_evidence.cli.app import app
from agentsec_evidence.core.identity import semantic_hash
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.reporting import html as renderer
from agentsec_evidence.reporting import presentation
from agentsec_evidence.reporting.models import CommonReport, PublicPilotSource
from agentsec_evidence.reporting.service import write_common_report
from agentsec_evidence.reviews.service import write_review

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def projection(tmp_path: Path) -> tuple[PublicPilotSource, dict[str, Any]]:
    source, document = synthetic_projection(tmp_path)
    raw = source.model_dump(mode="json")
    for run, binding in zip(document["runs"], raw["summary"]["sarif_bindings"], strict=True):
        if binding["stage"] != "agent-audit":
            continue
        rep = source.summary.repetitions[binding["repetition"] - 1]
        run["properties"]["agentsecEvidence/nativeRunId"] = rep.agent_run_id
        run["properties"]["agentsecEvidence/nativeExecutionId"] = rep.agent_execution_id
        for result, finding in zip(run["results"], rep.agent_findings, strict=True):
            result["partialFingerprints"] = {
                "agentsecEvidenceRecord/v1": finding.fingerprints.record_v1
            }
        binding["run_sha256"] = semantic_hash(run)
    return PublicPilotSource.model_validate(raw), document


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / "outputs").mkdir(parents=True)
    schema = root / "schemas/vendor/oasis/sarif-schema-2.1.0.json"
    schema.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / schema.relative_to(root), schema)
    shutil.copyfile(ROOT / "pyproject.toml", root / "pyproject.toml")
    return root


def report_at(tmp_path: Path, *, state: str = "complete", findings: bool = True) -> Path:
    bundle = dependency_bundle(tmp_path, state=state, findings=findings)
    output = tmp_path / "report"
    write_common_report(project_root=ROOT, bundles=[bundle], output=output)
    return output


def tree(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}


class Page(HTMLParser):
    def __init__(self, text: str) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.feed(text)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))


def test_roundtrip_relocation_repeatability_and_no_execution(
    project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = report_at(tmp_path)
    before = tree(source)

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("Presentation attempted process or network execution")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    first, second = project / "outputs/one", project / "outputs/two"
    manifest = renderer.write_html_report(project=project, report_root=source, output=first)
    renderer.write_html_report(project=project, report_root=source, output=second)
    assert tree(first) == tree(second) and tree(source) == before
    assert set(tree(first)) == {"report.html", "html-manifest.json"}
    assert not manifest.original_sources_revalidated
    moved = tmp_path / "relocated"
    shutil.copytree(first, moved)
    assert renderer.validate_html_report(moved)["passed"] is True
    assert renderer.validate_html_report(moved)["validation_scope"] == "html-package-integrity-only"
    page = Page((moved / "report.html").read_text(encoding="utf-8"))
    ids = {a["id"] for _, a in page.tags if "id" in a}
    assert len(ids) == sum("id" in a for _, a in page.tags)
    for tag, attrs in page.tags:
        assert tag not in {"script", "iframe", "object", "embed", "base", "form"}
        assert not any(key.startswith("on") for key in attrs)
        assert not attrs.get("src")
        if "href" in attrs:
            href = attrs["href"]
            assert href is not None
            if href.startswith("#"):
                assert href[1:] in ids
            else:
                assert (moved / href).is_file()


@pytest.mark.parametrize("state", ["complete", "partial", "failed"])
@pytest.mark.parametrize("findings", [True, False])
def test_states_and_nulls_are_not_security_verdicts(
    project: Path, tmp_path: Path, state: str, findings: bool
) -> None:
    source = report_at(tmp_path, state=state, findings=findings)
    out = project / "outputs/report"
    renderer.write_html_report(project=project, report_root=source, output=out)
    text = (out / "report.html").read_text(encoding="utf-8")
    assert state in text and "not proof of safety" in text
    assert "osv-direct" in text and "osv-sbom" in text
    assert "Not defined: units, paths and repetitions are not additive" in text
    if state != "complete":
        assert "Not recorded" in text
    if not findings:
        assert "No result records in this export" in text


def test_explicit_exports_and_cli(project: Path, tmp_path: Path) -> None:
    source = report_at(tmp_path)
    out = project / "outputs/cli"
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "report",
            "html",
            str(source),
            "--output",
            str(out),
            "--include-export",
            "sarif",
            "--include-export",
            "report-json",
            "--project-root",
            str(project),
        ],
    )
    assert result.exit_code == 0, result.output
    assert (out / "evidence/results.sarif").read_bytes() == (source / "results.sarif").read_bytes()
    assert (out / "evidence/report.json").read_bytes() == (source / "report.json").read_bytes()
    checked = runner.invoke(app, ["report", "validate-html", str(out)])
    assert checked.exit_code == 0, checked.output
    assert json.loads(checked.output)["files"] == 3
    again = runner.invoke(
        app, ["report", "html", str(source), "--output", str(out), "--project-root", str(project)]
    )
    assert again.exit_code == 5


@pytest.mark.parametrize("exports", [("unknown",), ("sarif", "sarif"), ("review-json",)])
def test_invalid_export_selection_fails_before_writing(
    project: Path, exports: tuple[str, ...]
) -> None:
    out = project / "outputs/invalid"
    with pytest.raises(ValueError):
        renderer.write_html_report(
            project=project, report_root=project / "absent", output=out, exports=exports
        )
    assert not out.exists()


@pytest.mark.parametrize("marker", renderer.PROTECTED_MARKERS)
def test_output_refuses_protected_ancestors(project: Path, marker: str) -> None:
    parent = project / "outputs/protected"
    parent.mkdir()
    (parent / marker).write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="finalized"):
        renderer.write_html_report(
            project=project, report_root=project / "absent", output=parent / "new"
        )
    assert not (parent / "new").exists()


@pytest.mark.parametrize(
    "mutation", ["html", "extra", "missing", "export", "manifest", "empty-directory"]
)
def test_package_tamper_rejected(project: Path, tmp_path: Path, mutation: str) -> None:
    source = report_at(tmp_path)
    out = project / "outputs/valid"
    renderer.write_html_report(project=project, report_root=source, output=out, exports=("sarif",))
    if mutation == "html":
        (out / "report.html").write_text("tampered", encoding="utf-8")
    elif mutation == "extra":
        (out / "extra.txt").write_text("extra", encoding="utf-8")
    elif mutation == "missing":
        (out / "evidence/results.sarif").unlink()
    elif mutation == "export":
        (out / "evidence/results.sarif").write_text("{}", encoding="utf-8")
    elif mutation == "empty-directory":
        (out / "evidence/nested").mkdir()
    else:
        raw = json.loads((out / "html-manifest.json").read_bytes())
        raw["entries"][0]["path"] = "../outside"
        (out / "html-manifest.json").write_bytes(json_bytes(raw))
    with pytest.raises((ValueError, OSError)):
        renderer.validate_html_report(out)


@pytest.mark.parametrize(
    "mutation", ["duplicate-key", "malformed", "corrupt-report", "unmanifested", "too-large"]
)
def test_input_refuses_unsafe_or_invalid_evidence(
    project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    source = report_at(tmp_path)
    if mutation == "duplicate-key":
        raw = (source / "report.json").read_bytes()
        (source / "report.json").write_bytes(b'{"contract":"common-report-v1",' + raw[1:])
    elif mutation == "malformed":
        (source / "results.sarif").write_bytes(b"{broken")
    elif mutation == "corrupt-report":
        (source / "report.json").write_bytes(b"{}")
    elif mutation == "unmanifested":
        (source / "extra.txt").write_text("extra", encoding="utf-8")
    else:
        monkeypatch.setitem(presentation.REPORT_LIMITS, "report.json", 10)
    out = project / "outputs/invalid"
    with pytest.raises((ValueError, OSError)):
        renderer.write_html_report(project=project, report_root=source, output=out)
    assert not out.exists()


def test_source_change_during_render_refuses_publication(
    project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = report_at(tmp_path)
    original = renderer.render_html

    def changed(inputs: presentation.PresentationInputs, exports: Sequence[str] = ()) -> bytes:
        raw = original(inputs, exports)
        (source / "report.json").write_bytes(b"{}")
        return raw

    monkeypatch.setattr(renderer, "render_html", changed)
    with pytest.raises(ValueError, match="changed"):
        renderer.write_html_report(
            project=project, report_root=source, output=project / "outputs/no"
        )
    assert not (project / "outputs/no").exists()


def test_html_budget_refuses_instead_of_truncating(
    project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = report_at(tmp_path)
    monkeypatch.setattr(renderer, "MAX_HTML_BYTES", 100)
    with pytest.raises(ValueError, match="budget"):
        renderer.write_html_report(
            project=project, report_root=source, output=project / "outputs/no"
        )
    assert not (project / "outputs/no").exists()


def test_bound_review_and_native_confidence_survive(
    project: Path, tmp_path: Path, review_inputs: tuple[Path, Path, dict[str, Any]]
) -> None:
    report, batch, _ = review_inputs
    sidecar = tmp_path / "review"
    write_review(project=ROOT, report_root=report, batch_path=batch, output=sidecar)
    before = tree(report), tree(sidecar)
    out = project / "outputs/public"
    renderer.write_html_report(
        project=project,
        report_root=report,
        review_root=sidecar,
        output=out,
        exports=("review-json",),
    )
    text = (out / "report.html").read_text(encoding="utf-8")
    assert "claim-not-substantiated" in text and "ai-assistant" in text
    assert "Review decision" in text and "proposed" in text
    assert "Original normalized finding" in text and "Native confidence" in text
    assert "Per-file completion" not in text or "not-observable" in text
    assert "Repetition 1" in text and "Repetition 3" in text
    assert (out / "evidence/review.json").read_bytes() == (sidecar / "review.json").read_bytes()
    assert (tree(report), tree(sidecar)) == before


def test_reject_review_bound_to_another_report(
    project: Path, tmp_path: Path, review_inputs: tuple[Path, Path, dict[str, Any]]
) -> None:
    report, batch, _ = review_inputs
    sidecar = tmp_path / "review"
    write_review(project=ROOT, report_root=report, batch_path=batch, output=sidecar)
    other = report_at(tmp_path / "other")
    with pytest.raises(ValueError, match="another"):
        renderer.write_html_report(
            project=project, report_root=other, review_root=sidecar, output=project / "outputs/no"
        )


def test_untrusted_text_is_inert(project: Path, tmp_path: Path) -> None:
    source = report_at(tmp_path)
    raw = json.loads((source / "report.json").read_bytes())
    payload = '</style><script>alert(1)</script><img src="https://example.invalid/leak">\u202e'
    raw["sources"][0]["label"] = payload
    data = json_bytes(raw)
    (source / "report.json").write_bytes(data)
    manifest = json.loads((source / "report-manifest.json").read_bytes())
    entry = next(e for e in manifest["entries"] if e["path"] == "report.json")
    entry.update(sha256=hashlib.sha256(data).hexdigest(), bytes=len(data))
    (source / "report-manifest.json").write_bytes(json_bytes(manifest))
    out = project / "outputs/escaped"
    renderer.write_html_report(project=project, report_root=source, output=out)
    text = (out / "report.html").read_text(encoding="utf-8")
    assert "<script>alert" not in text and "\u202e" not in text
    assert "&lt;script&gt;" in text and "\\u202e" in text
    assert not any(tag in {"script", "img"} for tag, _ in Page(text).tags)


def test_manifest_schema_matches_model() -> None:
    path = ROOT / "schemas/offline-html-report-v1/manifest.schema.json"
    assert json.loads(path.read_bytes()) == renderer.HtmlManifest.model_json_schema()


@pytest.mark.parametrize("location", ["input", "html", "export"])
def test_linked_file_refused(project: Path, tmp_path: Path, location: str) -> None:
    source = report_at(tmp_path)
    out = project / "outputs/report"
    if location != "input":
        renderer.write_html_report(
            project=project, report_root=source, output=out, exports=("sarif",)
        )
    target = {
        "input": source / "report.json",
        "html": out / "report.html",
        "export": out / "evidence/results.sarif",
    }[location]
    (tmp_path / "hardlink").hardlink_to(target)
    with pytest.raises(ValueError):
        if location == "input":
            renderer.write_html_report(project=project, report_root=source, output=out)
        else:
            renderer.validate_html_report(out)


def test_native_binding_requires_unambiguous_execution_identity(
    projection: tuple[PublicPilotSource, dict[str, Any]],
) -> None:
    source, sarif = projection
    inputs = presentation.PresentationInputs(
        report=cast(CommonReport, SimpleNamespace(sources=[source])),
        sarif=sarif,
        review=None,
        review_validation=None,
        files=(),
    )
    run = next(r for r in sarif["runs"] if r["properties"].get("agentsecEvidence/nativeRunId"))
    result = run["results"][0]
    assert renderer._native_finding(inputs, run, result) is not None
    run["properties"]["agentsecEvidence/nativeExecutionId"] = "different"
    assert renderer._native_finding(inputs, run, result) is None
    run["properties"]["agentsecEvidence/nativeExecutionId"] = source.summary.repetitions[
        0
    ].agent_execution_id
    findings = source.summary.repetitions[0].agent_findings
    findings.append(findings[0].model_copy(update={"record_id": "different-record"}))
    assert renderer._native_finding(inputs, run, result) is None


def test_source_and_logical_locations_are_visible() -> None:
    physical: dict[str, JsonValue] = {
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "<unsafe>.py"},
                    "region": {"startLine": 4, "endLine": 7},
                }
            }
        ]
    }
    text = renderer._locations(physical)
    assert "&lt;unsafe&gt;.py" in text and "<td>4</td>" in text
    assert "No source or logical location" in renderer._locations({})
    assert "pkg:pypi/test@1" in renderer._locations(
        {"locations": [{"logicalLocations": [{"fullyQualifiedName": "pkg:pypi/test@1"}]}]}
    )


@pytest.mark.parametrize("case_id", ["inline", "defaults", "missing-include", "malformed-python"])
def test_controlled_research_views_and_refusals(
    project: Path, tmp_path: Path, case_id: str
) -> None:
    cell = matrix(tmp_path, case_id)
    report = tmp_path / "research-report"
    write_common_report(project_root=ROOT, bundles=[cell], output=report)
    out = project / "outputs/research"
    renderer.write_html_report(project=project, report_root=report, output=out)
    text = (out / "report.html").read_text(encoding="utf-8")
    assert "common-report-v3" in text
    if case_id in {"inline", "defaults"}:
        assert "research" in text and "repository-policy" in text
        assert "Reported locations" in text
    else:
        assert "scanner not run" in text and "Finding count is unknown" in text
