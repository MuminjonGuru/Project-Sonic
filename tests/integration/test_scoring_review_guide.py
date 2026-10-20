from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_offline_scoring import no_execution, scoring_plan
from test_semgrep_benchmark import fake_producer, plan_file, tree
from test_semgrep_benchmark import project as project

from agentsec_evidence.benchmarks import attempts
from agentsec_evidence.core.identity import sha256_file
from agentsec_evidence.scoring.review_guide import write_review_guide
from agentsec_evidence.scoring.service import write_scores


def test_existing_bundle_is_preserved_and_review_repeats_offline(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_producer(monkeypatch, project)
    run = attempts.run_benchmark(project, plan_file(project, 1))
    plan = scoring_plan(project, Path(run.session))
    (project / "outputs").mkdir(exist_ok=True)
    source = project / "outputs/scored"
    write_scores(project, plan, source)
    before = tree(source)
    no_execution(monkeypatch)
    receipt = write_review_guide(project, source, project / "outputs/guide-1")
    write_review_guide(project, source, project / "outputs/guide-2")
    assert tree(source) == before
    assert tree(project / "outputs/guide-1") == tree(project / "outputs/guide-2")
    assert (
        receipt["native_sources_replayed"] is False and receipt["student_acceptance"] == "pending"
    )
    raw = json.loads((project / "outputs/guide-1/review-guide-manifest.json").read_bytes())
    for name, digest in raw["files"].items():
        assert sha256_file(project / "outputs/guide-1" / name) == digest
    with pytest.raises(ValueError, match="new"):
        write_review_guide(project, source, project / "outputs/guide-1")
    with pytest.raises(ValueError, match="finalized"):
        write_review_guide(project, source, project / "outputs/guide-1/nested")
    with pytest.raises(ValueError):
        write_review_guide(project, source, source / "nested")
    assert tree(source) == before
    (source / "SUMMARY.md").write_bytes(b"tampered\n")
    with pytest.raises(ValueError, match="integrity"):
        write_review_guide(project, source, project / "outputs/tampered")
    assert not (project / "outputs/tampered").exists()


@pytest.mark.parametrize(
    "marker",
    [
        "review-manifest.json",
        "scoring-manifest.json",
        "validation.json",
        "report-manifest.json",
        "evidence-manifest.json",
    ],
)
def test_protected_destinations_refused_before_reading_source(project: Path, marker: str) -> None:
    source = project / "workspace/empty-source"
    source.mkdir()
    parent = project / "outputs/protected"
    parent.mkdir(parents=True)
    (parent / marker).write_bytes(b"{}")
    before = tree(parent)
    with pytest.raises(ValueError, match="finalized"):
        write_review_guide(project, source, parent / "guide")
    assert tree(parent) == before


def test_non_outputs_destination_is_refused(project: Path) -> None:
    with pytest.raises(ValueError, match="existing outputs"):
        write_review_guide(project, project / "workspace", project / "workspace/new-guide")
