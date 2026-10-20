from __future__ import annotations

from pathlib import Path

import pytest

from agentsec_evidence.scoring.calculations import count, ratio
from agentsec_evidence.scoring.models import (
    MeasurementRow,
    Metric,
    Reference,
    ScorePlan,
    ScoreReport,
    SessionInput,
)
from agentsec_evidence.scoring.review_guide import render_review_guide, review_topics


def row(metric: Metric, **changes: object) -> MeasurementRow:
    raw = {
        "row_id": "a" * 64,
        "session": "b" * 64,
        "case_id": "controlled-example",
        "evidence_role": "development",
        "attempt_id": "attempt-example",
        "repetition": 1,
        "stage": "example",
        "state": "partial-analysis",
        "analysis_completeness": "incomplete",
        "metrics": (metric,),
        "observations": {},
        "references": (
            Reference(path="workspace/a file (1).json", sha256="c" * 64, pointer="/results/0"),
        ),
    }
    raw.update(changes)
    return MeasurementRow.model_validate(raw)


def metric(name: str, n: int | None, d: int | None = None) -> Metric:
    if d is not None:
        return ratio(
            name,
            n,
            d,
            unit="example-units",
            eligibility="finite fixture",
            limitation="No general accuracy claim",
        )
    return count(name, n, unit="example-units", limitation="No general accuracy claim")


@pytest.mark.parametrize(
    ("name", "n", "d", "topic"),
    [
        ("reported-path-coverage", 12, 26, "coverage"),
        ("analysis-completion", None, None, "coverage"),
        ("unrepresented-export-fields", 24, None, "exports"),
        ("incorrect-or-missing-export-fields", 1, None, "exports"),
        ("source-qualifier-losses", 159, None, "packages"),
        ("package-projection-retention", 3, 4, "packages"),
        ("matching-completion", None, None, "matching"),
        ("unsupported-package-observations", 1, None, "matching"),
        ("native-rule-reports", 4, None, "claims"),
        ("reported-package-advisory-pairs", 3, None, "claims"),
        ("semantic-agreement-to-first", 1, 2, "agreement"),
        ("finite-match-recall", 2, 3, "agreement"),
    ],
)
def test_evidence_driven_topics(name: str, n: int | None, d: int | None, topic: str) -> None:
    assert review_topics(row(metric(name, n, d))) == (topic,)


@pytest.mark.parametrize(("n", "d"), [(0, 0), (None, 4), (4, 4)])
def test_undefined_unknown_or_full_retention_is_not_a_measured_loss(n: int | None, d: int) -> None:
    assert review_topics(row(metric("package-projection-retention", n, d))) == ()


def test_added_identity_is_visible_even_when_retention_is_complete() -> None:
    assert review_topics(
        row(metric("package-projection-retention", 4, 4), observations={"added": [["new", "1"]]})
    ) == ("packages",)


def render(tmp_path: Path, rows: tuple[MeasurementRow, ...]) -> dict[str, bytes]:
    plan = ScorePlan(
        sessions=(
            SessionInput(
                session="b" * 64,
                plan_sha256="c" * 64,
                validation_sha256="d" * 64,
                role="development",
            ),
        ),
        selection_rationale="Finite development-only rendering test",
        exclusions=(),
    )
    report = ScoreReport(
        plan_sha256="e" * 64,
        analysis_sources=(),
        rows=rows,
        attempts=({"state": "execution-failed"}, {"state": "not-attempted"}),
        reviews=(),
        limitations=(),
    )
    return render_review_guide(
        report,
        plan,
        project=tmp_path,
        bundle=tmp_path / "outputs/source",
        output=tmp_path / "outputs/guide",
    )


def test_literal_untrusted_text_and_encoded_local_links(tmp_path: Path) -> None:
    payload = "![image](https://example.invalid/a) <script>bad()</script> `x` | next\nline"
    result = render(tmp_path, (row(metric("native-rule-reports", 4), case_id=payload),))
    details = result["DETAILS.md"].decode()
    assert "<script>" not in details and "![image]" not in details
    assert "&lt;script&gt;" in details and "&#124;" in details
    assert "workspace/a%20file%20%281%29.json" in details
    assert "pointer: /results/0" in details
    assert "not deduplication" in details


def test_unknowns_no_pilot_claim_and_repeats_remain_separate(tmp_path: Path) -> None:
    first = row(metric("matching-completion", None))
    second = row(metric("matching-completion", None), row_id="f" * 64, repetition=2)
    result = render(tmp_path, (first, second))
    summary = result["REVIEW.md"].decode()
    details = result["DETAILS.md"].decode()
    assert "one formative public pilot" not in summary
    assert "No review sidecar selected" in summary
    assert "execution-failed | 1" in summary and "not-attempted | 1" in summary
    assert "Student acceptance is not recorded" in summary
    assert "repetition 1" in details and "repetition 2" in details
    assert "| unknown | example-units |" in details
    assert result == render(tmp_path, (first, second))


def test_bidirectional_and_terminal_controls_render_visibly(tmp_path: Path) -> None:
    result = render(tmp_path, (row(metric("native-rule-reports", 1), case_id="a\u202eb\x1b[31m"),))
    details = result["DETAILS.md"].decode()
    assert "\u202e" not in details and "&#8238;" not in details
    assert "\x1b" not in details
    assert "U+202E" in details and "U+001B" in details
