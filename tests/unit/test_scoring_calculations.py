from __future__ import annotations

import pytest

from agentsec_evidence.dependencies.models import AdvisoryMatch
from agentsec_evidence.scoring.calculations import (
    advisory_sets,
    field_retention,
    ratio,
    retained_sets,
)
from agentsec_evidence.scoring.models import Metric, ScorePlan, SessionInput


def test_condition_outcomes_do_not_turn_failures_into_true_negatives() -> None:
    from agentsec_evidence.scoring.calculations import condition_outcomes

    expected = {"positive": True, "corrected": False, "missed": True, "near-miss": False}
    assert condition_outcomes(expected, {"positive", "near-miss"}, analysis_eligible=True) == {
        "tp": 1,
        "fp": 1,
        "fn": 1,
        "tn": 1,
        "unscored": 0,
    }
    assert condition_outcomes(expected, set(), analysis_eligible=False) == {
        "tp": None,
        "fp": None,
        "fn": None,
        "tn": None,
        "unscored": 4,
    }


@pytest.mark.parametrize(
    ("n", "d", "status", "value"),
    [
        (3, 4, "measured", 0.75),
        (0, 4, "measured", 0),
        (0, 0, "undefined", None),
        (None, 4, "unknown", None),
        (None, 0, "unknown", None),
        (None, None, "unknown", None),
    ],
)
def test_ratio_unknown_and_zero(
    n: int | None, d: int | None, status: str, value: float | None
) -> None:
    result = ratio(
        "test",
        n,
        d,
        unit="identities",
        eligibility="Independent finite example",
        limitation="Test only",
    )
    assert result.status == status and result.value == value


@pytest.mark.parametrize(("n", "d"), [(5, 4), (-1, 4), (1, 0), (True, 1)])
def test_ratio_rejects_bad_counts(n: int, d: int) -> None:
    with pytest.raises(ValueError):
        ratio("test", n, d, unit="identities", eligibility="Example", limitation="Test")


def test_ratio_rejects_tampered_value() -> None:
    metric = ratio("test", 1, 2, unit="identity", eligibility="Example", limitation="Test")
    raw = metric.model_dump()
    raw["value"] = 1
    with pytest.raises(ValueError):
        Metric.model_validate(raw)


def test_empty_ratio_cannot_be_relabelled_measured() -> None:
    raw = ratio(
        "empty", 0, 0, unit="cases", eligibility="Empty set", limitation="Test"
    ).model_dump()
    raw["status"] = "measured"
    with pytest.raises(ValueError):
        Metric.model_validate(raw)


def test_identity_duplicates_versions_and_missing_evidence() -> None:
    expected = {("requests", "1"), ("requests", "2")}
    observed = set([("requests", "1"), ("requests", "1"), ("other", "3")])
    assert retained_sets(expected, observed) == (1, 2, 1, 1)
    assert retained_sets(expected, None) == (None, 2, None, None)
    assert retained_sets(set(), set()) == (0, 0, 0, 0)


def match(advisory: str, aliases: list[str], version: str = "1") -> AdvisoryMatch:
    return AdvisoryMatch(
        package_pointer="/results/0/packages/0",
        name="example",
        version=version,
        canonical_advisory=advisory,
        original_ids=[advisory],
        aliases=aliases,
    )


def test_alias_transitivity_occurrences_and_versions() -> None:
    records = [
        match("GHSA-A", ["CVE-1"]),
        match("OSV-B", ["CVE-1"]),
        match("GHSA-A", ["CVE-1"]),
        match("GHSA-A", ["CVE-1"], "2"),
    ]
    observed, expected = advisory_sets(records, {("example", "1", "OSV-B")})
    assert len(observed) == 2 and len(observed & expected) == 1
    assert advisory_sets(reversed(records), {("example", "1", "OSV-B")}) == (observed, expected)


def test_field_retention_separates_missing_incorrect_and_unrepresented() -> None:
    result = field_retention(
        [
            ("correct", "A", "A", True),
            ("wrong", "A", "B", True),
            ("missing", "A", None, True),
            ("confidence", "high", None, False),
            ("not-present", None, None, False),
            ("false-is-a-value", False, False, True),
        ]
    )
    assert result == {
        "preserved": ["correct", "false-is-a-value"],
        "incorrect": ["wrong"],
        "missing": ["missing"],
        "unrepresented": ["confidence"],
        "not-present": ["not-present"],
    }


def test_duplicate_session_rejected() -> None:
    session = SessionInput(
        session="a" * 64, plan_sha256="b" * 64, validation_sha256="c" * 64, role="development"
    )
    with pytest.raises(ValueError):
        ScorePlan(
            sessions=(session, session),
            selection_rationale="Finite independently testable example",
            exclusions=(),
        )
