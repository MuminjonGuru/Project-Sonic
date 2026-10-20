"""Small independently calculable measurements with explicit unknown/zero semantics."""

from collections.abc import Iterable
from typing import Literal

from agentsec_evidence.dependencies.models import AdvisoryMatch
from agentsec_evidence.scoring.models import Metric


def ratio(
    name: str,
    numerator: int | None,
    denominator: int | None,
    *,
    unit: str,
    eligibility: str,
    limitation: str,
    excluded: int = 0,
    unknown: int | None = 0,
) -> Metric:
    status: Literal["unknown", "undefined", "measured"] = (
        "unknown"
        if numerator is None or denominator is None
        else "undefined"
        if denominator == 0
        else "measured"
    )
    return Metric(
        name=name,
        status=status,
        numerator=numerator,
        denominator=denominator,
        value=numerator / denominator if numerator is not None and denominator else None,
        unit=unit,
        eligibility=eligibility,
        excluded=excluded,
        unknown=unknown,
        limitation=limitation,
    )


def count(name: str, value: int | None, unit: str, limitation: str) -> Metric:
    return Metric(
        name=name,
        status="measured" if value is not None else "unknown",
        numerator=value,
        denominator=None,
        value=float(value) if value is not None else None,
        unit=unit,
        eligibility="Observed records in this row only; no pooling across paths or repeats",
        excluded=0,
        unknown=None if value is None else 0,
        limitation=limitation,
    )


def not_applicable(name: str, unit: str, reason: str) -> Metric:
    return Metric(
        name=name,
        status="not-applicable",
        numerator=None,
        denominator=None,
        value=None,
        unit=unit,
        eligibility=reason,
        excluded=0,
        unknown=0,
        limitation=reason,
    )


def retained_sets[ItemT](
    expected: set[ItemT],
    observed: set[ItemT] | None,
) -> tuple[int | None, int, int | None, int | None]:
    """Return retained, eligible, missing and unexpected counts; duplicates are not identities."""
    if observed is None:
        return None, len(expected), None, None
    return (
        len(expected & observed),
        len(expected),
        len(expected - observed),
        len(observed - expected),
    )


def condition_outcomes(
    expected: dict[str, bool], observed: set[str], *, analysis_eligible: bool
) -> dict[str, int | None]:
    """Only explicit condition IDs are scored; failures never manufacture true negatives."""
    if not analysis_eligible:
        return {"tp": None, "fp": None, "fn": None, "tn": None, "unscored": len(expected)}
    return {
        "tp": sum(present and key in observed for key, present in expected.items()),
        "fp": sum(not present and key in observed for key, present in expected.items()),
        "fn": sum(present and key not in observed for key, present in expected.items()),
        "tn": sum(not present and key not in observed for key, present in expected.items()),
        "unscored": 0,
    }


def advisory_sets(
    matches: Iterable[AdvisoryMatch],
    expected: set[tuple[str, str, str]],
) -> tuple[set[tuple[str, str, str]], set[tuple[str, str, str]]]:
    """Alias closure affects advisory identity only, never package name/version identity."""
    groups: list[set[str]] = []
    records = list(matches)
    for record in records:
        incoming = {record.canonical_advisory, *record.aliases, *record.original_ids}
        touched = [group for group in groups if group & incoming]
        for group in touched:
            incoming.update(group)
            groups.remove(group)
        groups.append(incoming)
    aliases = {identity: min(group) for group in groups for identity in group}
    observed = {(m.name, m.version, aliases[m.canonical_advisory]) for m in records}
    oracle = {
        (name, version, aliases.get(advisory, advisory)) for name, version, advisory in expected
    }
    return observed, oracle


def field_retention(
    fields: Iterable[tuple[str, object, object, bool]],
) -> dict[str, list[str]]:
    """Separate missing, incorrect and explicitly unrepresented fields."""
    result: dict[str, list[str]] = {
        key: [] for key in ("preserved", "incorrect", "missing", "unrepresented", "not-present")
    }
    for name, expected, observed, represented in fields:
        category = (
            "not-present"
            if expected is None
            else "unrepresented"
            if not represented
            else "missing"
            if observed is None
            else "preserved"
            if expected == observed
            else "incorrect"
        )
        result[category].append(name)
    return result
