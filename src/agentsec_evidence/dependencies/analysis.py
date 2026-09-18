from __future__ import annotations

from collections import defaultdict
from typing import cast

from pydantic import JsonValue

from agentsec_evidence.core.identity import semantic_hash
from agentsec_evidence.dependencies.models import (
    DependencyScope,
    Fraction,
    StageComparison,
    StageEvidence,
)


def fraction(numerator: int, denominator: int) -> Fraction:
    return Fraction(
        numerator=numerator,
        denominator=denominator,
        value=numerator / denominator if denominator else None,
    )


def package_set(stage: StageEvidence) -> set[tuple[str, str]]:
    return {key for item in stage.observations if (key := item.projection) is not None}


def match_set(stage: StageEvidence, scope: DependencyScope) -> set[tuple[str, str, str]]:
    return {
        (item.name, item.version, item.canonical_advisory)
        for item in stage.matches
        if (item.name, item.version) in scope.eligible
    }


def compare_stages(
    left: StageEvidence,
    right: StageEvidence,
    scope: DependencyScope,
) -> StageComparison:
    eligible = set(scope.eligible)
    left_all, right_all = package_set(left), package_set(right)
    left_set, right_set = left_all & eligible, right_all & eligible
    left_sources: dict[tuple[str, str], set[str]] = defaultdict(set)
    right_sources: dict[tuple[str, str], set[str]] = defaultdict(set)
    for stage, values in ((left, left_sources), (right, right_sources)):
        for item in stage.observations:
            key = item.projection
            if key:
                values[key].update(item.source_qualifiers.values())
    comparable = left.state == right.state == "complete"
    return StageComparison(
        left=left.stage,
        right=right.stage,
        comparable=comparable,
        package_projection_retention=(
            fraction(len(left_set & right_set), len(left_set)) if comparable else None
        ),
        missing=sorted(left_set - right_set),
        added=sorted(right_set - left_set),
        left_out_of_scope=sorted(left_all - eligible),
        right_out_of_scope=sorted(right_all - eligible),
        source_qualifier_losses=sorted(
            key for key in left_set & right_set if left_sources[key] - right_sources[key]
        ),
        missing_identifiers=[
            item.native_pointer
            for item in right.observations
            if not item.purl and right.stage == "cyclonedx"
        ],
        limitations=[
            "Ratios use the predeclared PyPI name/version projection, not full qualified identity.",
            "Missing output alone cannot distinguish ingestion, filtering or reporting losses.",
            "Relationship and occurrence fidelity are not inferred from package retention.",
        ]
        + ([] if comparable else ["At least one stage is incomplete; ratios are withheld."]),
    )


SEMANTIC_VERSION = "dependency-semantic-v2"


def dependency_semantic_hash(
    stages: list[StageEvidence], scope: DependencyScope, *, version: str = SEMANTIC_VERSION
) -> str:
    if version not in {"dependency-semantic-v1", SEMANTIC_VERSION}:
        raise ValueError("Unsupported dependency semantic projection")
    values: list[JsonValue] = []
    for stage in sorted(stages, key=lambda item: item.stage):
        value = stage.model_dump(mode="json", exclude={"raw_sha256"})
        if stage.stage == "syft" and version == SEMANTIC_VERSION:
            # Syft emits uv optional extras from a map; their order carries no meaning.
            # Do not sort arbitrary arrays: trajectory and other sequence order may matter.
            for observation in value["observations"]:
                metadata = observation["context"].get("metadata", {})
                extras = metadata.get("extras") if isinstance(metadata, dict) else None
                if isinstance(extras, list):
                    for extra in extras:
                        if isinstance(extra, dict) and isinstance(extra.get("dependencies"), list):
                            extra["dependencies"] = sorted(
                                extra["dependencies"], key=lambda item: semantic_hash(item)
                            )
                    metadata["extras"] = sorted(extras, key=lambda item: semantic_hash(item))
        # These collections are sets of observations, not an execution trajectory.
        for key in ("observations", "relationships", "matches", "limitations"):
            value[key] = sorted(value[key], key=lambda item: semantic_hash(cast(JsonValue, item)))
        values.append(value)
    return semantic_hash(
        {
            "version": version,
            "scope": scope.model_dump(mode="json"),
            "stages": values,
        }
    )
