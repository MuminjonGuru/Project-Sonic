"""Byte-bound governance for the existing fixed public pilot, not new admission."""

from pathlib import Path

from agentsec_evidence.benchmarks.dependency_plan import ADMITTED_PINS as DEPENDENCY_PINS
from agentsec_evidence.benchmarks.dependency_plan import database_pin
from agentsec_evidence.benchmarks.models import (
    MAX_PIN_BYTES,
    MAX_PLAN_BYTES,
    PublicPilotBenchmarkPlan,
    PublicPilotCell,
    PublicPilotPreview,
)
from agentsec_evidence.benchmarks.service import file_pin, implementation_pins
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.intake.source_preparation import SourcePreparationSpec
from agentsec_evidence.pilot.inputs import PLAN_PATH, PROFILE_PATH, SPEC_PATH, load_plan
from agentsec_evidence.research.models import (
    MAX_FILE_BYTES,
    load_research_profile,
    verify_rule_bytes,
)
from agentsec_evidence.research.retained import bounded_file, plain_path

PILOT_SHA256 = "fe82a84580cb069a97ff4ef3eb64e9b0746e28601bd8764e7cd8afe7bb327196"
EXTRA_PINS = {
    p: digest
    for p, digest in DEPENDENCY_PINS.items()
    if p.startswith("schemas/") or p == "pyproject.toml"
}
EXTRA_PINS["schemas/vendor/oasis/sarif-schema-2.1.0.json"] = (
    "ad6db49878699b091f3eeb765b6e29e92a34bad4da88664d000c923b549c3a25"
)


def build_public_pilot_plan(
    project: Path,
    *,
    plan_id: str,
    cache_path: str,
    rule_source: str,
    database: str,
) -> PublicPilotBenchmarkPlan:
    project = plain_path(project, directory=True)
    raw = bounded_file(project / PLAN_PATH, MAX_PIN_BYTES)
    if sha256_bytes(raw) != PILOT_SHA256:
        raise ValueError("Pilot admission changed; re-pinning does not grant admission")
    admitted = load_plan(project)
    expected = {**admitted.pins, **EXTRA_PINS, PLAN_PATH: PILOT_SHA256}
    pins = tuple(file_pin(p, bounded_file(project / p, MAX_PIN_BYTES)) for p in sorted(expected))
    if any(p.sha256 != expected[p.path] for p in pins):
        raise ValueError("Protected pilot validation input changed")
    # Validate lexical paths before any filesystem reads, even for preparation arguments.
    from agentsec_evidence.agents.validation import canonical_artifact_path

    for path in (cache_path, rule_source):
        canonical_artifact_path(path)
        if not path.startswith("workspace/") or path.startswith("workspace/benchmarks/"):
            raise ValueError("Pilot inputs require a separate private workspace path")
        plain_path(project / path, directory=True)
    spec = SourcePreparationSpec.model_validate_json(
        bounded_file(project / SPEC_PATH, MAX_PIN_BYTES)
    )
    cache_hashes = {
        "commit.json": spec.commit_response_sha256,
        "tree-exact.json": spec.tree_response_sha256,
        "source.zip": spec.archive_sha256,
    }
    cache = tuple(
        file_pin(p, bounded_file(project / cache_path / p, 16 * 1024**2))
        for p in sorted(cache_hashes)
    )
    if any(p.sha256 != cache_hashes[p.path] for p in cache):
        raise ValueError("Cached pilot source differs from fixed admission")
    profile = load_research_profile(bounded_file(project / PROFILE_PATH, MAX_PIN_BYTES))
    rules = {
        r.source_path: bounded_file(project / rule_source / r.source_path, MAX_FILE_BYTES)
        for r in profile.rules
    }
    license_raw = bounded_file(project / rule_source / "LICENSE", MAX_FILE_BYTES)
    verify_rule_bytes(profile, rules, license_bytes=license_raw)
    return PublicPilotBenchmarkPlan(
        plan_id=plan_id,
        pins=pins,
        implementation=implementation_pins(project),
        cache_path=cache_path,
        rule_source=rule_source,
        cache_files=cache,
        rule_files=tuple(
            file_pin(p, data) for p, data in sorted({**rules, "LICENSE": license_raw}.items())
        ),
        database=database_pin(project, database),
    )


def validate_public_pilot_plan(
    project: Path,
    path: Path,
    raw: bytes,
    plan: PublicPilotBenchmarkPlan,
) -> PublicPilotPreview:
    expected = build_public_pilot_plan(
        project,
        plan_id=plan.plan_id,
        cache_path=plan.cache_path,
        rule_source=plan.rule_source,
        database=plan.database.path,
    )
    if plan != expected:
        raise ValueError("Pilot plan differs from admitted resources or current implementation")
    digest = semantic_hash(plan.model_dump(mode="json"))
    if (
        bounded_file(path, MAX_PLAN_BYTES) != raw
        or implementation_pins(project) != plan.implementation
    ):
        raise ValueError("Pilot plan changed during validation")
    return PublicPilotPreview(
        plan_id=plan.plan_id,
        plan_sha256=sha256_bytes(raw),
        plan_semantic_sha256=digest,
        treatment_sha256=semantic_hash(
            {
                "pins": [p.model_dump(mode="json") for p in plan.pins],
                "cache": [p.model_dump(mode="json") for p in plan.cache_files],
                "rules": [p.model_dump(mode="json") for p in plan.rule_files],
                "database": plan.database.model_dump(mode="json"),
            }
        ),
        implementation_sha256=semantic_hash(
            [p.model_dump(mode="json") for p in plan.implementation]
        ),
        cells=(PublicPilotCell(cell_id=semantic_hash({"plan": digest, "case": plan.case_id})),),
    )
