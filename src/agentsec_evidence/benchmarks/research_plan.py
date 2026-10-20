"""Govern the original controlled suppression cases, not a new detector benchmark."""

from pathlib import Path
from typing import Any, cast

from agentsec_evidence.agents.validation import canonical_artifact_path, load_agent_json
from agentsec_evidence.benchmarks.models import (
    MAX_PIN_BYTES,
    MAX_PLAN_BYTES,
    ResearchBenchmarkPlan,
    ResearchCase,
    ResearchCell,
    ResearchPreview,
)
from agentsec_evidence.benchmarks.service import ADMITTED_PINS as ENVIRONMENT_PINS
from agentsec_evidence.benchmarks.service import file_pin, implementation_pins
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.research.controlled import ADMITTED_PINS, PROFILE_PATH, REGISTRY_PATH
from agentsec_evidence.research.models import (
    MAX_FILE_BYTES,
    load_research_profile,
    verify_rule_bytes,
)
from agentsec_evidence.research.retained import bounded_file, plain_path


def build_research_plan(project: Path, *, plan_id: str, rule_source: str) -> ResearchBenchmarkPlan:
    project = plain_path(project, directory=True)
    canonical_artifact_path(rule_source)
    if not rule_source.startswith("workspace/") or rule_source.startswith("workspace/benchmarks/"):
        raise ValueError("Rules require a separate private workspace path")
    plain_path(project / rule_source, directory=True)
    expected = {
        **ADMITTED_PINS,
        **{p: ENVIRONMENT_PINS[p] for p in ("pyproject.toml", "uv.lock")},
    }
    raw = {p: bounded_file(project / p, MAX_PIN_BYTES) for p in sorted(expected)}
    if any(sha256_bytes(data) != expected[p] for p, data in raw.items()):
        raise ValueError("Controlled admission changed; re-pinning does not grant admission")
    profile = load_research_profile(raw[PROFILE_PATH])
    rules = {
        r.source_path: bounded_file(project / rule_source / r.source_path, MAX_FILE_BYTES)
        for r in profile.rules
    }
    license_raw = bounded_file(project / rule_source / "LICENSE", MAX_FILE_BYTES)
    verify_rule_bytes(profile, rules, license_bytes=license_raw)
    registry = cast(dict[str, Any], load_agent_json(raw[REGISTRY_PATH], max_bytes=MAX_PIN_BYTES))
    if (
        registry.get("role") != "development-not-held-out"
        or registry.get("target_execution") is not False
    ):
        raise ValueError("Only the original controlled development registry is admitted")
    return ResearchBenchmarkPlan(
        plan_id=plan_id,
        pins=tuple(file_pin(p, data) for p, data in raw.items()),
        implementation=implementation_pins(project),
        rule_source=rule_source,
        rule_files=tuple(
            file_pin(p, data) for p, data in sorted({**rules, "LICENSE": license_raw}.items())
        ),
        cases=tuple(
            ResearchCase(
                case_id=case["id"],
                case_sha256=semantic_hash(case),
                internal_repetitions=2 if case.get("repeat") is True else 1,
            )
            for case in registry["cases"]
        ),
    )


def validate_research_plan(
    project: Path, path: Path, raw: bytes, plan: ResearchBenchmarkPlan
) -> ResearchPreview:
    expected = build_research_plan(project, plan_id=plan.plan_id, rule_source=plan.rule_source)
    if plan != expected:
        raise ValueError("Research plan differs from admitted inputs or current implementation")
    if (
        bounded_file(path, MAX_PLAN_BYTES) != raw
        or implementation_pins(project) != plan.implementation
    ):
        raise ValueError("Research inputs changed during validation")
    digest = semantic_hash(plan.model_dump(mode="json"))
    return ResearchPreview(
        plan_id=plan.plan_id,
        plan_sha256=sha256_bytes(raw),
        plan_semantic_sha256=digest,
        treatment_sha256=semantic_hash(
            {
                "pins": [p.model_dump(mode="json") for p in plan.pins],
                "rules": [p.model_dump(mode="json") for p in plan.rule_files],
                "cases": [c.model_dump(mode="json") for c in plan.cases],
            }
        ),
        implementation_sha256=semantic_hash(
            [p.model_dump(mode="json") for p in plan.implementation]
        ),
        cells=tuple(
            ResearchCell(
                **case.model_dump(mode="json"),
                cell_id=semantic_hash({"plan": digest, "case": case.case_id}),
            )
            for case in plan.cases
        ),
    )
