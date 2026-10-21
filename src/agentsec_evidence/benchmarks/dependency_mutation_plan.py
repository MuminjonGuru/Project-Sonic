"""Bind the three existing copied-SBOM transformations without widening old plans."""

from pathlib import Path

from agentsec_evidence.benchmarks.dependency_plan import build_dependency_plan
from agentsec_evidence.benchmarks.models import (
    MAX_PIN_BYTES,
    MAX_PLAN_BYTES,
    DependencyMutationCase,
    DependencyMutationCaseId,
    DependencyMutationCell,
    DependencyMutationPlan,
    DependencyMutationPreview,
)
from agentsec_evidence.benchmarks.service import file_pin, implementation_pins
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.dependencies.execution import OSV_IMAGE, SYFT_IMAGE
from agentsec_evidence.dependencies.mutations import Mutation
from agentsec_evidence.research.retained import bounded_file, plain_path

MUTATIONS: dict[DependencyMutationCaseId, Mutation] = {
    "dev-dependency-remove-component-v1": "remove-component",
    "dev-dependency-remove-purl-v1": "remove-purl",
    "dev-dependency-change-version-v1": "change-version",
}
TRANSFORM = "src/agentsec_evidence/dependencies/mutations.py"
EXPECTATIONS = "tools/verify_dependency_pilot.py"
ADMITTED_MUTATION_PINS = {
    TRANSFORM: "291f11741334806bde433578f8a21f6bbdf9dcc31897fdf247531635ea7f83ea",
    EXPECTATIONS: "cd50ed6d41bfc951fbfb5451fad8807796d1b505870045509bac0c3e4b80b218",
}


def build_dependency_mutation_plan(
    project: Path,
    *,
    plan_id: str,
    case_ids: tuple[str, ...],
    database: str,
    repetitions: int = 1,
) -> DependencyMutationPlan:
    project = plain_path(project, directory=True)
    base = build_dependency_plan(
        project,
        plan_id=plan_id,
        case_ids=("dev-dependency-basic-v1",),
        database=database,
        repetitions=repetitions,
    )
    extra = tuple(
        file_pin(p, bounded_file(project / p, MAX_PIN_BYTES))
        for p in sorted(ADMITTED_MUTATION_PINS)
    )
    if any(p.sha256 != ADMITTED_MUTATION_PINS[p.path] for p in extra):
        raise ValueError(
            "Mutation transformation/expectations changed; re-pinning is not admission"
        )
    cases: dict[str, DependencyMutationCase] = {
        case_id: DependencyMutationCase(
            case_id=case_id,
            mutation=mutation,
            files=base.cases[0].files,
            expectation_sha256=ADMITTED_MUTATION_PINS[EXPECTATIONS],
        )
        for case_id, mutation in MUTATIONS.items()
    }
    if any(c not in cases for c in case_ids):
        raise ValueError("Unknown or unadmitted dependency mutation")
    return DependencyMutationPlan(
        plan_id=plan_id,
        pins=tuple(sorted((*base.pins, *extra), key=lambda p: p.path)),
        implementation=base.implementation,
        database=base.database,
        cases=tuple(cases[c] for c in case_ids),
        repetitions=repetitions,
    )


def validate_dependency_mutation_plan(
    project: Path,
    path: Path,
    raw: bytes,
    plan: DependencyMutationPlan,
) -> DependencyMutationPreview:
    expected = build_dependency_mutation_plan(
        project,
        plan_id=plan.plan_id,
        case_ids=tuple(c.case_id for c in plan.cases),
        database=plan.database.path,
        repetitions=plan.repetitions,
    )
    if plan != expected:
        raise ValueError(
            "Mutation plan differs from admitted inputs, transformation or implementation"
        )
    digest = semantic_hash(plan.model_dump(mode="json"))
    cells = tuple(
        DependencyMutationCell(
            cell_id=semantic_hash({"plan": digest, "case": case.case_id, "repetition": repeat}),
            case_id=case.case_id,
            mutation=case.mutation,
            repetition=repeat,
            input_files=case.files,
            expectation_sha256=case.expectation_sha256,
        )
        for case in plan.cases
        for repeat in range(1, plan.repetitions + 1)
    )
    if (
        bounded_file(path, MAX_PLAN_BYTES) != raw
        or implementation_pins(project) != plan.implementation
    ):
        raise ValueError("Mutation plan changed during validation")
    return DependencyMutationPreview(
        plan_id=plan.plan_id,
        plan_sha256=sha256_bytes(raw),
        plan_semantic_sha256=digest,
        treatment_sha256=semantic_hash(
            {
                "pins": [p.model_dump(mode="json") for p in plan.pins],
                "database": plan.database.model_dump(mode="json"),
            }
        ),
        implementation_sha256=semantic_hash(
            [p.model_dump(mode="json") for p in plan.implementation]
        ),
        cells=cells,
        database=plan.database,
        tool_images=(OSV_IMAGE, SYFT_IMAGE),
        limits={
            "max_workers": 1,
            "cpus": 2,
            "memory_mb": 2048,
            "pids": 256,
            "timeout_seconds_per_stage": 120,
            "max_native_bytes": 64 * 1024**2,
        },
    )
