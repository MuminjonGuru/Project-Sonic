"""Admit the four existing dependency input boundaries without widening older plans."""

from pathlib import Path

from agentsec_evidence.benchmarks.dependency_mutation_plan import (
    ADMITTED_MUTATION_PINS,
    EXPECTATIONS,
)
from agentsec_evidence.benchmarks.dependency_plan import build_dependency_plan
from agentsec_evidence.benchmarks.models import (
    MAX_PIN_BYTES,
    MAX_PLAN_BYTES,
    DependencyBoundaryCase,
    DependencyBoundaryCaseId,
    DependencyBoundaryCell,
    DependencyBoundaryPlan,
    DependencyBoundaryPreview,
    PlanFile,
)
from agentsec_evidence.benchmarks.service import file_pin, implementation_pins
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.dependencies.execution import OSV_IMAGE, SYFT_IMAGE
from agentsec_evidence.research.retained import bounded_file, plain_path

INPUT_PINS: dict[DependencyBoundaryCaseId, str] = {
    "dev-dependency-empty-v1": "50e8bd1f687fc71872a80b9921fb9e4cab9906a892b5251b7945dd1305735656",
    "dev-dependency-unresolved-v1": (
        "87848982234c6ebab3b0991891e1f7df1fd817356f247deed9afcb90ffa07175"
    ),
    "dev-dependency-malformed-v1": (
        "7d6c9d13c4511c141b84220bacade8daaebb9de7e8b68fce4243e2c10836ba9b"
    ),
    "dev-dependency-unsupported-v1": (
        "a9956bfd07161a8c44a77a756a7836036405906f2c87c9ff497701ad3efaaa6a"
    ),
}
CASE_ROOTS = {
    key: "test_cases/development/" + key.removeprefix("dev-").removesuffix("-v1")
    for key in INPUT_PINS
}
PARSER_FAILURES = {"dev-dependency-malformed-v1", "dev-dependency-unsupported-v1"}


def boundary_inputs(root: Path, case_id: DependencyBoundaryCaseId) -> tuple[PlanFile, ...]:
    plain_path(root, directory=True)
    if {p.name for p in root.iterdir()} != {"uv.lock"}:
        raise ValueError("Unadmitted dependency boundary input entry")
    pin = file_pin("uv.lock", bounded_file(root / "uv.lock", MAX_PIN_BYTES))
    if pin.sha256 != INPUT_PINS[case_id]:
        raise ValueError("Dependency boundary input changed; re-pinning is not admission")
    return (pin,)


def build_dependency_boundary_plan(
    project: Path, *, plan_id: str, case_ids: tuple[str, ...], database: str, repetitions: int = 1
) -> DependencyBoundaryPlan:
    project = plain_path(project, directory=True)
    base = build_dependency_plan(
        project,
        plan_id=plan_id,
        case_ids=("dev-dependency-basic-v1",),
        database=database,
        repetitions=repetitions,
    )
    oracle = file_pin(EXPECTATIONS, bounded_file(project / EXPECTATIONS, MAX_PIN_BYTES))
    if oracle.sha256 != ADMITTED_MUTATION_PINS[EXPECTATIONS]:
        raise ValueError("Boundary expectation helper changed; re-pinning is not admission")
    cases: dict[str, DependencyBoundaryCase] = {
        key: DependencyBoundaryCase(
            case_id=key,
            files=boundary_inputs(project / path / "target", key),
            expectation_sha256=oracle.sha256,
        )
        for key, path in CASE_ROOTS.items()
    }
    if any(c not in cases for c in case_ids):
        raise ValueError("Unknown or unadmitted dependency boundary case")
    return DependencyBoundaryPlan(
        plan_id=plan_id,
        pins=tuple(sorted((*base.pins, oracle), key=lambda p: p.path)),
        implementation=base.implementation,
        database=base.database,
        cases=tuple(cases[c] for c in case_ids),
        repetitions=repetitions,
    )


def validate_dependency_boundary_plan(
    project: Path, path: Path, raw: bytes, plan: DependencyBoundaryPlan
) -> DependencyBoundaryPreview:
    expected = build_dependency_boundary_plan(
        project,
        plan_id=plan.plan_id,
        case_ids=tuple(c.case_id for c in plan.cases),
        database=plan.database.path,
        repetitions=plan.repetitions,
    )
    if plan != expected:
        raise ValueError(
            "Boundary plan differs from admitted inputs, expectations or implementation"
        )
    digest = semantic_hash(plan.model_dump(mode="json"))
    cells = tuple(
        DependencyBoundaryCell(
            cell_id=semantic_hash({"plan": digest, "case": case.case_id, "repetition": repeat}),
            case_id=case.case_id,
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
        raise ValueError("Boundary plan changed during validation")
    return DependencyBoundaryPreview(
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
