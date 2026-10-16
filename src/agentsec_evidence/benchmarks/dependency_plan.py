"""Admit only the existing two successful-input dependency fixtures and frozen PyPI data."""

from pathlib import Path

from agentsec_evidence.benchmarks.models import (
    MAX_PIN_BYTES,
    MAX_PLAN_BYTES,
    DependencyBenchmarkPlan,
    DependencyCase,
    DependencyCaseId,
    DependencyCell,
    DependencyDatabase,
    DependencyPreview,
    PlanFile,
)
from agentsec_evidence.benchmarks.service import file_pin, implementation_pins
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes, sha256_file
from agentsec_evidence.dependencies.execution import OSV_IMAGE, SYFT_IMAGE
from agentsec_evidence.research.retained import bounded_file, plain_path

ORACLE = "test_cases/development/dependency-basic/expected.json"
DATABASE_SHA256 = "6f7b248e44eeadbf0d669c2e2842adc19bc1929f1b9da8ae2e69991dab3cbbdd"
CASE_ROOTS: dict[DependencyCaseId, str] = {
    "dev-dependency-basic-v1": "test_cases/development/dependency-basic",
    "dev-dependency-clean-v1": "test_cases/development/dependency-clean",
}
ADMITTED_PINS = {
    "configs/dependency/osv.toml": (
        "0ce7ce124bbe33592a7d166230971e220f7f59177b6b0e295983fe7506757871"
    ),
    "configs/dependency/syft.yaml": (
        "aff991297d3b515fe9fb0a8467cc26c3a419421aa0c5bdc61e74422ca84c18d7"
    ),
    "configs/dependency/tools.json": (
        "176c2099bc13a2c7d120c27ca014e91808bbcaba58bfa017d79b7e84cd6b8f96"
    ),
    ORACLE: "e0a700edf90a05b26df870c6514128709f75caf01fec4d6522ecfce9b00abb80",
    "schemas/vendor/cyclonedx/1.6/bom-1.6.schema.json": (
        "3e92dddbc30cf7f6a02b80f0942b1a4cfd4fb1c26f1dfc4310afa9d613cafb93"
    ),
    "schemas/vendor/cyclonedx/1.6/jsf-0.82.schema.json": (
        "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae"
    ),
    "schemas/vendor/cyclonedx/1.6/spdx.schema.json": (
        "baa9d3bd1ed57b6751b0887edead6b5063ff53ff7429cf85d476c6c94af0166e"
    ),
    "uv.lock": "b072464773b77a68d6f03345f6f913568773903671821eb6b61d4ea312fcfb6c",
    "pyproject.toml": "91179196237aeb58bae2b6a9c111d9f000346aad7c7c05d653c07c7beae3badd",
}
INPUT_PINS: dict[DependencyCaseId, dict[str, str]] = {
    "dev-dependency-basic-v1": {
        "osv-scanner.toml": "69764e8ed2408f003e024a946ea14d2788f91fef17a46b6472fd5f9375b213bc",
        "uv.lock": "32d3c26ddf91ec6265043b8d80b32fcce8867d2b94618a796808bdb83b1224f9",
    },
    "dev-dependency-clean-v1": {
        "uv.lock": "079d18587ef6708c332378eb514148c8195e6f44ad56f7113c9b112e7524b442",
    },
}


def dependency_inputs(root: Path, case_id: DependencyCaseId) -> tuple[PlanFile, ...]:
    plain_path(root, directory=True)
    pins = INPUT_PINS[case_id]
    if {p.name for p in root.iterdir()} != set(pins):
        raise ValueError("Unadmitted dependency target entry")
    files = tuple(file_pin(p, bounded_file(root / p, MAX_PIN_BYTES)) for p in sorted(pins))
    if any(f.sha256 != pins[f.path] for f in files):
        raise ValueError("Dependency fixture changed; re-pinning does not grant admission")
    return files


def database_pin(project: Path, relative: str) -> DependencyDatabase:
    # Validate the lexical path before touching it, then reject links in every component.
    candidate = DependencyDatabase(path=relative, bytes=1, sha256=DATABASE_SHA256)
    path = plain_path(project / candidate.path, directory=False)
    if not path.is_relative_to(project / "workspace") or not 0 < path.stat().st_size <= 2 * 1024**3:
        raise ValueError("Frozen dependency database outside bounds")
    size = path.stat().st_size
    digest = sha256_file(path)
    if digest != DATABASE_SHA256 or path.stat().st_size != size:
        raise ValueError("Frozen dependency database missing, changed or not admitted; no refresh")
    return DependencyDatabase(path=relative, bytes=size, sha256=digest)


def build_dependency_plan(
    project: Path,
    *,
    plan_id: str,
    case_ids: tuple[str, ...],
    database: str,
    repetitions: int = 1,
) -> DependencyBenchmarkPlan:
    project = plain_path(project, directory=True)
    pins = tuple(
        file_pin(p, bounded_file(project / p, MAX_PIN_BYTES)) for p in sorted(ADMITTED_PINS)
    )
    if any(f.sha256 != ADMITTED_PINS[f.path] for f in pins):
        raise ValueError("Dependency admission changed; re-pinning does not grant admission")
    cases: dict[str, DependencyCase] = {
        case_id: DependencyCase(
            case_id=case_id,
            files=dependency_inputs(project / relative / "target", case_id),
            expectation_sha256=ADMITTED_PINS[ORACLE],
        )
        for case_id, relative in CASE_ROOTS.items()
    }
    if any(case_id not in cases for case_id in case_ids):
        raise ValueError("Unknown or unadmitted dependency case")
    return DependencyBenchmarkPlan(
        plan_id=plan_id,
        pins=pins,
        implementation=implementation_pins(project),
        database=database_pin(project, database),
        cases=tuple(cases[c] for c in case_ids),
        repetitions=repetitions,
    )


def validate_dependency_plan(
    project: Path,
    path: Path,
    raw: bytes,
    plan: DependencyBenchmarkPlan,
) -> DependencyPreview:
    expected = build_dependency_plan(
        project,
        plan_id=plan.plan_id,
        case_ids=tuple(c.case_id for c in plan.cases),
        database=plan.database.path,
        repetitions=plan.repetitions,
    )
    if plan != expected:
        raise ValueError("Dependency plan differs from admitted inputs, database or implementation")
    digest = semantic_hash(plan.model_dump(mode="json"))
    cells = tuple(
        DependencyCell(
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
        raise ValueError("Dependency plan changed during validation")
    return DependencyPreview(
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
