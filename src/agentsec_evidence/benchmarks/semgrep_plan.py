"""Exact admission for the original first-slice fixture; no arbitrary targets or new rules."""

from pathlib import Path

from agentsec_evidence.benchmarks.models import (
    MAX_PIN_BYTES,
    MAX_PLAN_BYTES,
    PlanFile,
    SemgrepBenchmarkPlan,
    SemgrepCase,
    SemgrepCell,
    SemgrepExpectation,
    SemgrepPreview,
)
from agentsec_evidence.benchmarks.service import file_pin, implementation_pins
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.execution.config import ExecutionProfile, SemgrepToolConfig, load_toml_bytes
from agentsec_evidence.research.retained import bounded_file, plain_path

CASE_ROOT = "test_cases/development/semgrep-basic"
PROFILE = "configs/profiles/development.toml"
TOOL = "configs/tools/semgrep.toml"
RULE = "rules/project-authored/semgrep-first-slice.yml"
ADMITTED_PINS = {
    f"{CASE_ROOT}/case.toml": "5cd73ea9556f786f3b67a21a0e89ee6c8c26daf33f245c3af0587488ca3900c1",
    PROFILE: "a4d380d96cc7c67dff5a3334eefe6544e2fe2f2e2f6325eb6818fba8add6a240",
    TOOL: "b6c763fd1a4ce104ce3d2c321b8ed483ac0b39a2656f2a7d6ee38958e9b19ef2",
    RULE: "1acb7e395a6771ad58d7f0f9294dc50234d793642d72ab611ecd289ff583125d",
    "uv.lock": "b072464773b77a68d6f03345f6f913568773903671821eb6b61d4ea312fcfb6c",
    "pyproject.toml": "91179196237aeb58bae2b6a9c111d9f000346aad7c7c05d653c07c7beae3badd",
}
INPUT_PINS = {
    "clean.py": "496f21a3fd47f44970fda6d3379529ffe2f905f1d3c4bfe895c688c12773e13f",
    "ignored/ignored.py": "3c340cb33a9fe3156f0af4a6ed2ece9852c50110379b7ebcb77e7edd2c23377a",
    "vulnerable.py": "36dd5215721015da0ab2c113315f383587286d7d9e48905165dff621a5643eee",
}


def semgrep_inputs(root: Path) -> tuple[PlanFile, ...]:
    """Check exact names before descent, including hidden files and unexpected directories."""
    plain_path(root, directory=True)
    if {p.name for p in root.iterdir()} != {"clean.py", "vulnerable.py", "ignored"}:
        raise ValueError("Unadmitted Semgrep target entry")
    ignored = plain_path(root / "ignored", directory=True)
    if {p.name for p in ignored.iterdir()} != {"ignored.py"}:
        raise ValueError("Unadmitted Semgrep target entry")
    records = tuple(file_pin(p, bounded_file(root / p, MAX_PIN_BYTES)) for p in sorted(INPUT_PINS))
    if any(f.sha256 != INPUT_PINS[f.path] for f in records):
        raise ValueError("Semgrep fixture changed; re-pinning does not grant admission")
    return records


def build_semgrep_plan(
    project: Path, *, plan_id: str, repetitions: int = 1
) -> SemgrepBenchmarkPlan:
    project = plain_path(project, directory=True)
    pins = tuple(
        file_pin(p, bounded_file(project / p, MAX_PIN_BYTES)) for p in sorted(ADMITTED_PINS)
    )
    if any(f.sha256 != ADMITTED_PINS[f.path] for f in pins):
        raise ValueError("Semgrep admission changed; re-pinning does not grant admission")
    expectation = SemgrepExpectation()
    case = SemgrepCase(
        files=semgrep_inputs(project / CASE_ROOT / "target"),
        expectation=expectation,
        expectation_sha256=semantic_hash(expectation.model_dump(mode="json")),
    )
    return SemgrepBenchmarkPlan(
        plan_id=plan_id,
        pins=pins,
        implementation=implementation_pins(project),
        cases=(case,),
        repetitions=repetitions,
    )


def validate_semgrep_plan(
    project: Path, path: Path, raw: bytes, plan: SemgrepBenchmarkPlan
) -> SemgrepPreview:
    expected = build_semgrep_plan(project, plan_id=plan.plan_id, repetitions=plan.repetitions)
    if plan != expected:
        raise ValueError(
            "Semgrep plan differs from admitted input, expectation or current implementation"
        )
    profile = load_toml_bytes(
        bounded_file(project / PROFILE, MAX_PIN_BYTES), ExecutionProfile, source=Path(PROFILE)
    ).value
    tool = load_toml_bytes(
        bounded_file(project / TOOL, MAX_PIN_BYTES), SemgrepToolConfig, source=Path(TOOL)
    ).value
    digest = semantic_hash(plan.model_dump(mode="json"))
    case = plan.cases[0]
    cells = tuple(
        SemgrepCell(
            cell_id=semantic_hash({"plan": digest, "case": case.case_id, "repetition": repeat}),
            repetition=repeat,
            input_files=case.files,
            selected_paths=case.selected_paths,
            expectation=case.expectation,
        )
        for repeat in range(1, plan.repetitions + 1)
    )
    if (
        bounded_file(path, MAX_PLAN_BYTES) != raw
        or build_semgrep_plan(project, plan_id=plan.plan_id, repetitions=plan.repetitions)
        != expected
    ):
        raise ValueError("Semgrep plan inputs changed during validation")
    return SemgrepPreview(
        plan_id=plan.plan_id,
        plan_sha256=sha256_bytes(raw),
        plan_semantic_sha256=digest,
        treatment_sha256=semantic_hash([p.model_dump(mode="json") for p in plan.pins]),
        implementation_sha256=semantic_hash(
            [p.model_dump(mode="json") for p in plan.implementation]
        ),
        cells=cells,
        tool_image=tool.image,
        limits=profile.limits.model_dump(mode="json"),
    )
