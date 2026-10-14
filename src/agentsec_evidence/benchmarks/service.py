"""Read-only planning over the existing finite admission; never dispatch a scanner."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal, overload

from agentsec_evidence.agents.development import APPROVED_CASES, DevelopmentCase, DevelopmentCases
from agentsec_evidence.agents.execution import AgentAuditToolConfig
from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.benchmarks.models import (
    MAX_PIN_BYTES,
    MAX_PIN_TOTAL,
    MAX_PLAN_BYTES,
    AdmittedPlan,
    AdmittedPreview,
    BenchmarkDryRunV2,
    BenchmarkDryRunV3,
    BenchmarkPlan,
    BenchmarkPlanV2,
    KicsBenchmarkPlan,
    PlanFile,
    PlannedCase,
    PlannedCell,
    PlannedExpectation,
    PrelaunchRetryPolicy,
    SemgrepBenchmarkPlan,
)
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.execution.config import ExecutionProfile, load_toml_bytes
from agentsec_evidence.research.retained import bounded_file, plain_path

REGISTRY = "test_cases/development/agent-artifacts/cases.json"
TOOL = "configs/tools/agent-audit.toml"
PROFILE = "configs/profiles/agent-development.toml"
# Changing and re-hashing a file in the plan cannot silently redefine the finite admission.
ADMITTED_PINS = {
    REGISTRY: "0294435246d90b8e036547dd545cd55392432f4a7300213438f8989db1bb812b",
    TOOL: "449980ad953f95802e712d3d397598dafb9afb9601805bb6d51819c34fa8e231",
    PROFILE: "2e133b817c87ce454d7a148da177fda593d0effe639688226e8b24f8600aea77",
    "configs/agent-artifacts/properties.json": (
        "c1d066e152915e9ea11e8b71368b22c47e40fc99bcc8d1749af5bcf7434a3135"
    ),
    "uv.lock": "b072464773b77a68d6f03345f6f913568773903671821eb6b61d4ea312fcfb6c",
    "pyproject.toml": "91179196237aeb58bae2b6a9c111d9f000346aad7c7c05d653c07c7beae3badd",
}


def file_pin(path: str, raw: bytes) -> PlanFile:
    return PlanFile(path=path, bytes=len(raw), sha256=sha256_bytes(raw))


def _admission(
    project: Path,
) -> tuple[tuple[PlanFile, ...], DevelopmentCases, AgentAuditToolConfig, ExecutionProfile]:
    raw = {path: bounded_file(project / path, MAX_PIN_BYTES) for path in sorted(ADMITTED_PINS)}
    if any(sha256_bytes(data) != ADMITTED_PINS[path] for path, data in raw.items()):
        raise ValueError("Protected admission input changed; re-pinning does not grant admission")
    registry = DevelopmentCases.model_validate(load_agent_json(raw[REGISTRY], max_bytes=256 * 1024))
    if {case.id for case in registry.cases} != APPROVED_CASES:
        raise ValueError("Development registry differs from approved case scope")
    tool = load_toml_bytes(raw[TOOL], AgentAuditToolConfig, source=project / TOOL).value
    profile = load_toml_bytes(raw[PROFILE], ExecutionProfile, source=project / PROFILE).value
    if (
        tool.treatment != "authored-agent-static-v1"
        or profile.profile_kind != "development"
        or profile.max_workers != 1
    ):
        raise ValueError("Benchmark requires existing sequential authored development treatment")
    return tuple(file_pin(path, data) for path, data in raw.items()), registry, tool, profile


def _walk_error(error: OSError) -> None:
    raise error


def implementation_pins(project: Path) -> tuple[PlanFile, ...]:
    root = plain_path(project / "src", directory=True)
    records: list[PlanFile] = []
    byte_count = 0
    entries = 0
    # Walk without following links, checking directories before descent on Windows and Linux.
    for directory, dirs, names in os.walk(root, followlinks=False, onerror=_walk_error):
        entries += len(dirs) + len(names)
        if entries > 8192 or len(Path(directory).relative_to(root).parts) > 32:
            raise ValueError("Implementation inventory exceeds entry/depth budget")
        for name in list(dirs):
            plain_path(Path(directory) / name, directory=True)
        for name in names:
            if not name.lower().endswith(".py"):
                continue
            if not name.endswith(".py"):
                raise ValueError("Non-portable Python source suffix")
            path = Path(directory) / name
            raw = bounded_file(path, MAX_PIN_BYTES)
            byte_count += len(raw)
            if byte_count > MAX_PIN_TOTAL or len(records) >= 2048:
                raise ValueError("Implementation inventory exceeds byte/file budget")
            records.append(file_pin(path.relative_to(project).as_posix(), raw))
    return tuple(sorted(records, key=lambda record: record.path))


def _case(case: DevelopmentCase) -> PlannedCase:
    if case.input_path in case.extra_files:
        raise ValueError("Fixture input collides with context")
    contents = {case.input_path: case.content, **case.extra_files}
    expectation = PlannedExpectation.model_validate(
        {
            "expected_parse": case.expected_parse,
            "expected_condition": case.expected_condition,
            "policy_observation": case.policy_observation,
        }
    )
    return PlannedCase.model_validate(
        {
            "case_id": case.id,
            "property_id": case.property_id,
            "files": [
                file_pin(path, text.encode("utf-8")).model_dump(mode="json")
                for path, text in sorted(contents.items())
            ],
            "selected_paths": [case.input_path],
            "expectation": expectation.model_dump(mode="json"),
            "expectation_sha256": semantic_hash(expectation.model_dump(mode="json")),
        }
    )


@overload
def build_development_plan(
    project: Path,
    *,
    plan_id: str,
    case_ids: tuple[str, ...],
    repetitions: int = 1,
    allow_prelaunch_retry: Literal[False] = False,
) -> BenchmarkPlan: ...


@overload
def build_development_plan(
    project: Path,
    *,
    plan_id: str,
    case_ids: tuple[str, ...],
    repetitions: int = 1,
    allow_prelaunch_retry: Literal[True],
) -> BenchmarkPlanV2: ...


@overload
def build_development_plan(
    project: Path,
    *,
    plan_id: str,
    case_ids: tuple[str, ...],
    repetitions: int = 1,
    allow_prelaunch_retry: bool,
) -> AdmittedPlan: ...


def build_development_plan(
    project: Path,
    *,
    plan_id: str,
    case_ids: tuple[str, ...],
    repetitions: int = 1,
    allow_prelaunch_retry: bool = False,
) -> AdmittedPlan:
    """Bind explicit approved case IDs to current implementation bytes; no file writes."""
    project = plain_path(project, directory=True)
    pins, registry, _, _ = _admission(project)
    cases = {case.id: case for case in registry.cases}
    if any(case not in cases for case in case_ids):
        raise ValueError("Unknown or unadmitted benchmark case")
    if type(allow_prelaunch_retry) is not bool:
        raise ValueError("Retry opt-in must be a boolean")
    plan = BenchmarkPlan(
        plan_id=plan_id,
        pins=pins,
        implementation=implementation_pins(project),
        cases=tuple(_case(cases[case]) for case in case_ids),
        repetitions=repetitions,
    )
    if allow_prelaunch_retry:
        fields = plan.model_dump(mode="json", exclude={"contract"})
        return BenchmarkPlanV2.model_validate(
            {**fields, "retry_policy": PrelaunchRetryPolicy().model_dump(mode="json")}
        )
    return plan


def _parse_plan(data: bytes) -> AdmittedPlan:
    raw = load_agent_json(data, max_bytes=MAX_PLAN_BYTES)
    if raw.get("contract") == "benchmark-plan-v2":
        return BenchmarkPlanV2.model_validate(raw)
    if raw.get("contract") == "benchmark-semgrep-plan-v1":
        return SemgrepBenchmarkPlan.model_validate(raw)
    if raw.get("contract") == "benchmark-kics-plan-v1":
        return KicsBenchmarkPlan.model_validate(raw)
    return BenchmarkPlan.model_validate(raw)


def load_plan(path: Path) -> AdmittedPlan:
    return _parse_plan(bounded_file(path, MAX_PLAN_BYTES))


def validate_plan(project: Path, path: Path) -> AdmittedPreview:
    """Validate exact data/code bindings and expand planned cells, without reading target ASTs."""
    project = plain_path(project, directory=True)
    raw = bounded_file(path, MAX_PLAN_BYTES)
    plan = _parse_plan(raw)
    if isinstance(plan, KicsBenchmarkPlan):
        from agentsec_evidence.benchmarks.kics_plan import validate_kics_plan

        return validate_kics_plan(project, path, raw, plan)
    if isinstance(plan, SemgrepBenchmarkPlan):
        from agentsec_evidence.benchmarks.semgrep_plan import validate_semgrep_plan

        return validate_semgrep_plan(project, path, raw, plan)
    pins, registry, tool, profile = _admission(project)
    implementation = implementation_pins(project)
    if plan.pins != pins or plan.implementation != implementation:
        raise ValueError("Benchmark treatment/implementation pins differ from current bytes")
    cases = {case.id: _case(case) for case in registry.cases}
    if any(cases.get(case.case_id) != case for case in plan.cases):
        raise ValueError(
            "Benchmark input, family, selection or expectation differs from admitted case"
        )
    plan_sha = semantic_hash(plan.model_dump(mode="json"))
    cells = tuple(
        PlannedCell(
            cell_id=semantic_hash({"plan": plan_sha, "case": case.case_id, "repetition": repeat}),
            case_id=case.case_id,
            repetition=repeat,
            input_files=case.files,
            selected_paths=case.selected_paths,
            expectation=case.expectation,
        )
        for case in plan.cases
        for repeat in range(1, plan.repetitions + 1)
    )
    # Recheck before returning; a receipt is a point-in-time check, not a future execution lease.
    if (
        bounded_file(path, MAX_PLAN_BYTES) != raw
        or implementation_pins(project) != implementation
        or _admission(project)[0] != pins
    ):
        raise ValueError("Plan inputs changed during validation")
    preview = BenchmarkDryRunV2(
        plan_id=plan.plan_id,
        plan_sha256=sha256_bytes(raw),
        plan_semantic_sha256=plan_sha,
        treatment_sha256=semantic_hash([pin.model_dump(mode="json") for pin in pins]),
        implementation_sha256=semantic_hash(
            [pin.model_dump(mode="json") for pin in implementation]
        ),
        cells=cells,
        limits=profile.limits.model_dump(mode="json"),
        tool_image=tool.image,
        validator_image=tool.validator_image,
    )
    if isinstance(plan, BenchmarkPlanV2):
        return BenchmarkDryRunV3.model_validate(
            {
                **preview.model_dump(mode="json", exclude={"contract", "resume_scope"}),
                "retry_policy": plan.retry_policy.model_dump(mode="json"),
            }
        )
    return preview


def plan_bytes(plan: AdmittedPlan) -> bytes:
    return json_bytes(plan.model_dump(mode="json"))
