"""Bind only the four existing G2 KICS fixtures and unchanged two-query treatment."""

import tomllib
from pathlib import Path

from agentsec_evidence.benchmarks.models import (
    MAX_PIN_BYTES,
    MAX_PLAN_BYTES,
    KicsBenchmarkPlan,
    KicsCase,
    KicsCaseId,
    KicsCell,
    KicsExpectation,
    KicsPreview,
    PlanFile,
)
from agentsec_evidence.benchmarks.service import file_pin, implementation_pins
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.execution.config import ExecutionProfile, KicsToolConfig, load_toml_bytes
from agentsec_evidence.research.retained import bounded_file, plain_path

PROFILE = "configs/profiles/development.toml"
TOOL = "configs/tools/kics.toml"
CASE_ROOTS: dict[KicsCaseId, str] = {
    "dev-kics-basic-v1": "test_cases/development/kics-basic",
    "dev-kics-clean-v1": "test_cases/development/kics-clean",
    "dev-kics-malformed-v1": "test_cases/development/kics-malformed",
    "dev-kics-unsupported-v1": "test_cases/development/kics-unsupported",
}
ADMITTED_PINS = {
    "test_cases/development/kics-basic/case.toml": (
        "c32468a58df489fb49d748a3b11a519e147701a509a0aa4a4436c9aac573951d"
    ),
    "test_cases/development/kics-clean/case.toml": (
        "c5870f86fe86e2b1336e75c9d255a7a234139089bfe9a5a3f7fb20a3089867fa"
    ),
    "test_cases/development/kics-malformed/case.toml": (
        "40ac2de2f64009223e7675ffdba8bd5aa8e1670f14cdb25e3e314c915c74f926"
    ),
    "test_cases/development/kics-unsupported/case.toml": (
        "8a4905690b105e80be4f8d20f5d315c3e0dc8646ea51179dd77dd8be08519c67"
    ),
    PROFILE: "a4d380d96cc7c67dff5a3334eefe6544e2fe2f2e2f6325eb6818fba8add6a240",
    TOOL: "6bbc06ec9215a759a2153a6584389fd4702831b5a29a3a038fc67e99bdb04f36",
    "uv.lock": "b072464773b77a68d6f03345f6f913568773903671821eb6b61d4ea312fcfb6c",
    "pyproject.toml": "91179196237aeb58bae2b6a9c111d9f000346aad7c7c05d653c07c7beae3badd",
}
INPUT_PINS: dict[KicsCaseId, dict[str, str]] = {
    "dev-kics-basic-v1": {
        "corrected-pod.yaml": "08f6486ce05d41ec65626aae1e65eb9497e72286eb4b697b4898b3e120b2766a",
        "corrected.tf": "35888aaa15bc7233317473bd700c8d390426d2d53b801de5ac0d4f7bfb8ce146",
        "notes.txt": "fd54dd9a2508656993061b60904e8d4d103b4ef416327418374d49474b8685f5",
        "privileged-pod.yaml": "61f8ed257784bc3d3c510eaf34034ebce32d981256f524520752056c0dc5d6eb",
        "vulnerable.tf": "00d9b29460df1478c30781962f1920fa71c60f982518805fd6c3df1ce239f9a3",
    },
    "dev-kics-clean-v1": {
        "corrected-pod.yaml": "08f6486ce05d41ec65626aae1e65eb9497e72286eb4b697b4898b3e120b2766a",
        "corrected.tf": "35888aaa15bc7233317473bd700c8d390426d2d53b801de5ac0d4f7bfb8ce146",
    },
    "dev-kics-malformed-v1": {
        "broken.tf": "0eb8c1a64255888c6ed43e0801ab2eabcc86588c313e017f1042b925050cfa86",
    },
    "dev-kics-unsupported-v1": {
        "README.txt": "63fb27f351004b5843b9eb30cce3d52a874c2638ee4ab11314de53e4065936d6",
    },
}


def kics_inputs(root: Path, case_id: KicsCaseId) -> tuple[PlanFile, ...]:
    plain_path(root, directory=True)
    pins = INPUT_PINS[case_id]
    # All admitted cases are flat; unexpected directories/policy files cannot be silently omitted.
    if {p.name for p in root.iterdir()} != set(pins):
        raise ValueError("Unadmitted KICS target entry")
    files = tuple(file_pin(p, bounded_file(root / p, MAX_PIN_BYTES)) for p in sorted(pins))
    if any(f.sha256 != pins[f.path] for f in files):
        raise ValueError("KICS fixture changed; re-pinning does not grant admission")
    return files


def build_kics_plan(
    project: Path, *, plan_id: str, case_ids: tuple[str, ...], repetitions: int = 1
) -> KicsBenchmarkPlan:
    project = plain_path(project, directory=True)
    pins = tuple(
        file_pin(p, bounded_file(project / p, MAX_PIN_BYTES)) for p in sorted(ADMITTED_PINS)
    )
    if any(f.sha256 != ADMITTED_PINS[f.path] for f in pins):
        raise ValueError("KICS admission changed; re-pinning does not grant admission")
    cases: dict[str, KicsCase] = {}
    for case_id, relative in CASE_ROOTS.items():
        raw = bounded_file(project / relative / "case.toml", MAX_PIN_BYTES)
        if sha256_bytes(raw) != ADMITTED_PINS[f"{relative}/case.toml"]:
            raise ValueError("KICS case changed during admission")
        metadata = tomllib.loads(raw.decode("utf-8"))
        expectation = KicsExpectation.model_validate(
            {key: value for key, value in metadata.items() if key.startswith("expected_")}
        )
        files = kics_inputs(project / relative / "target", case_id)
        cases[case_id] = KicsCase(
            case_id=case_id,
            files=files,
            selected_paths=tuple(f.path for f in files if f.path.endswith((".tf", ".yaml"))),
            expectation=expectation,
            expectation_sha256=semantic_hash(expectation.model_dump(mode="json")),
        )
    if any(case_id not in cases for case_id in case_ids):
        raise ValueError("Unknown or unadmitted KICS case")
    return KicsBenchmarkPlan(
        plan_id=plan_id,
        pins=pins,
        implementation=implementation_pins(project),
        cases=tuple(cases[case_id] for case_id in case_ids),
        repetitions=repetitions,
    )


def validate_kics_plan(
    project: Path, path: Path, raw: bytes, plan: KicsBenchmarkPlan
) -> KicsPreview:
    case_ids = tuple(c.case_id for c in plan.cases)
    expected = build_kics_plan(
        project, plan_id=plan.plan_id, case_ids=case_ids, repetitions=plan.repetitions
    )
    if plan != expected:
        raise ValueError("KICS plan differs from admitted inputs, expectations or implementation")
    profile = load_toml_bytes(
        bounded_file(project / PROFILE, MAX_PIN_BYTES), ExecutionProfile, source=Path(PROFILE)
    ).value
    tool = load_toml_bytes(
        bounded_file(project / TOOL, MAX_PIN_BYTES), KicsToolConfig, source=Path(TOOL)
    ).value
    digest = semantic_hash(plan.model_dump(mode="json"))
    cells = tuple(
        KicsCell(
            cell_id=semantic_hash({"plan": digest, "case": case.case_id, "repetition": repeat}),
            case_id=case.case_id,
            repetition=repeat,
            input_files=case.files,
            selected_paths=case.selected_paths,
            expectation=case.expectation,
        )
        for case in plan.cases
        for repeat in range(1, plan.repetitions + 1)
    )
    if (
        bounded_file(path, MAX_PLAN_BYTES) != raw
        or build_kics_plan(
            project, plan_id=plan.plan_id, case_ids=case_ids, repetitions=plan.repetitions
        )
        != expected
    ):
        raise ValueError("KICS plan inputs changed during validation")
    return KicsPreview(
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
