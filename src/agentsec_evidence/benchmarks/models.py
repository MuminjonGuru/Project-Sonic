from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import Field, StrictInt, model_validator

from agentsec_evidence.agents.validation import canonical_artifact_path
from agentsec_evidence.dependencies.mutations import Mutation
from agentsec_evidence.models.contracts import Sha256
from agentsec_evidence.research.models import ResearchModel

Identifier = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,79}$")]
MAX_PLAN_BYTES = 2 * 1024**2
MAX_PIN_BYTES = 2 * 1024**2
MAX_PIN_TOTAL = 32 * 1024**2


class PlanFile(ResearchModel):
    path: str = Field(min_length=1, max_length=512)
    bytes: StrictInt = Field(ge=0, le=MAX_PIN_BYTES)
    sha256: Sha256

    @model_validator(mode="after")
    def check_path(self) -> Self:
        canonical_artifact_path(self.path)
        if len(self.path.split("/")) > 32:
            raise ValueError("Plan path depth exceeded")
        return self


def check_file_set(files: tuple[PlanFile, ...]) -> None:
    paths = [file.path for file in files]
    if paths != sorted(paths) or len({path.casefold() for path in paths}) != len(paths):
        raise ValueError("Plan file paths must be sorted and portable-unique")
    if sum(file.bytes for file in files) > MAX_PIN_TOTAL:
        raise ValueError("Plan file set exceeds total byte budget")


class PlannedExpectation(ResearchModel):
    expected_parse: Literal["parsed", "malformed", "unsupported"]
    expected_condition: Literal["present", "absent", "not-assessable"]
    policy_observation: Literal["none", "target-exclusion", "inline-suppression"]
    provenance: Literal["authored-condition-expectation-not-scanner-derived"] = (
        "authored-condition-expectation-not-scanner-derived"
    )
    review_status: Literal["student-approved-categories-exact-text-not-independent"] = (
        "student-approved-categories-exact-text-not-independent"
    )


class PlannedCase(ResearchModel):
    case_id: Identifier
    source_family: Literal["agent-artifact-development-v1"] = "agent-artifact-development-v1"
    split: Literal["development-not-held-out"] = "development-not-held-out"
    property_id: Literal["python.tool-argument-to-eval", "mcp.filesystem-root-declaration"]
    files: tuple[PlanFile, ...] = Field(min_length=1, max_length=8)
    selected_paths: tuple[str, ...] = Field(min_length=1, max_length=1)
    expectation: PlannedExpectation
    expectation_sha256: Sha256

    @model_validator(mode="after")
    def check_inputs(self) -> Self:
        check_file_set(self.files)
        for path in self.selected_paths:
            canonical_artifact_path(path)
            if path not in {file.path for file in self.files}:
                raise ValueError("Selected case input is not inventoried")
        return self


class BenchmarkPlanFields(ResearchModel):
    plan_id: Identifier
    admission: Literal["agent-development-2026-10-02-v1"] = "agent-development-2026-10-02-v1"
    purpose: Literal["development-governance-rehearsal"] = "development-governance-rehearsal"
    split: Literal["development-not-held-out"] = "development-not-held-out"
    treatment: Literal["authored-agent-static-v1"] = "authored-agent-static-v1"
    pins: tuple[PlanFile, ...] = Field(min_length=6, max_length=6)
    implementation: tuple[PlanFile, ...] = Field(min_length=1, max_length=2048)
    cases: tuple[PlannedCase, ...] = Field(min_length=1, max_length=13)
    repetitions: StrictInt = Field(ge=1, le=3)
    order: Literal["case-order-then-repetition"] = "case-order-then-repetition"
    max_workers: StrictInt = Field(default=1, ge=1, le=1)
    automatic_retries: StrictInt = Field(default=0, ge=0, le=0)
    target_execution: Literal[False] = False
    metrics: tuple[
        Literal["condition-accounting-v1", "execution-status-v1", "semantic-repeatability-v1"], ...
    ] = ("condition-accounting-v1", "execution-status-v1", "semantic-repeatability-v1")
    protocol_status: Literal["development-plan-not-confirmatory-freeze"] = (
        "development-plan-not-confirmatory-freeze"
    )

    @model_validator(mode="after")
    def check_plan(self) -> Self:
        check_file_set(self.pins)
        check_file_set(self.implementation)
        ids = [case.case_id for case in self.cases]
        if len(set(ids)) != len(ids):
            raise ValueError("Duplicate benchmark case ID")
        if self.metrics != (
            "condition-accounting-v1",
            "execution-status-v1",
            "semantic-repeatability-v1",
        ):
            raise ValueError("This plan requires the fixed metric-design identifiers")
        if any(
            not file.path.startswith("src/") or not file.path.endswith(".py")
            for file in self.implementation
        ):
            raise ValueError("Implementation pins must name src Python files")
        return self


class BenchmarkPlan(BenchmarkPlanFields):
    contract: Literal["benchmark-plan-v1"] = "benchmark-plan-v1"


class PrelaunchRetryPolicy(ResearchModel):
    policy_id: Literal["missing-docker-prelaunch-once-v1"] = "missing-docker-prelaunch-once-v1"
    cause: Literal["docker-unavailable-before-launch"] = "docker-unavailable-before-launch"
    max_manual_retries_per_cell: Literal[1] = 1
    explicit_attempt_selection: Literal[True] = True
    interrupted_attempts: Literal["blocked"] = "blocked"
    other_failures: Literal["blocked"] = "blocked"


class BenchmarkPlanV2(BenchmarkPlanFields):
    contract: Literal["benchmark-plan-v2"] = "benchmark-plan-v2"
    retry_policy: PrelaunchRetryPolicy


class SemgrepExpectation(ResearchModel):
    expected_native_results: Literal[1] = 1
    expected_rule_id: Literal["project.first-slice.python-eval"] = "project.first-slice.python-eval"
    positive_path: Literal["vulnerable.py"] = "vulnerable.py"
    corrected_path: Literal["clean.py"] = "clean.py"
    excluded_path: Literal["ignored/ignored.py"] = "ignored/ignored.py"
    provenance: Literal["existing-authored-case-not-new-scanner-derived-oracle"] = (
        "existing-authored-case-not-new-scanner-derived-oracle"
    )
    review_status: Literal["historical-engineering-expectation-not-independent"] = (
        "historical-engineering-expectation-not-independent"
    )


class SemgrepCase(ResearchModel):
    case_id: Literal["dev-semgrep-basic-v1"] = "dev-semgrep-basic-v1"
    source_family: Literal["semgrep-basic-development-v1"] = "semgrep-basic-development-v1"
    split: Literal["development-not-held-out"] = "development-not-held-out"
    files: tuple[PlanFile, ...] = Field(min_length=3, max_length=3)
    selected_paths: tuple[Literal["clean.py"], Literal["vulnerable.py"]] = (
        "clean.py",
        "vulnerable.py",
    )
    expectation: SemgrepExpectation
    expectation_sha256: Sha256

    @model_validator(mode="after")
    def check_files(self) -> Self:
        check_file_set(self.files)
        if {f.path for f in self.files} != {"clean.py", "vulnerable.py", "ignored/ignored.py"}:
            raise ValueError("Semgrep fixture file set differs")
        return self


class SemgrepBenchmarkPlan(ResearchModel):
    contract: Literal["benchmark-semgrep-plan-v1"] = "benchmark-semgrep-plan-v1"
    plan_id: Identifier
    admission: Literal["existing-semgrep-basic-fixture-v1"] = "existing-semgrep-basic-fixture-v1"
    treatment: Literal["authored-semgrep-first-slice-v1"] = "authored-semgrep-first-slice-v1"
    split: Literal["development-not-held-out"] = "development-not-held-out"
    pins: tuple[PlanFile, ...] = Field(min_length=6, max_length=6)
    implementation: tuple[PlanFile, ...] = Field(min_length=1, max_length=2048)
    cases: tuple[SemgrepCase]
    repetitions: StrictInt = Field(ge=1, le=3)
    order: Literal["case-order-then-repetition"] = "case-order-then-repetition"
    max_workers: Literal[1] = 1
    automatic_retries: Literal[0] = 0
    manual_retries: Literal[0] = 0
    target_execution: Literal[False] = False
    protocol_status: Literal["development-plan-not-confirmatory-freeze"] = (
        "development-plan-not-confirmatory-freeze"
    )

    @model_validator(mode="after")
    def check_bindings(self) -> Self:
        check_file_set(self.pins)
        check_file_set(self.implementation)
        if any(
            not f.path.startswith("src/") or not f.path.endswith(".py") for f in self.implementation
        ):
            raise ValueError("Implementation pins must name src Python files")
        return self


KicsCaseId = Literal[
    "dev-kics-basic-v1", "dev-kics-clean-v1", "dev-kics-malformed-v1", "dev-kics-unsupported-v1"
]


class KicsExpectation(ResearchModel):
    expected_native_results: StrictInt = Field(ge=0)
    expected_files_scanned: StrictInt = Field(ge=0)
    expected_files_parsed: StrictInt = Field(ge=0)
    expected_query_ids: tuple[str, ...] = ()
    expected_terminal_state: Literal["partial"] | None = None
    expected_execution_outcome: Literal["unsupported"] | None = None
    provenance: Literal["existing-authored-case-not-new-scanner-derived-oracle"] = (
        "existing-authored-case-not-new-scanner-derived-oracle"
    )
    review_status: Literal["historical-engineering-expectation-not-independent"] = (
        "historical-engineering-expectation-not-independent"
    )


class KicsCase(ResearchModel):
    case_id: KicsCaseId
    source_family: Literal["kics-g2-development-v1"] = "kics-g2-development-v1"
    split: Literal["development-not-held-out"] = "development-not-held-out"
    files: tuple[PlanFile, ...] = Field(min_length=1, max_length=5)
    selected_paths: tuple[str, ...] = Field(max_length=4)
    expectation: KicsExpectation
    expectation_sha256: Sha256

    @model_validator(mode="after")
    def check_inputs(self) -> Self:
        check_file_set(self.files)
        if self.selected_paths != tuple(sorted(set(self.selected_paths))):
            raise ValueError("KICS selected paths must be sorted and unique")
        if not set(self.selected_paths).issubset(f.path for f in self.files):
            raise ValueError("KICS selected input is not inventoried")
        return self


class KicsBenchmarkPlan(ResearchModel):
    contract: Literal["benchmark-kics-plan-v1"] = "benchmark-kics-plan-v1"
    plan_id: Identifier
    admission: Literal["existing-kics-g2-fixtures-v1"] = "existing-kics-g2-fixtures-v1"
    treatment: Literal["authored-kics-g2-static-v1"] = "authored-kics-g2-static-v1"
    split: Literal["development-not-held-out"] = "development-not-held-out"
    pins: tuple[PlanFile, ...] = Field(min_length=8, max_length=8)
    implementation: tuple[PlanFile, ...] = Field(min_length=1, max_length=2048)
    cases: tuple[KicsCase, ...] = Field(min_length=1, max_length=4)
    repetitions: StrictInt = Field(ge=1, le=3)
    order: Literal["case-order-then-repetition"] = "case-order-then-repetition"
    max_workers: Literal[1] = 1
    automatic_retries: Literal[0] = 0
    manual_retries: Literal[0] = 0
    target_execution: Literal[False] = False
    protocol_status: Literal["development-plan-not-confirmatory-freeze"] = (
        "development-plan-not-confirmatory-freeze"
    )

    @model_validator(mode="after")
    def check_bindings(self) -> Self:
        check_file_set(self.pins)
        check_file_set(self.implementation)
        if len({c.case_id for c in self.cases}) != len(self.cases):
            raise ValueError("Duplicate KICS benchmark case")
        if any(
            not f.path.startswith("src/") or not f.path.endswith(".py") for f in self.implementation
        ):
            raise ValueError("Implementation pins must name src Python files")
        return self


DependencyCaseId = Literal["dev-dependency-basic-v1", "dev-dependency-clean-v1"]


class DependencyDatabase(ResearchModel):
    path: str = Field(min_length=1, max_length=512)
    bytes: StrictInt = Field(gt=0, le=2 * 1024**3)
    sha256: Sha256

    @model_validator(mode="after")
    def check_path(self) -> Self:
        canonical_artifact_path(self.path)
        if not self.path.startswith("workspace/") or len(self.path.split("/")) > 32:
            raise ValueError("Frozen database must use a project-workspace relative path")
        return self


class DependencyCase(ResearchModel):
    case_id: DependencyCaseId
    source_family: Literal["dependency-development-v1"] = "dependency-development-v1"
    split: Literal["development-not-held-out"] = "development-not-held-out"
    files: tuple[PlanFile, ...] = Field(min_length=1, max_length=2)
    selected_paths: tuple[Literal["uv.lock"]] = ("uv.lock",)
    expectation_reference: Literal["existing-finite-oracle-and-corrected-fixture"] = (
        "existing-finite-oracle-and-corrected-fixture"
    )
    expectation_sha256: Sha256
    review_status: Literal["finite-student-scope-not-independent-adjudication"] = (
        "finite-student-scope-not-independent-adjudication"
    )

    @model_validator(mode="after")
    def check_files(self) -> Self:
        check_file_set(self.files)
        if "uv.lock" not in {f.path for f in self.files}:
            raise ValueError("Dependency fixture requires its recorded lockfile")
        return self


class DependencyBenchmarkPlan(ResearchModel):
    contract: Literal["benchmark-dependency-plan-v1"] = "benchmark-dependency-plan-v1"
    plan_id: Identifier
    admission: Literal["existing-dependency-basic-clean-v1"] = "existing-dependency-basic-clean-v1"
    treatment: Literal["paired-offline-pypi-dependency-v1"] = "paired-offline-pypi-dependency-v1"
    split: Literal["development-not-held-out"] = "development-not-held-out"
    pins: tuple[PlanFile, ...] = Field(min_length=9, max_length=9)
    implementation: tuple[PlanFile, ...] = Field(min_length=1, max_length=2048)
    database: DependencyDatabase
    cases: tuple[DependencyCase, ...] = Field(min_length=1, max_length=2)
    repetitions: StrictInt = Field(ge=1, le=3)
    order: Literal["case-order-then-repetition"] = "case-order-then-repetition"
    stage_order: tuple[Literal["osv-direct"], Literal["syft"], Literal["osv-sbom"]] = (
        "osv-direct",
        "syft",
        "osv-sbom",
    )
    max_workers: Literal[1] = 1
    automatic_retries: Literal[0] = 0
    manual_retries: Literal[0] = 0
    mutation: None = None
    target_execution: Literal[False] = False
    protocol_status: Literal["development-plan-not-confirmatory-freeze"] = (
        "development-plan-not-confirmatory-freeze"
    )

    @model_validator(mode="after")
    def check_bindings(self) -> Self:
        check_file_set(self.pins)
        check_file_set(self.implementation)
        if len({c.case_id for c in self.cases}) != len(self.cases):
            raise ValueError("Duplicate dependency benchmark case")
        if any(
            not f.path.startswith("src/") or not f.path.endswith(".py") for f in self.implementation
        ):
            raise ValueError("Implementation pins must name src Python files")
        return self


type AdmittedPlan = (
    BenchmarkPlan
    | BenchmarkPlanV2
    | SemgrepBenchmarkPlan
    | KicsBenchmarkPlan
    | DependencyBenchmarkPlan
    | DependencyMutationPlan
    | DependencyBoundaryPlan
    | PublicPilotBenchmarkPlan
    | ResearchBenchmarkPlan
)


class PlannedCell(ResearchModel):
    cell_id: Sha256
    case_id: Identifier
    repetition: StrictInt = Field(ge=1, le=3)
    input_files: tuple[PlanFile, ...]
    selected_paths: tuple[str, ...]
    expectation: PlannedExpectation
    state: Literal["not-attempted"] = "not-attempted"
    producer_invocations: Literal[0] = 0
    finding_records: None = None
    coverage: Literal["not-measured"] = "not-measured"


class BenchmarkPreview(ResearchModel):
    plan_id: Identifier
    plan_sha256: Sha256
    plan_semantic_sha256: Sha256
    treatment_sha256: Sha256
    implementation_sha256: Sha256
    plan_valid: Literal[True] = True
    validation_scope: Literal["fixed-development-metadata-and-byte-bindings"] = (
        "fixed-development-metadata-and-byte-bindings"
    )
    execution_authorized: Literal[False] = False
    runtime_readiness: Literal["not-checked"] = "not-checked"
    review_assurance: Literal["declared-not-independent-or-authenticated"] = (
        "declared-not-independent-or-authenticated"
    )
    metric_scoring_implemented: Literal[False] = False
    cells: tuple[PlannedCell, ...] = Field(min_length=1, max_length=39)
    prospective_steps: tuple[str, ...] = (
        "isolated-input-validation",
        "conditional-agent-audit-only-if-input-admitted",
        "native-evidence-capture",
        "normalization-and-export",
        "bundle-validation",
    )
    limits: dict[str, int | float]
    tool_image: str
    validator_image: str
    limitations: tuple[str, ...] = (
        "No producer, target, container, image inspection, network call or scoring was run",
        "Expected parse/policy states are authored assertions, not measured outcomes",
        "Malformed, unsupported and policy-refused cases are retained, not true negatives",
        "Only the fixed development registry/treatment is supported; no public/held-out plan",
        "Hash consistency is not reviewer authentication or independent scientific validation",
    )


# Historical increment-A receipt retains its original capability statement and schema.
class BenchmarkDryRun(BenchmarkPreview):
    contract: Literal["benchmark-dry-run-v1"] = "benchmark-dry-run-v1"
    resume_implemented: Literal[False] = False


class BenchmarkDryRunV2(BenchmarkPreview):
    contract: Literal["benchmark-dry-run-v2"] = "benchmark-dry-run-v2"
    resume_implemented: Literal[True] = True
    resume_scope: Literal["verified-terminal-authored-agent-attempts-only-no-retry"] = (
        "verified-terminal-authored-agent-attempts-only-no-retry"
    )


class BenchmarkDryRunV3(BenchmarkPreview):
    contract: Literal["benchmark-dry-run-v3"] = "benchmark-dry-run-v3"
    resume_implemented: Literal[True] = True
    resume_scope: Literal["verified-terminal-reuse-and-explicit-prelaunch-retry"] = (
        "verified-terminal-reuse-and-explicit-prelaunch-retry"
    )
    retry_policy: PrelaunchRetryPolicy


class SemgrepCell(ResearchModel):
    cell_id: Sha256
    case_id: Literal["dev-semgrep-basic-v1"] = "dev-semgrep-basic-v1"
    repetition: StrictInt = Field(ge=1, le=3)
    input_files: tuple[PlanFile, ...]
    selected_paths: tuple[Literal["clean.py"], Literal["vulnerable.py"]]
    expectation: SemgrepExpectation
    state: Literal["not-attempted"] = "not-attempted"
    producer_invocations: Literal[0] = 0
    finding_records: None = None
    coverage: Literal["not-measured"] = "not-measured"


class SemgrepPreview(ResearchModel):
    contract: Literal["benchmark-semgrep-dry-run-v1"] = "benchmark-semgrep-dry-run-v1"
    plan_id: Identifier
    plan_sha256: Sha256
    plan_semantic_sha256: Sha256
    treatment_sha256: Sha256
    implementation_sha256: Sha256
    cells: tuple[SemgrepCell, ...] = Field(min_length=1, max_length=3)
    limits: dict[str, int | float]
    tool_image: str
    plan_valid: Literal[True] = True
    validation_scope: Literal["fixed-development-metadata-and-byte-bindings"] = (
        "fixed-development-metadata-and-byte-bindings"
    )
    execution_authorized: Literal[False] = False
    runtime_readiness: Literal["not-checked"] = "not-checked"
    resume_implemented: Literal[True] = True
    resume_scope: Literal["verified-terminal-controlled-semgrep-no-retry"] = (
        "verified-terminal-controlled-semgrep-no-retry"
    )
    metric_scoring_implemented: Literal[False] = False
    limitations: tuple[str, ...] = (
        "Existing three-file authored fixture and first-slice rule only, not the research profile",
        "Selected paths describe intended scope, not native completion or detection coverage",
        "No containers, target execution, network requests or scoring during plan validation",
        "Historical engineering expectations are not independent outcome adjudication",
    )


class KicsCell(ResearchModel):
    cell_id: Sha256
    case_id: KicsCaseId
    repetition: StrictInt = Field(ge=1, le=3)
    input_files: tuple[PlanFile, ...]
    selected_paths: tuple[str, ...]
    expectation: KicsExpectation
    state: Literal["not-attempted"] = "not-attempted"
    producer_invocations: Literal[0] = 0
    finding_records: None = None
    coverage: Literal["not-measured"] = "not-measured"


class KicsPreview(ResearchModel):
    contract: Literal["benchmark-kics-dry-run-v1"] = "benchmark-kics-dry-run-v1"
    plan_id: Identifier
    plan_sha256: Sha256
    plan_semantic_sha256: Sha256
    treatment_sha256: Sha256
    implementation_sha256: Sha256
    cells: tuple[KicsCell, ...] = Field(min_length=1, max_length=12)
    limits: dict[str, int | float]
    tool_image: str
    plan_valid: Literal[True] = True
    validation_scope: Literal["fixed-development-metadata-and-byte-bindings"] = (
        "fixed-development-metadata-and-byte-bindings"
    )
    execution_authorized: Literal[False] = False
    runtime_readiness: Literal["not-checked"] = "not-checked"
    resume_implemented: Literal[True] = True
    resume_scope: Literal["verified-terminal-controlled-kics-no-retry"] = (
        "verified-terminal-controlled-kics-no-retry"
    )
    metric_scoring_implemented: Literal[False] = False
    limitations: tuple[str, ...] = (
        "Four existing authored fixtures and two Terraform/Kubernetes queries only",
        "Full fixture snapshots are mounted; selected paths denote intended IaC inputs only",
        "No Dockerfile support, target execution, network requests or independent oracle",
        "Native aggregate counters do not establish per-file or per-query coverage",
        "Unsupported and malformed-input observations are not clean analysis or true negatives",
    )


class DependencyCell(ResearchModel):
    cell_id: Sha256
    case_id: DependencyCaseId
    repetition: StrictInt = Field(ge=1, le=3)
    input_files: tuple[PlanFile, ...]
    selected_paths: tuple[Literal["uv.lock"]] = ("uv.lock",)
    expectation_sha256: Sha256
    state: Literal["not-attempted"] = "not-attempted"
    producer_invocations: Literal[0] = 0
    finding_records: None = None
    coverage: Literal["not-measured"] = "not-measured"


class DependencyPreview(ResearchModel):
    contract: Literal["benchmark-dependency-dry-run-v1"] = "benchmark-dependency-dry-run-v1"
    plan_id: Identifier
    plan_sha256: Sha256
    plan_semantic_sha256: Sha256
    treatment_sha256: Sha256
    implementation_sha256: Sha256
    cells: tuple[DependencyCell, ...] = Field(min_length=1, max_length=6)
    database: DependencyDatabase
    limits: dict[str, int | float]
    tool_images: tuple[str, str]
    plan_valid: Literal[True] = True
    validation_scope: Literal["fixed-development-byte-bindings-and-database-hash"] = (
        "fixed-development-byte-bindings-and-database-hash"
    )
    execution_authorized: Literal[False] = False
    runtime_readiness: Literal["containers-not-checked"] = "containers-not-checked"
    resume_implemented: Literal[True] = True
    resume_scope: Literal["verified-paired-dependency-attempts-no-retry"] = (
        "verified-paired-dependency-attempts-no-retry"
    )
    metric_scoring_implemented: Literal[False] = False
    limitations: tuple[str, ...] = (
        "Existing basic/corrected fixtures only; no pilot, mutation or new input admission",
        "One attempt comprises direct OSV, one Syft discovery/export and SBOM OSV",
        "Database bytes are checked; no containers, downloads, target installation or scoring",
        "Package visibility is not proof of per-package matching; paired findings are not summed",
        "Retained replay requires the same frozen database; no network or refresh fallback",
    )


DependencyMutationCaseId = Literal[
    "dev-dependency-remove-component-v1",
    "dev-dependency-remove-purl-v1",
    "dev-dependency-change-version-v1",
]


class DependencyMutationCase(ResearchModel):
    case_id: DependencyMutationCaseId
    mutation: Mutation
    source_family: Literal["dependency-development-v1"] = "dependency-development-v1"
    source_case: Literal["dev-dependency-basic-v1"] = "dev-dependency-basic-v1"
    split: Literal["development-not-held-out"] = "development-not-held-out"
    files: tuple[PlanFile, ...] = Field(min_length=2, max_length=2)
    selected_paths: tuple[Literal["uv.lock"]] = ("uv.lock",)
    expectation_sha256: Sha256
    expectation_reference: Literal["existing-finite-oracle-and-mutation-helper"] = (
        "existing-finite-oracle-and-mutation-helper"
    )
    review_status: Literal["historical-engineering-expectation-not-independent"] = (
        "historical-engineering-expectation-not-independent"
    )

    @model_validator(mode="after")
    def check_files(self) -> Self:
        check_file_set(self.files)
        if {f.path for f in self.files} != {"uv.lock", "osv-scanner.toml"}:
            raise ValueError("Mutation case requires the original basic fixture")
        if self.case_id != f"dev-dependency-{self.mutation}-v1":
            raise ValueError("Mutation case and transformation differ")
        return self


class DependencyMutationPlan(ResearchModel):
    contract: Literal["benchmark-dependency-mutation-plan-v1"] = (
        "benchmark-dependency-mutation-plan-v1"
    )
    plan_id: Identifier
    admission: Literal["existing-dependency-sbom-mutations-v1"] = (
        "existing-dependency-sbom-mutations-v1"
    )
    treatment: Literal["paired-offline-pypi-sbom-mutations-v1"] = (
        "paired-offline-pypi-sbom-mutations-v1"
    )
    split: Literal["development-not-held-out"] = "development-not-held-out"
    pins: tuple[PlanFile, ...] = Field(min_length=11, max_length=11)
    implementation: tuple[PlanFile, ...] = Field(min_length=1, max_length=2048)
    database: DependencyDatabase
    cases: tuple[DependencyMutationCase, ...] = Field(min_length=1, max_length=3)
    repetitions: StrictInt = Field(ge=1, le=3)
    order: Literal["case-order-then-repetition"] = "case-order-then-repetition"
    stage_order: tuple[Literal["osv-direct"], Literal["syft"], Literal["osv-sbom"]] = (
        "osv-direct",
        "syft",
        "osv-sbom",
    )
    max_workers: Literal[1] = 1
    automatic_retries: Literal[0] = 0
    manual_retries: Literal[0] = 0
    target_execution: Literal[False] = False
    protocol_status: Literal["development-plan-not-confirmatory-freeze"] = (
        "development-plan-not-confirmatory-freeze"
    )

    @model_validator(mode="after")
    def check_bindings(self) -> Self:
        check_file_set(self.pins)
        check_file_set(self.implementation)
        if len({c.case_id for c in self.cases}) != len(self.cases):
            raise ValueError("Duplicate dependency mutation case")
        if any(
            not f.path.startswith("src/") or not f.path.endswith(".py") for f in self.implementation
        ):
            raise ValueError("Implementation pins must name src Python files")
        return self


class DependencyMutationCell(ResearchModel):
    cell_id: Sha256
    case_id: DependencyMutationCaseId
    mutation: Mutation
    repetition: StrictInt = Field(ge=1, le=3)
    input_files: tuple[PlanFile, ...]
    selected_paths: tuple[Literal["uv.lock"]] = ("uv.lock",)
    expectation_sha256: Sha256
    state: Literal["not-attempted"] = "not-attempted"
    producer_invocations: Literal[0] = 0
    finding_records: None = None
    coverage: Literal["not-measured"] = "not-measured"


class DependencyMutationPreview(ResearchModel):
    contract: Literal["benchmark-dependency-mutation-dry-run-v1"] = (
        "benchmark-dependency-mutation-dry-run-v1"
    )
    plan_id: Identifier
    plan_sha256: Sha256
    plan_semantic_sha256: Sha256
    treatment_sha256: Sha256
    implementation_sha256: Sha256
    cells: tuple[DependencyMutationCell, ...] = Field(min_length=1, max_length=9)
    database: DependencyDatabase
    limits: dict[str, int | float]
    tool_images: tuple[str, str]
    plan_valid: Literal[True] = True
    validation_scope: Literal["fixed-development-byte-bindings-database-and-transformation"] = (
        "fixed-development-byte-bindings-database-and-transformation"
    )
    execution_authorized: Literal[False] = False
    runtime_readiness: Literal["containers-not-checked"] = "containers-not-checked"
    resume_implemented: Literal[True] = True
    metric_scoring_implemented: Literal[False] = False
    limitations: tuple[str, ...] = (
        "Three existing post-export mutations of one basic fixture, not independent repositories",
        "Original Syft export is preserved; only the copied export is changed and consumed",
        "Version change includes consistent identifiers/references, not a single JSON-field edit",
        "Exact replay verifies treatment/evidence, not accuracy or expected outcome agreement",
        "No public input, target execution, new mutation, retry or database refresh",
    )


DependencyBoundaryCaseId = Literal[
    "dev-dependency-empty-v1",
    "dev-dependency-unresolved-v1",
    "dev-dependency-malformed-v1",
    "dev-dependency-unsupported-v1",
]


class DependencyBoundaryCase(ResearchModel):
    case_id: DependencyBoundaryCaseId
    source_family: Literal["dependency-development-v1"] = "dependency-development-v1"
    split: Literal["development-not-held-out"] = "development-not-held-out"
    files: tuple[PlanFile, ...] = Field(min_length=1, max_length=1)
    selected_paths: tuple[Literal["uv.lock"]] = ("uv.lock",)
    expectation_sha256: Sha256
    review_status: Literal["historical-engineering-expectation-not-independent"] = (
        "historical-engineering-expectation-not-independent"
    )


class DependencyBoundaryPlan(ResearchModel):
    contract: Literal["benchmark-dependency-boundary-plan-v1"] = (
        "benchmark-dependency-boundary-plan-v1"
    )
    plan_id: Identifier
    pins: tuple[PlanFile, ...] = Field(min_length=10, max_length=10)
    implementation: tuple[PlanFile, ...] = Field(min_length=1, max_length=2048)
    database: DependencyDatabase
    cases: tuple[DependencyBoundaryCase, ...] = Field(min_length=1, max_length=4)
    repetitions: StrictInt = Field(ge=1, le=3)
    order: Literal["case-order-then-repetition"] = "case-order-then-repetition"
    stage_order: tuple[Literal["osv-direct"], Literal["syft"], Literal["osv-sbom"]] = (
        "osv-direct",
        "syft",
        "osv-sbom",
    )
    max_workers: Literal[1] = 1
    automatic_retries: Literal[0] = 0
    manual_retries: Literal[0] = 0
    mutation: None = None
    target_execution: Literal[False] = False
    protocol_status: Literal["development-plan-not-confirmatory-freeze"] = (
        "development-plan-not-confirmatory-freeze"
    )

    @model_validator(mode="after")
    def check_bindings(self) -> Self:
        check_file_set(self.pins)
        check_file_set(self.implementation)
        if len({c.case_id for c in self.cases}) != len(self.cases):
            raise ValueError("Duplicate dependency boundary case")
        if any(
            not p.path.startswith("src/") or not p.path.endswith(".py") for p in self.implementation
        ):
            raise ValueError("Implementation pins must name src Python files")
        return self


class DependencyBoundaryCell(ResearchModel):
    cell_id: Sha256
    case_id: DependencyBoundaryCaseId
    repetition: StrictInt = Field(ge=1, le=3)
    input_files: tuple[PlanFile, ...]
    selected_paths: tuple[Literal["uv.lock"]] = ("uv.lock",)
    expectation_sha256: Sha256
    state: Literal["not-attempted"] = "not-attempted"
    producer_invocations: Literal[0] = 0
    finding_records: None = None
    coverage: Literal["not-measured"] = "not-measured"


class DependencyBoundaryPreview(ResearchModel):
    contract: Literal["benchmark-dependency-boundary-dry-run-v1"] = (
        "benchmark-dependency-boundary-dry-run-v1"
    )
    plan_id: Identifier
    plan_sha256: Sha256
    plan_semantic_sha256: Sha256
    treatment_sha256: Sha256
    implementation_sha256: Sha256
    cells: tuple[DependencyBoundaryCell, ...] = Field(min_length=1, max_length=12)
    database: DependencyDatabase
    limits: dict[str, int | float]
    tool_images: tuple[str, str]
    plan_valid: Literal[True] = True
    validation_scope: Literal["fixed-development-input-boundary-byte-bindings"] = (
        "fixed-development-input-boundary-byte-bindings"
    )
    execution_authorized: Literal[False] = False
    runtime_readiness: Literal["containers-not-checked"] = "containers-not-checked"
    resume_implemented: Literal[True] = True
    metric_scoring_implemented: Literal[False] = False
    limitations: tuple[str, ...] = (
        "Four existing development input boundaries; no new target or scanner",
        "Malformed/unsupported format remains a blocked producer failure, not clean analysis",
        "No output is not zero findings; no-package exit is preserved with missing-output state",
        "Only verified partial/completed attempts can be reused; no retry or bypass",
        "Historical engineering expectations are not independent labels or scoring",
    )


class PublicPilotBenchmarkPlan(ResearchModel):
    contract: Literal["benchmark-public-pilot-plan-v1"] = "benchmark-public-pilot-plan-v1"
    plan_id: Identifier
    case_id: Literal["langgraph-cicd-source-pilot-v1"] = "langgraph-cicd-source-pilot-v1"
    source_family: Literal["langchain-samples-cicd-pipeline-example"] = (
        "langchain-samples-cicd-pipeline-example"
    )
    split: Literal["formative-pilot-not-held-out"] = "formative-pilot-not-held-out"
    pins: tuple[PlanFile, ...]
    implementation: tuple[PlanFile, ...] = Field(min_length=1, max_length=2048)
    cache_path: str
    rule_source: str
    cache_files: tuple[PlanFile, ...] = Field(min_length=3, max_length=3)
    rule_files: tuple[PlanFile, ...] = Field(min_length=69, max_length=69)
    database: DependencyDatabase
    repetitions: Literal[1] = 1
    internal_repetitions: Literal[3] = 3
    execution_unit: Literal["whole-fixed-pilot"] = "whole-fixed-pilot"
    max_workers: Literal[1] = 1
    automatic_retries: Literal[0] = 0
    manual_retries: Literal[0] = 0
    target_execution: Literal[False] = False
    oracle: Literal["no-complete-public-vulnerability-oracle"] = (
        "no-complete-public-vulnerability-oracle"
    )

    @model_validator(mode="after")
    def check_bindings(self) -> Self:
        for records in (self.pins, self.implementation, self.cache_files, self.rule_files):
            check_file_set(records)
        for path in (self.cache_path, self.rule_source):
            canonical_artifact_path(path)
            if not path.startswith("workspace/") or path.startswith("workspace/benchmarks/"):
                raise ValueError("Pilot inputs require a separate private workspace path")
        if any(
            not p.path.startswith("src/") or not p.path.endswith(".py") for p in self.implementation
        ):
            raise ValueError("Implementation pins must name src Python files")
        return self


class PublicPilotCell(ResearchModel):
    cell_id: Sha256
    case_id: Literal["langgraph-cicd-source-pilot-v1"] = "langgraph-cicd-source-pilot-v1"
    repetition: Literal[1] = 1
    internal_repetitions: Literal[3] = 3
    state: Literal["not-attempted"] = "not-attempted"
    finding_records: None = None
    producer_invocations: Literal[0] = 0
    coverage: Literal["not-measured"] = "not-measured"


class PublicPilotPreview(ResearchModel):
    contract: Literal["benchmark-public-pilot-dry-run-v1"] = "benchmark-public-pilot-dry-run-v1"
    plan_id: Identifier
    plan_sha256: Sha256
    plan_semantic_sha256: Sha256
    treatment_sha256: Sha256
    implementation_sha256: Sha256
    cells: tuple[PublicPilotCell, ...] = Field(min_length=1, max_length=1)
    validation_scope: Literal["fixed-pilot-resource-byte-bindings"] = (
        "fixed-pilot-resource-byte-bindings"
    )
    plan_valid: Literal[True] = True
    execution_authorized: Literal[False] = False
    runtime_readiness: Literal["containers-not-checked"] = "containers-not-checked"
    resume_implemented: Literal[True] = True
    metric_scoring_implemented: Literal[False] = False
    limitations: tuple[str, ...] = (
        "One fixed public pilot with three internal repetitions, not independent samples",
        "Only whole-attempt verified reuse; no per-stage recovery or retry",
        "Dry run checks input bytes, not target parsing or container availability",
        "No public vulnerability oracle, target execution, new repository or profile",
    )


class ResearchCase(ResearchModel):
    case_id: Identifier
    case_sha256: Sha256
    internal_repetitions: StrictInt = Field(ge=1, le=2)


class ResearchBenchmarkPlan(ResearchModel):
    contract: Literal["benchmark-research-plan-v1"] = "benchmark-research-plan-v1"
    plan_id: Identifier
    source_family: Literal["controlled-research-runner"] = "controlled-research-runner"
    split: Literal["development-not-held-out"] = "development-not-held-out"
    pins: tuple[PlanFile, ...] = Field(min_length=6, max_length=6)
    implementation: tuple[PlanFile, ...] = Field(min_length=1, max_length=2048)
    rule_source: str
    rule_files: tuple[PlanFile, ...] = Field(min_length=69, max_length=69)
    cases: tuple[ResearchCase, ...] = Field(min_length=15, max_length=15)
    repetitions: Literal[1] = 1
    order: Literal["registry-order"] = "registry-order"
    execution_unit: Literal["whole-controlled-case"] = "whole-controlled-case"
    max_workers: Literal[1] = 1
    automatic_retries: Literal[0] = 0
    manual_retries: Literal[0] = 0
    target_execution: Literal[False] = False
    oracle: Literal["authored-engineering-expectations-not-independent-labels"] = (
        "authored-engineering-expectations-not-independent-labels"
    )

    @model_validator(mode="after")
    def check_bindings(self) -> Self:
        for records in (self.pins, self.implementation, self.rule_files):
            check_file_set(records)
        canonical_artifact_path(self.rule_source)
        if not self.rule_source.startswith("workspace/") or self.rule_source.startswith(
            "workspace/benchmarks/"
        ):
            raise ValueError("Rules require a separate private workspace path")
        if len({case.case_id for case in self.cases}) != len(self.cases):
            raise ValueError("Duplicate controlled research case")
        if any(
            not p.path.startswith("src/") or not p.path.endswith(".py") for p in self.implementation
        ):
            raise ValueError("Implementation pins must name src Python files")
        return self


class ResearchCell(ResearchCase):
    cell_id: Sha256
    repetition: Literal[1] = 1
    state: Literal["not-attempted"] = "not-attempted"
    finding_records: None = None
    producer_invocations: Literal[0] = 0
    coverage: Literal["not-measured"] = "not-measured"


class ResearchPreview(ResearchModel):
    contract: Literal["benchmark-research-dry-run-v1"] = "benchmark-research-dry-run-v1"
    plan_id: Identifier
    plan_sha256: Sha256
    plan_semantic_sha256: Sha256
    treatment_sha256: Sha256
    implementation_sha256: Sha256
    cells: tuple[ResearchCell, ...] = Field(min_length=15, max_length=15)
    validation_scope: Literal["fixed-controlled-research-byte-bindings"] = (
        "fixed-controlled-research-byte-bindings"
    )
    plan_valid: Literal[True] = True
    execution_authorized: Literal[False] = False
    runtime_readiness: Literal["containers-not-checked"] = "containers-not-checked"
    resume_implemented: Literal[True] = True
    metric_scoring_implemented: Literal[False] = False
    limitations: tuple[str, ...] = (
        "Fifteen existing cases in one development family; no held-out or public admission",
        "One whole case per cell, retaining original internal dual-view repetitions",
        "Expected detector outcomes do not govern execution success",
        "No retry, per-pass recovery, accuracy scoring or complete-analysis claim",
        "Byte validation does not establish Docker or image availability",
    )


type AdmittedCell = (
    PlannedCell
    | SemgrepCell
    | KicsCell
    | DependencyCell
    | DependencyMutationCell
    | DependencyBoundaryCell
    | PublicPilotCell
    | ResearchCell
)
type AdmittedPreview = (
    BenchmarkDryRunV2
    | BenchmarkDryRunV3
    | SemgrepPreview
    | KicsPreview
    | DependencyPreview
    | DependencyMutationPreview
    | DependencyBoundaryPreview
    | PublicPilotPreview
    | ResearchPreview
)
