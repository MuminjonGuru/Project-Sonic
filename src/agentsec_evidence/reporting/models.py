from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, JsonValue, StrictInt, model_validator

from agentsec_evidence.agents.inventory import ArtifactInventory, artifact_inventory_semantic_sha256
from agentsec_evidence.agents.records import AgentRunDetails
from agentsec_evidence.agents.validation import canonical_artifact_path
from agentsec_evidence.core.identity import semantic_hash
from agentsec_evidence.dependencies.models import DependencyModel, StageComparison
from agentsec_evidence.intake.input_plan import ToolInputPlan
from agentsec_evidence.models.contracts import (
    CoverageRecord,
    FailureRecord,
    Finding,
    Sha256,
    Summary,
)
from agentsec_evidence.pilot.models import STAGES, PilotRow, PilotStage, repeatability
from agentsec_evidence.reporting.research_models import ResearchCaseSummary
from agentsec_evidence.research.models import SemgrepDualView

Count = Annotated[int, Field(ge=0)]


class DependencyStageSummary(DependencyModel):
    stage: str
    state: Literal["complete", "partial", "failed", "unsupported", "missing"]
    observations: Count | None
    identified_unique_packages: Count | None
    eligible_reported_packages: Count | None
    reported_package_advisory_matches: Count | None
    reported_match_occurrences: Count | None
    eligible_package_advisory_matches: Count | None
    unsupported_observations: Count | None
    relationships: Count | None
    per_package_matching_completion: Literal["not-observable"] = "not-observable"


class DependencySummary(DependencyModel):
    contract: Literal["dependency-summary-v1"] = "dependency-summary-v1"
    run_id: str
    state: Literal["complete", "partial", "failed"]
    scope_available: bool
    eligible_unique_packages: Count | None
    separate_local_packages: Count | None
    unsupported_scope_records: Count | None
    ambiguous_projections: Count | None
    database_sha256: Sha256 | None
    stages: list[DependencyStageSummary]
    comparisons: list[StageComparison]
    timing_ns: dict[str, Count]
    limitations: list[str]


class SourceBase(DependencyModel):
    run_id: str
    state: str
    label: str
    revision: str
    target_content_sha256: Sha256 | None
    source_manifest_sha256: Sha256
    source_semantic_sha256: Sha256 | None


class StaticSource(SourceBase):
    kind: Literal["static"] = "static"
    summary: Summary
    coverage: list[CoverageRecord]
    failures: list[FailureRecord]


class DependencySource(SourceBase):
    kind: Literal["dependency"] = "dependency"
    summary: DependencySummary


class AgentSource(SourceBase):
    kind: Literal["agent-static"] = "agent-static"
    summary: Summary
    coverage: list[CoverageRecord]
    failures: list[FailureRecord]
    agent_details: AgentRunDetails

    @model_validator(mode="after")
    def validate_source(self) -> AgentSource:
        if self.run_id != self.agent_details.run_id or self.run_id != self.summary.run_id:
            raise ValueError("Agent source identity differs from its details")
        count = self.agent_details.native_result_count
        if self.summary.normalized_finding_count != (count if count is not None else 0):
            raise ValueError("Agent stored-record count differs from native evidence")
        return self


class ResearchSource(SourceBase):
    kind: Literal["semgrep-research"] = "semgrep-research"
    summary: ResearchCaseSummary

    @model_validator(mode="after")
    def validate_source(self) -> ResearchSource:
        if self.state != self.summary.state:
            raise ValueError("Research source state differs")
        expected = (
            "research-"
            + semantic_hash(
                {"manifest": self.source_manifest_sha256, "case": self.summary.case_id}
            )[:32]
        )
        if self.run_id != expected:
            raise ValueError("Research source identity differs from its manifest and case")
        return self


class PilotFileReference(DependencyModel):
    path: str
    sha256: Sha256

    @model_validator(mode="after")
    def validate_path(self) -> PilotFileReference:
        canonical_artifact_path(self.path)
        return self


class PilotDirectorySkip(DependencyModel):
    native_pointer: str = Field(pattern=r"^/paths/skipped/[0-9]+$")
    path: str
    reason: Literal["semgrepignore_patterns_match", "gitignore_patterns_match"]
    selected_descendants: tuple[str, ...] = Field(min_length=1)
    interpretation: Literal["Ancestor skip evidence, not individual native file observations"]

    @model_validator(mode="after")
    def validate_paths(self) -> PilotDirectorySkip:
        canonical_artifact_path(self.path)
        for path in self.selected_descendants:
            canonical_artifact_path(path)
            if not path.startswith(self.path + "/"):
                raise ValueError("Directory context must reference descendants")
        if list(self.selected_descendants) != sorted(set(self.selected_descendants)):
            raise ValueError("Directory descendants must be unique and ordered")
        return self


class PilotRepetitionSummary(DependencyModel):
    repetition: StrictInt = Field(ge=1, le=3)
    semgrep: SemgrepDualView
    directory_skips: dict[Literal["research", "repository-policy"], list[PilotDirectorySkip]]
    agent_run_id: str
    agent_execution_id: str
    agent_native_scanned_files: Count
    agent_per_file_completion: Literal["not-observable"] = "not-observable"
    agent_findings: list[Finding]
    dependency: DependencySummary

    @model_validator(mode="after")
    def validate_repetition(self) -> PilotRepetitionSummary:
        if set(self.directory_skips) != {"research", "repository-policy"}:
            raise ValueError("Both policy-view directory contexts are required")
        if self.semgrep.research is None or self.semgrep.repository_policy is None:
            raise ValueError("Completed pilot requires both retained Semgrep views")
        if len({f.record_id for f in self.agent_findings}) != len(self.agent_findings):
            raise ValueError("Duplicate pilot finding IDs")
        if any(
            f.run_id != self.agent_run_id
            or f.execution_id != self.agent_execution_id
            or f.assessment.verification_state != "unreviewed"
            for f in self.agent_findings
        ):
            raise ValueError("Pilot findings must retain their unreviewed native run identity")
        return self


class PilotSarifBinding(DependencyModel):
    repetition: StrictInt = Field(ge=1, le=3)
    stage: PilotStage
    result_count: Count
    run_sha256: Sha256


class PilotPlanRecord(DependencyModel):
    """Read-model plan metadata, not permission to execute a new repository or profile."""

    contract: Literal["same-repository-pilot-plan-v1"]
    approval: str
    repository: str
    revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    content_sha256: Sha256
    database_sha256: Sha256
    expected_files: Count
    python_paths: tuple[str, ...] = Field(min_length=1, max_length=64)
    repetitions: Literal[3]
    order: tuple[PilotStage, ...]
    pins: dict[str, Sha256]
    split: Literal["formative-pilot-not-held-out"]
    target_execution: Literal[False]
    oracle: Literal["no-complete-public-vulnerability-oracle"]
    implicit_git_filtering: Literal[False]
    dockerfile: Literal["present-unsupported-not-run"]

    @model_validator(mode="after")
    def validate_record(self) -> PilotPlanRecord:
        if self.order != STAGES or list(self.python_paths) != sorted(set(self.python_paths)):
            raise ValueError("Retained plan order or selection differs")
        for path in (*self.python_paths, *self.pins):
            canonical_artifact_path(path)
        return self


class PublicPilotSummary(DependencyModel):
    contract: Literal["public-source-pilot-summary-v1"] = "public-source-pilot-summary-v1"
    evidence_role: Literal["formative-pilot-not-held-out"] = "formative-pilot-not-held-out"
    plan: PilotPlanRecord
    inventory: ArtifactInventory
    input_plans: tuple[ToolInputPlan, ToolInputPlan]
    rows: tuple[PilotRow, ...] = Field(min_length=18, max_length=18)
    repetitions: tuple[PilotRepetitionSummary, ...] = Field(min_length=3, max_length=3)
    repeatability: dict[str, bool | None]
    repetition_wall_ns: tuple[Count, Count, Count]
    attempt_wall_ns: Count
    manual_recovery_actions_during_attempt: Count
    manual_preparation_and_adjudication_time_ns: None = None
    retained_coverage: list[dict[str, JsonValue]] = Field(min_length=10, max_length=10)
    references: tuple[PilotFileReference, ...] = Field(min_length=1)
    sarif_bindings: tuple[PilotSarifBinding, ...] = Field(min_length=15, max_length=15)
    vulnerability_total: None = None
    analysis_completeness: Literal["not-established"] = "not-established"
    limitations: tuple[str, ...]

    @model_validator(mode="after")
    def validate_pilot(self) -> PublicPilotSummary:
        if self.repeatability != repeatability(list(self.rows)):
            raise ValueError("Public pilot repeatability differs from its rows")
        if any(r.state not in {"partial", "complete"} for r in self.rows):
            raise ValueError("Only fully retained completed pilot attempts are admitted")
        if [r.repetition for r in self.repetitions] != [1, 2, 3]:
            raise ValueError("Pilot repetitions must remain separate and ordered")
        run_ids = [
            run_id
            for rep in self.repetitions
            for run_id in (rep.agent_run_id, rep.dependency.run_id)
        ]
        execution_ids = [rep.agent_execution_id for rep in self.repetitions]
        execution_ids.extend(
            view.execution_id
            for rep in self.repetitions
            for view in (rep.semgrep.research, rep.semgrep.repository_policy)
            if view is not None
        )
        # Equal semantic results are expected; reusing one execution as a repeat is not.
        if len(set(run_ids)) != len(run_ids) or len(set(execution_ids)) != len(execution_ids):
            raise ValueError("Pilot repetitions must retain distinct run and execution identities")
        if self.inventory.snapshot.content_sha256 != self.plan.content_sha256:
            raise ValueError("Pilot inventory refers to another target")
        if len(self.inventory.records) != self.plan.expected_files:
            raise ValueError("Pilot full inventory count differs")
        if self.inventory.snapshot.revision != self.plan.revision:
            raise ValueError("Pilot inventory revision differs")
        if [p.tool_id for p in self.input_plans] != ["semgrep", "agent-audit"]:
            raise ValueError("Pilot input plans must identify both source tools in order")
        for plan in self.input_plans:
            if (
                plan.target_snapshot_id != self.inventory.snapshot.snapshot_id
                or plan.artifact_inventory_semantic_sha256
                != artifact_inventory_semantic_sha256(self.inventory)
                or [s.path for s in plan.selections]
                != sorted(r.source.path for r in self.inventory.records)
            ):
                raise ValueError("Pilot plan is not bound to the full inventory")
            if tuple(s.path for s in plan.selections if s.disposition == "selected") != (
                self.plan.python_paths
            ):
                raise ValueError("Pilot source selection differs")
        paths = [ref.path for ref in self.references]
        if paths != sorted(set(paths)):
            raise ValueError("Pilot references must be unique and ordered")
        if not {p for row in self.rows for p in row.evidence}.issubset(paths):
            raise ValueError("Pilot row evidence is missing from references")
        expected = [(i, stage) for i in range(1, 4) for stage in STAGES if stage != "syft"]
        if [(b.repetition, b.stage) for b in self.sarif_bindings] != expected:
            raise ValueError("Pilot SARIF views and repetitions cannot be omitted or combined")
        for binding in self.sarif_bindings:
            row = next(
                r
                for r in self.rows
                if (r.repetition, r.stage) == (binding.repetition, binding.stage)
            )
            if binding.result_count != row.finding_records:
                raise ValueError("Pilot SARIF count differs from native records")
        for rep in self.repetitions:
            if rep.dependency.database_sha256 != self.plan.database_sha256:
                raise ValueError("Pilot dependency database differs from the frozen plan")
            dependency_stages = {stage.stage: stage for stage in rep.dependency.stages}
            if len(dependency_stages) != len(rep.dependency.stages) or not {
                "osv-direct",
                "syft",
                "osv-sbom",
            }.issubset(dependency_stages):
                raise ValueError("Pilot dependency stages are missing or duplicated")
            rows: dict[str, PilotRow] = {
                r.stage: r for r in self.rows if r.repetition == rep.repetition
            }
            if len(rep.agent_findings) != rows["agent-audit"].finding_records:
                raise ValueError("Pilot agent finding accounting differs")
            for stage, evidence in (
                ("semgrep-research", rep.semgrep.research),
                ("semgrep-policy", rep.semgrep.repository_policy),
            ):
                if evidence is None:
                    raise ValueError("Missing pilot Semgrep view")
                if [f.path for f in evidence.files] != list(self.plan.python_paths):
                    raise ValueError("Pilot native file denominator differs from selection")
                if len(evidence.findings) != rows[stage].finding_records:
                    raise ValueError("Pilot Semgrep finding accounting differs")
                for skip in rep.directory_skips[evidence.role]:
                    if not set(skip.selected_descendants).issubset(self.plan.python_paths):
                        raise ValueError("Directory context includes unselected input")
            if any(
                f.target_snapshot_id != self.inventory.snapshot.snapshot_id
                or any(loc.artifact_path not in self.plan.python_paths for loc in f.locations)
                for f in rep.agent_findings
            ):
                raise ValueError("Pilot agent finding is outside selected source")
            for stage in ("osv-direct", "syft", "osv-sbom"):
                observation = dependency_stages[stage]
                if (
                    rows[stage].package_identities != observation.identified_unique_packages
                    or rows[stage].state != observation.state
                    or (
                        stage != "syft"
                        and rows[stage].finding_records != observation.reported_match_occurrences
                    )
                ):
                    raise ValueError("Pilot dependency identity projection differs")
        for row in self.rows:
            expected_unit = (
                "package-identities"
                if row.stage == "syft"
                else "package-advisory-occurrences"
                if row.stage.startswith("osv-")
                else "native-rule-reports"
            )
            if row.unit != expected_unit or (
                row.stage == "syft" and row.finding_records is not None
            ):
                raise ValueError("Pilot counting unit differs from its stage")
        if self.attempt_wall_ns < sum(self.repetition_wall_ns):
            raise ValueError("Pilot timing hierarchy differs")
        return self


class PublicPilotSource(SourceBase):
    kind: Literal["public-source-pilot"] = "public-source-pilot"
    state: Literal["partial"] = "partial"
    source_semantic_sha256: None = None
    summary: PublicPilotSummary

    @model_validator(mode="after")
    def validate_source(self) -> PublicPilotSource:
        expected = "public-pilot-" + semantic_hash({"manifest": self.source_manifest_sha256})[:32]
        if (
            self.run_id != expected
            or self.revision != self.summary.plan.revision
            or self.target_content_sha256 != self.summary.plan.content_sha256
            or self.label != self.summary.plan.repository
        ):
            raise ValueError("Public pilot identity differs from its plan and evidence seal")
        return self


type ReportSource = Annotated[
    StaticSource | DependencySource | AgentSource | ResearchSource | PublicPilotSource,
    Field(discriminator="kind"),
]


class CommonReport(DependencyModel):
    contract: Literal[
        "common-report-v1", "common-report-v2", "common-report-v3", "common-report-v4"
    ] = "common-report-v1"
    generated_at: AwareDatetime
    sensitivity: Literal["internal"] = "internal"
    sources: list[ReportSource]
    sarif_runs: Count
    counting_policy: str = (
        "Keep sources and comparison paths separate; do not sum paired OSV results, "
        "package observations or heterogeneous finding units into a vulnerability total."
    )
    limitations: list[str] = Field(
        default_factory=lambda: [
            "This derivative is not a new scan or an independent security adjudication.",
            "Valid SARIF does not guarantee consumer support; upload compatibility is untested.",
            "Internal evidence has not passed public-release redaction or license clearance.",
        ]
    )
    exporter: str = "agentsec-evidence-common-report/1"
    provenance: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_agent_version(self) -> CommonReport:
        expected = (
            "common-report-v4"
            if any(isinstance(source, PublicPilotSource) for source in self.sources)
            else "common-report-v3"
            if any(isinstance(source, ResearchSource) for source in self.sources)
            else "common-report-v2"
            if any(isinstance(source, AgentSource) for source in self.sources)
            else "common-report-v1"
        )
        if self.contract != expected:
            raise ValueError("Source kinds require the corresponding common report version")
        return self
