from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, StrictInt, model_validator

from agentsec_evidence.agents.validation import canonical_artifact_path
from agentsec_evidence.core.identity import semantic_hash
from agentsec_evidence.research.execution import ResearchExecutionAssessment
from agentsec_evidence.research.models import (
    Count,
    ResearchModel,
    SemgrepDualView,
    SemgrepPassEvidence,
    SemgrepResearchScope,
)
from agentsec_evidence.research.policy import SemgrepPolicyAssessment


class ResearchPassSummary(ResearchModel):
    key: str = Field(pattern=r"^(research|repository-policy)-[12]$")
    repetition: StrictInt = Field(ge=1, le=2)
    evidence: SemgrepPassEvidence
    execution: ResearchExecutionAssessment
    exit_code: StrictInt | None
    duration_ns: Count
    native_finding_records: Count
    native_json_path: str
    native_sarif_path: str

    @model_validator(mode="after")
    def validate_pass(self) -> Self:
        canonical_artifact_path(self.native_json_path)
        canonical_artifact_path(self.native_sarif_path)
        if self.key != f"{self.evidence.role}-{self.repetition}":
            raise ValueError("Research pass identity differs")
        if self.native_finding_records != len(self.evidence.findings):
            raise ValueError("Research native finding count differs")
        if self.execution.report_state != "reconciled":
            raise ValueError("Retained matrix pass requires paired evidence")
        return self


class ResearchCaseSummary(ResearchModel):
    contract: Literal["semgrep-research-summary-v1"] = "semgrep-research-summary-v1"
    case_id: str = Field(pattern=r"^[a-z0-9-]+$", max_length=100)
    evidence_role: Literal["controlled-development-not-held-out"] = (
        "controlled-development-not-held-out"
    )
    state: Literal["policy-refused", "syntax-refused", "observed"]
    selected_file_count: Count
    policy: SemgrepPolicyAssessment
    scope: SemgrepResearchScope | None
    syntax_state: Literal["not-run", "rejected", "parsed"]
    passes: tuple[ResearchPassSummary, ...] = Field(max_length=4)
    dual_views: tuple[SemgrepDualView, ...] = Field(max_length=2)
    unrun_finding_count: None = None
    vulnerability_total: None = None
    analysis_completeness: Literal["not-established"] = "not-established"
    limitations: tuple[str, ...] = (
        "This is replayed controlled development evidence, not a public-source scan.",
        "Views and repetitions are separate observations, not additive vulnerabilities.",
        "Native suppression does not establish reviewer approval or remediation.",
        "Recorded commands and hashes are not external execution attestation.",
    )

    @model_validator(mode="after")
    def validate_accounting(self) -> Self:
        if self.state == "policy-refused":
            if not self.policy.blockers or self.scope is not None or self.syntax_state != "not-run":
                raise ValueError("Policy refusal disagrees with evidence")
        elif self.policy.blockers or self.scope is None:
            raise ValueError("Accepted policy needs scope without blockers")
        if self.scope and self.selected_file_count != len(self.scope.selected_files):
            raise ValueError("Selected-file denominator differs")
        if self.state != "observed":
            if self.passes or self.dual_views:
                raise ValueError("Refused input cannot claim scanner observations")
            if self.state == "syntax-refused" and self.syntax_state != "rejected":
                raise ValueError("Syntax refusal disagrees")
            return self
        if self.syntax_state != "parsed" or len(self.passes) not in {2, 4}:
            raise ValueError("Observed controlled case requires syntax and paired passes")
        if len(self.dual_views) != len(self.passes) // 2:
            raise ValueError("Dual-view count differs")
        keys = [p.key for p in self.passes]
        expected = [
            f"{role}-{i}"
            for i in range(1, len(self.dual_views) + 1)
            for role in ("research", "repository-policy")
        ]
        if keys != expected or len({p.evidence.execution_id for p in self.passes}) != len(keys):
            raise ValueError("Passes must remain unique and ordered by repetition and role")
        for row in self.passes:
            if (
                row.native_json_path != f"{self.case_id}/{row.key}/native.json"
                or row.native_sarif_path != f"{self.case_id}/{row.key}/native.sarif"
            ):
                raise ValueError("Native evidence path differs from its case and pass")
        assert self.scope is not None
        scope_hash = semantic_hash(self.scope.model_dump(mode="json"))
        for index, view in enumerate(self.dual_views):
            pair = self.passes[index * 2 : index * 2 + 2]
            if view.research != pair[0].evidence or view.repository_policy != pair[1].evidence:
                raise ValueError("Dual view differs from retained passes")
            if any(
                p.evidence.scope_sha256 != scope_hash
                or p.evidence.profile_sha256 != self.scope.profile_sha256
                for p in pair
            ):
                raise ValueError("Pass refers to another treatment or selected input")
        return self
