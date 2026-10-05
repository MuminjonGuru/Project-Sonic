from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, JsonValue, StrictInt, StringConstraints, model_validator

from agentsec_evidence.agents.validation import canonical_artifact_path, load_agent_json
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.models.contracts import ContractModel, InventoryEntry, NonEmpty, Sha256

RuleId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.-]+$", max_length=256)]
Count = Annotated[StrictInt, Field(ge=0)]
Coordinate = Annotated[StrictInt, Field(ge=1)]
MAX_FILES = 64
MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 1024 * 1024
MAX_REPORT_BYTES = 4 * 1024 * 1024


class ResearchModel(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CandidateRule(ResearchModel):
    source_path: NonEmpty
    sha256: Sha256
    native_rule_id: RuleId
    license_expression: Literal["MIT"] = "MIT"
    upstream_test_state: Literal["passed", "no-active-assertions"]

    @model_validator(mode="after")
    def validate_path(self) -> Self:
        canonical_artifact_path(self.source_path)
        if not self.source_path.startswith("python/") or not self.source_path.endswith(".yml"):
            raise ValueError("Candidate rule requires a Python YAML source path")
        return self


class SemgrepResearchProfile(ResearchModel):
    contract: Literal["semgrep-research-profile-v1"] = "semgrep-research-profile-v1"
    profile_id: NonEmpty
    status: Literal["development-candidate"] = "development-candidate"
    tool_id: Literal["semgrep"] = "semgrep"
    tool_version: Literal["1.174.0"] = "1.174.0"
    image: Literal[
        "semgrep/semgrep@sha256:f1f7b71861c7b28b6e0f661225a2c4f58a484f5d0f182465c6d6b3b22f972ade"
    ]
    source_repository: Literal["https://gitlab.com/gitlab-org/security-products/sast-rules"]
    source_revision: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
    source_license_sha256: Sha256
    rules: tuple[CandidateRule, ...] = Field(min_length=1, max_length=256)
    views: Literal["research-and-repository-policy"] = "research-and-repository-policy"
    native_formats: tuple[Literal["json", "sarif"], ...] = ("json", "sarif")
    public_source_admission: Literal["not-granted"] = "not-granted"
    limitations: tuple[NonEmpty, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_rules(self) -> Self:
        paths = [r.source_path for r in self.rules]
        ids = [r.native_rule_id for r in self.rules]
        if paths != sorted(paths) or len(set(p.casefold() for p in paths)) != len(paths):
            raise ValueError("Rules must have sorted unique portable source paths")
        if len(set(ids)) != len(ids) or self.native_formats != ("json", "sarif"):
            raise ValueError("Unique rule IDs and paired native JSON/SARIF are required")
        return self


def load_research_profile(raw: bytes) -> SemgrepResearchProfile:
    return SemgrepResearchProfile.model_validate(load_agent_json(raw, max_bytes=MAX_TOTAL_BYTES))


def verify_rule_bytes(
    profile: SemgrepResearchProfile, files: Mapping[str, bytes], *, license_bytes: bytes
) -> None:
    """Bind a candidate to exact rule bytes without parsing or executing third-party YAML."""
    checked = SemgrepResearchProfile.model_validate(profile.model_dump(mode="json"))
    if set(files) != {rule.source_path for rule in checked.rules}:
        raise ValueError("Rule input set differs from candidate manifest")
    if (
        len(license_bytes) > MAX_FILE_BYTES
        or sha256_bytes(license_bytes) != checked.source_license_sha256
    ):
        raise ValueError("Upstream license bytes differ")
    if sum(len(data) for data in files.values()) > MAX_TOTAL_BYTES:
        raise ValueError("Rule pack exceeds byte budget")
    for rule in checked.rules:
        data = files[rule.source_path]
        if len(data) > MAX_FILE_BYTES or sha256_bytes(data) != rule.sha256:
            raise ValueError("Candidate rule bytes differ or exceed budget")


class ResearchInput(InventoryEntry):
    byte_length: Count


class SemgrepResearchScope(ResearchModel):
    contract: Literal["semgrep-research-scope-v1"] = "semgrep-research-scope-v1"
    target_snapshot_id: NonEmpty
    selection_sha256: Sha256
    profile_sha256: Sha256
    selected_files: tuple[ResearchInput, ...] = Field(min_length=1, max_length=MAX_FILES)
    policy_files: tuple[ResearchInput, ...] = Field(default=(), max_length=MAX_FILES)
    policy_context: Literal["full-parent-required"] = "full-parent-required"
    execution_authorization: Literal["not-granted"] = "not-granted"

    @model_validator(mode="after")
    def validate_inventory(self) -> Self:
        combined = (*self.selected_files, *self.policy_files)
        if len(combined) > MAX_FILES:
            raise ValueError("Combined source and policy file budget exceeded")
        for group in (self.selected_files, self.policy_files):
            paths = [canonical_artifact_path(item.path) for item in group]
            if paths != sorted(paths):
                raise ValueError("Scope paths must be sorted")
        if len({item.path.casefold() for item in combined}) != len(combined):
            raise ValueError("Selected and policy inputs must be unique and disjoint")
        if any(not item.path.endswith(".py") for item in self.selected_files):
            raise ValueError("First research treatment selects Python files only")
        if any(
            type(item.byte_length) is not int or item.byte_length > MAX_FILE_BYTES
            for item in combined
        ):
            raise ValueError("File byte budget exceeded")
        if sum(item.byte_length for item in combined) > MAX_TOTAL_BYTES:
            raise ValueError("Scope byte budget exceeded")
        return self


class FindingAnchor(ResearchModel):
    rule_id: RuleId
    path: NonEmpty
    start_line: Coordinate
    start_column: Coordinate
    end_line: Coordinate
    end_column: Coordinate

    @model_validator(mode="after")
    def validate_region(self) -> Self:
        canonical_artifact_path(self.path)
        if (self.end_line, self.end_column) <= (self.start_line, self.start_column):
            raise ValueError("A nonempty ordered source range is required")
        return self


class ResearchFinding(ResearchModel):
    anchor: FindingAnchor
    message: NonEmpty
    json_pointer: Annotated[str, StringConstraints(pattern=r"^/results/(0|[1-9][0-9]*)$")] | None
    sarif_pointer: Annotated[str, StringConstraints(pattern=r"^/runs/0/results/(0|[1-9][0-9]*)$")]
    native_suppressions: tuple[dict[str, JsonValue], ...] = ()
    review_state: Literal["unreviewed"] = "unreviewed"


class ResearchFileObservation(ResearchModel):
    path: NonEmpty
    state: Literal["reported", "reported-with-native-issue", "native-skipped", "unreported"]
    native_reason: NonEmpty | None = None

    @model_validator(mode="after")
    def validate_reason(self) -> Self:
        canonical_artifact_path(self.path)
        if (self.state in {"native-skipped", "reported-with-native-issue"}) != (
            self.native_reason is not None
        ):
            raise ValueError("A native skip/issue requires its native reason")
        return self


class SemgrepPassEvidence(ResearchModel):
    contract: Literal["semgrep-pass-evidence-v1"] = "semgrep-pass-evidence-v1"
    profile_sha256: Sha256
    scope_sha256: Sha256
    execution_id: NonEmpty
    role: Literal["research", "repository-policy"]
    native_json_sha256: Sha256
    native_sarif_sha256: Sha256
    files: tuple[ResearchFileObservation, ...] = Field(min_length=1, max_length=MAX_FILES)
    findings: tuple[ResearchFinding, ...] = Field(max_length=10_000)
    native_errors: tuple[JsonValue, ...] = ()
    native_skipped_rules: tuple[JsonValue, ...] = ()
    native_execution_successful: bool | None = None
    native_notifications: tuple[JsonValue, ...] = ()
    native_skip_details_available: bool
    native_declared_rule_ids: tuple[RuleId, ...]
    analysis_completeness: Literal["not-established"] = "not-established"

    @model_validator(mode="after")
    def validate_observations(self) -> Self:
        paths = [item.path for item in self.files]
        anchors = [semantic_hash(item.anchor.model_dump(mode="json")) for item in self.findings]
        if paths != sorted(paths) or len(set(p.casefold() for p in paths)) != len(paths):
            raise ValueError("File observations must be sorted and unique")
        if len(set(anchors)) != len(anchors):
            raise ValueError("Ambiguous repeated finding anchors")
        reported = {
            item.path
            for item in self.files
            if item.state in {"reported", "reported-with-native-issue"}
        }
        if any(finding.anchor.path not in reported for finding in self.findings):
            raise ValueError("A finding must refer to a reported input")
        if self.role == "research" and any(f.json_pointer is None for f in self.findings):
            raise ValueError("Research evidence must retain every finding in JSON and SARIF")
        if any(f.json_pointer is None and not f.native_suppressions for f in self.findings):
            raise ValueError("Unexplained SARIF-only finding")
        if tuple(sorted(set(self.native_declared_rule_ids))) != self.native_declared_rule_ids:
            raise ValueError("Declared rule IDs must be sorted and unique")
        if any(f.anchor.rule_id not in self.native_declared_rule_ids for f in self.findings):
            raise ValueError("Finding rule missing from native SARIF declarations")
        return self


class PolicyFindingView(ResearchModel):
    research_index: Count
    policy_index: Count | None
    state: Literal[
        "reported", "native-suppression-marked", "file-excluded", "not-observed", "unknown"
    ]


class SemgrepDualView(ResearchModel):
    contract: Literal["semgrep-dual-view-v1"] = "semgrep-dual-view-v1"
    research: SemgrepPassEvidence
    repository_policy: SemgrepPassEvidence | None
    findings: tuple[PolicyFindingView, ...]
    policy_state: Literal["not-run", "observed"]
    vulnerability_total: None = None
    analysis_completeness: Literal["not-established"] = "not-established"

    @model_validator(mode="after")
    def validate_views(self) -> Self:
        if self.research.role != "research":
            raise ValueError("Research pass required")
        policy = self.repository_policy
        if (policy is None) != (self.policy_state == "not-run"):
            raise ValueError("Policy execution state differs")
        if policy and (
            policy.role != "repository-policy"
            or policy.profile_sha256 != self.research.profile_sha256
            or policy.scope_sha256 != self.research.scope_sha256
            or policy.execution_id == self.research.execution_id
        ):
            raise ValueError("Dual views must bind separate passes of the same treatment and scope")
        if [r.research_index for r in self.findings] != list(range(len(self.research.findings))):
            raise ValueError("Every research finding requires one policy-view observation")
        if self.findings != policy_observations(self.research, policy):
            raise ValueError("Policy observations differ from retained evidence")
        return self


def policy_observations(
    research: SemgrepPassEvidence, policy: SemgrepPassEvidence | None
) -> tuple[PolicyFindingView, ...]:
    if policy is None:
        return tuple(
            PolicyFindingView(research_index=i, policy_index=None, state="unknown")
            for i in range(len(research.findings))
        )
    if [f.path for f in research.files] != [f.path for f in policy.files]:
        raise ValueError("Policy and research input denominators differ")
    research_by_anchor = {f.anchor: f for f in research.findings}
    policy_by_anchor = {f.anchor: (i, f) for i, f in enumerate(policy.findings)}
    if not set(policy_by_anchor).issubset(research_by_anchor):
        raise ValueError("Policy finding absent from evidence-retaining pass")
    files = {f.path: f for f in policy.files}
    observations: list[PolicyFindingView] = []
    for index, finding in enumerate(research.findings):
        match = policy_by_anchor.get(finding.anchor)
        policy_index = None
        state: Literal[
            "reported", "native-suppression-marked", "file-excluded", "not-observed", "unknown"
        ]
        if match is not None:
            policy_index, native = match
            if (
                native.message != finding.message
                or native.native_suppressions != finding.native_suppressions
            ):
                raise ValueError("Matched findings disagree across passes")
            state = "native-suppression-marked" if native.native_suppressions else "reported"
        elif files[finding.anchor.path].state == "native-skipped" and files[
            finding.anchor.path
        ].native_reason in {"semgrepignore_patterns_match", "gitignore_patterns_match"}:
            state = "file-excluded"
        elif (
            files[finding.anchor.path].state != "reported"
            or policy.native_errors
            or policy.native_skipped_rules
            or policy.native_notifications
            or policy.native_execution_successful is not True
        ):
            state = "unknown"
        else:
            state = "not-observed"
        observations.append(
            PolicyFindingView(research_index=index, policy_index=policy_index, state=state)
        )
    return tuple(observations)
