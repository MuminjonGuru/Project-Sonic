from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    field_validator,
)

from agentsec_evidence.core.paths import normalize_relative_path

SCHEMA_VERSION: Literal["0.1.0"] = "0.1.0"

Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
NonEmpty = Annotated[str, StringConstraints(min_length=1)]
RelativePath = Annotated[str, StringConstraints(min_length=1, max_length=4096)]
NormalizedSeverity = Literal["informational", "low", "medium", "high", "critical", "unknown"]
CoverageExecution = Literal["not-run", "success", "partial", "failed", "timed-out", "cancelled"]
FailureStage = Literal[
    "intake",
    "planning",
    "launch",
    "execution",
    "capture",
    "parse",
    "normalize",
    "validate",
    "export",
    "analyze",
    "release",
]
FailureCategory = Literal[
    "configuration",
    "missing-tool",
    "incompatible-version",
    "unsafe-target",
    "timeout",
    "resource-limit",
    "nonzero-exit",
    "malformed-output",
    "unsupported-schema",
    "parser-defect",
    "network",
    "authentication",
    "quota",
    "vendor",
    "internal",
]
ValidationKind = Literal["schema", "sarif", "provenance", "bundle"]


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class RunState(StrEnum):
    CREATED = "created"
    ACQUIRING = "acquiring"
    READY = "ready"
    PLANNED = "planned"
    RUNNING = "running"
    CAPTURED = "captured"
    PARSING = "parsing"
    NORMALIZING = "normalizing"
    VALIDATING = "validating"
    COMPLETE = "complete"
    PARTIAL = "partial"
    TIMED_OUT = "timed-out"
    CANCELLED = "cancelled"
    EXECUTION_FAILED = "execution-failed"
    PARSE_FAILED = "parse-failed"
    VALIDATION_FAILED = "validation-failed"
    REJECTED = "rejected"
    FINALIZED = "finalized"


class ExecutionOutcome(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    CANCELLED = "cancelled"
    UNSUPPORTED = "unsupported"
    UNSAFE_TO_RUN = "unsafe-to-run"


class Sensitivity(StrEnum):
    PUBLIC = "public"
    PUBLIC_REDACTED = "public-redacted"
    METADATA_ONLY = "metadata-only"
    RESTRICTED_VENDOR = "restricted-vendor"
    DISCLOSURE_SENSITIVE = "disclosure-sensitive"
    SECRET = "secret"
    INTERNAL = "internal"


class Producer(ContractModel):
    tool_id: NonEmpty
    tool_version: NonEmpty
    adapter_id: NonEmpty
    adapter_version: NonEmpty


class TaxonomyMapping(ContractModel):
    taxonomy: NonEmpty
    value: NonEmpty
    origin: Literal["native-observed", "mechanically-derived", "researcher-adjudicated"]


class Rule(ContractModel):
    native_id: NonEmpty
    name: str | None = None
    help_uri: str | None = None
    mappings: list[TaxonomyMapping] = Field(default_factory=list)


class FindingMessage(ContractModel):
    title: NonEmpty
    description: str | None = None
    remediation: str | None = None


class Severity(ContractModel):
    native_label: str | None = None
    native_score: float | None = None
    normalized: NormalizedSeverity
    mapping_id: NonEmpty


class Confidence(ContractModel):
    native_label: str | None = None
    normalized: Literal["low", "medium", "high", "unknown"] | None = None


class Location(ContractModel):
    artifact_path: RelativePath
    start_line: int | None = Field(default=None, ge=1)
    start_column: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    end_column: int | None = Field(default=None, ge=1)

    @field_validator("artifact_path")
    @classmethod
    def validate_artifact_path(cls, value: str) -> str:
        return normalize_relative_path(value)


class EvidenceReference(ContractModel):
    origin: Literal["native-observed", "mechanically-derived", "researcher-adjudicated"]
    blob_sha256: Sha256
    json_pointer: str | None = None
    byte_start: int | None = Field(default=None, ge=0)
    byte_end: int | None = Field(default=None, ge=0)


class Assessment(ContractModel):
    verification_state: Literal[
        "unreviewed", "confirmed", "rejected", "uncertain", "disputed", "disclosure-pending"
    ]
    exposure_statement: Literal["static-observable-condition"]


class Fingerprints(ContractModel):
    native: str | None = None
    record_v1: Sha256
    candidate_equivalence_v1: Sha256


class Finding(ContractModel):
    schema_version: Literal["0.1.0"] = SCHEMA_VERSION
    record_id: NonEmpty
    run_id: NonEmpty
    execution_id: NonEmpty
    target_snapshot_id: NonEmpty
    domain: Literal["static"] = "static"
    producer: Producer
    rule: Rule
    message: FindingMessage
    severity: Severity
    confidence: Confidence
    locations: list[Location]
    evidence: list[EvidenceReference] = Field(min_length=1)
    assessment: Assessment
    fingerprints: Fingerprints
    limitations: list[str] = Field(default_factory=list)
    native_extension: dict[str, JsonValue] = Field(default_factory=dict)


class CoverageRecord(ContractModel):
    schema_version: Literal["0.1.0"] = SCHEMA_VERSION
    coverage_id: NonEmpty
    run_id: NonEmpty
    execution_id: NonEmpty
    target_snapshot_id: NonEmpty
    property_id: NonEmpty
    producer: Producer
    applicability: Literal["applicable", "not-applicable", "unknown"]
    adapter_support: Literal["supported", "partial", "unsupported", "unknown"]
    execution: CoverageExecution
    observation: Literal["observed-risk", "observed-control", "no-observation", "unknown"]
    limitations: list[str] = Field(default_factory=list)


class FailureRecord(ContractModel):
    schema_version: Literal["0.1.0"] = SCHEMA_VERSION
    failure_id: NonEmpty
    run_id: NonEmpty
    execution_id: str | None = None
    stage: FailureStage
    category: FailureCategory
    retryability: Literal["yes", "no", "unknown"]
    affected_scope: NonEmpty
    native_exit_code: int | None = None
    native_signal: int | None = None
    sanitized_message: NonEmpty
    evidence_blob_sha256: list[Sha256] = Field(default_factory=list)
    partial_evidence_usable: bool
    retry_of: str | None = None
    final_disposition: NonEmpty


class InventoryEntry(ContractModel):
    schema_version: Literal["0.1.0"] = SCHEMA_VERSION
    path: RelativePath
    sha256: Sha256
    byte_length: int = Field(ge=0)
    media_type: NonEmpty

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return normalize_relative_path(value)


class TargetSnapshot(ContractModel):
    schema_version: Literal["0.1.0"] = SCHEMA_VERSION
    target_id: NonEmpty
    snapshot_id: NonEmpty
    source_kind: Literal["project-fixture", "local", "git"]
    source_label: NonEmpty
    revision: NonEmpty
    retrieved_at: AwareDatetime
    license_status: Literal["project-authored-private", "identified", "unknown"]
    content_sha256: Sha256
    inventory_sha256: Sha256
    file_count: int = Field(ge=0)
    total_bytes: int = Field(ge=0)


class ExecutionLimits(ContractModel):
    timeout_seconds: int = Field(gt=0)
    cpu_count: float = Field(gt=0)
    memory_mb: int = Field(gt=0)
    pids: int = Field(gt=0)
    tmpfs_mb: int = Field(gt=0)
    max_stdout_bytes: int = Field(gt=0)
    max_stderr_bytes: int = Field(gt=0)
    max_native_bytes: int = Field(gt=0)


class ExecutionRecord(ContractModel):
    schema_version: Literal["0.1.0"] = SCHEMA_VERSION
    execution_id: NonEmpty
    run_id: NonEmpty
    target_snapshot_id: NonEmpty
    producer: Producer
    image: NonEmpty
    argv: list[str] = Field(min_length=1)
    approved_environment_names: list[str] = Field(default_factory=list)
    profile_id: NonEmpty
    config_sha256: Sha256
    ruleset_sha256: Sha256
    limits: ExecutionLimits
    started_at: AwareDatetime
    ended_at: AwareDatetime
    duration_ns: int = Field(ge=0)
    exit_code: int | None = None
    outcome: ExecutionOutcome
    timed_out: bool
    stdout_byte_length: int = Field(ge=0)
    stderr_byte_length: int = Field(ge=0)
    native_byte_length: int = Field(ge=0)
    peak_host_rss_bytes: int = Field(ge=0)
    output_limited: bool
    stdout_truncated: bool
    stderr_truncated: bool
    container_cleanup_attempted: bool
    container_cleanup_succeeded: bool | None = None


class RunEvent(ContractModel):
    schema_version: Literal["0.1.0"] = SCHEMA_VERSION
    event_id: NonEmpty
    run_id: NonEmpty
    occurred_at: AwareDatetime
    component: NonEmpty
    previous_state: RunState | None = None
    next_state: RunState
    reason: NonEmpty


class RunRecord(ContractModel):
    schema_version: Literal["0.1.0"] = SCHEMA_VERSION
    run_id: NonEmpty
    run_label: NonEmpty
    profile_id: NonEmpty
    target_snapshot_id: NonEmpty
    state: RunState
    terminal_state: RunState | None = None
    created_at: AwareDatetime
    finalized_at: AwareDatetime | None = None
    execution_ids: list[str] = Field(default_factory=list)
    config_sha256: Sha256
    semantic_hash_version: Literal["run-semantic-v2"] = "run-semantic-v2"
    semantic_sha256: Sha256 | None = None


class BlobDescriptor(ContractModel):
    schema_version: Literal["0.1.0"] = SCHEMA_VERSION
    sha256: Sha256
    byte_length: int = Field(ge=0)
    media_type: NonEmpty
    sensitivity: Sensitivity
    producer: NonEmpty
    logical_role: NonEmpty
    relative_path: RelativePath

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        return normalize_relative_path(value)


class BlobIndex(ContractModel):
    schema_version: Literal["0.1.0"] = SCHEMA_VERSION
    blobs: list[BlobDescriptor]


class ParserReport(ContractModel):
    schema_version: Literal["0.1.0"] = SCHEMA_VERSION
    parser_id: NonEmpty
    parser_version: NonEmpty
    execution_id: NonEmpty
    source_blob_sha256: Sha256
    parsed_at: AwareDatetime
    native_result_count: int = Field(ge=0)
    native_error_count: int = Field(ge=0)
    native_scanned_path_count: int = Field(ge=0)
    native_skipped_path_count: int = Field(ge=0)
    native_skipped_rule_count: int = Field(ge=0)
    normalized_finding_count: int = Field(ge=0)
    unknown_top_level_fields: list[str] = Field(default_factory=list)
    complete: bool


class ValidationCheck(ContractModel):
    name: NonEmpty
    passed: bool
    detail: str


class ValidationReport(ContractModel):
    schema_version: Literal["0.1.0"] = SCHEMA_VERSION
    validation_id: NonEmpty
    run_id: NonEmpty
    kind: ValidationKind
    checked_at: AwareDatetime
    passed: bool
    checks: list[ValidationCheck]


class ManifestEntry(ContractModel):
    relative_path: RelativePath
    sha256: Sha256
    byte_length: int = Field(ge=0)
    sensitivity: Sensitivity

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        return normalize_relative_path(value)


class BundleManifest(ContractModel):
    schema_version: Literal["0.1.0"] = SCHEMA_VERSION
    bundle_id: NonEmpty
    run_id: NonEmpty
    state: Literal["finalized"] = "finalized"
    created_at: AwareDatetime
    entries: list[ManifestEntry]
    entries_sha256: Sha256


class Summary(ContractModel):
    schema_version: Literal["0.1.0"] = SCHEMA_VERSION
    run_id: NonEmpty
    generated_at: AwareDatetime
    execution_outcome: ExecutionOutcome
    native_result_count: int = Field(ge=0)
    native_error_count: int = Field(ge=0)
    normalized_finding_count: int = Field(ge=0)
    normalized_coverage_count: int = Field(ge=0)
    normalized_failure_count: int = Field(ge=0)
    provenance_resolution_rate: float = Field(ge=0, le=1)
    sarif_representability_rate: float = Field(ge=0, le=1)
    sarif_valid: bool
    duration_ns: int = Field(ge=0)
    statement: Literal["Semgrep detection was unchanged and was not evaluated as improved"] = (
        "Semgrep detection was unchanged and was not evaluated as improved"
    )
