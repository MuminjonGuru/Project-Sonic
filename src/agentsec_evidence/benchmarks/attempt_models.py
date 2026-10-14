"""Append-only attempt records; workflow completion is not analysis completeness."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal, Self

from pydantic import Field, StrictInt, model_validator

from agentsec_evidence.benchmarks.models import Identifier
from agentsec_evidence.models.contracts import Sha256
from agentsec_evidence.research.models import ResearchModel
from agentsec_evidence.research.retained import RetainedManifest

AttemptId = Annotated[str, Field(pattern=r"^attempt_[0-9a-f]{32}$")]
RunId = Annotated[str, Field(pattern=r"^run_[0-9a-f]{32}$")]
AttemptState = Literal["partial-analysis", "refused", "execution-failed", "interrupted"]


class AttemptStart(ResearchModel):
    contract: Literal["benchmark-attempt-start-v1"] = "benchmark-attempt-start-v1"
    attempt_id: AttemptId
    ordinal: StrictInt = Field(ge=1, le=39)
    cell_id: Sha256
    case_id: Identifier
    repetition: StrictInt = Field(ge=1, le=3)
    plan_sha256: Sha256
    previous_finish_sha256: Sha256 | None
    started_at: datetime


class RetryAuthorization(ResearchModel):
    policy_id: Literal["missing-docker-prelaunch-once-v1"] = "missing-docker-prelaunch-once-v1"
    prior_attempt_id: AttemptId
    cause: Literal["docker-unavailable-before-launch"]
    remediation: Literal["docker-command-availability-restored"]
    authorization: Literal["explicit-cli-request-not-authenticated-identity"] = (
        "explicit-cli-request-not-authenticated-identity"
    )


class AttemptStartV2(ResearchModel):
    contract: Literal["benchmark-attempt-start-v2"] = "benchmark-attempt-start-v2"
    attempt_id: AttemptId
    ordinal: StrictInt = Field(ge=1, le=78)
    cell_id: Sha256
    case_id: Identifier
    repetition: StrictInt = Field(ge=1, le=3)
    plan_sha256: Sha256
    previous_finish_sha256: Sha256 | None
    started_at: datetime
    retry: RetryAuthorization | None = None


class AttemptEvidence(ResearchModel):
    run_id: RunId
    terminal_state: str
    semantic_sha256: Sha256
    bundle_files: RetainedManifest
    state: Literal["partial-analysis", "refused", "execution-failed"]
    scanner_invocations: StrictInt = Field(ge=0, le=1)
    finding_records: StrictInt | None = Field(default=None, ge=0)
    per_file_completion: Literal["unknown", "not-run"]


class AttemptFinish(ResearchModel):
    contract: Literal["benchmark-attempt-finish-v1"] = "benchmark-attempt-finish-v1"
    attempt_id: AttemptId
    start_sha256: Sha256
    ended_at: datetime
    duration_ns: StrictInt = Field(ge=0)
    state: AttemptState
    evidence: AttemptEvidence | None = None
    error_kind: Literal["runner-or-verification-error", "keyboard-interrupt"] | None = None

    @model_validator(mode="after")
    def check_outcome(self) -> Self:
        if self.evidence is not None:
            if self.state != self.evidence.state or self.error_kind is not None:
                raise ValueError("Attempt outcome differs from its verified evidence")
        elif (self.state, self.error_kind) not in {
            ("execution-failed", "runner-or-verification-error"),
            ("interrupted", "keyboard-interrupt"),
        }:
            raise ValueError("Unverified attempt must remain failed or interrupted")
        return self


class CellProgress(ResearchModel):
    cell_id: Sha256
    case_id: Identifier
    repetition: StrictInt
    state: Literal[
        "not-attempted", "partial-analysis", "refused", "execution-failed", "interrupted"
    ]
    attempt_id: AttemptId | None = None
    run_id: RunId | None = None
    finding_records: StrictInt | None = None
    scanner_invocations: StrictInt | None = None
    verified_terminal_attempt: bool = False


class BenchmarkProgress(ResearchModel):
    contract: Literal["benchmark-progress-v1"] = "benchmark-progress-v1"
    plan_sha256: Sha256
    plan_semantic_sha256: Sha256
    session: str
    cells: tuple[CellProgress, ...]
    workflow_complete: bool
    blocked: bool
    newly_attempted_cells: StrictInt = Field(ge=0, le=39)
    reused_verified_cells: StrictInt = Field(ge=0, le=39)
    scoring_implemented: Literal[False] = False
    analysis_complete: Literal[False] = False
    limitations: tuple[str, ...] = (
        "Fixed authored Agent Audit development cases only; not a held-out benchmark",
        "Partial analysis and policy refusal can finish an attempt; neither means safe",
        "Interrupted/failed attempts block continuation; no automatic or manual retry yet",
        "Hash consistency and process locking do not authenticate evidence against its owner",
    )


class BenchmarkProgressV2(ResearchModel):
    contract: Literal["benchmark-progress-v2"] = "benchmark-progress-v2"
    plan_sha256: Sha256
    plan_semantic_sha256: Sha256
    session: str
    cells: tuple[CellProgress, ...]
    attempts: tuple[CellProgress, ...] = Field(max_length=78)
    workflow_complete: bool
    blocked: bool
    newly_attempted_cells: StrictInt = Field(ge=0, le=39)
    newly_created_attempts: StrictInt = Field(ge=0, le=39)
    reused_verified_cells: StrictInt = Field(ge=0, le=39)
    manual_retry_attempts: StrictInt = Field(ge=0, le=39)
    scoring_implemented: Literal[False] = False
    analysis_complete: Literal[False] = False
    limitations: tuple[str, ...] = (
        "Fixed authored Agent Audit development cases only; not a held-out benchmark",
        "Cells show latest state; attempts preserve earlier failures and must be reported too",
        "One explicit retry only for verified missing Docker before any container launch",
        "Interrupted, unverified and other failed attempts remain blocked; no automatic retry",
        "Partial analysis and policy refusal do not mean safe or complete security coverage",
        "Recorded retry cause/remediation is an operator assertion, not identity attestation",
    )


SemgrepAttemptState = Literal[
    "completed-with-findings",
    "completed-without-findings",
    "partial-analysis",
    "execution-failed",
    "interrupted",
]


class SemgrepAttemptEvidence(ResearchModel):
    run_id: RunId
    terminal_state: str
    semantic_sha256: Sha256
    bundle_files: RetainedManifest
    snapshot_files: RetainedManifest
    state: SemgrepAttemptState
    scanner_invocations: StrictInt = Field(ge=0, le=1)
    finding_records: StrictInt | None = Field(default=None, ge=0)
    per_file_completion: Literal["unknown", "not-run"]


class SemgrepAttemptFinish(ResearchModel):
    contract: Literal["benchmark-semgrep-attempt-finish-v1"] = "benchmark-semgrep-attempt-finish-v1"
    attempt_id: AttemptId
    start_sha256: Sha256
    ended_at: datetime
    duration_ns: StrictInt = Field(ge=0)
    state: SemgrepAttemptState
    evidence: SemgrepAttemptEvidence | None = None
    error_kind: Literal["runner-or-verification-error", "keyboard-interrupt"] | None = None

    @model_validator(mode="after")
    def check_outcome(self) -> Self:
        if self.evidence is not None:
            if self.state != self.evidence.state or self.error_kind is not None:
                raise ValueError("Attempt outcome differs from verified Semgrep evidence")
        elif (self.state, self.error_kind) not in {
            ("execution-failed", "runner-or-verification-error"),
            ("interrupted", "keyboard-interrupt"),
        }:
            raise ValueError("Unverified Semgrep attempt must remain failed or interrupted")
        return self


class SemgrepCellProgress(ResearchModel):
    cell_id: Sha256
    case_id: Identifier
    repetition: StrictInt
    state: Literal[
        "not-attempted",
        "completed-with-findings",
        "completed-without-findings",
        "partial-analysis",
        "execution-failed",
        "interrupted",
    ]
    attempt_id: AttemptId | None = None
    run_id: RunId | None = None
    finding_records: StrictInt | None = None
    scanner_invocations: StrictInt | None = None
    verified_terminal_attempt: bool = False


class SemgrepProgress(ResearchModel):
    contract: Literal["benchmark-semgrep-progress-v1"] = "benchmark-semgrep-progress-v1"
    plan_sha256: Sha256
    plan_semantic_sha256: Sha256
    session: str
    cells: tuple[SemgrepCellProgress, ...]
    workflow_complete: bool
    blocked: bool
    newly_attempted_cells: StrictInt = Field(ge=0, le=3)
    reused_verified_cells: StrictInt = Field(ge=0, le=3)
    scoring_implemented: Literal[False] = False
    analysis_complete: Literal[False] = False
    limitations: tuple[str, ...] = (
        "Existing controlled Semgrep fixture only; not the public research treatment",
        "Completed means native workflow completion, not comprehensive analysis or safety",
        "Native reported paths do not independently prove per-file analysis completeness",
        "All failures and interruptions block; no automatic or manual Semgrep retry",
        "Historical expected outcomes remain unscored and are not independently adjudicated",
    )


KicsAttemptState = Literal[
    "completed-with-findings",
    "completed-without-findings",
    "partial-analysis",
    "unsupported",
    "execution-failed",
    "interrupted",
]


class KicsAttemptEvidence(ResearchModel):
    run_id: RunId
    terminal_state: str
    semantic_sha256: Sha256
    bundle_files: RetainedManifest
    snapshot_files: RetainedManifest
    state: KicsAttemptState
    scanner_invocations: StrictInt = Field(ge=0, le=1)
    finding_records: StrictInt | None = Field(default=None, ge=0)
    native_files_scanned: StrictInt | None = Field(default=None, ge=0)
    native_files_parsed: StrictInt | None = Field(default=None, ge=0)
    native_queries_total: StrictInt | None = Field(default=None, ge=0)
    per_file_completion: Literal["unknown", "not-run"]


class KicsAttemptFinish(ResearchModel):
    contract: Literal["benchmark-kics-attempt-finish-v1"] = "benchmark-kics-attempt-finish-v1"
    attempt_id: AttemptId
    start_sha256: Sha256
    ended_at: datetime
    duration_ns: StrictInt = Field(ge=0)
    state: KicsAttemptState
    evidence: KicsAttemptEvidence | None = None
    error_kind: Literal["runner-or-verification-error", "keyboard-interrupt"] | None = None

    @model_validator(mode="after")
    def check_outcome(self) -> Self:
        if self.evidence is not None:
            if self.state != self.evidence.state or self.error_kind is not None:
                raise ValueError("Attempt outcome differs from verified KICS evidence")
        elif (self.state, self.error_kind) not in {
            ("execution-failed", "runner-or-verification-error"),
            ("interrupted", "keyboard-interrupt"),
        }:
            raise ValueError("Unverified KICS attempt must remain failed or interrupted")
        return self


class KicsCellProgress(ResearchModel):
    cell_id: Sha256
    case_id: Identifier
    repetition: StrictInt
    state: Literal[
        "not-attempted",
        "completed-with-findings",
        "completed-without-findings",
        "partial-analysis",
        "unsupported",
        "execution-failed",
        "interrupted",
    ]
    attempt_id: AttemptId | None = None
    run_id: RunId | None = None
    finding_records: StrictInt | None = None
    scanner_invocations: StrictInt | None = None
    native_files_scanned: StrictInt | None = None
    native_files_parsed: StrictInt | None = None
    native_queries_total: StrictInt | None = None
    verified_terminal_attempt: bool = False


class KicsProgress(ResearchModel):
    contract: Literal["benchmark-kics-progress-v1"] = "benchmark-kics-progress-v1"
    plan_sha256: Sha256
    plan_semantic_sha256: Sha256
    session: str
    cells: tuple[KicsCellProgress, ...]
    workflow_complete: bool
    blocked: bool
    newly_attempted_cells: StrictInt = Field(ge=0, le=12)
    reused_verified_cells: StrictInt = Field(ge=0, le=12)
    scoring_implemented: Literal[False] = False
    analysis_complete: Literal[False] = False
    limitations: tuple[str, ...] = (
        "Existing four KICS development cases only; no public Dockerfile treatment",
        "Completed means native workflow completion, not safety or independent oracle agreement",
        "Unsupported and partial-analysis are separate terminal observations, not clean results",
        "Reported aggregate file/query counts do not establish per-file completion",
        "All execution failures and interruptions block; no automatic or manual KICS retry",
    )


type AdmittedProgress = BenchmarkProgress | BenchmarkProgressV2 | SemgrepProgress | KicsProgress
type AdmittedFinish = AttemptFinish | SemgrepAttemptFinish | KicsAttemptFinish
type AdmittedEvidence = AttemptEvidence | SemgrepAttemptEvidence | KicsAttemptEvidence
type AdmittedCellProgress = CellProgress | SemgrepCellProgress | KicsCellProgress
type AdmittedState = AttemptState | SemgrepAttemptState | KicsAttemptState
