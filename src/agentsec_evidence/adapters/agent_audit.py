from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Annotated, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from agentsec_evidence.agents.inputs import CheckedAgentInput
from agentsec_evidence.agents.validation import canonical_artifact_path, load_agent_json
from agentsec_evidence.core.identity import new_opaque_id, semantic_hash, sha256_bytes
from agentsec_evidence.models.contracts import (
    Assessment,
    Confidence,
    EvidenceReference,
    Finding,
    FindingMessage,
    Fingerprints,
    Location,
    NormalizedSeverity,
    Producer,
    Rule,
    Severity,
    TaxonomyMapping,
)

NATIVE_VERSION = "0.20.0"
MAX_NATIVE_BYTES = 2 * 1024 * 1024
Count = Annotated[int, Field(ge=0)]
NonEmpty = Annotated[str, Field(min_length=1)]


class AgentAuditParseError(ValueError):
    """Incompatible evidence; error messages never interpolate target content."""


class NativeModel(BaseModel):
    model_config = ConfigDict(extra="allow", strict=True)


class NativeLocation(NativeModel):
    file_path: NonEmpty
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    start_column: Count | None
    end_column: Count | None
    snippet: str | None


class NativeRemediation(NativeModel):
    description: str
    code_example: str | None
    reference_url: str | None


class NativeFinding(NativeModel):
    rule_id: NonEmpty
    title: NonEmpty
    description: str
    severity: NonEmpty
    category: NonEmpty
    location: NativeLocation
    confidence: float = Field(ge=0, le=1)
    tier: Literal["BLOCK", "WARN", "INFO", "SUPPRESSED"]
    suppressed: bool
    suppressed_reason: str | None
    suppressed_by: str | None
    needs_review: bool
    cwe_id: str | None
    owasp_id: str | None
    asi_categories: list[str]
    remediation: NativeRemediation
    metadata: dict[str, JsonValue]
    detected_at: NonEmpty
    reason: str


class NativeSummary(NativeModel):
    total: Count
    actionable: Count
    suppressed: Count
    by_severity: dict[str, Count]
    by_category: dict[str, Count]
    by_tier: dict[str, Count]
    risk_score: float = Field(ge=0)
    risk_label: str


class NativeDocument(NativeModel):
    version: Literal["0.20.0"]
    scan_timestamp: NonEmpty
    scan_path: Literal["/target"]
    scanned_files: Count
    summary: NativeSummary
    findings: list[NativeFinding]


@dataclass(frozen=True)
class ParsedAgentAudit:
    document: NativeDocument
    raw_bytes: bytes
    source_blob_sha256: str
    unknown_field_paths: tuple[str, ...]


@dataclass(frozen=True)
class NormalizedAgentAudit:
    findings: tuple[Finding, ...]
    native_scanned_files: int
    per_file_coverage: Literal["not-observable"] = "not-observable"
    limitations: tuple[str, ...] = (
        "Native counters are not proof of per-file or per-property analysis completion",
        "Native confidence, risk and actionable counts are unvalidated producer assertions",
        "Process outcome, diagnostics, input admission and bundle validation remain separate",
    )


def _unknown_paths(model: NativeModel, prefix: str = "") -> list[str]:
    def escape(value: str) -> str:
        return value.replace("~", "~0").replace("/", "~1")

    paths = [f"{prefix}/{escape(key)}" for key in (model.model_extra or {})]
    for key in type(model).model_fields:
        value = getattr(model, key)
        if isinstance(value, NativeModel):
            paths.extend(_unknown_paths(value, f"{prefix}/{key}"))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                if isinstance(child, NativeModel):
                    paths.extend(_unknown_paths(child, f"{prefix}/{key}/{index}"))
    return paths


def _validate_counts(document: NativeDocument) -> None:
    findings, summary = document.findings, document.summary
    # This reproduces the pinned producer's counter, not operational actionability.
    actionable = sum(
        not item.suppressed and item.confidence >= 0.30 and item.tier != "SUPPRESSED"
        for item in findings
    )
    expected_tiers = dict.fromkeys(("BLOCK", "WARN", "INFO", "SUPPRESSED"), 0)
    expected_tiers.update(Counter(item.tier for item in findings))
    if (
        summary.total != len(findings)
        or summary.actionable != actionable
        or summary.suppressed != sum(item.suppressed for item in findings)
        or summary.by_severity != dict(Counter(item.severity for item in findings))
        or summary.by_category != dict(Counter(item.category for item in findings))
        or summary.by_tier != expected_tiers
    ):
        raise AgentAuditParseError("Native summary counters disagree with retained findings")
    for item in findings:
        location = item.location
        if location.end_line < location.start_line or (
            location.end_line == location.start_line
            and location.start_column is not None
            and location.end_column is not None
            and location.end_column < location.start_column
        ):
            raise AgentAuditParseError("Native source range is reversed")


def parse_agent_audit_json(data: bytes) -> ParsedAgentAudit:
    try:
        raw = load_agent_json(data, max_bytes=MAX_NATIVE_BYTES)
        document = NativeDocument.model_validate(raw)
        _validate_counts(document)
    except AgentAuditParseError:
        raise
    except (ValueError, RecursionError, MemoryError):
        raise AgentAuditParseError(
            "Native JSON is invalid or outside the pinned contract"
        ) from None
    return ParsedAgentAudit(
        document, data, sha256_bytes(data), tuple(sorted(_unknown_paths(document)))
    )


def normalize_agent_audit(
    parsed: ParsedAgentAudit,
    *,
    inputs: Iterable[CheckedAgentInput],
    run_id: str,
    execution_id: str,
    target_snapshot_id: str,
) -> NormalizedAgentAudit:
    """Normalize evidence only. This does not admit a scan or mark coverage complete."""
    # Revalidate against retained bytes so mutable parsed models cannot alter the evidence.
    original = parse_agent_audit_json(parsed.raw_bytes)
    if (
        original.document != parsed.document
        or original.source_blob_sha256 != parsed.source_blob_sha256
        or original.unknown_field_paths != parsed.unknown_field_paths
    ):
        raise AgentAuditParseError("Parsed document does not match retained native bytes")
    checked: dict[str, CheckedAgentInput] = {}
    for checked_input in inputs:
        artifact = checked_input.artifact
        if artifact.target_snapshot_id != target_snapshot_id or artifact.source.path in checked:
            raise AgentAuditParseError("Input identity is ambiguous or belongs to another snapshot")
        checked[artifact.source.path] = checked_input
    findings: list[Finding] = []
    severity_map: dict[str, NormalizedSeverity] = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "informational",
    }
    producer = Producer(
        tool_id="agent-audit",
        tool_version=NATIVE_VERSION,
        adapter_id="agent-audit-json",
        adapter_version="0.1.0",
    )
    for index, native in enumerate(original.document.findings):
        if not native.location.file_path.startswith("/target/"):
            raise AgentAuditParseError("Finding is outside the admitted target mount")
        try:
            path = canonical_artifact_path(native.location.file_path.removeprefix("/target/"))
        except ValueError as exc:
            raise AgentAuditParseError("Finding has a non-canonical artifact path") from exc
        item = checked.get(path)
        if item is None or item.artifact.parse_state != "parsed":
            raise AgentAuditParseError("Finding does not reference a validated input")
        limitations = [
            "Native finding and remediation are unreviewed; static evidence is not exploitability",
            "Native confidence is preserved, not calibrated or normalized",
            "Native column coordinates are retained only; their convention is not admitted",
        ]
        if item.artifact.kind == "mcp-config":
            location = Location(artifact_path=path)
            limitations.append("MCP fallback line positions are not source-precise; path only")
        elif item.artifact.kind == "python-source":
            if item.line_count is None or native.location.end_line > item.line_count:
                raise AgentAuditParseError("Finding source range exceeds validated input")
            location = Location(
                artifact_path=path,
                start_line=native.location.start_line,
                end_line=native.location.end_line,
            )
        else:
            raise AgentAuditParseError("Finding references an unsupported artifact kind")
        if native.suppressed or native.tier == "SUPPRESSED":
            limitations.append("Native suppression retained; not removed from evidence")
        if native.severity not in severity_map:
            limitations.append("Unrecognized native severity maps to unknown")
        if native.rule_id == "AGENT-001":
            limitations.append(
                "Preflight eval case received a shell-injection mapping; adjudication is required"
            )
        mappings = [
            TaxonomyMapping(taxonomy=taxonomy, value=value, origin="native-observed")
            for taxonomy, value in (("CWE", native.cwe_id), ("OWASP", native.owasp_id))
            if value
        ]
        fingerprint_data: dict[str, JsonValue] = {
            "tool": producer.tool_id,
            "rule": native.rule_id,
            "path": path,
            "input_sha256": item.artifact.source.sha256,
            "start_line": location.start_line,
            "end_line": location.end_line,
            "message": native.description,
        }
        findings.append(
            Finding(
                record_id=new_opaque_id("finding"),
                run_id=run_id,
                execution_id=execution_id,
                target_snapshot_id=target_snapshot_id,
                producer=producer,
                rule=Rule(native_id=native.rule_id, name=native.title, mappings=mappings),
                message=FindingMessage(
                    title=native.title,
                    description=native.description,
                    remediation=native.remediation.description or None,
                ),
                severity=Severity(
                    native_label=native.severity,
                    native_score=None,
                    normalized=severity_map.get(native.severity, "unknown"),
                    mapping_id="agent-audit-severity-v1",
                ),
                confidence=Confidence(native_label=str(native.confidence), normalized=None),
                locations=[location],
                evidence=[
                    EvidenceReference(
                        origin="native-observed",
                        blob_sha256=original.source_blob_sha256,
                        json_pointer=f"/findings/{index}",
                    )
                ],
                assessment=Assessment(
                    verification_state="unreviewed",
                    exposure_statement="static-observable-condition",
                ),
                fingerprints=Fingerprints(
                    native=None,
                    record_v1=semantic_hash(fingerprint_data),
                    candidate_equivalence_v1=semantic_hash(
                        {
                            "target": target_snapshot_id,
                            "path": path,
                            "line": location.start_line,
                            "rule": native.rule_id,
                        }
                    ),
                ),
                limitations=limitations,
                native_extension={
                    "agent_audit": cast(dict[str, JsonValue], native.model_dump(mode="json"))
                },
            )
        )
    return NormalizedAgentAudit(tuple(findings), original.document.scanned_files)
