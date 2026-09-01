from __future__ import annotations

import json
from dataclasses import dataclass
from typing import cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from agentsec_evidence.core.identity import new_opaque_id, semantic_hash
from agentsec_evidence.core.paths import normalize_relative_path
from agentsec_evidence.execution.config import SemgrepToolConfig
from agentsec_evidence.models.contracts import (
    Assessment,
    Confidence,
    CoverageRecord,
    EvidenceReference,
    FailureRecord,
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


class SemgrepParseError(ValueError):
    """Native Semgrep JSON was malformed or incompatible."""


class NativeModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class NativePoint(NativeModel):
    line: int = Field(ge=1)
    col: int = Field(ge=1)
    offset: int | None = Field(default=None, ge=0)


class NativeExtra(NativeModel):
    message: str
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
    severity: str | None = None
    fingerprint: str | None = None
    lines: str | None = None
    validation_state: str | None = None
    engine_kind: str | None = None


class NativeResult(NativeModel):
    check_id: str
    path: str
    start: NativePoint
    end: NativePoint
    extra: NativeExtra


class NativePaths(NativeModel):
    scanned: list[str] = Field(default_factory=list)
    skipped: list[JsonValue] = Field(default_factory=list)


class NativeDocument(NativeModel):
    version: str
    results: list[NativeResult]
    errors: list[JsonValue]
    paths: NativePaths
    skipped_rules: list[JsonValue] = Field(default_factory=list)


@dataclass(frozen=True)
class ParsedSemgrep:
    document: NativeDocument
    unknown_top_level_fields: tuple[str, ...]


@dataclass(frozen=True)
class NormalizedSemgrep:
    findings: tuple[Finding, ...]
    coverage: tuple[CoverageRecord, ...]
    failures: tuple[FailureRecord, ...]


def _reject_constant(value: str) -> None:
    raise SemgrepParseError(f"Non-finite JSON number rejected: {value}")


def _reject_duplicate_pairs(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise SemgrepParseError(f"Duplicate JSON key rejected: {key}")
        result[key] = value
    return result


def parse_semgrep_json(data: bytes) -> ParsedSemgrep:
    try:
        decoded = data.decode("utf-8", errors="strict")
        raw = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
        document = NativeDocument.model_validate(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        if isinstance(exc, SemgrepParseError):
            raise
        raise SemgrepParseError(str(exc)) from exc

    known = set(NativeDocument.model_fields)
    raw_mapping = cast(dict[str, JsonValue], raw)
    unknown = tuple(sorted(set(raw_mapping) - known))
    return ParsedSemgrep(document=document, unknown_top_level_fields=unknown)


def _relative_semgrep_path(native_path: str) -> str:
    normalized = native_path.replace("\\", "/")
    if normalized.startswith("/src/"):
        return normalize_relative_path(normalized.removeprefix("/src/"))
    if normalized == "/src":
        raise SemgrepParseError("Finding path points to target root, not an artifact")
    return normalize_relative_path(normalized)


def _severity(native_label: str | None) -> Severity:
    severity_map: dict[str, NormalizedSeverity] = {
        "ERROR": "high",
        "WARNING": "medium",
        "INFO": "informational",
        "INVENTORY": "informational",
    }
    normalized = severity_map.get((native_label or "").upper(), "unknown")
    return Severity(
        native_label=native_label,
        native_score=None,
        normalized=normalized,
        mapping_id="semgrep-severity-v1",
    )


def _taxonomy_mappings(metadata: dict[str, JsonValue]) -> list[TaxonomyMapping]:
    native_cwe = metadata.get("cwe")
    values: list[str] = []
    if isinstance(native_cwe, str):
        values = [native_cwe]
    elif isinstance(native_cwe, list):
        values = [item for item in native_cwe if isinstance(item, str)]
    return [
        TaxonomyMapping(taxonomy="CWE", value=value, origin="native-observed") for value in values
    ]


def normalize_semgrep(
    parsed: ParsedSemgrep,
    *,
    tool: SemgrepToolConfig,
    run_id: str,
    execution_id: str,
    target_snapshot_id: str,
    source_blob_sha256: str,
) -> NormalizedSemgrep:
    producer = Producer(
        tool_id=tool.tool_id,
        tool_version=parsed.document.version,
        adapter_id=tool.adapter_id,
        adapter_version=tool.adapter_version,
    )
    findings: list[Finding] = []
    for index, native in enumerate(parsed.document.results):
        path = _relative_semgrep_path(native.path)
        location = Location(
            artifact_path=path,
            start_line=native.start.line,
            start_column=native.start.col,
            end_line=native.end.line,
            end_column=native.end.col,
        )
        mappings = _taxonomy_mappings(native.extra.metadata)
        record_fingerprint = semantic_hash(
            cast(
                JsonValue,
                {
                    "tool": tool.tool_id,
                    "rule": native.check_id,
                    "path": path,
                    "region": [
                        native.start.line,
                        native.start.col,
                        native.end.line,
                        native.end.col,
                    ],
                    "message": native.extra.message,
                },
            )
        )
        equivalence_fingerprint = semantic_hash(
            cast(
                JsonValue,
                {
                    "target": target_snapshot_id,
                    "weaknesses": sorted(mapping.value for mapping in mappings),
                    "path": path,
                    "line": native.start.line,
                },
            )
        )
        confidence_value = native.extra.metadata.get("confidence")
        native_confidence = confidence_value if isinstance(confidence_value, str) else None
        findings.append(
            Finding(
                record_id=new_opaque_id("finding"),
                run_id=run_id,
                execution_id=execution_id,
                target_snapshot_id=target_snapshot_id,
                producer=producer,
                rule=Rule(
                    native_id=native.check_id,
                    name=native.check_id,
                    mappings=mappings,
                ),
                message=FindingMessage(
                    title=native.extra.message,
                    description=native.extra.message,
                ),
                severity=_severity(native.extra.severity),
                confidence=Confidence(native_label=native_confidence, normalized=None),
                locations=[location],
                evidence=[
                    EvidenceReference(
                        origin="native-observed",
                        blob_sha256=source_blob_sha256,
                        json_pointer=f"/results/{index}",
                    )
                ],
                assessment=Assessment(
                    verification_state="unreviewed",
                    exposure_statement="static-observable-condition",
                ),
                fingerprints=Fingerprints(
                    native=native.extra.fingerprint,
                    record_v1=record_fingerprint,
                    candidate_equivalence_v1=equivalence_fingerprint,
                ),
                native_extension={
                    "engine_kind": native.extra.engine_kind,
                    "validation_state": native.extra.validation_state,
                },
            )
        )

    failures: list[FailureRecord] = []
    for error in parsed.document.errors:
        error_text = json.dumps(error, ensure_ascii=False, sort_keys=True)
        failures.append(
            FailureRecord(
                failure_id=new_opaque_id("failure"),
                run_id=run_id,
                execution_id=execution_id,
                stage="execution",
                category="internal",
                retryability="unknown",
                affected_scope="semgrep native error",
                sanitized_message=error_text[:2000],
                evidence_blob_sha256=[source_blob_sha256],
                partial_evidence_usable=bool(findings),
                final_disposition="preserved for review",
            )
        )

    coverage = CoverageRecord(
        coverage_id=new_opaque_id("coverage"),
        run_id=run_id,
        execution_id=execution_id,
        target_snapshot_id=target_snapshot_id,
        property_id="code.static-analysis.semgrep",
        producer=producer,
        applicability="applicable",
        adapter_support="supported",
        execution="partial" if failures else "success",
        observation="observed-risk" if findings else "no-observation",
        limitations=[
            "No observation means no matching evidence under this exact rule and "
            "configuration, not safe."
        ],
    )
    return NormalizedSemgrep(tuple(findings), (coverage,), tuple(failures))
