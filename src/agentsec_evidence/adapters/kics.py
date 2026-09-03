from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from agentsec_evidence.core.identity import new_opaque_id, semantic_hash
from agentsec_evidence.core.paths import normalize_relative_path
from agentsec_evidence.execution.config import KicsToolConfig
from agentsec_evidence.models.contracts import (
    Assessment,
    Confidence,
    CoverageExecution,
    CoverageRecord,
    EvidenceReference,
    FailureCategory,
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


class KicsParseError(ValueError):
    """Native KICS JSON was malformed or incompatible."""


class NativeModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class NativeKicsFile(NativeModel):
    file_name: str
    similarity_id: str | None = None
    line: int = -1
    resource_type: str | None = None
    resource_name: str | None = None
    issue_type: str | None = None
    search_key: str | None = None
    search_line: int = -1
    search_value: str | None = None
    expected_value: str | None = None
    actual_value: str | None = None
    remediation: JsonValue | None = None
    remediation_type: str | None = None


class NativeKicsQuery(NativeModel):
    query_name: str
    query_id: str
    query_url: str | None = None
    severity: str | None = None
    platform: str | None = None
    cwe: JsonValue = None
    risk_score: JsonValue = None
    cloud_provider: str | None = None
    category: str | None = None
    experimental: bool = False
    description: str | None = None
    description_id: str | None = None
    files: list[NativeKicsFile] = Field(default_factory=list)


class NativeKicsDocument(NativeModel):
    kics_version: str
    files_scanned: int = Field(ge=0)
    lines_scanned: int = Field(ge=0)
    files_parsed: int = Field(ge=0)
    lines_parsed: int = Field(ge=0)
    lines_ignored: int = Field(ge=0)
    files_failed_to_scan: int = Field(ge=0)
    queries_total: int = Field(ge=0)
    queries_failed_to_execute: int = Field(ge=0)
    queries_failed_to_compute_similarity_id: int = Field(ge=0)
    scan_id: str
    severity_counters: dict[str, int]
    total_counter: int = Field(ge=0)
    total_bom_resources: int = Field(ge=0)
    start: str
    end: str
    paths: list[str]
    queries: list[NativeKicsQuery]


@dataclass(frozen=True)
class ParsedKics:
    document: NativeKicsDocument
    unknown_fields: tuple[str, ...]

    @property
    def native_result_count(self) -> int:
        return sum(len(query.files) for query in self.document.queries)


@dataclass(frozen=True)
class NormalizedKics:
    findings: tuple[Finding, ...]
    coverage: tuple[CoverageRecord, ...]
    failures: tuple[FailureRecord, ...]


def _reject_constant(value: str) -> None:
    raise KicsParseError(f"Non-finite JSON number rejected: {value}")


def _reject_duplicate_pairs(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise KicsParseError(f"Duplicate JSON key rejected: {key}")
        result[key] = value
    return result


def _unknown_fields(document: NativeKicsDocument, raw: dict[str, JsonValue]) -> tuple[str, ...]:
    unknown = {f"/{key}" for key in set(raw) - set(NativeKicsDocument.model_fields)}
    for query_index, query in enumerate(document.queries):
        unknown.update(f"/queries/{query_index}/{key}" for key in (query.model_extra or {}))
        for file_index, native_file in enumerate(query.files):
            unknown.update(
                f"/queries/{query_index}/files/{file_index}/{key}"
                for key in (native_file.model_extra or {})
            )
    return tuple(sorted(unknown))


def parse_kics_json(data: bytes) -> ParsedKics:
    try:
        decoded = data.decode("utf-8", errors="strict")
        raw = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
        if not isinstance(raw, dict):
            raise KicsParseError("KICS JSON root must be an object")
        raw_mapping = cast(dict[str, JsonValue], raw)
        document = NativeKicsDocument.model_validate(raw_mapping)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        if isinstance(exc, KicsParseError):
            raise
        raise KicsParseError(str(exc)) from exc
    return ParsedKics(document=document, unknown_fields=_unknown_fields(document, raw_mapping))


def _relative_kics_path(native_path: str) -> str:
    normalized = native_path.replace("\\", "/")
    for prefix in ("../../src/", "/src/", "src/"):
        if normalized.startswith(prefix):
            return normalize_relative_path(normalized.removeprefix(prefix))
    raise KicsParseError("KICS finding path is outside the controlled target mount")


def _severity(native_label: str | None, risk_score: JsonValue) -> Severity:
    severity_map: dict[str, NormalizedSeverity] = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFO": "informational",
        "TRACE": "informational",
    }
    native_score: float | None = None
    if isinstance(risk_score, int | float) and not isinstance(risk_score, bool):
        native_score = float(risk_score)
    elif isinstance(risk_score, str):
        try:
            native_score = float(risk_score)
        except ValueError:
            native_score = None
    return Severity(
        native_label=native_label,
        native_score=native_score,
        normalized=severity_map.get((native_label or "").upper(), "unknown"),
        mapping_id="kics-severity-v1",
    )


def _taxonomy_mappings(native_cwe: JsonValue) -> list[TaxonomyMapping]:
    values: list[str] = []
    if isinstance(native_cwe, str) and native_cwe.strip():
        values = [native_cwe]
    elif isinstance(native_cwe, int) and not isinstance(native_cwe, bool):
        values = [str(native_cwe)]
    elif isinstance(native_cwe, list):
        values = [
            str(item)
            for item in native_cwe
            if isinstance(item, str | int) and not isinstance(item, bool)
        ]
    return [
        TaxonomyMapping(taxonomy="CWE", value=value, origin="native-observed") for value in values
    ]


def _remediation(value: JsonValue) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _counter_failure(
    *,
    run_id: str,
    execution_id: str,
    source_blob_sha256: str,
    message: str,
    category: FailureCategory,
    partial: bool,
) -> FailureRecord:
    return FailureRecord(
        failure_id=new_opaque_id("failure"),
        run_id=run_id,
        execution_id=execution_id,
        stage="parse",
        category=category,
        retryability="no",
        affected_scope="KICS native coverage and accounting",
        sanitized_message=message,
        evidence_blob_sha256=[source_blob_sha256],
        partial_evidence_usable=partial,
        final_disposition="preserved as an explicit partial observation",
    )


def normalize_kics(
    parsed: ParsedKics,
    *,
    tool: KicsToolConfig,
    run_id: str,
    execution_id: str,
    target_snapshot_id: str,
    source_blob_sha256: str,
) -> NormalizedKics:
    document = parsed.document
    producer = Producer(
        tool_id=tool.tool_id,
        tool_version=document.kics_version,
        adapter_id=tool.adapter_id,
        adapter_version=tool.adapter_version,
    )
    findings: list[Finding] = []
    for query_index, query in enumerate(document.queries):
        mappings = _taxonomy_mappings(query.cwe)
        for file_index, native in enumerate(query.files):
            path = _relative_kics_path(native.file_name)
            line = native.line if native.line >= 1 else None
            record_fingerprint = semantic_hash(
                cast(
                    JsonValue,
                    {
                        "tool": tool.tool_id,
                        "rule": query.query_id,
                        "path": path,
                        "line": line,
                        "issue_type": native.issue_type,
                        "search_key": native.search_key,
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
                        "line": line,
                    },
                )
            )
            findings.append(
                Finding(
                    record_id=new_opaque_id("finding"),
                    run_id=run_id,
                    execution_id=execution_id,
                    target_snapshot_id=target_snapshot_id,
                    producer=producer,
                    rule=Rule(
                        native_id=query.query_id,
                        name=query.query_name,
                        help_uri=query.query_url,
                        mappings=mappings,
                    ),
                    message=FindingMessage(
                        title=query.query_name,
                        description=query.description,
                        remediation=_remediation(native.remediation),
                    ),
                    severity=_severity(query.severity, query.risk_score),
                    confidence=Confidence(native_label=None, normalized=None),
                    locations=[Location(artifact_path=path, start_line=line)],
                    evidence=[
                        EvidenceReference(
                            origin="native-observed",
                            blob_sha256=source_blob_sha256,
                            json_pointer=f"/queries/{query_index}/files/{file_index}",
                        )
                    ],
                    assessment=Assessment(
                        verification_state="unreviewed",
                        exposure_statement="static-observable-condition",
                    ),
                    fingerprints=Fingerprints(
                        native=native.similarity_id,
                        record_v1=record_fingerprint,
                        candidate_equivalence_v1=equivalence_fingerprint,
                    ),
                    limitations=[
                        "KICS reports a static IaC condition; runtime deployment and "
                        "exploitability were not established."
                    ],
                    native_extension={
                        "actual_value": native.actual_value,
                        "category": query.category,
                        "cloud_provider": query.cloud_provider,
                        "description_id": query.description_id,
                        "expected_value": native.expected_value,
                        "experimental": query.experimental,
                        "issue_type": native.issue_type,
                        "platform": query.platform,
                        "remediation_type": native.remediation_type,
                        "resource_name": native.resource_name,
                        "resource_type": native.resource_type,
                        "risk_score": query.risk_score,
                        "search_key": native.search_key,
                        "search_line": native.search_line,
                        "search_value": native.search_value,
                    },
                )
            )

    failures: list[FailureRecord] = []
    partial = bool(findings) or document.files_parsed > 0
    if document.files_scanned > document.files_parsed:
        failures.append(
            _counter_failure(
                run_id=run_id,
                execution_id=execution_id,
                source_blob_sha256=source_blob_sha256,
                message=(
                    f"KICS parsed {document.files_parsed} of {document.files_scanned} "
                    "scanned IaC files."
                ),
                category="configuration",
                partial=partial,
            )
        )
    elif document.files_failed_to_scan:
        failures.append(
            _counter_failure(
                run_id=run_id,
                execution_id=execution_id,
                source_blob_sha256=source_blob_sha256,
                message=f"KICS reported {document.files_failed_to_scan} files failed to scan.",
                category="configuration",
                partial=partial,
            )
        )
    expected_queries = len(tool.include_queries)
    if document.files_parsed > 0 and document.queries_total != expected_queries:
        failures.append(
            _counter_failure(
                run_id=run_id,
                execution_id=execution_id,
                source_blob_sha256=source_blob_sha256,
                message=(
                    f"KICS executed {document.queries_total} queries; "
                    f"the frozen selection requires {expected_queries}."
                ),
                category="configuration",
                partial=partial,
            )
        )
    if document.queries_failed_to_execute:
        failures.append(
            _counter_failure(
                run_id=run_id,
                execution_id=execution_id,
                source_blob_sha256=source_blob_sha256,
                message=(
                    f"KICS reported {document.queries_failed_to_execute} queries failed to execute."
                ),
                category="internal",
                partial=partial,
            )
        )
    if document.queries_failed_to_compute_similarity_id:
        failures.append(
            _counter_failure(
                run_id=run_id,
                execution_id=execution_id,
                source_blob_sha256=source_blob_sha256,
                message=(
                    "KICS failed to compute similarity IDs for "
                    f"{document.queries_failed_to_compute_similarity_id} query results."
                ),
                category="internal",
                partial=partial,
            )
        )
    if document.total_counter != len(findings):
        failures.append(
            _counter_failure(
                run_id=run_id,
                execution_id=execution_id,
                source_blob_sha256=source_blob_sha256,
                message=(
                    f"KICS total counter is {document.total_counter}, but "
                    f"{len(findings)} native result records were present."
                ),
                category="malformed-output",
                partial=partial,
            )
        )

    if document.files_scanned == 0:
        applicability: Literal["applicable", "not-applicable", "unknown"] = "not-applicable"
        adapter_support: Literal["supported", "partial", "unsupported", "unknown"] = "unsupported"
        execution: CoverageExecution = "not-run"
        observation: Literal["observed-risk", "observed-control", "no-observation", "unknown"] = (
            "unknown"
        )
    else:
        applicability = "applicable"
        adapter_support = "supported"
        execution = "partial" if failures else "success"
        observation = "observed-risk" if findings else "no-observation"
    coverage = CoverageRecord(
        coverage_id=new_opaque_id("coverage"),
        run_id=run_id,
        execution_id=execution_id,
        target_snapshot_id=target_snapshot_id,
        property_id="infrastructure-as-code.static-analysis.kics",
        producer=producer,
        applicability=applicability,
        adapter_support=adapter_support,
        execution=execution,
        observation=observation,
        limitations=[
            "Only the frozen KICS platforms and query IDs were executed.",
            "KICS secret scanning was disabled for this IaC evidence path.",
            "No observation means no matching evidence under this exact query selection, not safe.",
        ],
    )
    return NormalizedKics(tuple(findings), (coverage,), tuple(failures))
