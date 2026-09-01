from __future__ import annotations

from collections.abc import Sequence

from agentsec_evidence.core.time import utc_now
from agentsec_evidence.models.contracts import (
    CoverageRecord,
    ExecutionRecord,
    FailureRecord,
    Finding,
    ParserReport,
    Summary,
)


def build_summary(
    *,
    execution: ExecutionRecord,
    parser_report: ParserReport | None,
    findings: Sequence[Finding],
    coverage: Sequence[CoverageRecord],
    failures: Sequence[FailureRecord],
    resolved_evidence_references: int,
    represented_findings: int,
    sarif_valid: bool,
) -> Summary:
    evidence_count = sum(len(finding.evidence) for finding in findings)
    provenance_rate = resolved_evidence_references / evidence_count if evidence_count else 1.0
    representability_rate = represented_findings / len(findings) if findings else 1.0
    return Summary(
        run_id=execution.run_id,
        generated_at=utc_now(),
        execution_outcome=execution.outcome,
        native_result_count=parser_report.native_result_count if parser_report else 0,
        native_error_count=parser_report.native_error_count if parser_report else 0,
        normalized_finding_count=len(findings),
        normalized_coverage_count=len(coverage),
        normalized_failure_count=len(failures),
        provenance_resolution_rate=provenance_rate,
        sarif_representability_rate=representability_rate,
        sarif_valid=sarif_valid,
        duration_ns=execution.duration_ns,
    )
