from __future__ import annotations

from collections.abc import Sequence

from pydantic import JsonValue

from agentsec_evidence.adapters.agent_audit import parse_agent_audit_json
from agentsec_evidence.agents.records import AgentRunDetails
from agentsec_evidence.models.contracts import ExecutionOutcome, FailureRecord, Finding


def native_projection(raw: bytes) -> JsonValue:
    document = parse_agent_audit_json(raw).document.model_dump(mode="json")
    document.pop("scan_timestamp")
    for finding in document["findings"]:
        finding.pop("detected_at")
    return document


def agent_semantic_document(
    *,
    config_sha: str,
    target_sha: str,
    details: AgentRunDetails,
    findings: Sequence[Finding],
    outcome: ExecutionOutcome,
    exit_code: int | None,
    failures: Sequence[FailureRecord],
    native_document: JsonValue = None,
) -> JsonValue:
    # Exclude identifiers, stage timing and known producer timestamps, not arbitrary ordering.
    detail_value = details.model_dump(
        mode="json",
        exclude={
            "run_id",
            "execution_id",
            "validation_duration_ns",
            "scanner_duration_ns",
            "total_duration_ns",
        },
    )
    for assessment in detail_value["assessments"]:
        assessment.pop("run_id")
        assessment.pop("execution_id")
        for evidence in assessment["evidence"]:
            evidence.pop("blob_sha256")
    values: list[JsonValue] = []
    for finding in findings:
        value = finding.model_dump(mode="json", exclude={"record_id", "run_id", "execution_id"})
        for evidence in value["evidence"]:
            evidence.pop("blob_sha256")
        value["native_extension"]["agent_audit"].pop("detected_at")
        values.append(value)
    return {
        "semantic_version": "agent-run-semantic-v1",
        "config_sha256": config_sha,
        "target_content_sha256": target_sha,
        "details": detail_value,
        "findings": values,
        "outcome": outcome.value,
        "exit_code": exit_code,
        "native_document": native_document,
        "failures": [
            item.model_dump(
                mode="json",
                exclude={
                    "failure_id",
                    "run_id",
                    "execution_id",
                    "evidence_blob_sha256",
                },
            )
            for item in failures
        ],
    }
