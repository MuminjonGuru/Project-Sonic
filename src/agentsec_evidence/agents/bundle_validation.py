from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from agentsec_evidence.adapters.agent_audit import normalize_agent_audit, parse_agent_audit_json
from agentsec_evidence.agents.inputs import plan_agent_input_admission
from agentsec_evidence.agents.records import (
    AgentInputReport,
    AgentInputRequest,
    AgentParserReport,
    AgentRunDetails,
    verify_input_report,
)
from agentsec_evidence.agents.semantics import agent_semantic_document, native_projection
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.core.io import (
    atomic_write_bytes,
    atomic_write_jsonl,
    atomic_write_model,
    json_bytes,
)
from agentsec_evidence.core.time import utc_now
from agentsec_evidence.exports.sarif import build_sarif
from agentsec_evidence.models.contracts import InventoryEntry
from agentsec_evidence.validation.checks import validate_bundle

if TYPE_CHECKING:
    from agentsec_evidence.operations.offline import ExistingRun


def _evidence(existing: ExistingRun, role: str) -> bytes:
    matches = [item for item in existing.blobs.blobs if item.logical_role == role]
    if len(matches) != 1:
        raise ValueError(f"Expected one retained {role}")
    return (existing.root / matches[0].relative_path).read_bytes()


def validate_agent_bundle(existing: ExistingRun) -> AgentRunDetails:
    """Verify archived relationships without reparsing target code or launching a process."""
    if not validate_bundle(existing.root).passed:
        raise ValueError("Agent bundle integrity failed")
    for blob in existing.blobs.blobs:
        path = existing.root / blob.relative_path
        if not path.resolve(strict=True).is_relative_to(existing.root.resolve()):
            raise ValueError("Evidence path escapes bundle")
        raw = path.read_bytes()
        if len(raw) != blob.byte_length or sha256_bytes(raw) != blob.sha256:
            raise ValueError("Agent evidence descriptor mismatch")
    details = AgentRunDetails.model_validate_json(
        (existing.root / "normalized/agent-details.json").read_bytes()
    )
    if (
        details.run_id != existing.run.run_id
        or details.execution_id != existing.execution.execution_id
        or details.target_snapshot_id != existing.target.snapshot_id
    ):
        raise ValueError("Agent run identities differ")
    request_raw = _evidence(existing, "agent-input-request")
    request = AgentInputRequest.model_validate_json(request_raw)
    inventory = [
        InventoryEntry.model_validate_json(line)
        for line in (existing.root / "target/inventory.jsonl").read_bytes().splitlines()
        if line
    ]
    if request.inventory != inventory or request.target_snapshot_id != existing.target.snapshot_id:
        raise ValueError("Worker request differs from registered target")
    target_blobs = [item for item in existing.blobs.blobs if item.logical_role == "target-input"]
    if len(target_blobs) != len(inventory):
        raise ValueError("Retained target inventory is incomplete")
    for entry in inventory:
        matches = [
            item
            for item in target_blobs
            if item.relative_path.endswith(f"/inputs/target/{entry.path}")
        ]
        if len(matches) != 1 or matches[0].sha256 != entry.sha256:
            raise ValueError("Retained input does not match inventory")
    report = None
    roles = [item.logical_role for item in existing.blobs.blobs]
    if details.scanner_launched != ("scanner-receipt" in roles):
        raise ValueError("Scanner launch state differs from stage evidence")
    if details.validation_state == "complete":
        receipt = json.loads(_evidence(existing, "validation-receipt"))
        if (
            receipt["exit_code"] != 0
            or receipt["timed_out"]
            or receipt["output_limited"]
            or not receipt["cleanup_succeeded"]
            or _evidence(existing, "validation-stderr")
        ):
            raise ValueError("Validation receipt does not support completed admission")
        report = AgentInputReport.model_validate_json(_evidence(existing, "agent-input-report"))
        verify_input_report(report, request, request_raw)
        admission = plan_agent_input_admission(
            [check.checked_input() for check in report.checks],
            snapshot_paths=[entry.path for entry in inventory],
        )
        if details.blockers != list(admission.blockers) or details.admitted != admission.admitted:
            raise ValueError("Recorded admission differs from retained validation evidence")
        if [item.artifact for item in details.assessments] != [
            item.artifact for item in report.checks
        ]:
            raise ValueError("Assessment inputs differ from validation evidence")
    native_counts: tuple[int | None, int | None, int | None, int | None] = (None, None, None, None)
    if existing.parser_report is not None:
        if not isinstance(existing.parser_report, AgentParserReport) or report is None:
            raise ValueError("Agent parser report has no validated inputs")
        raw = _evidence(existing, "native-report")
        parsed = parse_agent_audit_json(raw)
        normalized = normalize_agent_audit(
            parsed,
            inputs=[check.checked_input() for check in report.checks],
            run_id=existing.run.run_id,
            execution_id=existing.execution.execution_id,
            target_snapshot_id=existing.target.snapshot_id,
        )
        expected = sorted(normalized.findings, key=lambda item: item.fingerprints.record_v1)
        if [item.model_dump(exclude={"record_id"}) for item in expected] != [
            item.model_dump(exclude={"record_id"}) for item in existing.findings
        ]:
            raise ValueError("Normalized agent findings differ from retained native evidence")
        parser = existing.parser_report
        if (
            parser.source_blob_sha256 != sha256_bytes(raw)
            or parser.execution_id != existing.execution.execution_id
            or parser.native_result_count != len(expected)
            or parser.normalized_finding_count != len(expected)
            or parser.native_scanned_path_count != parsed.document.scanned_files
            or parser.unknown_top_level_fields != list(parsed.unknown_field_paths)
            or not parser.complete
        ):
            raise ValueError("Agent parser accounting differs")
        native_counts = (
            len(expected),
            parsed.document.scanned_files,
            parsed.document.summary.suppressed,
            parsed.document.summary.by_tier["SUPPRESSED"],
        )
    elif existing.findings:
        raise ValueError("Agent findings lack a completed parser report")
    if native_counts != (
        details.native_result_count,
        details.native_scanned_files,
        details.native_suppressed_count,
        details.native_tier_suppressed_count,
    ):
        raise ValueError("Agent native counts differ from parsed evidence")
    for assessment in details.assessments:
        observations = [
            item
            for item in existing.findings
            if item.locations[0].artifact_path == assessment.artifact.source.path
        ]
        if assessment.finding_count != (len(observations) if observations else None):
            raise ValueError("Unobserved per-file counts must remain unknown")
        expected_state = (
            "partial" if observations else "unknown" if details.scanner_launched else "skipped"
        )
        if assessment.state != expected_state:
            raise ValueError("Per-file state overclaims native observability")
        if assessment.evidence != [ref for item in observations for ref in item.evidence]:
            raise ValueError("Assessment evidence differs from normalized findings")
    stored_sarif = json.loads((existing.root / "exports/results.sarif").read_bytes())
    if stored_sarif != build_sarif(existing.findings, execution=existing.execution):
        raise ValueError("Agent SARIF differs from evidence-preserving projection")
    native_value = None
    if "native-report" in roles:
        try:
            native_value = native_projection(_evidence(existing, "native-report"))
        except ValueError:
            if existing.parser_report is not None:
                raise
    projection = agent_semantic_document(
        config_sha=existing.run.config_sha256,
        target_sha=existing.target.content_sha256,
        details=details,
        findings=existing.findings,
        outcome=existing.execution.outcome,
        exit_code=existing.execution.exit_code,
        failures=existing.failures,
        native_document=native_value,
    )
    if (
        existing.run.semantic_hash_version != "agent-run-semantic-v1"
        or semantic_hash(projection) != existing.run.semantic_sha256
        or json.loads((existing.root / "validation/agent-semantic.json").read_bytes()) != projection
    ):
        raise ValueError("Agent semantic projection, version or hash differs")
    return details


def reparse_agent_bundle(existing: ExistingRun, output: Path) -> Path:
    details = validate_agent_bundle(existing)
    if existing.parser_report is None:
        raise ValueError("No successfully parsed agent evidence to normalize")
    report = AgentInputReport.model_validate_json(_evidence(existing, "agent-input-report"))
    raw = _evidence(existing, "native-report")
    normalized = normalize_agent_audit(
        parse_agent_audit_json(raw),
        inputs=[check.checked_input() for check in report.checks],
        run_id=existing.run.run_id,
        execution_id=existing.execution.execution_id,
        target_snapshot_id=existing.target.snapshot_id,
    )
    output.mkdir(parents=True, exist_ok=False)
    findings = sorted(normalized.findings, key=lambda item: item.fingerprints.record_v1)
    atomic_write_jsonl(output / "findings.jsonl", findings)
    atomic_write_jsonl(output / "coverage.jsonl", existing.coverage)
    atomic_write_jsonl(output / "failures.jsonl", existing.failures)
    atomic_write_model(output / "agent-details.json", details)
    atomic_write_model(output / "parser-report.json", existing.parser_report)
    atomic_write_bytes(
        output / "derivative.json",
        json_bytes(
            {
                "source_run_id": existing.run.run_id,
                "generated_at": utc_now().isoformat(),
                "source_blob_sha256": sha256_bytes(raw),
                "operation": "offline-agent-reparse",
            }
        ),
    )
    return output
