from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from typing import Any

import pytest

from agentsec_evidence.adapters.agent_audit import (
    MAX_NATIVE_BYTES,
    AgentAuditParseError,
    NormalizedAgentAudit,
    normalize_agent_audit,
    parse_agent_audit_json,
)
from agentsec_evidence.agents.inputs import validate_agent_input
from agentsec_evidence.core.identity import sha256_bytes


def native_document() -> dict[str, Any]:
    """Authored parser example, not scanner output or an accuracy oracle."""
    return {
        "version": "0.20.0",
        "scan_timestamp": "2026-10-02T00:00:00",
        "scan_path": "/target",
        "scanned_files": 1,
        "summary": {
            "total": 1,
            "actionable": 1,
            "suppressed": 0,
            "by_severity": {"high": 1},
            "by_category": {"tool_misuse": 1},
            "by_tier": {"BLOCK": 0, "WARN": 1, "INFO": 0, "SUPPRESSED": 0},
            "risk_score": 2.0,
            "risk_label": "LOW",
        },
        "findings": [
            {
                "rule_id": "EXAMPLE-001",
                "title": "Authored example",
                "description": "Example only",
                "severity": "high",
                "category": "tool_misuse",
                "location": {
                    "file_path": "/target/agent.py",
                    "start_line": 2,
                    "end_line": 2,
                    "start_column": None,
                    "end_column": None,
                    "snippet": "return eval(value)",
                },
                "confidence": 0.85,
                "tier": "WARN",
                "suppressed": False,
                "suppressed_reason": None,
                "suppressed_by": None,
                "needs_review": False,
                "cwe_id": "CWE-94",
                "owasp_id": "ASI-05",
                "asi_categories": ["ASI-05"],
                "remediation": {
                    "description": "Review manually",
                    "code_example": None,
                    "reference_url": None,
                },
                "metadata": {"authored": True},
                "detected_at": "2026-10-02T00:00:00",
                "reason": "Example",
            }
        ],
    }


def normalized(document: dict[str, Any], *, mcp: bool = False) -> NormalizedAgentAudit:
    checked = validate_agent_input(
        b'{"mcpServers":{}}' if mcp else b"def f(value):\n    return eval(value)\n",
        path="mcp.json" if mcp else "agent.py",
        kind="mcp-config" if mcp else "python-source",
        target_snapshot_id="authored",
    )
    return normalize_agent_audit(
        parse_agent_audit_json(json.dumps(document).encode()),
        inputs=[checked],
        run_id="run",
        execution_id="exec",
        target_snapshot_id="authored",
    )


def test_loss_aware_normalization_and_blob_linkage() -> None:
    document = native_document()
    raw = json.dumps(document).encode()
    parsed = parse_agent_audit_json(raw)
    assert parsed.raw_bytes == raw
    assert parsed.source_blob_sha256 == sha256_bytes(raw)
    result = normalized(document)
    (finding,) = result.findings
    assert finding.evidence[0].json_pointer == "/findings/0"
    assert finding.evidence[0].blob_sha256 == sha256_bytes(raw)
    assert finding.native_extension["agent_audit"] == document["findings"][0]
    assert finding.confidence.normalized is None
    assert finding.assessment.verification_state == "unreviewed"
    assert finding.severity.normalized == "high"
    assert finding.locations[0].start_line == 2
    assert result.native_scanned_files == 1
    assert result.per_file_coverage == "not-observable"


@pytest.mark.parametrize(
    ("section", "key", "value"),
    [
        ("root", "version", "0.21.0"),
        ("root", "scan_path", "/other"),
        ("root", "scanned_files", True),
        ("root", "scanned_files", -1),
        ("summary", "total", 0),
        ("summary", "total", "1"),
        ("summary", "actionable", 0),
        ("summary", "suppressed", 1),
        ("summary", "by_severity", {"critical": 1}),
        ("summary", "by_category", {}),
        ("summary", "by_tier", {"WARN": 1}),
        ("finding", "confidence", 1.1),
        ("finding", "confidence", True),
        ("finding", "tier", "NEW"),
        ("finding", "suppressed", "false"),
        ("finding", "rule_id", ""),
        ("location", "start_line", 0),
        ("location", "end_line", 1),
        ("location", "start_line", "2"),
    ],
)
def test_incompatible_native_contract_rejected(section: str, key: str, value: Any) -> None:
    document = native_document()
    target = {
        "root": document,
        "summary": document["summary"],
        "finding": document["findings"][0],
        "location": document["findings"][0]["location"],
    }[section]
    target[key] = value
    with pytest.raises(AgentAuditParseError):
        parse_agent_audit_json(json.dumps(document).encode())


@pytest.mark.parametrize(
    "raw",
    [
        b'{"version":"0.20.0","version":"0.20.0"}',
        b'{"x":NaN}',
        b'{"x":1e999}',
        b'{"x":"\\ud800"}',
        b"\xff",
        b"[]",
        b"{}",
        b"{",
        b" " * (MAX_NATIVE_BYTES + 1),
    ],
    ids=[
        "duplicate-key",
        "nan",
        "overflow",
        "surrogate",
        "utf8",
        "array",
        "empty",
        "syntax",
        "byte-limit",
    ],
)
def test_native_invalid_json_and_size_limits(raw: bytes) -> None:
    with pytest.raises(AgentAuditParseError):
        parse_agent_audit_json(raw)


def test_unknown_fields_are_flagged_and_retained() -> None:
    document = native_document()
    document["new/field"] = {"raw": True}
    document["summary"]["extra"] = 5
    document["findings"][0]["location"]["future"] = "value"
    document["findings"][0]["extension"] = {"not": "discarded"}
    parsed = parse_agent_audit_json(json.dumps(document).encode())
    assert parsed.unknown_field_paths == (
        "/findings/0/extension",
        "/findings/0/location/future",
        "/new~1field",
        "/summary/extra",
    )
    assert parsed.document.model_dump(mode="json") == document
    assert (
        normalized(document).findings[0].native_extension["agent_audit"] == document["findings"][0]
    )


@pytest.mark.parametrize("mode", ["boolean", "tier", "low-confidence"])
def test_native_actionable_is_only_a_producer_counter(mode: str) -> None:
    document = native_document()
    document["summary"]["actionable"] = 0
    item = document["findings"][0]
    if mode == "boolean":
        item["suppressed"] = True
        item["suppressed_reason"] = "Authored exclusion example"
        document["summary"]["suppressed"] = 1
    elif mode == "tier":
        item["tier"] = "SUPPRESSED"
        document["summary"]["by_tier"]["WARN"] = 0
        document["summary"]["by_tier"]["SUPPRESSED"] = 1
    else:
        item["confidence"] = 0.29
    result = normalized(document)
    assert len(result.findings) == 1
    assert result.findings[0].native_extension["agent_audit"] == item
    assert result.findings[0].assessment.verification_state == "unreviewed"


def test_no_finding_document_is_not_coverage_proof() -> None:
    document = native_document()
    document["scanned_files"] = 0
    document["findings"] = []
    document["summary"].update(
        total=0,
        actionable=0,
        suppressed=0,
        by_severity={},
        by_category={},
        by_tier={"BLOCK": 0, "WARN": 0, "INFO": 0, "SUPPRESSED": 0},
        risk_score=0.0,
        risk_label="LOW",
    )
    result = normalized(document)
    assert result.findings == ()
    assert result.native_scanned_files == 0
    assert result.per_file_coverage == "not-observable"
    assert result.limitations


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "/target",
        "/target/../a.py",
        "/target/./agent.py",
        "/target/a\\b.py",
        "/target/nul.py",
        "/target/missing.py",
        "agent.py",
    ],
)
def test_finding_target_path_must_reference_validated_input(path: str) -> None:
    document = native_document()
    document["findings"][0]["location"]["file_path"] = path
    with pytest.raises(AgentAuditParseError):
        normalized(document)


def test_source_line_bounds_and_column_uncertainty() -> None:
    document = native_document()
    location = document["findings"][0]["location"]
    location.update(start_line=3, end_line=3)
    with pytest.raises(AgentAuditParseError):
        normalized(document)
    location.update(start_line=2, end_line=2, start_column=0, end_column=5)
    assert normalized(document).findings[0].locations[0].start_column is None
    location.update(start_column=5, end_column=0)
    with pytest.raises(AgentAuditParseError):
        normalized(document)


def test_mcp_fallback_line_not_published_and_missing_cwe_not_inferred() -> None:
    document = native_document()
    item = document["findings"][0]
    item["rule_id"] = "AGENT-029"
    item["cwe_id"] = None
    item["location"].update(file_path="/target/mcp.json", start_line=1, end_line=1)
    result = normalized(document, mcp=True).findings[0]
    assert result.locations[0].artifact_path == "mcp.json"
    assert result.locations[0].start_line is None
    assert not any(mapping.taxonomy == "CWE" for mapping in result.rule.mappings)


def test_unknown_severity_and_questionable_mapping_preserved() -> None:
    document = native_document()
    document["findings"][0].update(rule_id="AGENT-001", severity="future-severity", cwe_id="CWE-78")
    document["summary"]["by_severity"] = {"future-severity": 1}
    finding = normalized(document).findings[0]
    assert finding.severity.normalized == "unknown"
    assert finding.rule.mappings[0].value == "CWE-78"
    assert any("adjudication" in limitation for limitation in finding.limitations)


def test_fingerprint_ignores_timestamps_but_keeps_raw_changes() -> None:
    document = native_document()
    first = normalized(document).findings[0]
    document["scan_timestamp"] = "2026-10-03T00:00:00"
    document["findings"][0]["detected_at"] = document["scan_timestamp"]
    second = normalized(document).findings[0]
    assert first.fingerprints == second.fingerprints
    assert first.evidence[0].blob_sha256 != second.evidence[0].blob_sha256


def test_evidence_mutation_and_input_identity_guards() -> None:
    parsed = parse_agent_audit_json(json.dumps(native_document()).encode())
    checked = validate_agent_input(
        b"def f(value):\n    return eval(value)\n",
        path="agent.py",
        kind="python-source",
        target_snapshot_id="authored",
    )
    for inputs, snapshot in (
        ([], "authored"),
        ([checked, checked], "authored"),
        ([checked], "other"),
    ):
        with pytest.raises(AgentAuditParseError):
            normalize_agent_audit(
                parsed,
                inputs=inputs,
                run_id="r",
                execution_id="e",
                target_snapshot_id=snapshot,
            )
    with pytest.raises(AgentAuditParseError):
        normalize_agent_audit(
            replace(parsed, source_blob_sha256="0" * 64),
            inputs=[checked],
            run_id="r",
            execution_id="e",
            target_snapshot_id="authored",
        )
    parsed.document.findings[0].description = "changed after parsing"
    with pytest.raises(AgentAuditParseError):
        normalize_agent_audit(
            parsed,
            inputs=[checked],
            run_id="r",
            execution_id="e",
            target_snapshot_id="authored",
        )


def test_overlapping_native_findings_are_not_deduplicated() -> None:
    document = native_document()
    document["findings"].append(deepcopy(document["findings"][0]))
    document["summary"].update(
        total=2,
        actionable=2,
        by_severity={"high": 2},
        by_category={"tool_misuse": 2},
        by_tier={"BLOCK": 0, "WARN": 2, "INFO": 0, "SUPPRESSED": 0},
    )
    first, second = normalized(document).findings
    assert first.record_id != second.record_id
    assert first.fingerprints == second.fingerprints
    assert first.evidence[0].json_pointer != second.evidence[0].json_pointer
