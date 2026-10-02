from __future__ import annotations

from collections.abc import Sequence
from typing import cast
from urllib.parse import quote

from pydantic import JsonValue

from agentsec_evidence.models.contracts import ExecutionRecord, Finding, NormalizedSeverity

SARIF_SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"
)

_LEVELS: dict[NormalizedSeverity, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "note",
    "unknown": "none",
}

_TOOL_METADATA = {
    "agent-audit": ("Agent Audit", "https://github.com/HeadyZhang/agent-audit"),
    "semgrep": ("Semgrep", "https://semgrep.dev/"),
    "kics": ("KICS", "https://www.kics.io/"),
}


def _rule_descriptor(finding: Finding) -> dict[str, JsonValue]:
    properties: dict[str, JsonValue] = {}
    tags = sorted({f"{mapping.taxonomy}:{mapping.value}" for mapping in finding.rule.mappings})
    if tags:
        properties["tags"] = cast(JsonValue, tags)

    descriptor: dict[str, JsonValue] = {
        "id": finding.rule.native_id,
        "shortDescription": {"text": finding.message.title},
    }
    if finding.rule.help_uri is not None:
        descriptor["helpUri"] = finding.rule.help_uri
    if properties:
        descriptor["properties"] = properties
    return descriptor


def _location(finding: Finding) -> list[JsonValue]:
    locations: list[JsonValue] = []
    for location in finding.locations:
        physical: dict[str, JsonValue] = {
            "artifactLocation": {
                "uri": quote(location.artifact_path, safe="/-._~"),
                "uriBaseId": "SRCROOT",
            }
        }
        region: dict[str, JsonValue] = {}
        if location.start_line is not None:
            region["startLine"] = location.start_line
        if location.start_column is not None:
            region["startColumn"] = location.start_column
        if location.end_line is not None:
            region["endLine"] = location.end_line
        if location.end_column is not None:
            region["endColumn"] = location.end_column
        if region:
            physical["region"] = region
        locations.append({"physicalLocation": physical})
    return locations


def build_sarif(findings: Sequence[Finding], *, execution: ExecutionRecord) -> dict[str, JsonValue]:
    """Map normalized static findings to a deterministic SARIF 2.1.0 log."""
    sorted_findings = sorted(
        findings,
        key=lambda item: (
            item.rule.native_id,
            item.locations[0].artifact_path if item.locations else "",
            item.locations[0].start_line or 0 if item.locations else 0,
            item.fingerprints.record_v1,
        ),
    )
    representative: dict[str, Finding] = {}
    for finding in sorted_findings:
        representative.setdefault(finding.rule.native_id, finding)
    rule_ids = sorted(representative)
    rule_indexes = {rule_id: index for index, rule_id in enumerate(rule_ids)}

    results: list[JsonValue] = []
    for finding in sorted_findings:
        evidence = finding.evidence[0]
        properties: dict[str, JsonValue] = {
            "agentsecEvidence/sourceBlobSha256": evidence.blob_sha256,
            "agentsecEvidence/targetSnapshotId": finding.target_snapshot_id,
            "agentsecEvidence/nativeSeverity": finding.severity.native_label or "unknown",
            "agentsecEvidence/severityMappingId": finding.severity.mapping_id,
        }
        if evidence.json_pointer is not None:
            properties["agentsecEvidence/jsonPointer"] = evidence.json_pointer
        if execution.producer.tool_id == "agent-audit":
            native = finding.native_extension.get("agent_audit")
            if not isinstance(native, dict):
                raise ValueError("Agent evidence requires retained native assertions")
            properties.update(
                {
                    "agentsecEvidence/nativeSuppressed": native.get("suppressed"),
                    "agentsecEvidence/nativeTier": native.get("tier"),
                    "agentsecEvidence/nativeSuppressionReason": native.get("suppressed_reason"),
                    "agentsecEvidence/limitations": list(finding.limitations),
                    "agentsecEvidence/verificationState": "unreviewed",
                }
            )

        result: dict[str, JsonValue] = {
            "ruleId": finding.rule.native_id,
            "ruleIndex": rule_indexes[finding.rule.native_id],
            "kind": "fail",
            "level": _LEVELS[finding.severity.normalized],
            "message": {"text": finding.message.title},
            "partialFingerprints": {
                "agentsecEvidenceRecord/v1": finding.fingerprints.record_v1,
                "agentsecEvidenceCandidateEquivalence/v1": (
                    finding.fingerprints.candidate_equivalence_v1
                ),
            },
            "properties": properties,
        }
        if execution.producer.tool_id == "agent-audit":
            result["kind"] = "review"
            if (
                properties.get("agentsecEvidence/nativeSuppressed")
                or properties.get("agentsecEvidence/nativeTier") == "SUPPRESSED"
            ):
                result["suppressions"] = [
                    {
                        "kind": "external",
                        "status": "underReview",
                        "justification": (
                            "Native suppression retained; not approved by this platform"
                        ),
                    }
                ]
        if finding.fingerprints.native is not None:
            result["fingerprints"] = {
                f"{execution.producer.tool_id}/v1": finding.fingerprints.native
            }
        locations = _location(finding)
        if locations:
            result["locations"] = locations
        results.append(result)

    tool_name, information_uri = _TOOL_METADATA.get(
        execution.producer.tool_id,
        (execution.producer.tool_id, "https://example.invalid/unknown-tool"),
    )
    driver: dict[str, JsonValue] = {
        "name": tool_name,
        "semanticVersion": execution.producer.tool_version,
        "informationUri": information_uri,
        "rules": [_rule_descriptor(representative[rule_id]) for rule_id in rule_ids],
    }
    run: dict[str, JsonValue] = {
        "tool": {"driver": driver},
        "automationDetails": {"id": f"agentsec-evidence/{execution.producer.tool_id}"},
        "originalUriBaseIds": {"SRCROOT": {"uri": "file:///src/"}},
        "invocations": [
            {
                "executionSuccessful": execution.outcome.value in {"success", "unsupported"},
                "properties": {
                    "agentsecEvidence/configSha256": execution.config_sha256,
                    "agentsecEvidence/rulesetSha256": execution.ruleset_sha256,
                    "agentsecEvidence/targetSnapshotId": execution.target_snapshot_id,
                },
            }
        ],
        "results": results,
        "properties": {
            "agentsecEvidence/schemaVersion": "0.1.0",
            "agentsecEvidence/exporter": "agentsec-evidence-sarif/0.1.0",
        },
    }
    if execution.producer.tool_id == "agent-audit":
        cast(dict[str, JsonValue], run["properties"]).update(
            {
                "agentsecEvidence/perFileCompletion": "not-observable",
                "agentsecEvidence/evidenceDomain": "repository-static-unreviewed",
            }
        )
    return cast(
        dict[str, JsonValue],
        {"$schema": SARIF_SCHEMA_URI, "version": "2.1.0", "runs": [run]},
    )
