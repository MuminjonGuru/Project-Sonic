"""Loss-explicit SARIF projection of custom conditions, never inventory as vulnerabilities."""

from collections.abc import Sequence
from typing import Any, cast
from urllib.parse import quote

from pydantic import JsonValue

from agentsec_evidence.models.contracts import ContractModel
from agentsec_evidence.reporting.custom_contracts import NativeFile, catalog
from agentsec_evidence.reporting.custom_models import CustomSource


def custom_sarif_runs(source: CustomSource) -> list[dict[str, JsonValue]]:
    runs: list[dict[str, JsonValue]] = []
    for treatment in source.summary.treatments:
        native = treatment.native
        active = [rule for rule in catalog(native) if rule["status"] == "active-condition"]
        by_id = {str(rule["rule_id"]): rule for rule in active}
        results: list[dict[str, Any]] = []
        for file_index, file in enumerate(cast(Sequence[NativeFile], native.files)):
            for finding_index, finding in enumerate(file.findings or []):
                value = cast(ContractModel, finding).model_dump(mode="json")
                rule_id = value["rule"]["rule_id"] if "rule" in value else value["rule_id"]
                rule = by_id[rule_id]
                priority = value["rule"]["severity"] if "rule" in value else value["priority"]
                pointer = f"/files/{file_index}/findings/{finding_index}"
                span = value["location"]
                results.append(
                    {
                        "ruleId": rule_id,
                        "ruleIndex": list(by_id).index(rule_id),
                        "level": "warning",
                        "message": {"text": str(rule["title"]) + " (unreviewed static condition)"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": quote(file.path, safe="/")},
                                    "region": {
                                        "startLine": span["start_line"],
                                        "endLine": span["end_line"],
                                    },
                                }
                            }
                        ],
                        "partialFingerprints": {
                            "agentsecEvidence/nativeRecordId": value["record_id"]
                        },
                        "properties": {
                            "agentsecEvidence/verification": "unreviewed-static-condition",
                            "agentsecEvidence/nativePriority": priority,
                            "agentsecEvidence/priorityInterpretation": "uncalibrated priority",
                            "agentsecEvidence/nativePointer": pointer,
                            "agentsecEvidence/nativeReportSha256": treatment.stdout_sha256,
                            "agentsecEvidence/sourceSha256": file.source_sha256,
                            "agentsecEvidence/nativeUtf8ByteRange": span,
                            "agentsecEvidence/exportLosses": ["source-expression", "SARIF-columns"],
                            "agentsecEvidence/suppressionApplication": "not-applied",
                            "agentsecEvidence/reviewGrouping": "not-performed",
                        },
                    }
                )
        notifications = [
            {
                "descriptor": {"id": "custom-input-" + file.state},
                "level": "warning",
                "message": {"text": f"{file.path}: {file.state}; {file.reason}"},
            }
            for file in native.files
            if file.state != "analyzed"
        ]
        properties: dict[str, Any] = {
            "agentsecEvidence/sourceRunId": source.run_id,
            "agentsecEvidence/sourceManifestSha256": source.source_manifest_sha256,
            "agentsecEvidence/treatment": treatment.key,
            "agentsecEvidence/evidenceRole": source.summary.evidence_role,
            "agentsecEvidence/nativeReportSha256": treatment.stdout_sha256,
            "agentsecEvidence/policy": native.policy,
            "agentsecEvidence/analysisCompleteness": "not-established",
            "agentsecEvidence/inventoryObservations": sum(len(f.inventory) for f in native.files),
            "agentsecEvidence/limitationObservations": sum(
                len(f.limitations_observed) for f in native.files
            ),
            "agentsecEvidence/deferredRules": [
                str(rule["rule_id"]) for rule in catalog(native) if rule["status"] == "deferred"
            ],
            "agentsecEvidence/unparsedFiles": [
                file.path for file in native.files if file.findings is None
            ],
            "agentsecEvidence/uniqueVulnerabilities": None,
            "agentsecEvidence/exportBoundary": (
                "Conditions only; inventory and complete native records remain in report JSON."
            ),
        }
        run = {
            "tool": {
                "driver": {
                    "name": native.producer,
                    "version": native.version,
                    "rules": [
                        {
                            "id": str(rule["rule_id"]),
                            "shortDescription": {"text": str(rule["title"])},
                        }
                        for rule in active
                    ],
                }
            },
            "invocations": [
                {
                    "executionSuccessful": native.execution_state == "complete",
                    "toolExecutionNotifications": notifications,
                }
            ],
            "results": results,
            "properties": properties,
        }
        runs.append(cast(dict[str, JsonValue], run))
    return runs


def validate_custom_runs(source: CustomSource, runs: list[dict[str, JsonValue]]) -> None:
    # Recompute the entire export, not just result counts or mutable linkage properties.
    if runs != custom_sarif_runs(source):
        raise ValueError("Custom SARIF projection differs from preserved native evidence")
