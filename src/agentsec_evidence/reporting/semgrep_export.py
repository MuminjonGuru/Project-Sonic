"""Evidence-preserving SARIF for a reconciled Semgrep pass, independent of case split."""

from __future__ import annotations

import copy
from typing import Any
from urllib.parse import quote

from agentsec_evidence.core.identity import semantic_hash
from agentsec_evidence.research.execution import ResearchExecutionAssessment
from agentsec_evidence.research.models import SemgrepPassEvidence


def semgrep_sarif_run(
    *,
    evidence: SemgrepPassEvidence,
    execution: ResearchExecutionAssessment,
    native: dict[str, Any],
    native_json_path: str,
    native_sarif_path: str,
    target_sha256: str | None,
    exit_code: int | None,
    properties: dict[str, Any],
) -> dict[str, Any]:
    results = []
    for finding in evidence.findings:
        index = int(finding.sarif_pointer.rsplit("/", 1)[1])
        result = copy.deepcopy(native["results"][index])
        physical = result["locations"][0]["physicalLocation"]
        physical["artifactLocation"] = {"uri": quote(finding.anchor.path, safe="/")}
        result["kind"] = "review"
        result["partialFingerprints"] = {
            "agentsecEvidence/researchAnchor/v1": semantic_hash(
                {
                    "target": target_sha256,
                    "profile": evidence.profile_sha256,
                    "anchor": finding.anchor.model_dump(mode="json"),
                }
            )
        }
        result.setdefault("properties", {}).update(
            {
                "agentsecEvidence/reviewState": "unreviewed",
                "agentsecEvidence/nativeSuppressions": list(finding.native_suppressions),
                "agentsecEvidence/nativeJsonPath": native_json_path,
                "agentsecEvidence/nativeJsonSha256": evidence.native_json_sha256,
                "agentsecEvidence/nativeJsonPointer": finding.json_pointer,
                "agentsecEvidence/nativeSarifPath": native_sarif_path,
                "agentsecEvidence/nativeSarifSha256": evidence.native_sarif_sha256,
                "agentsecEvidence/nativeSarifPointer": finding.sarif_pointer,
            }
        )
        if finding.native_suppressions:
            result["suppressions"] = [
                {
                    "kind": s["kind"],
                    "status": "underReview",
                    "justification": "Native suppression retained; not approved by this platform",
                }
                for s in finding.native_suppressions
            ]
        results.append(result)
    return {
        "tool": native["tool"],
        **({"columnKind": native["columnKind"]} if "columnKind" in native else {}),
        "results": results,
        "invocations": [
            {
                "executionSuccessful": execution.analysis_state != "failed" and exit_code == 0,
                "toolExecutionNotifications": [
                    {
                        "level": "warning",
                        "message": {
                            "text": "Recorded analysis remains "
                            + execution.analysis_state
                            + "; complete rule coverage is not established."
                        },
                    }
                ],
            }
        ],
        "properties": {
            **properties,
            "agentsecEvidence/analysisState": execution.analysis_state,
            "agentsecEvidence/nativeExecutionSuccessful": evidence.native_execution_successful,
            "agentsecEvidence/nativeExitCode": exit_code,
        },
    }
