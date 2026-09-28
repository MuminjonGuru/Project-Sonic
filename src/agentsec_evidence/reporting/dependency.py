from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from pydantic import JsonValue

from agentsec_evidence.core.identity import semantic_hash, sha256_file
from agentsec_evidence.dependencies.analysis import compare_stages, package_set
from agentsec_evidence.dependencies.models import DependencyScope, StageEvidence
from agentsec_evidence.dependencies.parsers import object_value
from agentsec_evidence.dependencies.pipeline import validate_dependency_bundle
from agentsec_evidence.exports.sarif import SARIF_SCHEMA_URI
from agentsec_evidence.reporting.models import DependencyStageSummary, DependencySummary

DEPENDENCY_RUN_ID = re.compile(r"^dep-run-[0-9a-f]{32}$")
STAGES = ("lockfile", "syft", "cyclonedx", "osv-direct", "osv-sbom")
PAIRS = (
    ("lockfile", "syft"),
    ("syft", "cyclonedx"),
    ("cyclonedx", "osv-sbom"),
    ("lockfile", "osv-direct"),
    ("osv-direct", "osv-sbom"),
)


@dataclass(frozen=True)
class DependencyRun:
    root: Path
    report: dict[str, JsonValue]
    stages: dict[str, StageEvidence]
    scope: DependencyScope | None
    tools: dict[str, JsonValue]


def resolve_dependency_run(workspace: Path, run_id: str) -> Path:
    if not DEPENDENCY_RUN_ID.fullmatch(run_id):
        raise ValueError("Invalid dependency run ID")
    parent = (workspace / "dependency-runs").resolve(strict=True)
    root = (parent / run_id).resolve(strict=True)
    if root.parent != parent or not root.is_dir():
        raise ValueError("Dependency run escaped its workspace")
    return root


def load_dependency_run(root: Path) -> DependencyRun:
    root = root.resolve(strict=True)
    try:
        validate_dependency_bundle(root)
        report = object_value(json.loads((root / "report.json").read_bytes()))
        if report.get("contract") != "dependency-run-v1" or report.get("run_id") != root.name:
            raise ValueError("Dependency directory and report identities differ")
        if report.get("state") not in {"complete", "partial", "failed"}:
            raise ValueError("Unrecognized dependency run state")
        stages: dict[str, StageEvidence] = {}
        for path in sorted((root / "normalized").glob("*.json")):
            stage = StageEvidence.model_validate_json(path.read_bytes())
            if stage.stage in stages or path.stem != stage.stage:
                raise ValueError("Duplicate or misnamed normalized stage")
            stages[stage.stage] = stage
        scope_path = root / "scope.json"
        scope = (
            DependencyScope.model_validate_json(scope_path.read_bytes())
            if scope_path.exists()
            else None
        )
        if report["state"] == "complete" and (
            set(stages) != set(STAGES)
            or scope is None
            or any(stage.state != "complete" for stage in stages.values())
        ):
            raise ValueError("Complete dependency report lacks complete stage evidence")
        tools_path = root / "configuration/tools.json"
        tools = object_value(json.loads(tools_path.read_bytes())) if tools_path.exists() else {}
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError("Malformed dependency evidence structure") from exc
    return DependencyRun(root, report, stages, scope, tools)


def summarize_dependency(existing: DependencyRun) -> DependencySummary:
    # Missing stages use null counts, not zero; failed-stage counts are only observations.
    # Keep occurrences, distinct packages and package-advisory pairs as separate units.
    scope = existing.scope
    rows = []
    for name in STAGES:
        stage = existing.stages.get(name)
        matches = (
            {(item.name, item.version, item.canonical_advisory) for item in stage.matches}
            if stage
            else set()
        )
        rows.append(
            DependencyStageSummary(
                stage=name,
                state=stage.state if stage else "missing",
                observations=len(stage.observations) if stage else None,
                identified_unique_packages=len(package_set(stage)) if stage else None,
                eligible_reported_packages=len(package_set(stage) & set(scope.eligible))
                if stage and scope
                else None,
                reported_package_advisory_matches=len(matches)
                if stage and name.startswith("osv-")
                else None,
                reported_match_occurrences=len(stage.matches)
                if stage and name.startswith("osv-")
                else None,
                eligible_package_advisory_matches=sum(
                    (name, version) in set(scope.eligible) for name, version, _ in matches
                )
                if stage and scope and name.startswith("osv-")
                else None,
                unsupported_observations=sum(
                    item.status != "identified" for item in stage.observations
                )
                if stage
                else None,
                relationships=len(stage.relationships) if stage else None,
            )
        )
    comparisons = [
        compare_stages(existing.stages[left], existing.stages[right], scope)
        for left, right in PAIRS
        if scope and left in existing.stages and right in existing.stages
    ]
    timings = {
        key: value
        for key, value in existing.report.items()
        if key
        in {
            "direct_path_wall_ns",
            "sbom_initial_path_wall_ns",
            "sbom_consumer_only_wall_ns",
            "paired_end_to_end_ns",
        }
        and isinstance(value, int)
        and not isinstance(value, bool)
    }
    database_hash = existing.report.get("database_sha256")
    return DependencySummary(
        run_id=str(existing.report["run_id"]),
        state=cast("LiteralState", existing.report["state"]),
        scope_available=scope is not None,
        eligible_unique_packages=len(scope.eligible) if scope else None,
        separate_local_packages=len(scope.separate_local) if scope else None,
        unsupported_scope_records=len(scope.unsupported_pointers) if scope else None,
        ambiguous_projections=len(scope.ambiguous_projections) if scope else None,
        database_sha256=database_hash if isinstance(database_hash, str) else None,
        stages=rows,
        comparisons=comparisons,
        timing_ns=timings,
        limitations=[
            "Package ratios use PyPI name/version projections, not full qualified identity.",
            "Reported presence is not proof of ingestion or per-package matching completion.",
            "No reported match against this database is not a safety verdict.",
            "Counts for direct and SBOM paths are not independent vulnerabilities to sum.",
            "Native occurrence and relationship fidelity is not scored.",
            "Missing evidence is null, not zero; failed-stage counts are partial observations.",
        ],
    )


type LiteralState = Literal["complete", "partial", "failed"]


def dependency_sarif(existing: DependencyRun) -> dict[str, JsonValue]:
    # Separate comparison paths and use logical package locations rather than invented lines.
    # SARIF level "none" means severity is unmapped, not that the package is safe.
    runs: list[JsonValue] = []
    summary = summarize_dependency(existing)
    for path in ("osv-direct", "osv-sbom"):
        stage = existing.stages.get(path)
        matches = (
            sorted(
                stage.matches,
                key=lambda item: (
                    item.canonical_advisory,
                    item.name,
                    item.version,
                    item.package_pointer,
                ),
            )
            if stage
            else []
        )
        rule_ids = sorted({item.canonical_advisory for item in matches})
        results: list[JsonValue] = []
        for match in matches:
            identity: JsonValue = {
                "ecosystem": "PyPI",
                "name": match.name,
                "version": match.version,
                "advisory": match.canonical_advisory,
            }
            results.append(
                {
                    "ruleId": match.canonical_advisory,
                    "ruleIndex": rule_ids.index(match.canonical_advisory),
                    "kind": "fail",
                    "level": "none",
                    "message": {
                        "text": (
                            f"OSV reported {match.canonical_advisory} for "
                            f"PyPI {match.name}@{match.version}; "
                            "exploitability and severity are not inferred."
                        )
                    },
                    "locations": [
                        {
                            "logicalLocations": [
                                {
                                    "name": f"{match.name}@{match.version}",
                                    "fullyQualifiedName": f"PyPI/{match.name}@{match.version}",
                                }
                            ]
                        }
                    ],
                    "partialFingerprints": {
                        "agentsecEvidencePackageAdvisory/v1": semantic_hash(identity),
                        "agentsecEvidencePackageOccurrence/v1": semantic_hash(
                            {
                                "identity": identity,
                                "path": path,
                                "pointer": match.package_pointer,
                                "target": existing.report.get("snapshot_sha256"),
                            }
                        ),
                    },
                    "properties": {
                        "agentsecEvidence/sourceRunId": existing.report["run_id"],
                        "agentsecEvidence/comparisonPath": path,
                        "agentsecEvidence/sourceBlobSha256": stage.raw_sha256 if stage else None,
                        "agentsecEvidence/jsonPointer": match.package_pointer,
                        "agentsecEvidence/nativeArtifact": f"native/{path}/osv.json",
                        "agentsecEvidence/package": identity,
                        "agentsecEvidence/originalAdvisoryIds": cast(JsonValue, match.original_ids),
                        "agentsecEvidence/aliases": cast(JsonValue, match.aliases),
                        "agentsecEvidence/eligibility": "eligible"
                        if existing.scope and (match.name, match.version) in existing.scope.eligible
                        else "outside-comparison-scope-or-unknown",
                        "agentsecEvidence/severity": "not-mapped",
                    },
                }
            )
        executions = existing.report.get("stages")
        execution = executions.get(path) if isinstance(executions, dict) else None
        exit_code = execution.get("exit_code") if isinstance(execution, dict) else None
        successful = bool(
            stage
            and stage.state == "complete"
            and isinstance(execution, dict)
            and exit_code in (0, 1)
            and not execution.get("timed_out")
            and not execution.get("output_limited")
        )
        notifications: list[JsonValue] = []
        if not successful:
            notifications.append(
                {
                    "level": "error",
                    "message": {
                        "text": (
                            f"{path}: analysis is incomplete, failed, unsupported or missing; "
                            "results must not be interpreted as a clean scan."
                        )
                    },
                }
            )
        elif summary.state != "complete":
            notifications.append(
                {
                    "level": "warning",
                    "message": {
                        "text": (
                            "This OSV stage completed, but the surrounding "
                            "dependency evidence pipeline is incomplete."
                        )
                    },
                }
            )
        invocation: dict[str, JsonValue] = {
            "executionSuccessful": successful,
            "toolExecutionNotifications": notifications,
        }
        if isinstance(exit_code, int):
            invocation["exitCode"] = exit_code
        driver: dict[str, JsonValue] = {
            "name": "OSV-Scanner",
            "informationUri": "https://google.github.io/osv-scanner/",
            "rules": [{"id": rule} for rule in rule_ids],
        }
        osv = existing.tools.get("osv")
        if isinstance(osv, dict) and isinstance(osv.get("version"), str):
            driver["version"] = osv["version"]
        runs.append(
            {
                "tool": {"driver": driver},
                "automationDetails": {
                    "id": f"agentsec-evidence/dependency/{existing.report['run_id']}/{path}"
                },
                "invocations": [invocation],
                "results": results,
                "properties": {
                    "agentsecEvidence/exporter": "agentsec-evidence-dependency-sarif/1",
                    "agentsecEvidence/sourceRunId": existing.report["run_id"],
                    "agentsecEvidence/sourceManifestSha256": sha256_file(
                        existing.root / "manifest.json"
                    ),
                    "agentsecEvidence/comparisonPath": path,
                    "agentsecEvidence/pipelineState": summary.state,
                    "agentsecEvidence/stageState": stage.state if stage else "missing",
                    "agentsecEvidence/databaseSha256": summary.database_sha256,
                    "agentsecEvidence/targetContentSha256": existing.report.get("snapshot_sha256"),
                    "agentsecEvidence/eligiblePackages": summary.eligible_unique_packages,
                    "agentsecEvidence/matchingCompletion": "not-observable-per-package",
                    "agentsecEvidence/packageCountsAreNotSafety": True,
                    "agentsecEvidence/comparisons": [
                        item.model_dump(mode="json") for item in summary.comparisons
                    ],
                },
            }
        )
    return {"$schema": SARIF_SCHEMA_URI, "version": "2.1.0", "runs": runs}
