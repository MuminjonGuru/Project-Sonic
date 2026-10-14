"""Read the finite public pilot without treating it as controlled development evidence."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import JsonValue

from agentsec_evidence.adapters.agent_audit import parse_agent_audit_json
from agentsec_evidence.agents.inventory import ArtifactInventory
from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes, sha256_file
from agentsec_evidence.exports.sarif import SARIF_SCHEMA_URI
from agentsec_evidence.intake.input_plan import ToolInputPlan
from agentsec_evidence.models.contracts import ExecutionRecord, Finding
from agentsec_evidence.pilot.inputs import PLAN_PATH
from agentsec_evidence.pilot.models import PilotPlan, PilotRow
from agentsec_evidence.reporting.dependency import dependency_sarif, load_dependency_run
from agentsec_evidence.reporting.models import (
    DependencySummary,
    PilotDirectorySkip,
    PilotFileReference,
    PilotPlanRecord,
    PilotRepetitionSummary,
    PilotSarifBinding,
    PublicPilotSource,
    PublicPilotSummary,
)
from agentsec_evidence.reporting.semgrep_export import semgrep_sarif_run
from agentsec_evidence.research.execution import ResearchExecutionAssessment
from agentsec_evidence.research.models import SemgrepDualView
from agentsec_evidence.research.retained import RetainedResearch, read_retained_research


def _json(retained: RetainedResearch, path: str) -> dict[str, Any]:
    return cast(dict[str, Any], load_agent_json(retained.read(path), max_bytes=4 * 1024**2))


def load_pilot_source(project: Path, root: Path) -> tuple[PublicPilotSource, dict[str, JsonValue]]:
    # The pilot replay itself validates dependency common reports. Load it only after
    # the reporting service is initialized, without a module-import cycle.
    from agentsec_evidence.pilot.validation import validate_source_pilot, verify_seal

    retained = read_retained_research(root, manifest_contract="source-pilot-evidence-v1")
    try:
        replay = validate_source_pilot(project, retained.root)
        if replay["passed"] is not True:
            raise ValueError("Public pilot replay did not pass")
        source, document = _project_pilot(retained)
        if (
            verify_seal(retained.root) != replay["files_verified"]
            or sha256_file(retained.root / "evidence-manifest.json") != retained.manifest_sha256
        ):
            raise ValueError("Public pilot changed during report construction")
        return source, document
    except (KeyError, TypeError, IndexError, AttributeError, StopIteration) as exc:
        raise ValueError("Malformed completed public pilot evidence") from exc


def _project_pilot(retained: RetainedResearch) -> tuple[PublicPilotSource, dict[str, JsonValue]]:
    report = _json(retained, "pilot-report.json")
    plan = PilotPlan.model_validate(_json(retained, "frozen/" + PLAN_PATH))
    if report["repository"] != plan.repository or report["split"] != plan.split:
        raise ValueError("Public pilot label or evidence split differs from its frozen plan")
    inventory = ArtifactInventory.model_validate(
        _json(retained, "preparation/artifact-inventory.json")
    )
    rows = tuple(PilotRow.model_validate(row) for row in report["rows"])
    run_id = "public-pilot-" + semantic_hash({"manifest": retained.manifest_sha256})[:32]
    base = {
        "agentsecEvidence/sourceRunId": run_id,
        "agentsecEvidence/sourceManifestSha256": retained.manifest_sha256,
        "agentsecEvidence/evidenceRole": plan.split,
        "agentsecEvidence/targetContentSha256": plan.content_sha256,
        "agentsecEvidence/repository": plan.repository,
        "agentsecEvidence/revision": plan.revision,
    }
    references = {
        "pilot-report.json",
        "comparison.csv",
        "freeze.json",
        "frozen/" + PLAN_PATH,
        "preparation/artifact-inventory.json",
        "preparation/git-verification.json",
        "semgrep-input-plan.json",
        "agent-audit-input-plan.json",
    }
    references.update(path for row in rows for path in row.evidence)
    repetitions = []
    runs: list[dict[str, Any]] = []
    bindings = []
    for repetition in range(1, 4):
        prefix = f"repetition-{repetition}"
        current: dict[str, PilotRow] = {
            row.stage: row for row in rows if row.repetition == repetition
        }
        dual = SemgrepDualView.model_validate(_json(retained, prefix + "/dual-view.json"))
        references.add(prefix + "/dual-view.json")
        directory_skips: dict[
            Literal["research", "repository-policy"], list[PilotDirectorySkip]
        ] = {}
        for stage, evidence in (
            ("semgrep-research", dual.research),
            ("semgrep-policy", dual.repository_policy),
        ):
            if evidence is None:
                raise ValueError("Completed public pilot requires both Semgrep views")
            path = f"{prefix}/{stage}"
            directory_skips[evidence.role] = [
                PilotDirectorySkip.model_validate(item)
                for item in _json_list(retained, path + "/directory-skips.json")
            ]
            references.update({path + "/directory-skips.json", path + "/assessment.json"})
            run = semgrep_sarif_run(
                evidence=evidence,
                execution=ResearchExecutionAssessment.model_validate(
                    _json(retained, path + "/assessment.json")
                ),
                native=_json(retained, path + "/native.sarif")["runs"][0],
                native_json_path=path + "/native.json",
                native_sarif_path=path + "/native.sarif",
                target_sha256=plan.content_sha256,
                exit_code=current[stage].exit_code,
                properties={
                    **base,
                    "agentsecEvidence/pilotStage": stage,
                    "agentsecEvidence/repetition": repetition,
                    "agentsecEvidence/nativeExecutionId": evidence.execution_id,
                    "agentsecEvidence/policyView": evidence.role,
                    "agentsecEvidence/policyLabel": (
                        "Semgrep policy only; implicit Git filtering disabled"
                    ),
                    "agentsecEvidence/directorySkipContext": [
                        skip.model_dump(mode="json") for skip in directory_skips[evidence.role]
                    ],
                },
            )
            runs.append(run)
        agent_path = prefix + "/agent-audit"
        parsed = parse_agent_audit_json(retained.read(agent_path + "/native.json"))
        findings = [
            Finding.model_validate_json(line)
            for line in retained.read(agent_path + "/findings.jsonl").splitlines()
        ]
        execution = ExecutionRecord.model_validate(_json(retained, agent_path + "/execution.json"))
        references.add(agent_path + "/execution.json")
        run = copy.deepcopy(_json(retained, agent_path + "/results.sarif")["runs"][0])
        run.setdefault("properties", {}).update(
            {
                **base,
                "agentsecEvidence/pilotStage": "agent-audit",
                "agentsecEvidence/repetition": repetition,
                "agentsecEvidence/nativeRunId": execution.run_id,
                "agentsecEvidence/nativeExecutionId": execution.execution_id,
                "agentsecEvidence/analysisState": current["agent-audit"].state,
                "agentsecEvidence/nativeExitCode": current["agent-audit"].exit_code,
                "agentsecEvidence/perFileCompletion": "not-observable",
                "agentsecEvidence/selectedFileCount": len(plan.python_paths),
                "agentsecEvidence/nativeScannedFiles": parsed.document.scanned_files,
            }
        )
        for result in run["results"]:
            result.setdefault("properties", {}).update(
                {
                    "agentsecEvidence/nativeRunId": execution.run_id,
                    "agentsecEvidence/nativeJsonPath": agent_path + "/native.json",
                    "agentsecEvidence/nativeJsonSha256": sha256_bytes(
                        retained.read(agent_path + "/native.json")
                    ),
                    "agentsecEvidence/retainedSarifPath": agent_path + "/results.sarif",
                    "agentsecEvidence/retainedSarifSha256": sha256_bytes(
                        retained.read(agent_path + "/results.sarif")
                    ),
                }
            )
        runs.append(run)
        dependency_manifest = next(
            p for p in current["osv-direct"].evidence if p.endswith("/manifest.json")
        )
        dependency_root = (retained.root / dependency_manifest).parent
        dependency = load_dependency_run(dependency_root)
        dep_summary = DependencySummary.model_validate(
            _json(retained, prefix + "/dependency-summary.json")
        )
        for dep_run in cast(list[dict[str, Any]], dependency_sarif(dependency)["runs"]):
            props = dep_run["properties"]
            stage = props["agentsecEvidence/comparisonPath"]
            props.update(
                {
                    "agentsecEvidence/constituentRunId": props["agentsecEvidence/sourceRunId"],
                    "agentsecEvidence/constituentManifestSha256": props[
                        "agentsecEvidence/sourceManifestSha256"
                    ],
                    "agentsecEvidence/constituentManifestPath": dependency_manifest,
                    **base,
                    "agentsecEvidence/pilotStage": stage,
                    "agentsecEvidence/repetition": repetition,
                }
            )
            for result in dep_run["results"]:
                artifact = result["properties"]["agentsecEvidence/nativeArtifact"]
                result["properties"]["agentsecEvidence/pilotNativeArtifact"] = (
                    dependency_root.relative_to(retained.root).as_posix() + "/" + artifact
                )
            runs.append(dep_run)
        repetitions.append(
            PilotRepetitionSummary(
                repetition=repetition,
                semgrep=dual,
                directory_skips=directory_skips,
                agent_run_id=execution.run_id,
                agent_execution_id=execution.execution_id,
                agent_native_scanned_files=parsed.document.scanned_files,
                agent_findings=findings,
                dependency=dep_summary,
            )
        )
    for run in runs:
        props = run["properties"]
        bindings.append(
            PilotSarifBinding(
                repetition=props["agentsecEvidence/repetition"],
                stage=props["agentsecEvidence/pilotStage"],
                result_count=len(run["results"]),
                run_sha256=semantic_hash(run),
            )
        )
    source = PublicPilotSource(
        run_id=run_id,
        label=plan.repository,
        revision=plan.revision,
        target_content_sha256=plan.content_sha256,
        source_manifest_sha256=retained.manifest_sha256,
        summary=PublicPilotSummary(
            plan=PilotPlanRecord.model_validate(plan.model_dump(mode="json")),
            inventory=inventory,
            input_plans=(
                ToolInputPlan.model_validate(_json(retained, "semgrep-input-plan.json")),
                ToolInputPlan.model_validate(_json(retained, "agent-audit-input-plan.json")),
            ),
            rows=rows,
            repetitions=tuple(repetitions),
            repeatability=report["repeatability"],
            repetition_wall_ns=report["repetition_wall_ns"],
            attempt_wall_ns=report["attempt_wall_ns"],
            manual_recovery_actions_during_attempt=report["manual_recovery_actions_during_attempt"],
            manual_preparation_and_adjudication_time_ns=report[
                "manual_preparation_and_adjudication_time_ns"
            ],
            retained_coverage=report["coverage"],
            references=tuple(
                PilotFileReference(path=p, sha256=sha256_bytes(retained.read(p)))
                for p in sorted(references)
            ),
            sarif_bindings=tuple(bindings),
            limitations=(
                *report["limitations"],
                "Syft inventory has no SARIF vulnerability run; it remains a table stage.",
                "Coverage and wall timings retain the collection report's declarations; "
                "hashes are not external attestation.",
                "Original inventory/input-plan metadata retains its historical authorization "
                "boundary; the frozen pilot plan grants finite use.",
                "Build replays original evidence; standalone report validation checks "
                "only this derivative.",
            ),
        ),
    )
    document = {"$schema": SARIF_SCHEMA_URI, "version": "2.1.0", "runs": runs}
    validate_pilot_runs(source, cast(list[dict[str, JsonValue]], runs))
    return source, cast(dict[str, JsonValue], document)


def _json_list(retained: RetainedResearch, path: str) -> list[Any]:
    value = json.loads(retained.read(path))
    if not isinstance(value, list):
        raise ValueError("Expected retained array")
    return value


def validate_pilot_runs(source: PublicPilotSource, runs: list[dict[str, JsonValue]]) -> None:
    """Bind the derivative to each retained projection; this does not reopen source evidence."""
    if len(runs) != len(source.summary.sarif_bindings):
        raise ValueError("Missing public pilot SARIF runs")
    for binding, value in zip(source.summary.sarif_bindings, runs, strict=True):
        run = cast(dict[str, Any], value)
        props = run.get("properties", {})
        if (
            props.get("agentsecEvidence/repetition") != binding.repetition
            or props.get("agentsecEvidence/pilotStage") != binding.stage
            or props.get("agentsecEvidence/evidenceRole") != source.summary.evidence_role
            or props.get("agentsecEvidence/revision") != source.revision
            or props.get("agentsecEvidence/targetContentSha256") != source.target_content_sha256
            or len(run.get("results", [])) != binding.result_count
            or semantic_hash(value) != binding.run_sha256
        ):
            raise ValueError("Public pilot SARIF content or stage binding differs")
