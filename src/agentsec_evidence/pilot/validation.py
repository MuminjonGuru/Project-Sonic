"""Offline replay of a finished local pilot; never executes a target or scanner."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, cast

from jsonschema import Draft7Validator
from pydantic import JsonValue

from agentsec_evidence.adapters.agent_audit import normalize_agent_audit, parse_agent_audit_json
from agentsec_evidence.agents.inventory import ArtifactInventory
from agentsec_evidence.agents.records import AgentInputReport, AgentInputRequest
from agentsec_evidence.agents.semantics import native_projection
from agentsec_evidence.agents.validation import canonical_artifact_path
from agentsec_evidence.agents.view_validation import assess_agent_view_report
from agentsec_evidence.core.identity import semantic_hash, sha256_file
from agentsec_evidence.dependencies.analysis import dependency_semantic_hash
from agentsec_evidence.execution.process import ProcessCapture
from agentsec_evidence.exports.sarif import build_sarif
from agentsec_evidence.intake.git_verification import GitSourceVerification
from agentsec_evidence.intake.input_plan import ToolInputPlan
from agentsec_evidence.intake.views import (
    ToolInputView,
    ToolViewContext,
    replay_parent_source,
    verify_materialized_tool_view,
)
from agentsec_evidence.models.contracts import ExecutionRecord, Finding
from agentsec_evidence.pilot.inputs import PLAN_PATH, PROFILE_PATH, TOOL_PATH, load_plan
from agentsec_evidence.pilot.models import PilotRow, repeatability
from agentsec_evidence.pilot.runner import evidence_records, load, ready_capture, table_bytes
from agentsec_evidence.reporting.dependency import load_dependency_run, summarize_dependency
from agentsec_evidence.reporting.service import validate_common_report
from agentsec_evidence.research.execution import assess_research_execution
from agentsec_evidence.research.inputs import (
    assess_research_syntax,
    prepare_research_inputs,
    replay_research_inputs,
)
from agentsec_evidence.research.models import load_research_profile, verify_rule_bytes
from agentsec_evidence.research.retained import bounded_file, plain_path
from agentsec_evidence.research.semgrep import (
    build_dual_view,
    directory_skip_context,
    reconcile_semgrep_pass,
)


def read_capture(directory: Path) -> tuple[ProcessCapture, bool]:
    record = load(directory / "process.json")
    record["argv"] = tuple(record["argv"])
    record["started_at"] = datetime.fromisoformat(record["started_at"])
    record["ended_at"] = datetime.fromisoformat(record["ended_at"])
    capture = ProcessCapture(
        **record,
        stdout=bounded_file(directory / "stdout.bin", 4 * 1024**2),
        stderr=bounded_file(directory / "stderr.bin", 4 * 1024**2),
    )
    if list(capture.argv) != load(directory / "command.json")["argv"]:
        raise ValueError("Command and capture differ")
    return capture, load(directory / "cleanup.json")["succeeded"] is True


def verify_seal(root: Path) -> int:
    root = plain_path(root, directory=True)
    manifest = load(root / "evidence-manifest.json")
    if manifest.get("contract") != "source-pilot-evidence-v1":
        raise ValueError("Wrong pilot evidence contract")
    records = evidence_records(root)
    if manifest.get("files") != records:
        raise ValueError("Pilot evidence seal differs")
    return len(records)


def checked_retained_findings(expected: Sequence[Finding], raw: bytes) -> list[Finding]:
    actual = [Finding.model_validate_json(line) for line in raw.splitlines()]
    if len({f.record_id for f in actual}) != len(actual):
        raise ValueError("Duplicate retained finding ID")
    # Record IDs are opaque per-normalization IDs, not the semantic comparison key.
    if [f.model_dump(exclude={"record_id"}) for f in actual] != [
        f.model_dump(exclude={"record_id"}) for f in expected
    ]:
        raise ValueError("Agent finding content differs from native replay")
    return actual


def validate_source_pilot(project: Path, root: Path) -> dict[str, Any]:
    count = verify_seal(root)
    report = load(root / "pilot-report.json")
    if (
        report.get("contract") != "same-repository-pilot-report-v1"
        or report.get("instrument_finished") is not True
        or report.get("input_unchanged") is not True
    ):
        raise ValueError(
            "Only finished pilot attempts support full replay; failure seals remain inspectable"
        )
    plan = load_plan(root / "frozen")
    if (
        report["plan_sha256"] != sha256_file(root / "frozen" / PLAN_PATH)
        or report["freeze_sha256"] != sha256_file(root / "freeze.json")
        or report["revision"] != plan.revision
        or report["content_sha256"] != plan.content_sha256
        or report["target_execution"] is not False
        or report["vulnerability_total"] is not None
    ):
        raise ValueError("Pilot binding differs")
    freeze = load(root / "freeze.json")
    for entry in freeze["input_records"]:
        canonical_artifact_path(entry["path"])
        if sha256_file(root / entry["path"]) != entry["sha256"]:
            raise ValueError("Frozen input changed")
    base = root / "preparation"
    inventory = ArtifactInventory.model_validate_json(
        bounded_file(base / "artifact-inventory.json", 4 * 1024**2)
    )
    proof = GitSourceVerification.model_validate_json(
        bounded_file(base / "git-verification.json", 4 * 1024**2)
    )
    if proof.revision != plan.revision or inventory.snapshot.content_sha256 != plan.content_sha256:
        raise ValueError("Source identity differs")
    contexts = []
    for tool, config in (("semgrep", PROFILE_PATH), ("agent-audit", TOOL_PATH)):
        context = ToolViewContext(
            inventory,
            proof,
            ToolInputPlan.model_validate_json(
                bounded_file(root / f"{tool}-input-plan.json", 4 * 1024**2)
            ),
            bounded_file(root / "frozen" / config, 2 * 1024**2),
            bounded_file(base / "raw/commit.bin", 1024**2),
            bounded_file(base / "raw/tree-exact.json", 4 * 1024**2),
        )
        replay_parent_source(context, base / "source")
        if (
            tuple(s.path for s in context.plan.selections if s.disposition == "selected")
            != plan.python_paths
        ):
            raise ValueError("Selected source paths differ")
        contexts.append(context)
    semgrep, agent = contexts
    preparation = prepare_research_inputs(semgrep, base / "source")
    semgrep_view = ToolInputView.model_validate_json(
        bounded_file(root / "semgrep-view/view.json", 4 * 1024**2)
    )
    agent_view = ToolInputView.model_validate_json(
        bounded_file(root / "agent-view/view.json", 4 * 1024**2)
    )
    replay_research_inputs(
        semgrep,
        source=base / "source",
        preparation=preparation,
        view=semgrep_view,
        target=root / "semgrep-view/target",
    )
    verify_materialized_tool_view(agent_view, agent, root / "agent-view/target")
    profile = load_research_profile(semgrep.profile_bytes)
    verify_rule_bytes(
        profile,
        {
            r.source_path: bounded_file(root / "rules" / r.source_path, 256 * 1024)
            for r in profile.rules
        },
        license_bytes=bounded_file(root / "rules/LICENSE", 256 * 1024),
    )
    request_raw = bounded_file(root / "request.json", 1024**2)
    request = AgentInputRequest.model_validate_json(request_raw)
    rows = [PilotRow.model_validate(r) for r in report["rows"]]
    if report["repeatability"] != repeatability(rows) or bounded_file(
        root / "comparison.csv", 1024**2
    ) != table_bytes(rows):
        raise ValueError("Pilot repeatability or table differs")
    schema = load(project / "schemas/vendor/oasis/sarif-schema-2.1.0.json")
    assert preparation.scope is not None
    for repetition in range(1, 4):
        cell = root / f"repetition-{repetition}"
        worker, cleaned = read_capture(cell / "syntax")
        assessment = assess_agent_view_report(agent, agent_view, request, worker.stdout)
        if (
            not ready_capture(worker, cleaned, {0})
            or worker.stderr
            or not assessment.input_gate_passed
            or assessment.model_dump(mode="json") != load(cell / "input-assessment.json")
            or not assess_research_syntax(request, request_raw, worker.stdout)
        ):
            raise ValueError("Syntax/policy evidence differs")
        checks = AgentInputReport.model_validate_json(worker.stdout).checks
        pair = []
        for row in (r for r in rows if r.repetition == repetition):
            for path in row.evidence:
                plain_path(root / path, directory=False)
            native = cell / row.stage
            if row.stage.startswith("semgrep-"):
                capture, cleaned = read_capture(native / "capture")
                role: Literal["research", "repository-policy"] = (
                    "research" if row.stage == "semgrep-research" else "repository-policy"
                )
                execution_id = capture.argv[capture.argv.index("--name") + 1]
                evidence = reconcile_semgrep_pass(
                    profile_bytes=semgrep.profile_bytes,
                    scope=preparation.scope,
                    execution_id=execution_id,
                    role=role,
                    native_json=bounded_file(native / "native.json", 4 * 1024**2),
                    native_sarif=bounded_file(native / "native.sarif", 4 * 1024**2),
                    allow_policy_directory_skips=True,
                )
                if load(native / "directory-skips.json") != directory_skip_context(
                    preparation.scope, bounded_file(native / "native.json", 4 * 1024**2)
                ):
                    raise ValueError("Directory skip context differs")
                execution = assess_research_execution(
                    capture, cleanup_succeeded=cleaned, evidence=evidence
                )
                projection: JsonValue = {
                    "directory_skips": load(native / "directory-skips.json"),
                    "evidence": evidence.model_dump(
                        mode="json",
                        exclude={"execution_id", "native_json_sha256", "native_sarif_sha256"},
                    ),
                    "assessment": execution.model_dump(mode="json"),
                    "exit_code": capture.exit_code,
                }
                if (
                    load(native / "evidence.json") != evidence.model_dump(mode="json")
                    or load(native / "assessment.json") != execution.model_dump(mode="json")
                    or load(native / "semantic.json") != projection
                    or row.semantic_sha256 != semantic_hash(projection)
                    or row.finding_records != len(evidence.findings)
                    or row.duration_ns != capture.duration_ns
                    or row.exit_code != capture.exit_code
                    or row.state
                    != ("failed" if execution.analysis_state == "failed" else "partial")
                ):
                    raise ValueError("Semgrep derivative differs")
                Draft7Validator(schema).validate(load(native / "native.sarif"))
                pair.append(evidence)
            elif row.stage == "agent-audit":
                capture, cleaned = read_capture(native)
                parsed = parse_agent_audit_json(bounded_file(native / "native.json", 2 * 1024**2))
                execution_record = ExecutionRecord.model_validate(load(native / "execution.json"))
                findings = normalize_agent_audit(
                    parsed,
                    inputs=[c.checked_input() for c in checks],
                    run_id=execution_record.run_id,
                    execution_id=execution_record.execution_id,
                    target_snapshot_id=inventory.snapshot.snapshot_id,
                ).findings
                actual = checked_retained_findings(
                    findings, bounded_file(native / "findings.jsonl", 4 * 1024**2)
                )
                reasons = ["native-per-file-completion-not-observable"]
                if capture.stderr:
                    reasons.append("native-stderr-retained-for-review")
                if parsed.document.scanned_files != 26:
                    reasons.append("native-file-count-differs-from-selection")
                state = "partial" if ready_capture(capture, cleaned, {0, 1}) else "failed"
                if state == "failed":
                    reasons.append("process-or-cleanup-failed")
                projection = {
                    "native": native_projection(capture.stdout),
                    "state": state,
                    "reasons": cast(JsonValue, reasons),
                    "exit_code": capture.exit_code,
                }
                expected_sarif = build_sarif(actual, execution=execution_record)
                if (
                    capture.stdout != bounded_file(native / "native.json", 2 * 1024**2)
                    or load(native / "results.sarif") != expected_sarif
                    or load(native / "semantic.json") != projection
                    or row.semantic_sha256 != semantic_hash(projection)
                    or row.finding_records != len(findings)
                    or row.state != state
                    or row.duration_ns != capture.duration_ns
                    or row.exit_code != capture.exit_code
                ):
                    raise ValueError("Agent derivative differs")
                Draft7Validator(schema).validate(expected_sarif)
            else:
                manifest = next(p for p in row.evidence if p.endswith("/manifest.json"))
                existing = load_dependency_run((root / manifest).parent)
                summary = summarize_dependency(existing)
                observation = next(s for s in summary.stages if s.stage == row.stage)
                process = cast(dict[str, Any], existing.report["stages"])[row.stage]
                if existing.scope is None:
                    raise ValueError("Missing dependency scope")
                if (
                    summary.model_dump(mode="json") != load(cell / "dependency-summary.json")
                    or row.semantic_sha256
                    != dependency_semantic_hash([existing.stages[row.stage]], existing.scope)
                    or row.package_identities != observation.identified_unique_packages
                    or row.finding_records
                    != (None if row.stage == "syft" else observation.reported_match_occurrences)
                    or row.duration_ns != process["duration_ns"]
                    or row.exit_code != process["exit_code"]
                    or row.state != observation.state
                ):
                    raise ValueError("Dependency row differs")
        if load(cell / "dual-view.json") != build_dual_view(*pair).model_dump(mode="json"):
            raise ValueError("Dual-view report differs")
    validate_common_report(project, root / "dependency-common-report")
    return {
        "passed": True,
        "files_verified": count,
        "rows_replayed": len(rows),
        "repeatability": repeatability(rows),
        "target_execution": False,
        "limitations": "Local consistency replay, not external attestation or detection accuracy",
    }
