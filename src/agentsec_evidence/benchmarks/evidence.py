"""Revalidate agent bundles and bind them to an admitted benchmark cell."""

from __future__ import annotations

import os
import re
from pathlib import Path

from pydantic import JsonValue

from agentsec_evidence.agents.execution import AgentAuditToolConfig
from agentsec_evidence.agents.records import AgentInputRequest, AgentRunDetails
from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.benchmarks.attempt_models import AttemptEvidence
from agentsec_evidence.benchmarks.models import BenchmarkPlan, BenchmarkPlanV2, PlannedCell
from agentsec_evidence.benchmarks.service import PROFILE, REGISTRY, TOOL
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.execution.config import ExecutionProfile, load_toml_bytes
from agentsec_evidence.models.contracts import RunRecord, RunState
from agentsec_evidence.operations.offline import load_existing_run, validate_existing_run
from agentsec_evidence.research.retained import (
    MAX_ENTRY_BYTES,
    MAX_TREE_BYTES,
    RetainedEntry,
    RetainedManifest,
    bounded_file,
    plain_path,
)


def bundle_inventory(root: Path) -> RetainedManifest:
    """Reject links and over-budget trees before legacy validators read bundle files."""
    root = plain_path(root, directory=True)
    entries: list[RetainedEntry] = []
    size = count = 0

    def onerror(error: OSError) -> None:
        raise error

    for directory, dirs, names in os.walk(root, followlinks=False, onerror=onerror):
        count += len(dirs) + len(names)
        if count > 8192 or len(Path(directory).relative_to(root).parts) > 32:
            raise ValueError("Attempt bundle exceeds tree budget")
        for name in dirs:
            plain_path(Path(directory) / name, directory=True)
        for name in names:
            path = Path(directory) / name
            raw = bounded_file(path, MAX_ENTRY_BYTES)
            size += len(raw)
            if size > MAX_TREE_BYTES or len(entries) >= 4096:
                raise ValueError("Attempt bundle exceeds evidence budget")
            entries.append(
                RetainedEntry(
                    path=path.relative_to(root).as_posix(), bytes=len(raw), sha256=sha256_bytes(raw)
                )
            )
    return RetainedManifest(files=tuple(sorted(entries, key=lambda item: item.path)))


def verify_attempt_run(
    project: Path,
    execution: Path,
    run_id: str,
    plan: BenchmarkPlan | BenchmarkPlanV2,
    cell: PlannedCell,
) -> AttemptEvidence:
    if (
        not run_id.startswith("run_")
        or len(run_id) != 36
        or any(c not in "0123456789abcdef" for c in run_id[4:])
    ):
        raise ValueError("Invalid attempt run ID")
    root = execution / "runs" / run_id
    plain_path(root.parent, directory=True)
    if {path.name for path in root.parent.iterdir()} != {run_id}:
        raise ValueError("Attempt must retain exactly one run bundle")
    before = bundle_inventory(root)
    record = RunRecord.model_validate_json(bounded_file(root / "run.json", MAX_ENTRY_BYTES))
    if len(record.execution_ids) != 1 or not re.fullmatch(
        r"execution_[0-9a-f]{32}", record.execution_ids[0]
    ):
        raise ValueError("Unsafe or ambiguous retained execution ID")
    existing = load_existing_run(execution, run_id)
    if not validate_existing_run(
        project_root=project, workspace_root=execution, run_id=run_id
    ).passed:
        raise ValueError("Attempt bundle validation failed")
    details = AgentRunDetails.model_validate_json(
        bounded_file(root / "normalized/agent-details.json", MAX_ENTRY_BYTES)
    )

    def evidence(role: str) -> bytes:
        matches = [blob for blob in existing.blobs.blobs if blob.logical_role == role]
        if len(matches) != 1:
            raise ValueError("Missing or duplicate attempt evidence role: " + role)
        return bounded_file(root / matches[0].relative_path, MAX_ENTRY_BYTES)

    pins = {item.path: item.sha256 for item in plan.pins}
    for path, role in (
        (PROFILE, "execution-profile"),
        (TOOL, "tool-config"),
        (REGISTRY, "development-case-registry"),
    ):
        if sha256_bytes(evidence(role)) != pins[path]:
            raise ValueError("Attempt configuration differs from the plan")
    sources: list[JsonValue] = [
        {"path": item.path.removeprefix("src/"), "sha256": item.sha256}
        for item in plan.implementation
    ]
    if evidence("worker-code-identity") != json_bytes(sources):
        raise ValueError("Attempt worker implementation differs from the plan")
    config = load_toml_bytes(evidence("tool-config"), AgentAuditToolConfig, source=Path(TOOL)).value
    profile = load_toml_bytes(
        evidence("execution-profile"), ExecutionProfile, source=Path(PROFILE)
    ).value
    rules = load_agent_json(evidence("ruleset"), max_bytes=MAX_ENTRY_BYTES)
    if (
        rules != {"image": config.image, "selection": "builtin-rules/severity-info/static-only"}
        or existing.execution.image != config.image
        or existing.execution.producer.tool_id != "agent-audit"
        or existing.execution.producer.tool_version != config.tool_version
    ):
        raise ValueError("Attempt ruleset differs from the admitted selection")
    config_sha = semantic_hash(
        {
            "profile": pins[PROFILE],
            "tool": pins[TOOL],
            "rules": sha256_bytes(evidence("ruleset")),
            "worker_sources": sources,
            "case_registry": pins[REGISTRY],
        }
    )
    request = AgentInputRequest.model_validate_json(evidence("agent-input-request"))
    actual = [(item.path, item.byte_length, item.sha256) for item in request.inventory]
    expected = [(item.path, item.bytes, item.sha256) for item in cell.input_files]
    if (
        sorted(actual) != sorted(expected)
        or tuple(request.selected) != cell.selected_paths
        or details.case_id != cell.case_id
        or existing.run.run_label != f"agent-development:{cell.case_id}"
        or existing.run.config_sha256 != config_sha
        or existing.execution.config_sha256 != config_sha
        or existing.execution.ruleset_sha256 != sha256_bytes(evidence("ruleset"))
        or existing.execution.run_id != run_id
        or existing.execution.target_snapshot_id != existing.target.snapshot_id
        or existing.execution.profile_id != profile.profile_id
        or existing.run.profile_id != profile.profile_id
        or existing.execution.limits != profile.limits
        or existing.run.state != RunState.FINALIZED
        or existing.run.semantic_sha256 is None
        or existing.run.terminal_state is None
    ):
        raise ValueError("Attempt case/input/configuration/finalization binding differs")
    roles = {item.logical_role for item in existing.blobs.blobs}
    for role, expected_image in (
        ("validation-receipt", config.validator_image),
        ("scanner-receipt", config.image),
    ):
        if (
            role in roles
            and load_agent_json(evidence(role), max_bytes=MAX_ENTRY_BYTES).get("image")
            != expected_image
        ):
            raise ValueError("Attempt stage image differs from pinned treatment")
    if before != bundle_inventory(root):
        raise ValueError("Attempt evidence changed during validation")
    state = "execution-failed"
    if (
        details.input_unchanged
        and details.validation_state == "complete"
        and details.admitted
        and details.scanner_launched
        and existing.run.terminal_state == RunState.PARTIAL
        and existing.parser_report is not None
        and not existing.failures
    ):
        state = "partial-analysis"
    elif (
        details.input_unchanged
        and details.validation_state == "complete"
        and not details.admitted
        and not details.scanner_launched
        and details.blockers
        and existing.run.terminal_state == RunState.REJECTED
        and all(f.category == "unsafe-target" for f in existing.failures)
    ):
        state = "refused"
    return AttemptEvidence.model_validate(
        {
            "run_id": run_id,
            "terminal_state": existing.run.terminal_state.value,
            "semantic_sha256": existing.run.semantic_sha256,
            "bundle_files": before.model_dump(mode="json"),
            "state": state,
            "scanner_invocations": int(details.scanner_launched),
            "finding_records": details.native_result_count,
            "per_file_completion": "unknown" if details.scanner_launched else "not-run",
        }
    )


def require_prelaunch_failure(execution: Path, evidence: AttemptEvidence) -> None:
    """Call only after full bundle replay; no launch means no orphan cleanup inference."""
    existing = load_existing_run(execution, evidence.run_id)
    details = AgentRunDetails.model_validate_json(
        bounded_file(
            execution / "runs" / evidence.run_id / "normalized/agent-details.json",
            MAX_ENTRY_BYTES,
        )
    )
    roles = {blob.logical_role for blob in existing.blobs.blobs}
    failures = [(f.category, f.affected_scope, f.sanitized_message) for f in existing.failures]
    if (
        evidence.state != "execution-failed"
        or evidence.scanner_invocations != 0
        or evidence.finding_records is not None
        or not details.input_unchanged
        or details.validation_state != "not-run"
        or details.admitted
        or details.scanner_launched
        or details.validation_duration_ns != 0
        or details.scanner_duration_ns != 0
        or details.blockers != ["validation-not-complete"]
        or existing.parser_report is not None
        or existing.run.terminal_state != RunState.REJECTED
        or any(role.startswith(("validation-", "scanner-")) for role in roles)
        or failures
        != [
            (
                "missing-tool",
                "agent validation",
                "Docker unavailable; neither validation nor scanner launched",
            ),
            (
                "unsafe-target",
                "agent admission",
                "Scanner not launched: input/policy admission was refused",
            ),
        ]
    ):
        raise ValueError("Retry requires verified missing Docker before all container launches")
