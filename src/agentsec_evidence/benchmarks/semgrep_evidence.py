"""Replay the first-slice native evidence without changing or rescanning the fixture."""

import re
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel

from agentsec_evidence.adapters.semgrep import normalize_semgrep, parse_semgrep_json
from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.benchmarks.attempt_models import SemgrepAttemptEvidence, SemgrepAttemptState
from agentsec_evidence.benchmarks.evidence import bundle_inventory
from agentsec_evidence.benchmarks.models import SemgrepBenchmarkPlan, SemgrepCell
from agentsec_evidence.benchmarks.semgrep_plan import PROFILE, RULE, TOOL, semgrep_inputs
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.execution.config import ExecutionProfile, SemgrepToolConfig, load_toml_bytes
from agentsec_evidence.exports.sarif import build_sarif
from agentsec_evidence.models.contracts import (
    ExecutionOutcome,
    InventoryEntry,
    ParserReport,
    RunRecord,
    RunState,
    Summary,
)
from agentsec_evidence.operations.offline import (
    load_existing_run,
    rebuild_summary,
    validate_existing_run,
)
from agentsec_evidence.orchestration.shared import build_semantic_document
from agentsec_evidence.research.retained import MAX_ENTRY_BYTES, bounded_file, plain_path


def _values(items: Sequence[BaseModel], *, exclude: set[str]) -> list[dict[str, object]]:
    return [item.model_dump(mode="json", exclude=exclude) for item in items]


def verify_semgrep_attempt(
    project: Path, execution: Path, run_id: str, plan: SemgrepBenchmarkPlan, cell: SemgrepCell
) -> SemgrepAttemptEvidence:
    if not re.fullmatch(r"run_[0-9a-f]{32}", run_id):
        raise ValueError("Invalid Semgrep run identity")
    root = execution / "runs" / run_id
    plain_path(root.parent, directory=True)
    if {p.name for p in root.parent.iterdir()} != {run_id}:
        raise ValueError("Semgrep attempt requires exactly one run")
    before = bundle_inventory(root)
    record = RunRecord.model_validate_json(bounded_file(root / "run.json", MAX_ENTRY_BYTES))
    if len(record.execution_ids) != 1 or not re.fullmatch(
        r"execution_[0-9a-f]{32}", record.execution_ids[0]
    ):
        raise ValueError("Unsafe Semgrep execution identity")
    existing = load_existing_run(execution, run_id)
    if not validate_existing_run(
        project_root=project, workspace_root=execution, run_id=run_id
    ).passed:
        raise ValueError("Semgrep bundle validation failed")

    def evidence(role: str) -> bytes:
        matches = [b for b in existing.blobs.blobs if b.logical_role == role]
        if len(matches) != 1:
            raise ValueError("Missing or duplicate Semgrep evidence role: " + role)
        raw = bounded_file(root / matches[0].relative_path, MAX_ENTRY_BYTES)
        if sha256_bytes(raw) != matches[0].sha256 or len(raw) != matches[0].byte_length:
            raise ValueError("Semgrep evidence blob differs")
        return raw

    pins = {p.path: p.sha256 for p in plan.pins}
    for path, role in ((PROFILE, "execution-profile"), (TOOL, "tool-config"), (RULE, "ruleset")):
        if sha256_bytes(evidence(role)) != pins[path]:
            raise ValueError("Semgrep evidence configuration differs from frozen plan")
    profile = load_toml_bytes(
        evidence("execution-profile"), ExecutionProfile, source=Path(PROFILE)
    ).value
    tool = load_toml_bytes(evidence("tool-config"), SemgrepToolConfig, source=Path(TOOL)).value
    config_sha = semantic_hash(
        {
            "profile_sha256": pins[PROFILE],
            "tool_config_sha256": pins[TOOL],
            "ruleset_sha256": pins[RULE],
        }
    )
    target = existing.target
    if not re.fullmatch(r"snapshot_[0-9a-f]{64}", target.snapshot_id):
        raise ValueError("Unsafe snapshot identity")
    snapshot = execution / "targets" / target.snapshot_id
    plain_path(snapshot.parent, directory=True)
    if {p.name for p in snapshot.parent.iterdir()} != {target.snapshot_id}:
        raise ValueError("Ambiguous Semgrep target snapshot")
    snapshot_before = bundle_inventory(snapshot)
    if semgrep_inputs(snapshot / "content") != cell.input_files:
        raise ValueError("Retained target differs from benchmark case")
    inventory_raw = bounded_file(root / "target/inventory.jsonl", MAX_ENTRY_BYTES)
    inventory = tuple(
        InventoryEntry.model_validate_json(line)
        for line in inventory_raw.splitlines()
        if line.strip()
    )
    # Preserve the legacy traversal order in its content identity, but compare file sets separately.
    inventory_files = sorted((i.path, i.byte_length, i.sha256) for i in inventory)
    if inventory_files != [(f.path, f.bytes, f.sha256) for f in cell.input_files]:
        raise ValueError("Semgrep inventory differs from frozen fixture")
    content_sha = semantic_hash(
        [{"byte_length": i.byte_length, "path": i.path, "sha256": i.sha256} for i in inventory]
    )
    ex = existing.execution
    # This is the frozen first-slice invocation, not a configurable research-profile command.
    limits = profile.limits
    expected_argv = [
        "docker",
        "run",
        "--rm",
        "--pull",
        "never",
        "--name",
        f"agentsec-{run_id[-12:]}-{ex.execution_id[-8:]}",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,size={limits.tmpfs_mb}m",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(limits.pids),
        "--cpus",
        str(limits.cpu_count),
        "--memory",
        f"{limits.memory_mb}m",
        "--user",
        "65534:65534",
        "--env",
        "HOME=/tmp",
        "--env",
        "SEMGREP_SEND_METRICS=off",
        "--mount",
        "type=bind,source=<TARGET_SNAPSHOT>,target=/src,readonly",
        "--mount",
        "type=bind,source=<RULE_FILE>,target=/rules.yml,readonly",
        "--mount",
        "type=bind,source=<OUTPUT_STAGING>,target=/output",
        tool.image,
        "semgrep",
        "scan",
        "--config",
        "/rules.yml",
        "--json",
        "--json-output",
        "/output/semgrep.json",
        "--metrics=off",
        "--disable-version-check",
        "--strict",
        "--no-git-ignore",
        "--exclude",
        "ignored/**",
        "/src",
    ]
    if ex.argv not in (expected_argv, ["docker", "run"]):
        raise ValueError("Semgrep invocation differs from the admitted first-slice command")
    if (
        bounded_file(snapshot / "inventory.jsonl", MAX_ENTRY_BYTES) != inventory_raw
        or bounded_file(snapshot / "snapshot.json", MAX_ENTRY_BYTES)
        != bounded_file(root / "target/snapshot.json", MAX_ENTRY_BYTES)
        or target.content_sha256 != content_sha
        or target.snapshot_id != "snapshot_" + content_sha
        or target.inventory_sha256 != sha256_bytes(inventory_raw)
        or target.file_count != len(cell.input_files)
        or target.total_bytes != sum(f.bytes for f in cell.input_files)
        or target.source_label != "fixture:semgrep-basic"
        or target.revision != "fixture-v1"
        or target.source_kind != "project-fixture"
        or target.license_status != "project-authored-private"
        or existing.run.run_label != "benchmark:dev-semgrep-basic-v1"
        or existing.run.target_snapshot_id != target.snapshot_id
        or ex.target_snapshot_id != target.snapshot_id
        or existing.run.config_sha256 != config_sha
        or ex.config_sha256 != config_sha
        or ex.ruleset_sha256 != pins[RULE]
        or ex.image != tool.image
        or ex.producer.tool_id != tool.tool_id
        or ex.producer.tool_version != tool.tool_version
        or ex.producer.adapter_id != tool.adapter_id
        or ex.producer.adapter_version != tool.adapter_version
        or ex.profile_id != profile.profile_id
        or existing.run.profile_id != profile.profile_id
        or ex.limits != profile.limits
        or ex.run_id != run_id
        or ex.execution_id != record.execution_ids[0]
        or existing.run.state != RunState.FINALIZED
        or existing.run.terminal_state is None
        or existing.run.semantic_hash_version != "run-semantic-v2"
    ):
        raise ValueError("Semgrep attempt input/configuration/finalization binding differs")
    parser = existing.parser_report
    native_count = None
    native_version_matches = False
    if parser is not None:
        if not isinstance(parser, ParserReport):
            raise ValueError("Wrong Semgrep parser contract")
        raw = evidence("native-report")
        parsed = parse_semgrep_json(raw)
        native_version_matches = parsed.document.version == tool.tool_version
        normalized = normalize_semgrep(
            parsed,
            tool=tool,
            run_id=run_id,
            execution_id=ex.execution_id,
            target_snapshot_id=target.snapshot_id,
            source_blob_sha256=sha256_bytes(raw),
        )
        findings = sorted(normalized.findings, key=lambda f: f.fingerprints.record_v1)
        if _values(findings, exclude={"record_id"}) != _values(
            existing.findings, exclude={"record_id"}
        ) or _values(list(normalized.coverage), exclude={"coverage_id"}) != _values(
            existing.coverage, exclude={"coverage_id"}
        ):
            raise ValueError("Semgrep native normalization replay differs")
        expected_parser = ParserReport(
            parser_id=tool.adapter_id,
            parser_version=tool.adapter_version,
            execution_id=ex.execution_id,
            source_blob_sha256=sha256_bytes(raw),
            parsed_at=parser.parsed_at,
            native_result_count=len(parsed.document.results),
            native_error_count=len(parsed.document.errors),
            native_scanned_path_count=len(parsed.document.paths.scanned),
            native_skipped_path_count=len(parsed.document.paths.skipped),
            native_skipped_rule_count=len(parsed.document.skipped_rules),
            normalized_finding_count=len(findings),
            unknown_top_level_fields=list(parsed.unknown_top_level_fields),
            complete=len(findings) == len(parsed.document.results),
        )
        if parser != expected_parser:
            raise ValueError("Semgrep parser receipt differs from native evidence")
        native_failures = _values(list(normalized.failures), exclude={"failure_id"})
        retained_failures = _values(existing.failures, exclude={"failure_id"})
        if any(f not in retained_failures for f in native_failures):
            raise ValueError("Semgrep native diagnostics were lost")
        native_count = len(parsed.document.results)
    elif existing.findings:
        raise ValueError("Semgrep findings require parsed native evidence")
    sarif = build_sarif(list(existing.findings), execution=ex)
    if sarif != load_agent_json(
        bounded_file(root / "exports/results.sarif", MAX_ENTRY_BYTES), max_bytes=MAX_ENTRY_BYTES
    ):
        raise ValueError("Semgrep SARIF replay differs")
    retained_summary = Summary.model_validate_json(
        bounded_file(root / "exports/summary.json", MAX_ENTRY_BYTES)
    )
    if rebuild_summary(project_root=project, workspace_root=execution, run_id=run_id).model_dump(
        mode="json", exclude={"generated_at"}
    ) != retained_summary.model_dump(mode="json", exclude={"generated_at"}):
        raise ValueError("Semgrep summary replay differs")
    semantic = build_semantic_document(
        snapshot=target,
        execution=ex,
        parser_report=parser,
        findings=list(existing.findings),
        coverage=list(existing.coverage),
        failures=list(existing.failures),
        sarif=sarif,
    )
    if existing.run.semantic_sha256 != semantic_hash(semantic):
        raise ValueError("Semgrep semantic replay differs")
    launched = ex.argv != ["docker", "run"]
    state: SemgrepAttemptState = "execution-failed"
    if (
        parser is not None
        and native_version_matches
        and launched
        and ex.exit_code in tool.exit_codes.clean_or_findings
        and not ex.timed_out
        and not ex.output_limited
        and (not ex.container_cleanup_attempted or ex.container_cleanup_succeeded is True)
    ):
        if (
            existing.run.terminal_state == RunState.COMPLETE
            and ex.outcome == ExecutionOutcome.SUCCESS
            and not existing.failures
        ):
            state = "completed-with-findings" if native_count else "completed-without-findings"
        elif (
            existing.run.terminal_state == RunState.PARTIAL
            and ex.outcome == ExecutionOutcome.PARTIAL
        ):
            state = "partial-analysis"
    if before != bundle_inventory(root) or snapshot_before != bundle_inventory(snapshot):
        raise ValueError("Semgrep evidence changed during verification")
    return SemgrepAttemptEvidence(
        run_id=run_id,
        terminal_state=existing.run.terminal_state.value,
        semantic_sha256=existing.run.semantic_sha256,
        bundle_files=before,
        snapshot_files=snapshot_before,
        state=state,
        scanner_invocations=int(launched),
        finding_records=native_count,
        per_file_completion="unknown" if launched else "not-run",
    )
