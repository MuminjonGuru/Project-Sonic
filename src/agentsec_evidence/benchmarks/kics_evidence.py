"""Replay KICS JSON as evidence; native SARIF remains a comparison artifact only."""

import re
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel

from agentsec_evidence.adapters.kics import normalize_kics, parse_kics_json
from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.benchmarks.attempt_models import KicsAttemptEvidence, KicsAttemptState
from agentsec_evidence.benchmarks.evidence import bundle_inventory
from agentsec_evidence.benchmarks.kics_plan import CASE_ROOTS, PROFILE, TOOL, kics_inputs
from agentsec_evidence.benchmarks.models import KicsBenchmarkPlan, KicsCell
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.execution.config import ExecutionProfile, KicsToolConfig, load_toml_bytes
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


def _comparison_matches(raw: bytes | None, count: int) -> bool:
    if raw is None:
        return False
    try:
        document = load_agent_json(raw, max_bytes=MAX_ENTRY_BYTES)
        runs = document.get("runs")
        if document.get("version") != "2.1.0" or not isinstance(runs, list) or len(runs) != 1:
            return False
        if not isinstance(runs[0], dict):
            return False
        results = runs[0].get("results")
        if "results" in runs[0] and not isinstance(results, list):
            return False
        return (len(results) if isinstance(results, list) else 0) == count
    except ValueError:
        return False


def _expected_argv(
    tool: KicsToolConfig, profile: ExecutionProfile, run_id: str, execution_id: str
) -> list[str]:
    limits = profile.limits
    return [
        "docker",
        "run",
        "--rm",
        "--pull",
        "never",
        "--name",
        f"agentsec-{run_id[-12:]}-{execution_id[-8:]}",
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
        "--mount",
        "type=bind,source=<TARGET_SNAPSHOT>,target=/src,readonly",
        "--mount",
        "type=bind,source=<OUTPUT_STAGING>,target=/output",
        tool.image,
        "scan",
        "--path",
        "/src",
        "--output-path",
        "/output",
        "--output-name",
        "results",
        "--report-formats",
        ",".join(tool.report_formats),
        "--type",
        ",".join(tool.platforms),
        "--include-queries",
        ",".join(tool.include_queries),
        "--disable-secrets",
        "--disable-full-descriptions",
        "--exclude-gitignore",
        "--no-progress",
        "--parallel",
        str(tool.parallel),
        "--timeout",
        str(tool.query_timeout_seconds),
        "--max-file-size",
        str(tool.max_file_size_mb),
        "--max-resolver-depth",
        str(tool.max_resolver_depth),
        "--ignore-on-exit",
        tool.ignore_on_exit,
        "--fail-on",
        "critical,high,medium,low,info",
        "--silent",
        "--no-color",
    ]


def verify_kics_attempt(
    project: Path, execution: Path, run_id: str, plan: KicsBenchmarkPlan, cell: KicsCell
) -> KicsAttemptEvidence:
    if not re.fullmatch(r"run_[0-9a-f]{32}", run_id):
        raise ValueError("Invalid KICS run identity")
    root = execution / "runs" / run_id
    plain_path(root.parent, directory=True)
    if {p.name for p in root.parent.iterdir()} != {run_id}:
        raise ValueError("KICS attempt requires exactly one run")
    before = bundle_inventory(root)
    record = RunRecord.model_validate_json(bounded_file(root / "run.json", MAX_ENTRY_BYTES))
    if len(record.execution_ids) != 1 or not re.fullmatch(
        r"execution_[0-9a-f]{32}", record.execution_ids[0]
    ):
        raise ValueError("Unsafe KICS execution identity")
    existing = load_existing_run(execution, run_id)
    if not validate_existing_run(
        project_root=project, workspace_root=execution, run_id=run_id
    ).passed:
        raise ValueError("KICS bundle validation failed")

    def optional_evidence(role: str) -> bytes | None:
        matches = [b for b in existing.blobs.blobs if b.logical_role == role]
        if not matches:
            return None
        if len(matches) != 1:
            raise ValueError("Duplicate KICS evidence role: " + role)
        raw = bounded_file(root / matches[0].relative_path, MAX_ENTRY_BYTES)
        if sha256_bytes(raw) != matches[0].sha256 or len(raw) != matches[0].byte_length:
            raise ValueError("KICS evidence blob differs")
        return raw

    def evidence(role: str) -> bytes:
        raw = optional_evidence(role)
        if raw is None:
            raise ValueError("Missing KICS evidence role: " + role)
        return raw

    pins = {p.path: p.sha256 for p in plan.pins}
    for path, role in ((PROFILE, "execution-profile"), (TOOL, "tool-config")):
        if sha256_bytes(evidence(role)) != pins[path]:
            raise ValueError("KICS configuration differs from frozen plan")
    profile = load_toml_bytes(
        evidence("execution-profile"), ExecutionProfile, source=Path(PROFILE)
    ).value
    tool = load_toml_bytes(evidence("tool-config"), KicsToolConfig, source=Path(TOOL)).value
    query_manifest = json_bytes(
        {
            "image": tool.image,
            "image_source_revision": tool.image_source_revision,
            "include_queries": list(tool.include_queries),
            "platforms": list(tool.platforms),
            "query_pack_file_count": tool.query_pack_file_count,
            "query_pack_sha256": tool.query_pack_sha256,
            "query_pack_total_bytes": tool.query_pack_total_bytes,
            "query_selection_id": tool.query_selection_id,
        }
    )
    if evidence("ruleset-manifest") != query_manifest:
        raise ValueError("KICS query selection differs from frozen treatment")
    ruleset_sha = sha256_bytes(query_manifest)
    config_sha = semantic_hash(
        {
            "profile_sha256": pins[PROFILE],
            "tool_config_sha256": pins[TOOL],
            "ruleset_sha256": ruleset_sha,
        }
    )
    target = existing.target
    if not re.fullmatch(r"snapshot_[0-9a-f]{64}", target.snapshot_id):
        raise ValueError("Unsafe KICS snapshot identity")
    snapshot = execution / "targets" / target.snapshot_id
    plain_path(snapshot.parent, directory=True)
    if {p.name for p in snapshot.parent.iterdir()} != {target.snapshot_id}:
        raise ValueError("Ambiguous KICS target snapshot")
    snapshot_before = bundle_inventory(snapshot)
    if kics_inputs(snapshot / "content", cell.case_id) != cell.input_files:
        raise ValueError("Retained KICS input differs from frozen case")
    inventory_raw = bounded_file(root / "target/inventory.jsonl", MAX_ENTRY_BYTES)
    inventory = tuple(
        InventoryEntry.model_validate_json(line)
        for line in inventory_raw.splitlines()
        if line.strip()
    )
    if sorted((i.path, i.byte_length, i.sha256) for i in inventory) != [
        (f.path, f.bytes, f.sha256) for f in cell.input_files
    ]:
        raise ValueError("KICS inventory differs from frozen fixture")
    # Preserve legacy traversal order for snapshot identity; compare file sets independently.
    content_sha = semantic_hash(
        [{"byte_length": i.byte_length, "path": i.path, "sha256": i.sha256} for i in inventory]
    )
    ex = existing.execution
    if ex.argv not in (_expected_argv(tool, profile, run_id, ex.execution_id), ["docker", "run"]):
        raise ValueError("KICS invocation differs from admitted command")
    if (
        bounded_file(snapshot / "inventory.jsonl", MAX_ENTRY_BYTES) != inventory_raw
        or bounded_file(snapshot / "snapshot.json", MAX_ENTRY_BYTES)
        != bounded_file(root / "target/snapshot.json", MAX_ENTRY_BYTES)
        or target.content_sha256 != content_sha
        or target.snapshot_id != "snapshot_" + content_sha
        or target.inventory_sha256 != sha256_bytes(inventory_raw)
        or target.file_count != len(cell.input_files)
        or target.total_bytes != sum(f.bytes for f in cell.input_files)
        or target.source_label != "fixture:" + CASE_ROOTS[cell.case_id].rsplit("/", 1)[-1]
        or target.revision != "fixture-v1"
        or target.source_kind != "project-fixture"
        or target.license_status != "project-authored-private"
        or existing.run.run_label != "benchmark:" + cell.case_id
        or existing.run.target_snapshot_id != target.snapshot_id
        or ex.target_snapshot_id != target.snapshot_id
        or existing.run.config_sha256 != config_sha
        or ex.config_sha256 != config_sha
        or ex.ruleset_sha256 != ruleset_sha
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
        raise ValueError("KICS input/configuration/finalization binding differs")
    parser = existing.parser_report
    native_count = scanned = parsed_files = queries = None
    native_eligible = False
    normalized_failures: list[dict[str, object]] = []
    if parser is not None:
        if not isinstance(parser, ParserReport):
            raise ValueError("Wrong KICS parser contract")
        raw = evidence("native-report")
        parsed = parse_kics_json(raw)
        document = parsed.document
        normalized = normalize_kics(
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
        ) or _values(normalized.coverage, exclude={"coverage_id"}) != _values(
            existing.coverage, exclude={"coverage_id"}
        ):
            raise ValueError("KICS native normalization replay differs")
        if any(
            f.rule.native_id not in tool.include_queries
            or any(loc.artifact_path not in cell.selected_paths for loc in f.locations)
            for f in findings
        ):
            raise ValueError("KICS finding outside admitted rule/input selection")
        if document.files_parsed > document.files_scanned or document.files_scanned > len(
            cell.selected_paths
        ):
            raise ValueError("KICS aggregate counters exceed admitted input")
        expected_parser = ParserReport(
            parser_id=tool.adapter_id,
            parser_version=tool.adapter_version,
            execution_id=ex.execution_id,
            source_blob_sha256=sha256_bytes(raw),
            parsed_at=parser.parsed_at,
            native_result_count=parsed.native_result_count,
            native_error_count=len(existing.failures),
            native_scanned_path_count=document.files_scanned,
            native_skipped_path_count=max(target.file_count - document.files_scanned, 0),
            native_skipped_rule_count=max(len(tool.include_queries) - document.queries_total, 0),
            normalized_finding_count=len(findings),
            unknown_top_level_fields=list(parsed.unknown_fields),
            complete=not existing.failures and len(findings) == document.total_counter,
        )
        if parser != expected_parser:
            raise ValueError("KICS parser receipt differs from native evidence")
        normalized_failures = _values(normalized.failures, exclude={"failure_id"})
        if any(
            f not in _values(existing.failures, exclude={"failure_id"}) for f in normalized_failures
        ):
            raise ValueError("KICS native diagnostics were lost")
        native_count, scanned, parsed_files, queries = (
            parsed.native_result_count,
            document.files_scanned,
            document.files_parsed,
            document.queries_total,
        )
        native_eligible = document.kics_version == tool.tool_version and _comparison_matches(
            optional_evidence("native-sarif"), native_count
        )
    elif existing.findings:
        raise ValueError("KICS findings require parsed native evidence")
    sarif = build_sarif(list(existing.findings), execution=ex)
    if sarif != load_agent_json(
        bounded_file(root / "exports/results.sarif", MAX_ENTRY_BYTES), max_bytes=MAX_ENTRY_BYTES
    ):
        raise ValueError("KICS project SARIF replay differs")
    retained_summary = Summary.model_validate_json(
        bounded_file(root / "exports/summary.json", MAX_ENTRY_BYTES)
    )
    if rebuild_summary(project_root=project, workspace_root=execution, run_id=run_id).model_dump(
        mode="json", exclude={"generated_at"}
    ) != retained_summary.model_dump(mode="json", exclude={"generated_at"}):
        raise ValueError("KICS summary replay differs")
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
        raise ValueError("KICS semantic replay differs")
    launched = ex.argv != ["docker", "run"]
    state: KicsAttemptState = "execution-failed"
    # Zero counts and a legacy COMPLETE bundle do not establish supported, clean analysis.
    if (
        parser is not None
        and native_eligible
        and launched
        and ex.exit_code in tool.exit_codes.clean_or_findings
        and not ex.timed_out
        and not ex.output_limited
        and (not ex.container_cleanup_attempted or ex.container_cleanup_succeeded is True)
    ):
        if existing.run.terminal_state == RunState.COMPLETE and not existing.failures:
            if (
                ex.outcome == ExecutionOutcome.UNSUPPORTED
                and scanned == parsed_files == native_count == 0
            ):
                state = "unsupported"
            elif ex.outcome == ExecutionOutcome.SUCCESS and scanned is not None and scanned > 0:
                state = "completed-with-findings" if native_count else "completed-without-findings"
        elif (
            existing.run.terminal_state == RunState.PARTIAL
            and ex.outcome == ExecutionOutcome.PARTIAL
            and normalized_failures
            and normalized_failures == _values(existing.failures, exclude={"failure_id"})
        ):
            state = "partial-analysis"
    if before != bundle_inventory(root) or snapshot_before != bundle_inventory(snapshot):
        raise ValueError("KICS evidence changed during verification")
    return KicsAttemptEvidence(
        run_id=run_id,
        terminal_state=existing.run.terminal_state.value,
        semantic_sha256=existing.run.semantic_sha256,
        bundle_files=before,
        snapshot_files=snapshot_before,
        state=state,
        scanner_invocations=int(launched),
        finding_records=native_count,
        native_files_scanned=scanned,
        native_files_parsed=parsed_files,
        native_queries_total=queries,
        per_file_completion="unknown" if launched else "not-run",
    )
