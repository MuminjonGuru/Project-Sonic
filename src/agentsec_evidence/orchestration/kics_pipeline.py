from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from pydantic import JsonValue

from agentsec_evidence.adapters.kics import KicsParseError, normalize_kics, parse_kics_json
from agentsec_evidence.core.identity import new_opaque_id, semantic_hash, sha256_bytes
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.core.time import utc_now
from agentsec_evidence.execution.config import ExecutionProfile, KicsToolConfig, load_toml_config
from agentsec_evidence.execution.docker import build_kics_argv, portable_docker_argv
from agentsec_evidence.execution.process import ProcessCapture, run_bounded_process
from agentsec_evidence.intake.snapshot import SnapshotResult
from agentsec_evidence.models.contracts import (
    BlobDescriptor,
    BlobIndex,
    CoverageExecution,
    ExecutionOutcome,
    FailureRecord,
    ParserReport,
    RunState,
    Sensitivity,
)
from agentsec_evidence.orchestration.shared import (
    PipelineResult as PipelineResult,
)
from agentsec_evidence.orchestration.shared import (
    build_failed_coverage,
    cleanup_container,
    failure_record,
    finish_run,
    make_execution,
    prepare_workspace,
    remove_staging,
    resolve_docker,
    store_blob,
)
from agentsec_evidence.storage.blobs import BlobStore
from agentsec_evidence.storage.bundle import RunBundle


@dataclass(frozen=True)
class KicsScanRequest:
    project_root: Path
    workspace_root: Path
    target_source: Path
    source_label: str
    revision: str
    run_label: str
    source_kind: Literal["project-fixture", "local", "git"] = "local"
    license_status: Literal["project-authored-private", "identified", "unknown"] = "unknown"
    profile_path: Path | None = None
    tool_config_path: Path | None = None
    docker_executable: Path | None = None


def _query_manifest(tool: KicsToolConfig) -> bytes:
    value: JsonValue = {
        "image": tool.image,
        "image_source_revision": tool.image_source_revision,
        "include_queries": list(tool.include_queries),
        "platforms": list(tool.platforms),
        "query_pack_file_count": tool.query_pack_file_count,
        "query_pack_sha256": tool.query_pack_sha256,
        "query_pack_total_bytes": tool.query_pack_total_bytes,
        "query_selection_id": tool.query_selection_id,
    }
    return json_bytes(value)


def _native_sarif_problem(data: bytes, *, expected_results: int) -> str | None:
    try:
        document = json.loads(data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return f"KICS native SARIF was not valid UTF-8 JSON: {type(exc).__name__}."
    if not isinstance(document, dict) or document.get("version") != "2.1.0":
        return "KICS native SARIF did not declare SARIF 2.1.0."
    runs = document.get("runs")
    if not isinstance(runs, list) or len(runs) != 1 or not isinstance(runs[0], dict):
        return "KICS native SARIF did not contain exactly one run."
    results = runs[0].get("results")
    count = len(results) if isinstance(results, list) else 0
    if count != expected_results:
        return (
            f"KICS native SARIF represented {count} results; native JSON represented "
            f"{expected_results}."
        )
    return None


def _missing_docker_result(
    *,
    project_root: Path,
    profile: ExecutionProfile,
    tool: KicsToolConfig,
    config_sha256: str,
    ruleset_sha256: str,
    snapshot_result: SnapshotResult,
    bundle: RunBundle,
    execution_id: str,
    blob_store: BlobStore,
    environment: dict[str, str],
    input_descriptors: list[BlobDescriptor],
) -> PipelineResult:
    bundle.transition(RunState.RUNNING, "launch attempted")
    execution = make_execution(
        execution_id=execution_id,
        run_id=bundle.run.run_id,
        snapshot=snapshot_result.snapshot,
        tool=tool,
        profile=profile,
        config_sha256=config_sha256,
        ruleset_sha256=ruleset_sha256,
        portable_argv=["docker", "run"],
        environment=environment,
        capture=None,
        outcome=ExecutionOutcome.FAILED,
        native_byte_length=0,
        cleanup_attempted=False,
        cleanup_succeeded=None,
    )
    prefix = f"executions/{execution_id}"
    stdout_descriptor = store_blob(
        bundle=bundle,
        blob_store=blob_store,
        relative_path=f"{prefix}/stdout.bin",
        data=b"",
        media_type="application/octet-stream",
        sensitivity=Sensitivity.INTERNAL,
        producer="orchestrator",
        logical_role="stdout",
    )
    stderr_descriptor = store_blob(
        bundle=bundle,
        blob_store=blob_store,
        relative_path=f"{prefix}/stderr.bin",
        data=b"",
        media_type="application/octet-stream",
        sensitivity=Sensitivity.INTERNAL,
        producer="orchestrator",
        logical_role="stderr",
    )
    blob_index = BlobIndex(blobs=[*input_descriptors, stdout_descriptor, stderr_descriptor])
    bundle.write_model(f"{prefix}/execution.json", execution)
    bundle.write_model(f"{prefix}/blobs.json", blob_index)
    failure = failure_record(
        run_id=bundle.run.run_id,
        execution_id=execution_id,
        stage="launch",
        category="missing-tool",
        message="Docker executable was not available; KICS was not launched.",
        evidence=[],
        affected_scope="kics execution",
    )
    coverage = build_failed_coverage(
        run_id=bundle.run.run_id,
        execution_id=execution_id,
        snapshot=snapshot_result.snapshot,
        producer=execution.producer,
        execution="failed",
        property_id="infrastructure-as-code.static-analysis.kics",
    )
    bundle.transition(RunState.EXECUTION_FAILED, "required Docker executable unavailable")
    return finish_run(
        project_root=project_root,
        bundle=bundle,
        snapshot=snapshot_result.snapshot,
        execution=execution,
        parser_report=None,
        findings=[],
        coverage=[coverage],
        failures=[failure],
        blob_index=blob_index,
        desired_state=RunState.EXECUTION_FAILED,
    )


def run_kics_scan(request: KicsScanRequest) -> PipelineResult:
    project_root = request.project_root.resolve(strict=True)
    workspace_root = request.workspace_root.resolve()
    profile_loaded = load_toml_config(
        request.profile_path or project_root / "configs" / "profiles" / "development.toml",
        ExecutionProfile,
    )
    tool_loaded = load_toml_config(
        request.tool_config_path or project_root / "configs" / "tools" / "kics.toml",
        KicsToolConfig,
    )
    query_manifest = _query_manifest(tool_loaded.value)
    ruleset_sha256 = sha256_bytes(query_manifest)
    config_sha256 = semantic_hash(
        cast(
            JsonValue,
            {
                "profile_sha256": profile_loaded.sha256,
                "ruleset_sha256": ruleset_sha256,
                "tool_config_sha256": tool_loaded.sha256,
            },
        )
    )
    prepared = prepare_workspace(
        workspace_root=workspace_root,
        target_source=request.target_source,
        source_label=request.source_label,
        revision=request.revision,
        source_kind=request.source_kind,
        license_status=request.license_status,
    )
    snapshot_result = prepared.snapshot_result
    blob_store = prepared.blob_store
    environment = prepared.environment

    with RunBundle.create(
        workspace_root,
        run_label=request.run_label,
        profile_id=profile_loaded.value.profile_id,
        config_sha256=config_sha256,
        snapshot_result=snapshot_result,
    ) as bundle:
        execution_id = new_opaque_id("execution")
        bundle.add_execution_id(execution_id)
        prefix = f"executions/{execution_id}"
        input_descriptors = [
            store_blob(
                bundle=bundle,
                blob_store=blob_store,
                relative_path=f"{prefix}/inputs/profile.toml",
                data=profile_loaded.raw,
                media_type="application/toml",
                sensitivity=Sensitivity.METADATA_ONLY,
                producer="orchestrator",
                logical_role="execution-profile",
            ),
            store_blob(
                bundle=bundle,
                blob_store=blob_store,
                relative_path=f"{prefix}/inputs/tool-config.toml",
                data=tool_loaded.raw,
                media_type="application/toml",
                sensitivity=Sensitivity.METADATA_ONLY,
                producer="orchestrator",
                logical_role="tool-config",
            ),
            store_blob(
                bundle=bundle,
                blob_store=blob_store,
                relative_path=f"{prefix}/inputs/query-selection.json",
                data=query_manifest,
                media_type="application/json",
                sensitivity=Sensitivity.METADATA_ONLY,
                producer="orchestrator",
                logical_role="ruleset-manifest",
            ),
        ]
        bundle.transition(RunState.PLANNED, "pinned KICS execution planned")
        docker = resolve_docker(request.docker_executable)
        if docker is None:
            return _missing_docker_result(
                project_root=project_root,
                profile=profile_loaded.value,
                tool=tool_loaded.value,
                config_sha256=config_sha256,
                ruleset_sha256=ruleset_sha256,
                snapshot_result=snapshot_result,
                bundle=bundle,
                execution_id=execution_id,
                blob_store=blob_store,
                environment=environment,
                input_descriptors=input_descriptors,
            )

        staging_root = workspace_root / "staging"
        execution_staging = staging_root / execution_id
        output_staging = execution_staging / "output"
        output_staging.mkdir(parents=True, exist_ok=False)
        container_name = f"agentsec-{bundle.run.run_id[-12:]}-{execution_id[-8:]}"
        actual_argv = build_kics_argv(
            docker_executable=docker,
            tool=tool_loaded.value,
            profile=profile_loaded.value,
            container_name=container_name,
            target_root=snapshot_result.content_root,
            output_root=output_staging,
        )
        persisted_argv = portable_docker_argv(
            actual_argv,
            docker_executable=docker,
            mount_replacements={
                snapshot_result.content_root: "TARGET_SNAPSHOT",
                output_staging: "OUTPUT_STAGING",
            },
        )
        bundle.transition(RunState.RUNNING, "pinned KICS container launched")
        capture: ProcessCapture | None = None
        cleanup_attempted = False
        cleanup_succeeded: bool | None = None
        try:
            capture = run_bounded_process(
                actual_argv,
                cwd=project_root,
                environment=environment,
                timeout_seconds=profile_loaded.value.limits.timeout_seconds,
                max_stdout_bytes=profile_loaded.value.limits.max_stdout_bytes,
                max_stderr_bytes=profile_loaded.value.limits.max_stderr_bytes,
            )
            if capture.timed_out or capture.output_limited:
                cleanup_attempted = True
                cleanup_succeeded = cleanup_container(
                    docker=docker,
                    container_name=container_name,
                    cwd=project_root,
                    environment=environment,
                )

            descriptors = [
                *input_descriptors,
                store_blob(
                    bundle=bundle,
                    blob_store=blob_store,
                    relative_path=f"{prefix}/stdout.bin",
                    data=capture.stdout,
                    media_type="application/octet-stream",
                    sensitivity=Sensitivity.INTERNAL,
                    producer="docker-cli",
                    logical_role="stdout",
                ),
                store_blob(
                    bundle=bundle,
                    blob_store=blob_store,
                    relative_path=f"{prefix}/stderr.bin",
                    data=capture.stderr,
                    media_type="application/octet-stream",
                    sensitivity=Sensitivity.INTERNAL,
                    producer="docker-cli",
                    logical_role="stderr",
                ),
            ]
            allowed = {"results.json", "results.sarif"}
            output_files = [
                path
                for path in output_staging.rglob("*")
                if path.is_file() and not path.is_symlink()
            ]
            unsafe_outputs = [
                path
                for path in output_staging.rglob("*")
                if path.is_symlink()
                or (path.is_file() and path.relative_to(output_staging).as_posix() not in allowed)
            ]
            native_size = sum(path.stat().st_size for path in output_files)
            native_json: bytes | None = None
            native_sarif: bytes | None = None
            if not unsafe_outputs and native_size <= profile_loaded.value.limits.max_native_bytes:
                for name, role, media_type in (
                    ("results.json", "native-report", "application/json"),
                    ("results.sarif", "native-sarif", "application/sarif+json"),
                ):
                    path = output_staging / name
                    if not path.is_file():
                        continue
                    data = path.read_bytes()
                    if len(data) != path.stat().st_size:
                        raise RuntimeError(f"KICS {name} changed while reading")
                    if name == "results.json":
                        native_json = data
                    else:
                        native_sarif = data
                    descriptors.append(
                        store_blob(
                            bundle=bundle,
                            blob_store=blob_store,
                            relative_path=f"{prefix}/native/{name}",
                            data=data,
                            media_type=media_type,
                            sensitivity=Sensitivity.INTERNAL,
                            producer="kics",
                            logical_role=role,
                        )
                    )
            blob_index = BlobIndex(blobs=descriptors)
            source_blob_sha256 = sha256_bytes(native_json) if native_json is not None else None

            initial_outcome = ExecutionOutcome.SUCCESS
            if capture.timed_out:
                initial_outcome = ExecutionOutcome.TIMED_OUT
            elif (
                capture.output_limited
                or unsafe_outputs
                or capture.exit_code not in tool_loaded.value.exit_codes.clean_or_findings
            ):
                initial_outcome = ExecutionOutcome.FAILED
            execution = make_execution(
                execution_id=execution_id,
                run_id=bundle.run.run_id,
                snapshot=snapshot_result.snapshot,
                tool=tool_loaded.value,
                profile=profile_loaded.value,
                config_sha256=config_sha256,
                ruleset_sha256=ruleset_sha256,
                portable_argv=persisted_argv,
                environment=environment,
                capture=capture,
                outcome=initial_outcome,
                native_byte_length=native_size,
                cleanup_attempted=cleanup_attempted,
                cleanup_succeeded=cleanup_succeeded,
            )
            bundle.write_model(f"{prefix}/execution.json", execution)
            bundle.write_model(f"{prefix}/blobs.json", blob_index)

            early_failure: FailureRecord | None = None
            early_state: RunState | None = None
            coverage_execution: CoverageExecution = "failed"
            if capture.timed_out:
                early_state = RunState.TIMED_OUT
                coverage_execution = "timed-out"
                early_failure = failure_record(
                    run_id=bundle.run.run_id,
                    execution_id=execution_id,
                    stage="execution",
                    category="timeout",
                    message="KICS exceeded the configured wall-clock limit.",
                    evidence=[item.sha256 for item in descriptors],
                    exit_code=capture.exit_code,
                    affected_scope="kics execution",
                )
            elif capture.output_limited:
                early_state = RunState.EXECUTION_FAILED
                early_failure = failure_record(
                    run_id=bundle.run.run_id,
                    execution_id=execution_id,
                    stage="capture",
                    category="resource-limit",
                    message="KICS exceeded a configured stdout or stderr byte limit.",
                    evidence=[item.sha256 for item in descriptors],
                    exit_code=capture.exit_code,
                    affected_scope="kics execution",
                )
            elif cleanup_attempted and not cleanup_succeeded:
                early_state = RunState.EXECUTION_FAILED
                early_failure = failure_record(
                    run_id=bundle.run.run_id,
                    execution_id=execution_id,
                    stage="release",
                    category="internal",
                    message="KICS container cleanup could not be verified.",
                    evidence=[item.sha256 for item in descriptors],
                    exit_code=capture.exit_code,
                    affected_scope="kics execution",
                )
            elif unsafe_outputs:
                early_state = RunState.EXECUTION_FAILED
                early_failure = failure_record(
                    run_id=bundle.run.run_id,
                    execution_id=execution_id,
                    stage="capture",
                    category="unsafe-target",
                    message="KICS created an unexpected or unsafe output path.",
                    evidence=[item.sha256 for item in descriptors],
                    exit_code=capture.exit_code,
                    affected_scope="kics output directory",
                )
            elif native_size > profile_loaded.value.limits.max_native_bytes:
                early_state = RunState.EXECUTION_FAILED
                early_failure = failure_record(
                    run_id=bundle.run.run_id,
                    execution_id=execution_id,
                    stage="capture",
                    category="resource-limit",
                    message="KICS native outputs exceeded the configured aggregate byte limit.",
                    evidence=[item.sha256 for item in descriptors],
                    exit_code=capture.exit_code,
                    affected_scope="kics native output",
                )
            elif (
                capture.exit_code not in tool_loaded.value.exit_codes.clean_or_findings
                and native_json is None
            ):
                early_state = RunState.EXECUTION_FAILED
                early_failure = failure_record(
                    run_id=bundle.run.run_id,
                    execution_id=execution_id,
                    stage="execution",
                    category="nonzero-exit",
                    message=f"KICS exited with code {capture.exit_code} without native JSON.",
                    evidence=[item.sha256 for item in descriptors],
                    exit_code=capture.exit_code,
                    affected_scope="kics execution",
                )

            if early_failure is not None and early_state is not None:
                bundle.transition(early_state, early_failure.sanitized_message)
                failed_coverage = build_failed_coverage(
                    run_id=bundle.run.run_id,
                    execution_id=execution_id,
                    snapshot=snapshot_result.snapshot,
                    producer=execution.producer,
                    execution=coverage_execution,
                    property_id="infrastructure-as-code.static-analysis.kics",
                )
                return finish_run(
                    project_root=project_root,
                    bundle=bundle,
                    snapshot=snapshot_result.snapshot,
                    execution=execution,
                    parser_report=None,
                    findings=[],
                    coverage=[failed_coverage],
                    failures=[early_failure],
                    blob_index=blob_index,
                    desired_state=early_state,
                )

            bundle.transition(RunState.CAPTURED, "bounded KICS outputs and byte streams captured")
            bundle.transition(RunState.PARSING, "offline KICS JSON parsing started")
            if native_json is None or source_blob_sha256 is None:
                failure = failure_record(
                    run_id=bundle.run.run_id,
                    execution_id=execution_id,
                    stage="parse",
                    category="malformed-output",
                    message="KICS did not produce the required native JSON report.",
                    evidence=[item.sha256 for item in descriptors],
                    exit_code=capture.exit_code,
                    affected_scope="kics native output",
                )
                execution.outcome = ExecutionOutcome.FAILED
                bundle.write_model(f"{prefix}/execution.json", execution)
                bundle.transition(RunState.PARSE_FAILED, failure.sanitized_message)
                failed_coverage = build_failed_coverage(
                    run_id=bundle.run.run_id,
                    execution_id=execution_id,
                    snapshot=snapshot_result.snapshot,
                    producer=execution.producer,
                    execution="failed",
                    property_id="infrastructure-as-code.static-analysis.kics",
                )
                return finish_run(
                    project_root=project_root,
                    bundle=bundle,
                    snapshot=snapshot_result.snapshot,
                    execution=execution,
                    parser_report=None,
                    findings=[],
                    coverage=[failed_coverage],
                    failures=[failure],
                    blob_index=blob_index,
                    desired_state=RunState.PARSE_FAILED,
                )
            try:
                parsed = parse_kics_json(native_json)
            except KicsParseError as exc:
                failure = failure_record(
                    run_id=bundle.run.run_id,
                    execution_id=execution_id,
                    stage="parse",
                    category="malformed-output",
                    message=f"KICS JSON parsing failed: {type(exc).__name__}.",
                    evidence=[source_blob_sha256],
                    exit_code=capture.exit_code,
                    affected_scope="kics native output",
                )
                execution.outcome = ExecutionOutcome.FAILED
                bundle.write_model(f"{prefix}/execution.json", execution)
                bundle.transition(RunState.PARSE_FAILED, failure.sanitized_message)
                failed_coverage = build_failed_coverage(
                    run_id=bundle.run.run_id,
                    execution_id=execution_id,
                    snapshot=snapshot_result.snapshot,
                    producer=execution.producer,
                    execution="failed",
                    property_id="infrastructure-as-code.static-analysis.kics",
                )
                return finish_run(
                    project_root=project_root,
                    bundle=bundle,
                    snapshot=snapshot_result.snapshot,
                    execution=execution,
                    parser_report=None,
                    findings=[],
                    coverage=[failed_coverage],
                    failures=[failure],
                    blob_index=blob_index,
                    desired_state=RunState.PARSE_FAILED,
                )

            bundle.transition(RunState.NORMALIZING, "KICS records mapped without merging")
            normalized = normalize_kics(
                parsed,
                tool=tool_loaded.value,
                run_id=bundle.run.run_id,
                execution_id=execution_id,
                target_snapshot_id=snapshot_result.snapshot.snapshot_id,
                source_blob_sha256=source_blob_sha256,
            )
            findings = sorted(normalized.findings, key=lambda item: item.fingerprints.record_v1)
            normalized_coverage = list(normalized.coverage)
            failures = list(normalized.failures)
            if parsed.document.kics_version != tool_loaded.value.tool_version:
                failures.append(
                    failure_record(
                        run_id=bundle.run.run_id,
                        execution_id=execution_id,
                        stage="parse",
                        category="incompatible-version",
                        message="KICS native version did not match the pinned tool configuration.",
                        evidence=[source_blob_sha256],
                        exit_code=capture.exit_code,
                        partial=bool(findings),
                        affected_scope="kics native output",
                    )
                )
            if capture.exit_code not in tool_loaded.value.exit_codes.clean_or_findings:
                failures.append(
                    failure_record(
                        run_id=bundle.run.run_id,
                        execution_id=execution_id,
                        stage="execution",
                        category="nonzero-exit",
                        message=(
                            f"KICS exited with code {capture.exit_code}; evidence was retained."
                        ),
                        evidence=[source_blob_sha256],
                        exit_code=capture.exit_code,
                        partial=True,
                        affected_scope="kics execution",
                    )
                )
            if native_sarif is None:
                failures.append(
                    failure_record(
                        run_id=bundle.run.run_id,
                        execution_id=execution_id,
                        stage="capture",
                        category="malformed-output",
                        message=(
                            "KICS did not produce the configured native SARIF comparison report."
                        ),
                        evidence=[source_blob_sha256],
                        exit_code=capture.exit_code,
                        partial=True,
                        affected_scope="kics native SARIF",
                    )
                )
            else:
                sarif_problem = _native_sarif_problem(
                    native_sarif, expected_results=parsed.native_result_count
                )
                if sarif_problem is not None:
                    failures.append(
                        failure_record(
                            run_id=bundle.run.run_id,
                            execution_id=execution_id,
                            stage="validate",
                            category="malformed-output",
                            message=sarif_problem,
                            evidence=[sha256_bytes(native_sarif)],
                            exit_code=capture.exit_code,
                            partial=True,
                            affected_scope="kics native SARIF",
                        )
                    )
            parser_report = ParserReport(
                parser_id=tool_loaded.value.adapter_id,
                parser_version=tool_loaded.value.adapter_version,
                execution_id=execution_id,
                source_blob_sha256=source_blob_sha256,
                parsed_at=utc_now(),
                native_result_count=parsed.native_result_count,
                native_error_count=len(failures),
                native_scanned_path_count=parsed.document.files_scanned,
                native_skipped_path_count=max(
                    snapshot_result.snapshot.file_count - parsed.document.files_scanned, 0
                ),
                native_skipped_rule_count=max(
                    len(tool_loaded.value.include_queries) - parsed.document.queries_total, 0
                ),
                normalized_finding_count=len(findings),
                unknown_top_level_fields=list(parsed.unknown_fields),
                complete=not failures and len(findings) == parsed.document.total_counter,
            )
            bundle.write_model(f"{prefix}/parser-report.json", parser_report)
            unsupported = normalized_coverage[0].adapter_support == "unsupported" and not failures
            if unsupported:
                execution.outcome = ExecutionOutcome.UNSUPPORTED
            else:
                execution.outcome = (
                    ExecutionOutcome.PARTIAL if failures else ExecutionOutcome.SUCCESS
                )
            bundle.write_model(f"{prefix}/execution.json", execution)
            bundle.transition(RunState.VALIDATING, "schema, provenance, and SARIF checks started")
            return finish_run(
                project_root=project_root,
                bundle=bundle,
                snapshot=snapshot_result.snapshot,
                execution=execution,
                parser_report=parser_report,
                findings=findings,
                coverage=normalized_coverage,
                failures=failures,
                blob_index=blob_index,
                desired_state=RunState.PARTIAL if failures else RunState.COMPLETE,
            )
        finally:
            if execution_staging.exists():
                remove_staging(staging_root, execution_staging)
