from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from pydantic import JsonValue

from agentsec_evidence.adapters.semgrep import (
    SemgrepParseError,
    normalize_semgrep,
    parse_semgrep_json,
)
from agentsec_evidence.core.identity import (
    new_opaque_id,
    semantic_hash,
    sha256_bytes,
    sha256_file,
)
from agentsec_evidence.core.time import utc_now
from agentsec_evidence.execution.config import (
    ExecutionProfile,
    SemgrepToolConfig,
    load_toml_config,
)
from agentsec_evidence.execution.docker import (
    build_semgrep_argv,
    portable_docker_argv,
)
from agentsec_evidence.execution.process import ProcessCapture, run_bounded_process
from agentsec_evidence.models.contracts import (
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
from agentsec_evidence.storage.bundle import RunBundle


@dataclass(frozen=True)
class SemgrepScanRequest:
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
    rule_file: Path | None = None
    docker_executable: Path | None = None


def run_semgrep_scan(request: SemgrepScanRequest) -> PipelineResult:
    # Preserve native bytes before parsing so failures remain inspectable.
    # Normalization and validation must not turn an execution failure into a clean scan.
    project_root = request.project_root.resolve(strict=True)
    workspace_root = request.workspace_root.resolve()
    profile_loaded = load_toml_config(
        request.profile_path or project_root / "configs" / "profiles" / "development.toml",
        ExecutionProfile,
    )
    tool_loaded = load_toml_config(
        request.tool_config_path or project_root / "configs" / "tools" / "semgrep.toml",
        SemgrepToolConfig,
    )
    rule_file = (
        request.rule_file or project_root / "rules" / "project-authored" / "semgrep-first-slice.yml"
    ).resolve(strict=True)
    ruleset_sha256 = sha256_file(rule_file)
    config_sha256 = semantic_hash(
        cast(
            JsonValue,
            {
                "profile_sha256": profile_loaded.sha256,
                "tool_config_sha256": tool_loaded.sha256,
                "ruleset_sha256": ruleset_sha256,
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
                relative_path=f"{prefix}/inputs/ruleset.yml",
                data=rule_file.read_bytes(),
                media_type="application/yaml",
                sensitivity=Sensitivity.METADATA_ONLY,
                producer="orchestrator",
                logical_role="ruleset",
            ),
        ]
        bundle.transition(RunState.PLANNED, "pinned Semgrep execution planned")
        docker = resolve_docker(request.docker_executable)
        if docker is None:
            bundle.transition(RunState.RUNNING, "launch attempted")
            execution = make_execution(
                execution_id=execution_id,
                run_id=bundle.run.run_id,
                snapshot=snapshot_result.snapshot,
                tool=tool_loaded.value,
                profile=profile_loaded.value,
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
                affected_scope="semgrep execution",
                run_id=bundle.run.run_id,
                execution_id=execution_id,
                stage="launch",
                category="missing-tool",
                message="Docker executable was not available; Semgrep was not launched.",
                evidence=[],
            )
            failure_coverage = build_failed_coverage(
                property_id="code.static-analysis.semgrep",
                run_id=bundle.run.run_id,
                execution_id=execution_id,
                snapshot=snapshot_result.snapshot,
                producer=execution.producer,
                execution="failed",
            )
            bundle.transition(RunState.EXECUTION_FAILED, "required Docker executable unavailable")
            return finish_run(
                project_root=project_root,
                bundle=bundle,
                snapshot=snapshot_result.snapshot,
                execution=execution,
                parser_report=None,
                findings=[],
                coverage=[failure_coverage],
                failures=[failure],
                blob_index=blob_index,
                desired_state=RunState.EXECUTION_FAILED,
            )

        staging_root = workspace_root / "staging"
        execution_staging = staging_root / execution_id
        output_staging = execution_staging / "output"
        output_staging.mkdir(parents=True, exist_ok=False)
        container_name = f"agentsec-{bundle.run.run_id[-12:]}-{execution_id[-8:]}"
        actual_argv = build_semgrep_argv(
            docker_executable=docker,
            tool=tool_loaded.value,
            profile=profile_loaded.value,
            container_name=container_name,
            target_root=snapshot_result.content_root,
            rule_file=rule_file,
            output_root=output_staging,
        )
        persisted_argv = portable_docker_argv(
            actual_argv,
            docker_executable=docker,
            mount_replacements={
                snapshot_result.content_root: "TARGET_SNAPSHOT",
                rule_file: "RULE_FILE",
                output_staging: "OUTPUT_STAGING",
            },
        )
        bundle.transition(RunState.RUNNING, "pinned Semgrep container launched")
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
            native_path = output_staging / "semgrep.json"
            native_size = native_path.stat().st_size if native_path.is_file() else 0
            native_data: bytes | None = None
            if (
                native_size <= profile_loaded.value.limits.max_native_bytes
                and native_path.is_file()
            ):
                native_data = native_path.read_bytes()
                if len(native_data) != native_size:
                    raise RuntimeError("Semgrep native output changed while reading")
                descriptors.append(
                    store_blob(
                        bundle=bundle,
                        blob_store=blob_store,
                        relative_path=f"{prefix}/native/semgrep.json",
                        data=native_data,
                        media_type="application/json",
                        sensitivity=Sensitivity.INTERNAL,
                        producer="semgrep",
                        logical_role="native-report",
                    )
                )
            blob_index = BlobIndex(blobs=descriptors)
            source_blob_sha256 = sha256_bytes(native_data) if native_data is not None else None

            initial_outcome = ExecutionOutcome.SUCCESS
            if capture.timed_out:
                initial_outcome = ExecutionOutcome.TIMED_OUT
            elif (
                capture.output_limited
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
                    affected_scope="semgrep execution",
                    run_id=bundle.run.run_id,
                    execution_id=execution_id,
                    stage="execution",
                    category="timeout",
                    message="Semgrep exceeded the configured wall-clock limit.",
                    evidence=[item.sha256 for item in descriptors],
                    exit_code=capture.exit_code,
                )
            elif capture.output_limited:
                early_state = RunState.EXECUTION_FAILED
                early_failure = failure_record(
                    affected_scope="semgrep execution",
                    run_id=bundle.run.run_id,
                    execution_id=execution_id,
                    stage="capture",
                    category="resource-limit",
                    message="Semgrep exceeded a configured stdout or stderr byte limit.",
                    evidence=[item.sha256 for item in descriptors],
                    exit_code=capture.exit_code,
                )
            elif cleanup_attempted and not cleanup_succeeded:
                early_state = RunState.EXECUTION_FAILED
                early_failure = failure_record(
                    affected_scope="semgrep execution",
                    run_id=bundle.run.run_id,
                    execution_id=execution_id,
                    stage="release",
                    category="internal",
                    message="Container cleanup could not be verified.",
                    evidence=[item.sha256 for item in descriptors],
                    exit_code=capture.exit_code,
                )
            elif native_size > profile_loaded.value.limits.max_native_bytes:
                early_state = RunState.EXECUTION_FAILED
                early_failure = failure_record(
                    affected_scope="semgrep execution",
                    run_id=bundle.run.run_id,
                    execution_id=execution_id,
                    stage="capture",
                    category="resource-limit",
                    message="Semgrep native output exceeded the configured byte limit.",
                    evidence=[item.sha256 for item in descriptors],
                    exit_code=capture.exit_code,
                )

            if early_failure is not None and early_state is not None:
                bundle.transition(early_state, early_failure.sanitized_message)
                failure_coverage = build_failed_coverage(
                    property_id="code.static-analysis.semgrep",
                    run_id=bundle.run.run_id,
                    execution_id=execution_id,
                    snapshot=snapshot_result.snapshot,
                    producer=execution.producer,
                    execution=coverage_execution,
                )
                return finish_run(
                    project_root=project_root,
                    bundle=bundle,
                    snapshot=snapshot_result.snapshot,
                    execution=execution,
                    parser_report=None,
                    findings=[],
                    coverage=[failure_coverage],
                    failures=[early_failure],
                    blob_index=blob_index,
                    desired_state=early_state,
                )

            bundle.transition(RunState.CAPTURED, "bounded native output and byte streams captured")
            bundle.transition(RunState.PARSING, "offline Semgrep JSON parsing started")
            if native_data is None or source_blob_sha256 is None:
                failure = failure_record(
                    affected_scope="semgrep execution",
                    run_id=bundle.run.run_id,
                    execution_id=execution_id,
                    stage="parse",
                    category="malformed-output",
                    message="Semgrep did not produce the required native JSON report.",
                    evidence=[item.sha256 for item in descriptors],
                    exit_code=capture.exit_code,
                )
                execution.outcome = ExecutionOutcome.FAILED
                bundle.write_model(f"{prefix}/execution.json", execution)
                bundle.transition(RunState.PARSE_FAILED, failure.sanitized_message)
                failure_coverage = build_failed_coverage(
                    property_id="code.static-analysis.semgrep",
                    run_id=bundle.run.run_id,
                    execution_id=execution_id,
                    snapshot=snapshot_result.snapshot,
                    producer=execution.producer,
                    execution="failed",
                )
                return finish_run(
                    project_root=project_root,
                    bundle=bundle,
                    snapshot=snapshot_result.snapshot,
                    execution=execution,
                    parser_report=None,
                    findings=[],
                    coverage=[failure_coverage],
                    failures=[failure],
                    blob_index=blob_index,
                    desired_state=RunState.PARSE_FAILED,
                )
            try:
                parsed = parse_semgrep_json(native_data)
            except SemgrepParseError as exc:
                failure = failure_record(
                    affected_scope="semgrep execution",
                    run_id=bundle.run.run_id,
                    execution_id=execution_id,
                    stage="parse",
                    category="malformed-output",
                    message=f"Semgrep JSON parsing failed: {type(exc).__name__}.",
                    evidence=[source_blob_sha256],
                    exit_code=capture.exit_code,
                )
                execution.outcome = ExecutionOutcome.FAILED
                bundle.write_model(f"{prefix}/execution.json", execution)
                bundle.transition(RunState.PARSE_FAILED, failure.sanitized_message)
                failure_coverage = build_failed_coverage(
                    property_id="code.static-analysis.semgrep",
                    run_id=bundle.run.run_id,
                    execution_id=execution_id,
                    snapshot=snapshot_result.snapshot,
                    producer=execution.producer,
                    execution="failed",
                )
                return finish_run(
                    project_root=project_root,
                    bundle=bundle,
                    snapshot=snapshot_result.snapshot,
                    execution=execution,
                    parser_report=None,
                    findings=[],
                    coverage=[failure_coverage],
                    failures=[failure],
                    blob_index=blob_index,
                    desired_state=RunState.PARSE_FAILED,
                )

            bundle.transition(RunState.NORMALIZING, "native records mapped without merging")
            normalized = normalize_semgrep(
                parsed,
                tool=tool_loaded.value,
                run_id=bundle.run.run_id,
                execution_id=execution_id,
                target_snapshot_id=snapshot_result.snapshot.snapshot_id,
                source_blob_sha256=source_blob_sha256,
            )
            findings = sorted(normalized.findings, key=lambda item: item.fingerprints.record_v1)
            coverage = list(normalized.coverage)
            failures = list(normalized.failures)
            if parsed.document.version != tool_loaded.value.tool_version:
                failures.append(
                    failure_record(
                        affected_scope="semgrep execution",
                        run_id=bundle.run.run_id,
                        execution_id=execution_id,
                        stage="parse",
                        category="incompatible-version",
                        message=(
                            "Semgrep native version did not match the pinned tool configuration."
                        ),
                        evidence=[source_blob_sha256],
                        exit_code=capture.exit_code,
                        partial=bool(findings),
                    )
                )
            if capture.exit_code not in tool_loaded.value.exit_codes.clean_or_findings:
                failures.append(
                    failure_record(
                        affected_scope="semgrep execution",
                        run_id=bundle.run.run_id,
                        execution_id=execution_id,
                        stage="execution",
                        category="nonzero-exit",
                        message=(
                            f"Semgrep exited with code {capture.exit_code}; "
                            "native evidence was retained."
                        ),
                        evidence=[source_blob_sha256],
                        exit_code=capture.exit_code,
                        partial=True,
                    )
                )
            parser_report = ParserReport(
                parser_id=tool_loaded.value.adapter_id,
                parser_version=tool_loaded.value.adapter_version,
                execution_id=execution_id,
                source_blob_sha256=source_blob_sha256,
                parsed_at=utc_now(),
                native_result_count=len(parsed.document.results),
                native_error_count=len(parsed.document.errors),
                native_scanned_path_count=len(parsed.document.paths.scanned),
                native_skipped_path_count=len(parsed.document.paths.skipped),
                native_skipped_rule_count=len(parsed.document.skipped_rules),
                normalized_finding_count=len(findings),
                unknown_top_level_fields=list(parsed.unknown_top_level_fields),
                complete=len(findings) == len(parsed.document.results),
            )
            bundle.write_model(f"{prefix}/parser-report.json", parser_report)
            execution.outcome = ExecutionOutcome.PARTIAL if failures else ExecutionOutcome.SUCCESS
            bundle.write_model(f"{prefix}/execution.json", execution)
            bundle.transition(RunState.VALIDATING, "schema, provenance, and SARIF checks started")
            return finish_run(
                project_root=project_root,
                bundle=bundle,
                snapshot=snapshot_result.snapshot,
                execution=execution,
                parser_report=parser_report,
                findings=findings,
                coverage=coverage,
                failures=failures,
                blob_index=blob_index,
                desired_state=RunState.PARTIAL if failures else RunState.COMPLETE,
            )
        finally:
            if execution_staging.exists():
                remove_staging(staging_root, execution_staging)
