from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from pydantic import JsonValue

from agentsec_evidence.adapters.semgrep import (
    SemgrepParseError,
    normalize_semgrep,
    parse_semgrep_json,
)
from agentsec_evidence.analysis.summary import build_summary
from agentsec_evidence.core.identity import (
    new_opaque_id,
    semantic_hash,
    sha256_bytes,
    sha256_file,
)
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.core.time import utc_now
from agentsec_evidence.execution.config import (
    ExecutionProfile,
    SemgrepToolConfig,
    StaticToolConfig,
    load_toml_config,
)
from agentsec_evidence.execution.docker import (
    build_container_cleanup_argv,
    build_semgrep_argv,
    portable_docker_argv,
)
from agentsec_evidence.execution.process import ProcessCapture, run_bounded_process
from agentsec_evidence.exports.sarif import build_sarif
from agentsec_evidence.intake.snapshot import SnapshotResult, create_snapshot
from agentsec_evidence.models.contracts import (
    BlobDescriptor,
    BlobIndex,
    CoverageExecution,
    CoverageRecord,
    ExecutionOutcome,
    ExecutionRecord,
    FailureCategory,
    FailureRecord,
    FailureStage,
    Finding,
    ParserReport,
    Producer,
    RunState,
    Sensitivity,
    Summary,
    TargetSnapshot,
    ValidationReport,
)
from agentsec_evidence.storage.blobs import BlobStore
from agentsec_evidence.storage.bundle import RunBundle
from agentsec_evidence.validation.checks import (
    ProductSchema,
    ProvenanceResult,
    validate_product_schemas,
    validate_provenance,
    validate_sarif,
)


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


@dataclass(frozen=True)
class PipelineResult:
    run_id: str
    run_root: Path
    terminal_state: RunState
    semantic_sha256: str
    summary: Summary


@dataclass(frozen=True)
class _ProductResult:
    schema: ValidationReport
    sarif: ValidationReport
    provenance: ProvenanceResult
    summary: Summary

    @property
    def passed(self) -> bool:
        return self.schema.passed and self.sarif.passed and self.provenance.report.passed


def _producer(tool: StaticToolConfig) -> Producer:
    return Producer(
        tool_id=tool.tool_id,
        tool_version=tool.tool_version,
        adapter_id=tool.adapter_id,
        adapter_version=tool.adapter_version,
    )


def _minimal_environment(runtime_root: Path) -> dict[str, str]:
    runtime_root.mkdir(parents=True, exist_ok=True)
    home = runtime_root / "home"
    temporary = runtime_root / "tmp"
    docker_config = runtime_root / "docker-config"
    for directory in (home, temporary, docker_config):
        directory.mkdir(parents=True, exist_ok=True)

    environment: dict[str, str] = {}
    for name in ("SystemRoot", "WINDIR", "COMSPEC", "PATHEXT"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    environment.update(
        {
            "DOCKER_CLI_HINTS": "false",
            "DOCKER_CONFIG": str(docker_config),
            "HOME": str(home),
            "TEMP": str(temporary),
            "TMP": str(temporary),
            "USERPROFILE": str(home),
        }
    )
    return environment


def _resolve_docker(explicit: Path | None) -> Path | None:
    if explicit is not None:
        return explicit.resolve() if explicit.is_file() else None
    discovered = shutil.which("docker")
    return Path(discovered).resolve() if discovered else None


def _store_blob(
    *,
    bundle: RunBundle,
    blob_store: BlobStore,
    relative_path: str,
    data: bytes,
    media_type: str,
    sensitivity: Sensitivity,
    producer: str,
    logical_role: str,
) -> BlobDescriptor:
    stored = blob_store.put(data)
    destination = bundle.write_bytes(relative_path, data)
    if sha256_file(destination) != stored.sha256:
        raise RuntimeError(f"Run-bundle blob verification failed: {relative_path}")
    return BlobDescriptor(
        sha256=stored.sha256,
        byte_length=stored.byte_length,
        media_type=media_type,
        sensitivity=sensitivity,
        producer=producer,
        logical_role=logical_role,
        relative_path=relative_path,
    )


def _sanitize_message(message: str) -> str:
    sanitized = "".join(
        character if character >= " " and character != "\x7f" else "?" for character in message
    ).strip()
    return (sanitized or "Operation failed without a diagnostic message")[:2000]


def _failure(
    *,
    run_id: str,
    execution_id: str,
    stage: FailureStage,
    category: FailureCategory,
    message: str,
    evidence: list[str],
    exit_code: int | None = None,
    partial: bool = False,
    affected_scope: str = "semgrep execution",
) -> FailureRecord:
    return FailureRecord(
        failure_id=new_opaque_id("failure"),
        run_id=run_id,
        execution_id=execution_id,
        stage=stage,
        category=category,
        retryability="unknown",
        affected_scope=affected_scope,
        native_exit_code=exit_code,
        sanitized_message=_sanitize_message(message),
        evidence_blob_sha256=evidence,
        partial_evidence_usable=partial,
        final_disposition="preserved as an explicit failed or partial observation",
    )


def _failed_coverage(
    *,
    run_id: str,
    execution_id: str,
    snapshot: TargetSnapshot,
    producer: Producer,
    execution: CoverageExecution,
    property_id: str = "code.static-analysis.semgrep",
) -> CoverageRecord:
    return CoverageRecord(
        coverage_id=new_opaque_id("coverage"),
        run_id=run_id,
        execution_id=execution_id,
        target_snapshot_id=snapshot.snapshot_id,
        property_id=property_id,
        producer=producer,
        applicability="applicable",
        adapter_support="supported",
        execution=execution,
        observation="unknown",
        limitations=[
            "The scanner did not produce a complete, validated observation for this target."
        ],
    )


def _make_execution(
    *,
    execution_id: str,
    run_id: str,
    snapshot: TargetSnapshot,
    tool: StaticToolConfig,
    profile: ExecutionProfile,
    config_sha256: str,
    ruleset_sha256: str,
    portable_argv: list[str],
    environment: dict[str, str],
    capture: ProcessCapture | None,
    outcome: ExecutionOutcome,
    native_byte_length: int,
    cleanup_attempted: bool,
    cleanup_succeeded: bool | None,
) -> ExecutionRecord:
    instant = utc_now()
    return ExecutionRecord(
        execution_id=execution_id,
        run_id=run_id,
        target_snapshot_id=snapshot.snapshot_id,
        producer=_producer(tool),
        image=tool.image,
        argv=portable_argv,
        approved_environment_names=sorted(environment),
        profile_id=profile.profile_id,
        config_sha256=config_sha256,
        ruleset_sha256=ruleset_sha256,
        limits=profile.limits,
        started_at=capture.started_at if capture else instant,
        ended_at=capture.ended_at if capture else instant,
        duration_ns=capture.duration_ns if capture else 0,
        exit_code=capture.exit_code if capture else None,
        outcome=outcome,
        timed_out=capture.timed_out if capture else False,
        stdout_byte_length=len(capture.stdout) if capture else 0,
        stderr_byte_length=len(capture.stderr) if capture else 0,
        native_byte_length=native_byte_length,
        peak_host_rss_bytes=capture.peak_rss_bytes if capture else 0,
        output_limited=capture.output_limited if capture else False,
        stdout_truncated=capture.stdout_truncated if capture else False,
        stderr_truncated=capture.stderr_truncated if capture else False,
        container_cleanup_attempted=cleanup_attempted,
        container_cleanup_succeeded=cleanup_succeeded,
    )


def _cleanup_container(
    *,
    docker: Path,
    container_name: str,
    cwd: Path,
    environment: dict[str, str],
) -> bool:
    cleanup = run_bounded_process(
        build_container_cleanup_argv(docker_executable=docker, container_name=container_name),
        cwd=cwd,
        environment=environment,
        timeout_seconds=15,
        max_stdout_bytes=1024 * 1024,
        max_stderr_bytes=1024 * 1024,
    )
    if cleanup.exit_code == 0:
        return True
    diagnostic = (cleanup.stdout + cleanup.stderr).decode("utf-8", errors="replace").lower()
    return cleanup.exit_code == 1 and "no such container" in diagnostic


def _remove_staging(staging_root: Path, execution_root: Path) -> None:
    resolved_staging = staging_root.resolve()
    resolved_execution = execution_root.resolve()
    if not resolved_execution.is_relative_to(resolved_staging):
        raise RuntimeError("Refusing to clean staging path outside the staging root")
    shutil.rmtree(resolved_execution, ignore_errors=False)


def _semantic_document(
    *,
    snapshot: TargetSnapshot,
    execution: ExecutionRecord,
    parser_report: ParserReport | None,
    findings: list[Finding],
    coverage: list[CoverageRecord],
    failures: list[FailureRecord],
    sarif: dict[str, JsonValue],
) -> JsonValue:
    finding_values = [
        finding.model_dump(mode="json", exclude={"record_id", "run_id", "execution_id"})
        for finding in findings
    ]
    coverage_values = [
        item.model_dump(mode="json", exclude={"coverage_id", "run_id", "execution_id"})
        for item in coverage
    ]
    failure_values = [
        item.model_dump(mode="json", exclude={"failure_id", "run_id", "execution_id"})
        for item in failures
    ]
    parser_value: JsonValue = (
        parser_report.model_dump(
            mode="json", exclude={"execution_id", "parsed_at", "source_blob_sha256"}
        )
        if parser_report
        else None
    )
    return _semantic_projection(
        cast(
            JsonValue,
            {
                "semantic_version": "run-semantic-v2",
                "target_content_sha256": snapshot.content_sha256,
                "tool_image": execution.image,
                "config_sha256": execution.config_sha256,
                "ruleset_sha256": execution.ruleset_sha256,
                "execution": {
                    "outcome": execution.outcome.value,
                    "exit_code": execution.exit_code,
                    "timed_out": execution.timed_out,
                    "output_limited": execution.output_limited,
                },
                "parser": parser_value,
                "findings": finding_values,
                "coverage": coverage_values,
                "failures": failure_values,
                "sarif": sarif,
            },
        )
    )


def _semantic_projection(value: JsonValue) -> JsonValue:
    """Remove exact raw-blob locators while retaining their semantic pointers."""
    volatile_locator_keys = {
        "agentsecEvidence/sourceBlobSha256",
        "blob_sha256",
        "evidence_blob_sha256",
    }
    if isinstance(value, dict):
        return {
            key: _semantic_projection(item)
            for key, item in value.items()
            if key not in volatile_locator_keys
        }
    if isinstance(value, list):
        return [_semantic_projection(item) for item in value]
    return value


def _persist_products(
    *,
    project_root: Path,
    bundle: RunBundle,
    execution: ExecutionRecord,
    parser_report: ParserReport | None,
    findings: list[Finding],
    coverage: list[CoverageRecord],
    failures: list[FailureRecord],
    blob_index: BlobIndex,
) -> tuple[_ProductResult, dict[str, JsonValue]]:
    execution_prefix = f"executions/{execution.execution_id}"
    bundle.write_jsonl("normalized/findings.jsonl", findings)
    bundle.write_jsonl("normalized/coverage.jsonl", coverage)
    bundle.write_jsonl("normalized/failures.jsonl", failures)

    sarif_document = build_sarif(findings, execution=execution)
    bundle.write_bytes("exports/results.sarif", json_bytes(cast(JsonValue, sarif_document)))
    sarif_report = validate_sarif(
        run_id=execution.run_id,
        document=sarif_document,
        schema_path=(project_root / "schemas" / "vendor" / "oasis" / "sarif-schema-2.1.0.json"),
        expected_results=len(findings),
    )
    provenance = validate_provenance(
        run_id=execution.run_id,
        bundle_root=bundle.root,
        findings=findings,
        blob_index=blob_index,
    )
    summary = build_summary(
        execution=execution,
        parser_report=parser_report,
        findings=findings,
        coverage=coverage,
        failures=failures,
        resolved_evidence_references=provenance.resolved_references,
        represented_findings=len(findings),
        sarif_valid=sarif_report.passed,
    )
    bundle.write_model("exports/summary.json", summary)

    products = [
        ProductSchema("run.json", "run.schema.json"),
        ProductSchema("events.jsonl", "run-event.schema.json", json_lines=True),
        ProductSchema("target/snapshot.json", "target-snapshot.schema.json"),
        ProductSchema("target/inventory.jsonl", "inventory-entry.schema.json", json_lines=True),
        ProductSchema(f"{execution_prefix}/execution.json", "execution.schema.json"),
        ProductSchema(f"{execution_prefix}/blobs.json", "blob-index.schema.json"),
        ProductSchema(
            f"{execution_prefix}/parser-report.json",
            "parser-report.schema.json",
            required=parser_report is not None,
        ),
        ProductSchema("normalized/findings.jsonl", "finding.schema.json", json_lines=True),
        ProductSchema("normalized/coverage.jsonl", "coverage.schema.json", json_lines=True),
        ProductSchema("normalized/failures.jsonl", "failure.schema.json", json_lines=True),
        ProductSchema("exports/summary.json", "summary.schema.json"),
    ]
    schema_report = validate_product_schemas(
        run_id=execution.run_id,
        bundle_root=bundle.root,
        schema_root=project_root / "schemas" / "v0.1.0",
        products=products,
    )
    bundle.write_model("validation/schema.json", schema_report)
    bundle.write_model("validation/sarif.json", sarif_report)
    bundle.write_model("validation/provenance.json", provenance.report)
    return (
        _ProductResult(schema_report, sarif_report, provenance, summary),
        sarif_document,
    )


def _finish_run(
    *,
    project_root: Path,
    bundle: RunBundle,
    snapshot: TargetSnapshot,
    execution: ExecutionRecord,
    parser_report: ParserReport | None,
    findings: list[Finding],
    coverage: list[CoverageRecord],
    failures: list[FailureRecord],
    blob_index: BlobIndex,
    desired_state: RunState,
) -> PipelineResult:
    products, sarif_document = _persist_products(
        project_root=project_root,
        bundle=bundle,
        execution=execution,
        parser_report=parser_report,
        findings=findings,
        coverage=coverage,
        failures=failures,
        blob_index=blob_index,
    )
    terminal_state = desired_state if products.passed else RunState.VALIDATION_FAILED
    if bundle.run.state is RunState.VALIDATING:
        bundle.transition(terminal_state, "derived products validated")
    elif bundle.run.state is not terminal_state:
        raise RuntimeError(
            f"Failure finalization state mismatch: {bundle.run.state} != {terminal_state}"
        )
    semantic_document = _semantic_document(
        snapshot=snapshot,
        execution=execution,
        parser_report=parser_report,
        findings=findings,
        coverage=coverage,
        failures=failures,
        sarif=sarif_document,
    )
    bundle.finalize(semantic_document=semantic_document)
    assert bundle.run.semantic_sha256 is not None
    return PipelineResult(
        run_id=bundle.run.run_id,
        run_root=bundle.root,
        terminal_state=terminal_state,
        semantic_sha256=bundle.run.semantic_sha256,
        summary=products.summary,
    )


def run_semgrep_scan(request: SemgrepScanRequest) -> PipelineResult:
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
    snapshot_result: SnapshotResult = create_snapshot(
        request.target_source,
        workspace_root / "targets",
        source_label=request.source_label,
        revision=request.revision,
        source_kind=request.source_kind,
        license_status=request.license_status,
    )
    blob_store = BlobStore(workspace_root / "blobs")
    environment = _minimal_environment(workspace_root / "runtime")

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
            _store_blob(
                bundle=bundle,
                blob_store=blob_store,
                relative_path=f"{prefix}/inputs/profile.toml",
                data=profile_loaded.raw,
                media_type="application/toml",
                sensitivity=Sensitivity.METADATA_ONLY,
                producer="orchestrator",
                logical_role="execution-profile",
            ),
            _store_blob(
                bundle=bundle,
                blob_store=blob_store,
                relative_path=f"{prefix}/inputs/tool-config.toml",
                data=tool_loaded.raw,
                media_type="application/toml",
                sensitivity=Sensitivity.METADATA_ONLY,
                producer="orchestrator",
                logical_role="tool-config",
            ),
            _store_blob(
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
        docker = _resolve_docker(request.docker_executable)
        if docker is None:
            bundle.transition(RunState.RUNNING, "launch attempted")
            execution = _make_execution(
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
            stdout_descriptor = _store_blob(
                bundle=bundle,
                blob_store=blob_store,
                relative_path=f"{prefix}/stdout.bin",
                data=b"",
                media_type="application/octet-stream",
                sensitivity=Sensitivity.INTERNAL,
                producer="orchestrator",
                logical_role="stdout",
            )
            stderr_descriptor = _store_blob(
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
            failure = _failure(
                run_id=bundle.run.run_id,
                execution_id=execution_id,
                stage="launch",
                category="missing-tool",
                message="Docker executable was not available; Semgrep was not launched.",
                evidence=[],
            )
            failure_coverage = _failed_coverage(
                run_id=bundle.run.run_id,
                execution_id=execution_id,
                snapshot=snapshot_result.snapshot,
                producer=execution.producer,
                execution="failed",
            )
            bundle.transition(RunState.EXECUTION_FAILED, "required Docker executable unavailable")
            return _finish_run(
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
                cleanup_succeeded = _cleanup_container(
                    docker=docker,
                    container_name=container_name,
                    cwd=project_root,
                    environment=environment,
                )

            descriptors = [
                *input_descriptors,
                _store_blob(
                    bundle=bundle,
                    blob_store=blob_store,
                    relative_path=f"{prefix}/stdout.bin",
                    data=capture.stdout,
                    media_type="application/octet-stream",
                    sensitivity=Sensitivity.INTERNAL,
                    producer="docker-cli",
                    logical_role="stdout",
                ),
                _store_blob(
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
                    _store_blob(
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
            execution = _make_execution(
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
                early_failure = _failure(
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
                early_failure = _failure(
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
                early_failure = _failure(
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
                early_failure = _failure(
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
                failure_coverage = _failed_coverage(
                    run_id=bundle.run.run_id,
                    execution_id=execution_id,
                    snapshot=snapshot_result.snapshot,
                    producer=execution.producer,
                    execution=coverage_execution,
                )
                return _finish_run(
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
                failure = _failure(
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
                failure_coverage = _failed_coverage(
                    run_id=bundle.run.run_id,
                    execution_id=execution_id,
                    snapshot=snapshot_result.snapshot,
                    producer=execution.producer,
                    execution="failed",
                )
                return _finish_run(
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
                failure = _failure(
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
                failure_coverage = _failed_coverage(
                    run_id=bundle.run.run_id,
                    execution_id=execution_id,
                    snapshot=snapshot_result.snapshot,
                    producer=execution.producer,
                    execution="failed",
                )
                return _finish_run(
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
                    _failure(
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
                    _failure(
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
            return _finish_run(
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
                _remove_staging(staging_root, execution_staging)
