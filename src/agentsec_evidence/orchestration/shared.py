"""Producer-neutral preparation, evidence capture and static-product finalization."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, cast

from pydantic import JsonValue

from agentsec_evidence.agents.records import AgentParserReport
from agentsec_evidence.analysis.summary import build_summary
from agentsec_evidence.core.identity import new_opaque_id, sha256_file
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.core.time import utc_now
from agentsec_evidence.execution.config import ExecutionProfile
from agentsec_evidence.execution.docker import build_container_cleanup_argv
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


class ToolIdentity(Protocol):
    """The execution metadata shared by producer configurations."""

    @property
    def tool_id(self) -> str: ...

    @property
    def tool_version(self) -> str: ...

    @property
    def adapter_id(self) -> str: ...

    @property
    def adapter_version(self) -> str: ...

    @property
    def image(self) -> str: ...


@dataclass(frozen=True)
class PreparedWorkspace:
    snapshot_result: SnapshotResult
    blob_store: BlobStore
    environment: dict[str, str]


def prepare_workspace(
    *,
    workspace_root: Path,
    target_source: Path,
    source_label: str,
    revision: str,
    source_kind: Literal["project-fixture", "local", "git"],
    license_status: Literal["project-authored-private", "identified", "unknown"],
) -> PreparedWorkspace:
    snapshot_result = create_snapshot(
        target_source,
        workspace_root / "targets",
        source_label=source_label,
        revision=revision,
        source_kind=source_kind,
        license_status=license_status,
    )
    return PreparedWorkspace(
        snapshot_result=snapshot_result,
        blob_store=BlobStore(workspace_root / "blobs"),
        environment=minimal_environment(workspace_root / "runtime"),
    )


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


def producer_identity(tool: ToolIdentity) -> Producer:
    return Producer(
        tool_id=tool.tool_id,
        tool_version=tool.tool_version,
        adapter_id=tool.adapter_id,
        adapter_version=tool.adapter_version,
    )


def minimal_environment(runtime_root: Path) -> dict[str, str]:
    # Avoid inheriting host credentials and user-specific tool settings. Use an
    # allowlisted environment with workspace-local home, temporary and Docker config paths.
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


def resolve_docker(explicit: Path | None) -> Path | None:
    if explicit is not None:
        return explicit.resolve() if explicit.is_file() else None
    discovered = shutil.which("docker")
    return Path(discovered).resolve() if discovered else None


def store_blob(
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


def failure_record(
    *,
    run_id: str,
    execution_id: str,
    stage: FailureStage,
    category: FailureCategory,
    message: str,
    evidence: list[str],
    exit_code: int | None = None,
    partial: bool = False,
    affected_scope: str,
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


def build_failed_coverage(
    *,
    run_id: str,
    execution_id: str,
    snapshot: TargetSnapshot,
    producer: Producer,
    execution: CoverageExecution,
    property_id: str,
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


def make_execution(
    *,
    execution_id: str,
    run_id: str,
    snapshot: TargetSnapshot,
    tool: ToolIdentity,
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
        producer=producer_identity(tool),
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


def cleanup_container(
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


def remove_staging(staging_root: Path, execution_root: Path) -> None:
    resolved_staging = staging_root.resolve()
    resolved_execution = execution_root.resolve()
    if not resolved_execution.is_relative_to(resolved_staging):
        raise RuntimeError("Refusing to clean staging path outside the staging root")
    shutil.rmtree(resolved_execution, ignore_errors=False)


def build_semantic_document(
    *,
    snapshot: TargetSnapshot,
    execution: ExecutionRecord,
    parser_report: ParserReport | AgentParserReport | None,
    findings: list[Finding],
    coverage: list[CoverageRecord],
    failures: list[FailureRecord],
    sarif: dict[str, JsonValue],
) -> JsonValue:
    # Exclude per-run IDs, timestamps and raw-blob locators when comparing meaning.
    # Exact bytes remain separately preserved and hash-checked in the evidence bundle.
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


def persist_products(
    *,
    project_root: Path,
    bundle: RunBundle,
    execution: ExecutionRecord,
    parser_report: ParserReport | AgentParserReport | None,
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
            "../agent-v1/parser-report.schema.json"
            if execution.producer.tool_id == "agent-audit"
            else "parser-report.schema.json",
            required=parser_report is not None,
        ),
        ProductSchema("normalized/findings.jsonl", "finding.schema.json", json_lines=True),
        ProductSchema("normalized/coverage.jsonl", "coverage.schema.json", json_lines=True),
        ProductSchema("normalized/failures.jsonl", "failure.schema.json", json_lines=True),
        ProductSchema("exports/summary.json", "summary.schema.json"),
    ]
    if execution.producer.tool_id == "agent-audit":
        products.append(
            ProductSchema("normalized/agent-details.json", "../agent-v1/run-details.schema.json")
        )
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


def finish_run(
    *,
    project_root: Path,
    bundle: RunBundle,
    snapshot: TargetSnapshot,
    execution: ExecutionRecord,
    parser_report: ParserReport | AgentParserReport | None,
    findings: list[Finding],
    coverage: list[CoverageRecord],
    failures: list[FailureRecord],
    blob_index: BlobIndex,
    desired_state: RunState,
    semantic_override: JsonValue = None,
) -> PipelineResult:
    products, sarif_document = persist_products(
        project_root=project_root,
        bundle=bundle,
        execution=execution,
        parser_report=parser_report,
        findings=findings,
        coverage=coverage,
        failures=failures,
        blob_index=blob_index,
    )
    # The requested outcome is provisional until schema, SARIF and provenance checks pass;
    # invalid derived products cannot be finalized as a complete run.
    terminal_state = desired_state if products.passed else RunState.VALIDATION_FAILED
    if bundle.run.state is RunState.VALIDATING:
        bundle.transition(terminal_state, "derived products validated")
    elif bundle.run.state is not terminal_state:
        raise RuntimeError(
            f"Failure finalization state mismatch: {bundle.run.state} != {terminal_state}"
        )
    semantic_document = build_semantic_document(
        snapshot=snapshot,
        execution=execution,
        parser_report=parser_report,
        findings=findings,
        coverage=coverage,
        failures=failures,
        sarif=sarif_document,
    )
    bundle.finalize(
        semantic_document=semantic_override if semantic_override is not None else semantic_document
    )
    assert bundle.run.semantic_sha256 is not None
    return PipelineResult(
        run_id=bundle.run.run_id,
        run_root=bundle.root,
        terminal_state=terminal_state,
        semantic_sha256=bundle.run.semantic_sha256,
        summary=products.summary,
    )
