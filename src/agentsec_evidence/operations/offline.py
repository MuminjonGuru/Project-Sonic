from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from pydantic import BaseModel, JsonValue

from agentsec_evidence.adapters.kics import NormalizedKics, normalize_kics, parse_kics_json
from agentsec_evidence.adapters.semgrep import (
    NormalizedSemgrep,
    normalize_semgrep,
    parse_semgrep_json,
)
from agentsec_evidence.analysis.summary import build_summary
from agentsec_evidence.core.identity import sha256_file
from agentsec_evidence.core.io import (
    atomic_write_bytes,
    atomic_write_jsonl,
    atomic_write_model,
    json_bytes,
)
from agentsec_evidence.core.time import utc_now
from agentsec_evidence.execution.config import (
    KicsToolConfig,
    SemgrepToolConfig,
    load_toml_bytes,
    load_toml_config,
)
from agentsec_evidence.exports.sarif import build_sarif
from agentsec_evidence.models.contracts import (
    BlobIndex,
    CoverageRecord,
    ExecutionRecord,
    FailureRecord,
    Finding,
    ParserReport,
    RunRecord,
    Summary,
    TargetSnapshot,
    ValidationReport,
)
from agentsec_evidence.validation.checks import (
    ProductSchema,
    ProvenanceResult,
    validate_bundle,
    validate_product_schemas,
    validate_provenance,
    validate_sarif,
)

_RUN_ID = re.compile(r"^run_[0-9a-f]{32}$")


@dataclass(frozen=True)
class ExistingRun:
    root: Path
    run: RunRecord
    execution: ExecutionRecord
    target: TargetSnapshot
    blobs: BlobIndex
    parser_report: ParserReport | None
    findings: tuple[Finding, ...]
    coverage: tuple[CoverageRecord, ...]
    failures: tuple[FailureRecord, ...]


@dataclass(frozen=True)
class ValidationSuite:
    bundle: ValidationReport
    schema: ValidationReport
    sarif: ValidationReport
    provenance: ProvenanceResult

    @property
    def passed(self) -> bool:
        return (
            self.bundle.passed
            and self.schema.passed
            and self.sarif.passed
            and self.provenance.report.passed
        )


def resolve_run_root(workspace_root: Path, run_id: str) -> Path:
    if not _RUN_ID.fullmatch(run_id):
        raise ValueError("Run ID must match run_<32 lowercase hexadecimal characters>")
    runs_root = (workspace_root / "runs").resolve(strict=True)
    run_root = (runs_root / run_id).resolve(strict=True)
    if run_root.parent != runs_root or not run_root.is_dir():
        raise ValueError("Run ID does not resolve to a direct run-bundle directory")
    return run_root


def _read_jsonl[ModelT: BaseModel](path: Path, model: type[ModelT]) -> tuple[ModelT, ...]:
    return tuple(
        model.model_validate_json(line) for line in path.read_bytes().splitlines() if line.strip()
    )


def load_existing_run(workspace_root: Path, run_id: str) -> ExistingRun:
    root = resolve_run_root(workspace_root, run_id)
    run = RunRecord.model_validate_json((root / "run.json").read_bytes())
    if run.run_id != run_id:
        raise ValueError("Run directory and run record identities differ")
    if len(run.execution_ids) != 1:
        raise ValueError("First-slice operation requires exactly one execution")
    execution_id = run.execution_ids[0]
    prefix = root / "executions" / execution_id
    parser_path = prefix / "parser-report.json"
    return ExistingRun(
        root=root,
        run=run,
        execution=ExecutionRecord.model_validate_json((prefix / "execution.json").read_bytes()),
        target=TargetSnapshot.model_validate_json((root / "target" / "snapshot.json").read_bytes()),
        blobs=BlobIndex.model_validate_json((prefix / "blobs.json").read_bytes()),
        parser_report=(
            ParserReport.model_validate_json(parser_path.read_bytes())
            if parser_path.is_file()
            else None
        ),
        findings=_read_jsonl(root / "normalized" / "findings.jsonl", Finding),
        coverage=_read_jsonl(root / "normalized" / "coverage.jsonl", CoverageRecord),
        failures=_read_jsonl(root / "normalized" / "failures.jsonl", FailureRecord),
    )


def _load_sarif(path: Path) -> dict[str, JsonValue]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("SARIF root must be an object")
    return cast(dict[str, JsonValue], value)


def _schema_products(existing: ExistingRun) -> list[ProductSchema]:
    prefix = f"executions/{existing.execution.execution_id}"
    return [
        ProductSchema("run.json", "run.schema.json"),
        ProductSchema("events.jsonl", "run-event.schema.json", json_lines=True),
        ProductSchema("target/snapshot.json", "target-snapshot.schema.json"),
        ProductSchema("target/inventory.jsonl", "inventory-entry.schema.json", json_lines=True),
        ProductSchema(f"{prefix}/execution.json", "execution.schema.json"),
        ProductSchema(f"{prefix}/blobs.json", "blob-index.schema.json"),
        ProductSchema(
            f"{prefix}/parser-report.json",
            "parser-report.schema.json",
            required=existing.parser_report is not None,
        ),
        ProductSchema("normalized/findings.jsonl", "finding.schema.json", json_lines=True),
        ProductSchema("normalized/coverage.jsonl", "coverage.schema.json", json_lines=True),
        ProductSchema("normalized/failures.jsonl", "failure.schema.json", json_lines=True),
        ProductSchema("exports/summary.json", "summary.schema.json"),
        ProductSchema("validation/schema.json", "validation-report.schema.json"),
        ProductSchema("validation/sarif.json", "validation-report.schema.json"),
        ProductSchema("validation/provenance.json", "validation-report.schema.json"),
        ProductSchema("bundle-manifest.json", "bundle-manifest.schema.json"),
    ]


def validate_existing_run(
    *, project_root: Path, workspace_root: Path, run_id: str
) -> ValidationSuite:
    existing = load_existing_run(workspace_root, run_id)
    schema_report = validate_product_schemas(
        run_id=run_id,
        bundle_root=existing.root,
        schema_root=project_root / "schemas" / "v0.1.0",
        products=_schema_products(existing),
    )
    sarif_document = _load_sarif(existing.root / "exports" / "results.sarif")
    sarif_report = validate_sarif(
        run_id=run_id,
        document=sarif_document,
        schema_path=(project_root / "schemas" / "vendor" / "oasis" / "sarif-schema-2.1.0.json"),
        expected_results=len(existing.findings),
    )
    provenance = validate_provenance(
        run_id=run_id,
        bundle_root=existing.root,
        findings=list(existing.findings),
        blob_index=existing.blobs,
    )
    return ValidationSuite(
        bundle=validate_bundle(existing.root),
        schema=schema_report,
        sarif=sarif_report,
        provenance=provenance,
    )


def rebuild_sarif(
    *, project_root: Path, workspace_root: Path, run_id: str, output: Path
) -> ValidationReport:
    existing = load_existing_run(workspace_root, run_id)
    resolved_output = output.resolve()
    if resolved_output.is_relative_to(existing.root):
        raise ValueError("Derived export cannot modify a finalized run bundle")
    if resolved_output.exists():
        raise FileExistsError("SARIF output already exists")
    document = build_sarif(existing.findings, execution=existing.execution)
    report = validate_sarif(
        run_id=run_id,
        document=document,
        schema_path=(project_root / "schemas" / "vendor" / "oasis" / "sarif-schema-2.1.0.json"),
        expected_results=len(existing.findings),
    )
    if not report.passed:
        raise ValueError("Rebuilt SARIF did not pass validation")
    atomic_write_bytes(resolved_output, json_bytes(cast(JsonValue, document)))
    return report


def _represented_results(document: dict[str, JsonValue]) -> int:
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs or not isinstance(runs[0], dict):
        return 0
    results = runs[0].get("results")
    return len(results) if isinstance(results, list) else 0


def rebuild_summary(*, project_root: Path, workspace_root: Path, run_id: str) -> Summary:
    existing = load_existing_run(workspace_root, run_id)
    document = _load_sarif(existing.root / "exports" / "results.sarif")
    sarif_report = validate_sarif(
        run_id=run_id,
        document=document,
        schema_path=(project_root / "schemas" / "vendor" / "oasis" / "sarif-schema-2.1.0.json"),
        expected_results=len(existing.findings),
    )
    provenance = validate_provenance(
        run_id=run_id,
        bundle_root=existing.root,
        findings=list(existing.findings),
        blob_index=existing.blobs,
    )
    return build_summary(
        execution=existing.execution,
        parser_report=existing.parser_report,
        findings=existing.findings,
        coverage=existing.coverage,
        failures=existing.failures,
        resolved_evidence_references=provenance.resolved_references,
        represented_findings=_represented_results(document),
        sarif_valid=sarif_report.passed,
    )


def normalize_existing_run(
    *,
    project_root: Path,
    workspace_root: Path,
    run_id: str,
    output_root: Path,
) -> Path:
    existing = load_existing_run(workspace_root, run_id)
    resolved_output = output_root.resolve()
    if resolved_output.is_relative_to(existing.root):
        raise ValueError("Offline normalization cannot modify a finalized run bundle")
    if resolved_output.exists():
        raise FileExistsError("Offline normalization output already exists")
    native = next(
        (
            descriptor
            for descriptor in existing.blobs.blobs
            if descriptor.logical_role == "native-report"
        ),
        None,
    )
    if native is None:
        raise ValueError("Run has no native report to normalize")
    native_path = existing.root.joinpath(*native.relative_path.split("/"))
    if sha256_file(native_path) != native.sha256:
        raise ValueError("Native report hash does not match its descriptor")
    config_descriptor = next(
        (
            descriptor
            for descriptor in existing.blobs.blobs
            if descriptor.logical_role == "tool-config"
        ),
        None,
    )
    bundled_config: bytes | None = None
    if config_descriptor is not None:
        config_path = existing.root.joinpath(*config_descriptor.relative_path.split("/"))
        if sha256_file(config_path) != config_descriptor.sha256:
            raise ValueError("Bundled tool configuration hash does not match its descriptor")
        bundled_config = config_path.read_bytes()

    tool_id = existing.execution.producer.tool_id
    normalized: NormalizedSemgrep | NormalizedKics
    if tool_id == "semgrep":
        semgrep_tool = (
            load_toml_bytes(
                bundled_config,
                SemgrepToolConfig,
                source=Path("<bundled-semgrep-config>"),
            ).value
            if bundled_config is not None
            else load_toml_config(
                project_root / "configs" / "tools" / "semgrep.toml", SemgrepToolConfig
            ).value
        )
        semgrep_parsed = parse_semgrep_json(native_path.read_bytes())
        normalized = normalize_semgrep(
            semgrep_parsed,
            tool=semgrep_tool,
            run_id=existing.run.run_id,
            execution_id=existing.execution.execution_id,
            target_snapshot_id=existing.target.snapshot_id,
            source_blob_sha256=native.sha256,
        )
        parser_report = ParserReport(
            parser_id=semgrep_tool.adapter_id,
            parser_version=semgrep_tool.adapter_version,
            execution_id=existing.execution.execution_id,
            source_blob_sha256=native.sha256,
            parsed_at=utc_now(),
            native_result_count=len(semgrep_parsed.document.results),
            native_error_count=len(semgrep_parsed.document.errors),
            native_scanned_path_count=len(semgrep_parsed.document.paths.scanned),
            native_skipped_path_count=len(semgrep_parsed.document.paths.skipped),
            native_skipped_rule_count=len(semgrep_parsed.document.skipped_rules),
            normalized_finding_count=len(normalized.findings),
            unknown_top_level_fields=list(semgrep_parsed.unknown_top_level_fields),
            complete=len(normalized.findings) == len(semgrep_parsed.document.results),
        )
    elif tool_id == "kics":
        if bundled_config is None:
            raise ValueError("KICS offline normalization requires its bundled tool configuration")
        kics_tool = load_toml_bytes(
            bundled_config,
            KicsToolConfig,
            source=Path("<bundled-kics-config>"),
        ).value
        kics_parsed = parse_kics_json(native_path.read_bytes())
        normalized = normalize_kics(
            kics_parsed,
            tool=kics_tool,
            run_id=existing.run.run_id,
            execution_id=existing.execution.execution_id,
            target_snapshot_id=existing.target.snapshot_id,
            source_blob_sha256=native.sha256,
        )
        parser_report = ParserReport(
            parser_id=kics_tool.adapter_id,
            parser_version=kics_tool.adapter_version,
            execution_id=existing.execution.execution_id,
            source_blob_sha256=native.sha256,
            parsed_at=utc_now(),
            native_result_count=kics_parsed.native_result_count,
            native_error_count=len(normalized.failures),
            native_scanned_path_count=kics_parsed.document.files_scanned,
            native_skipped_path_count=max(
                existing.target.file_count - kics_parsed.document.files_scanned, 0
            ),
            native_skipped_rule_count=max(
                len(kics_tool.include_queries) - kics_parsed.document.queries_total, 0
            ),
            normalized_finding_count=len(normalized.findings),
            unknown_top_level_fields=list(kics_parsed.unknown_fields),
            complete=not normalized.failures
            and len(normalized.findings) == kics_parsed.document.total_counter,
        )
    else:
        raise ValueError(f"Unsupported offline normalization producer: {tool_id}")
    canonical_findings = sorted(
        normalized.findings,
        key=lambda item: item.fingerprints.record_v1,
    )
    resolved_output.mkdir(parents=True, exist_ok=False)
    atomic_write_jsonl(resolved_output / "findings.jsonl", canonical_findings)
    atomic_write_jsonl(resolved_output / "coverage.jsonl", normalized.coverage)
    atomic_write_jsonl(resolved_output / "failures.jsonl", normalized.failures)
    atomic_write_model(resolved_output / "parser-report.json", parser_report)
    metadata: JsonValue = {
        "adapter_id": existing.execution.producer.adapter_id,
        "adapter_version": existing.execution.producer.adapter_version,
        "generated_at": utc_now().isoformat(),
        "source_blob_sha256": native.sha256,
        "source_run_id": run_id,
    }
    atomic_write_bytes(resolved_output / "derivative.json", json_bytes(metadata))
    return resolved_output
