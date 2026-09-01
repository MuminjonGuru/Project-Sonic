from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from jsonschema import Draft7Validator, Draft202012Validator, FormatChecker
from pydantic import JsonValue

from agentsec_evidence.core.identity import new_opaque_id, semantic_hash, sha256_file
from agentsec_evidence.core.paths import normalize_relative_path
from agentsec_evidence.core.time import utc_now
from agentsec_evidence.models.contracts import (
    BlobIndex,
    BundleManifest,
    Finding,
    RunRecord,
    RunState,
    ValidationCheck,
    ValidationKind,
    ValidationReport,
)

_WINDOWS_DRIVE_URI = re.compile(r"^[A-Za-z]:")


@dataclass(frozen=True)
class ProductSchema:
    relative_path: str
    schema_file: str
    json_lines: bool = False
    required: bool = True


@dataclass(frozen=True)
class ProvenanceResult:
    report: ValidationReport
    resolved_references: int


def _loads_json(text: str) -> JsonValue:
    def reject_constant(value: str) -> None:
        raise ValueError(f"Non-finite JSON number rejected: {value}")

    def reject_duplicates(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON key rejected: {key}")
            result[key] = value
        return result

    return cast(
        JsonValue,
        json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        ),
    )


def _load_json(path: Path) -> JsonValue:
    return _loads_json(path.read_text(encoding="utf-8", errors="strict"))


def _validation_report(
    *, run_id: str, kind: ValidationKind, checks: list[ValidationCheck]
) -> ValidationReport:
    return ValidationReport(
        validation_id=new_opaque_id("validation"),
        run_id=run_id,
        kind=kind,
        checked_at=utc_now(),
        passed=all(check.passed for check in checks),
        checks=checks,
    )


def validate_product_schemas(
    *,
    run_id: str,
    bundle_root: Path,
    schema_root: Path,
    products: list[ProductSchema],
) -> ValidationReport:
    checks: list[ValidationCheck] = []
    for product in products:
        relative = normalize_relative_path(product.relative_path)
        path = bundle_root.joinpath(*relative.split("/"))
        if not path.is_file():
            checks.append(
                ValidationCheck(
                    name=f"schema:{relative}",
                    passed=not product.required,
                    detail="missing optional product"
                    if not product.required
                    else "missing product",
                )
            )
            continue
        try:
            schema_value = _load_json(schema_root / product.schema_file)
            schema = cast(dict[str, JsonValue], schema_value)
            validator = Draft202012Validator(schema, format_checker=FormatChecker())
            values: list[JsonValue]
            if product.json_lines:
                values = [
                    _loads_json(line)
                    for line in path.read_text(encoding="utf-8").splitlines()
                    if line
                ]
            else:
                values = [_load_json(path)]
            errors = [error.message for value in values for error in validator.iter_errors(value)]
            checks.append(
                ValidationCheck(
                    name=f"schema:{relative}",
                    passed=not errors,
                    detail="valid" if not errors else "; ".join(errors[:3]),
                )
            )
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            checks.append(
                ValidationCheck(
                    name=f"schema:{relative}",
                    passed=False,
                    detail=f"{type(exc).__name__}: {exc}",
                )
            )
    return _validation_report(run_id=run_id, kind="schema", checks=checks)


def _resolve_json_pointer(document: JsonValue, pointer: str) -> JsonValue:
    if pointer == "":
        return document
    if not pointer.startswith("/"):
        raise ValueError("JSON Pointer must be empty or start with '/'")
    current = document
    for raw_token in pointer[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            current = current[token]
        elif isinstance(current, list):
            if not token.isascii() or not token.isdecimal():
                raise ValueError("JSON Pointer list token must be a decimal index")
            current = current[int(token)]
        else:
            raise ValueError("JSON Pointer traversed a scalar value")
    return current


def validate_provenance(
    *,
    run_id: str,
    bundle_root: Path,
    findings: list[Finding],
    blob_index: BlobIndex,
) -> ProvenanceResult:
    descriptors = {descriptor.sha256: descriptor for descriptor in blob_index.blobs}
    checks: list[ValidationCheck] = []
    resolved = 0
    for finding in findings:
        for evidence in finding.evidence:
            descriptor = descriptors.get(evidence.blob_sha256)
            label = f"provenance:{finding.fingerprints.record_v1[:12]}"
            if descriptor is None:
                checks.append(ValidationCheck(name=label, passed=False, detail="blob not indexed"))
                continue
            path = bundle_root.joinpath(*descriptor.relative_path.split("/"))
            if not path.is_file() or path.is_symlink():
                checks.append(
                    ValidationCheck(name=label, passed=False, detail="blob path not a regular file")
                )
                continue
            if (
                path.stat().st_size != descriptor.byte_length
                or sha256_file(path) != descriptor.sha256
            ):
                checks.append(
                    ValidationCheck(name=label, passed=False, detail="blob length or hash mismatch")
                )
                continue
            try:
                if evidence.json_pointer is not None:
                    _resolve_json_pointer(_load_json(path), evidence.json_pointer)
            except (KeyError, IndexError, TypeError, ValueError, OSError) as exc:
                checks.append(
                    ValidationCheck(
                        name=label,
                        passed=False,
                        detail=f"unresolved pointer: {type(exc).__name__}",
                    )
                )
                continue
            resolved += 1
            checks.append(
                ValidationCheck(name=label, passed=True, detail="hash and pointer resolve")
            )
    if not checks:
        checks.append(
            ValidationCheck(
                name="provenance:no-findings",
                passed=True,
                detail="no finding evidence references require resolution",
            )
        )
    return ProvenanceResult(
        report=_validation_report(run_id=run_id, kind="provenance", checks=checks),
        resolved_references=resolved,
    )


def _sarif_artifact_uris(document: dict[str, JsonValue]) -> list[str]:
    uris: list[str] = []
    runs = document.get("runs")
    if not isinstance(runs, list):
        return uris
    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results")
        if not isinstance(results, list):
            continue
        for result in results:
            if not isinstance(result, dict):
                continue
            locations = result.get("locations")
            if not isinstance(locations, list):
                continue
            for location in locations:
                if not isinstance(location, dict):
                    continue
                physical = location.get("physicalLocation")
                if not isinstance(physical, dict):
                    continue
                artifact = physical.get("artifactLocation")
                if not isinstance(artifact, dict):
                    continue
                uri = artifact.get("uri")
                if isinstance(uri, str):
                    uris.append(uri)
    return uris


def validate_sarif(
    *,
    run_id: str,
    document: dict[str, JsonValue],
    schema_path: Path,
    expected_results: int,
) -> ValidationReport:
    checks: list[ValidationCheck] = []
    try:
        schema = cast(dict[str, JsonValue], _load_json(schema_path))
        errors = [
            error.message
            for error in Draft7Validator(schema, format_checker=FormatChecker()).iter_errors(
                document
            )
        ]
        checks.append(
            ValidationCheck(
                name="sarif:oasis-2.1.0-schema",
                passed=not errors,
                detail="valid" if not errors else "; ".join(errors[:3]),
            )
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        checks.append(
            ValidationCheck(
                name="sarif:oasis-2.1.0-schema",
                passed=False,
                detail=f"{type(exc).__name__}: {exc}",
            )
        )

    runs = document.get("runs")
    result_count = 0
    fingerprinted = 0
    if isinstance(runs, list) and len(runs) == 1 and isinstance(runs[0], dict):
        results = runs[0].get("results")
        if isinstance(results, list):
            result_count = len(results)
            fingerprinted = sum(
                1
                for result in results
                if isinstance(result, dict) and isinstance(result.get("partialFingerprints"), dict)
            )
    checks.append(
        ValidationCheck(
            name="sarif:result-accounting",
            passed=result_count == expected_results,
            detail=f"expected {expected_results}, represented {result_count}",
        )
    )
    checks.append(
        ValidationCheck(
            name="sarif:partial-fingerprints",
            passed=fingerprinted == result_count,
            detail=f"{fingerprinted}/{result_count} results fingerprinted",
        )
    )
    uris = _sarif_artifact_uris(document)
    unsafe = [
        uri for uri in uris if uri.startswith("/") or "://" in uri or _WINDOWS_DRIVE_URI.match(uri)
    ]
    checks.append(
        ValidationCheck(
            name="sarif:portable-artifact-paths",
            passed=not unsafe,
            detail="all result paths are relative URI references"
            if not unsafe
            else str(unsafe[:3]),
        )
    )
    return _validation_report(run_id=run_id, kind="sarif", checks=checks)


def validate_bundle(bundle_root: Path) -> ValidationReport:
    checks: list[ValidationCheck] = []
    run_id = bundle_root.name
    try:
        run = RunRecord.model_validate_json((bundle_root / "run.json").read_bytes())
        run_id = run.run_id
        checks.append(
            ValidationCheck(
                name="bundle:run-finalized",
                passed=run.state is RunState.FINALIZED and run.terminal_state is not None,
                detail=f"state={run.state}, terminal={run.terminal_state}",
            )
        )
        manifest = BundleManifest.model_validate_json(
            (bundle_root / "bundle-manifest.json").read_bytes()
        )
        checks.append(
            ValidationCheck(
                name="bundle:identity",
                passed=manifest.run_id == run.run_id,
                detail=f"manifest run={manifest.run_id}, record run={run.run_id}",
            )
        )
        entries = {entry.relative_path: entry for entry in manifest.entries}
        actual: dict[str, Path] = {}
        symlinks: list[str] = []
        for path in bundle_root.rglob("*"):
            relative = normalize_relative_path(path.relative_to(bundle_root).as_posix())
            if path.is_symlink():
                symlinks.append(relative)
            elif path.is_file() and relative not in {"bundle-manifest.json", ".write.lock"}:
                actual[relative] = path
        checks.append(
            ValidationCheck(
                name="bundle:file-set",
                passed=set(actual) == set(entries),
                detail=f"manifest={len(entries)}, actual={len(actual)}",
            )
        )
        checks.append(
            ValidationCheck(
                name="bundle:no-symlinks",
                passed=not symlinks,
                detail="none" if not symlinks else str(symlinks[:3]),
            )
        )
        checks.append(
            ValidationCheck(
                name="bundle:no-write-lock",
                passed=not (bundle_root / ".write.lock").exists(),
                detail="absent" if not (bundle_root / ".write.lock").exists() else "present",
            )
        )
        bad = [
            relative
            for relative, path in actual.items()
            if relative not in entries
            or path.stat().st_size != entries[relative].byte_length
            or sha256_file(path) != entries[relative].sha256
        ]
        checks.append(
            ValidationCheck(
                name="bundle:entry-integrity",
                passed=not bad,
                detail="all lengths and hashes match" if not bad else str(bad[:3]),
            )
        )
        entry_values: JsonValue = [entry.model_dump(mode="json") for entry in manifest.entries]
        expected_entries_sha256 = semantic_hash(entry_values)
        checks.append(
            ValidationCheck(
                name="bundle:entry-set-hash",
                passed=expected_entries_sha256 == manifest.entries_sha256,
                detail=manifest.entries_sha256,
            )
        )
        ordered_paths = [entry.relative_path for entry in manifest.entries]
        checks.append(
            ValidationCheck(
                name="bundle:manifest-order",
                passed=ordered_paths == sorted(ordered_paths),
                detail="sorted" if ordered_paths == sorted(ordered_paths) else "unsorted",
            )
        )
        checks.append(
            ValidationCheck(
                name="bundle:id",
                passed=manifest.bundle_id == f"bundle_{expected_entries_sha256}",
                detail=manifest.bundle_id,
            )
        )
    except (OSError, ValueError) as exc:
        checks.append(
            ValidationCheck(
                name="bundle:read",
                passed=False,
                detail=f"{type(exc).__name__}: {exc}",
            )
        )
    return _validation_report(run_id=run_id, kind="bundle", checks=checks)
