from __future__ import annotations

import json
import time
import tomllib
import uuid
from pathlib import Path
from typing import Literal, cast

from jsonschema.exceptions import ValidationError
from pydantic import JsonValue

from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.core.time import utc_now
from agentsec_evidence.dependencies.analysis import (
    SEMANTIC_VERSION,
    compare_stages,
    dependency_semantic_hash,
)
from agentsec_evidence.dependencies.database import inspect_database
from agentsec_evidence.dependencies.execution import build_dependency_argv, verify_tool_record
from agentsec_evidence.dependencies.models import DependencyScope, StageComparison, StageEvidence
from agentsec_evidence.dependencies.mutations import Mutation, mutate_sbom
from agentsec_evidence.dependencies.parsers import (
    parse_cyclonedx,
    parse_lockfile,
    parse_osv,
    parse_syft,
)
from agentsec_evidence.dependencies.validation import validate_cyclonedx
from agentsec_evidence.execution.process import run_bounded_process
from agentsec_evidence.intake.snapshot import SnapshotError
from agentsec_evidence.orchestration.shared import (
    cleanup_container,
    prepare_workspace,
    resolve_docker,
)

MAX_NATIVE_BYTES = 64 * 1024 * 1024


def _write(root: Path, relative: str, data: bytes) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(data)


def _json(root: Path, relative: str, value: JsonValue) -> None:
    _write(root, relative, json_bytes(value))


def seal_bundle(root: Path) -> None:
    entries: list[JsonValue] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("Evidence bundle contains a symbolic link")
        if path.is_file():
            entries.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": sha256_file(path),
                    "bytes": path.stat().st_size,
                }
            )
    _json(root, "manifest.json", {"contract": "dependency-bundle-v1", "entries": entries})


def validate_dependency_bundle(root: Path) -> dict[str, JsonValue]:
    # Check file integrity, native evidence pointers and the recorded semantic digest.
    # Passing these checks establishes evidence consistency, not a security verdict.
    root = root.resolve(strict=True)
    document = json.loads((root / "manifest.json").read_bytes())
    if document.get("contract") != "dependency-bundle-v1":
        raise ValueError("Unsupported dependency bundle version")
    paths: set[str] = set()
    for entry in document["entries"]:
        relative = entry["path"]
        if not isinstance(relative, str) or "\\" in relative or ":" in relative:
            raise ValueError("Unsafe manifest path")
        path = root / relative
        if path.is_symlink() or not path.resolve().is_relative_to(root) or relative in paths:
            raise ValueError("Unsafe or duplicate manifest entry")
        if (
            not path.is_file()
            or path.stat().st_size != entry["bytes"]
            or sha256_file(path) != entry["sha256"]
        ):
            raise ValueError(f"Evidence integrity failure: {relative}")
        paths.add(relative)
    actual = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("Symbolic link in dependency bundle")
        if path.is_file() and path != root / "manifest.json":
            actual.add(path.relative_to(root).as_posix())
    if paths != actual:
        raise ValueError("Unmanifested or missing dependency evidence")
    stages = []
    for path in (root / "normalized").glob("*.json") if (root / "normalized").exists() else []:
        stage = StageEvidence.model_validate_json(path.read_bytes())
        stages.append(stage)
        raw_paths = {
            "lockfile": "inputs/uv.lock",
            "syft": "native/syft/syft.json",
            "cyclonedx": "mutations/bom.cdx.json"
            if (root / "mutations/bom.cdx.json").is_file()
            else "native/syft/bom.cdx.json",
            "osv-direct": "native/osv-direct/osv.json",
            "osv-sbom": "native/osv-sbom/osv.json",
        }
        raw_path = root / raw_paths[stage.stage]
        if sha256_file(raw_path) != stage.raw_sha256:
            raise ValueError("Normalized stage is not bound to its native evidence")
        raw = (
            tomllib.loads(raw_path.read_text(encoding="utf-8"))
            if stage.stage == "lockfile"
            else json.loads(raw_path.read_bytes())
        )
        pointers = [item.native_pointer for item in stage.observations + stage.relationships]
        pointers.extend(item.package_pointer for item in stage.matches)
        for pointer in pointers:
            current = raw
            try:
                for token in pointer.lstrip("/").split("/"):
                    token = token.replace("~1", "/").replace("~0", "~")
                    current = current[int(token)] if isinstance(current, list) else current[token]
            except (KeyError, IndexError, TypeError, ValueError) as exc:
                raise ValueError(f"Unresolvable native evidence pointer: {pointer}") from exc
    if (root / "comparisons.json").is_file():
        for comparison in json.loads((root / "comparisons.json").read_bytes()):
            StageComparison.model_validate(comparison)
    if (root / "scope.json").is_file():
        scope = DependencyScope.model_validate_json((root / "scope.json").read_bytes())
        report = json.loads((root / "report.json").read_bytes())
        if (
            report.get("semantic_sha256")
            and dependency_semantic_hash(
                stages, scope, version=report.get("semantic_version", "dependency-semantic-v1")
            )
            != report["semantic_sha256"]
        ):
            raise ValueError("Dependency semantic projection does not match the report")
    return {"passed": True, "contract": "dependency-bundle-v1", "entries": len(paths)}


def run_dependency_scan(
    *,
    project_root: Path,
    workspace_root: Path,
    source: Path,
    label: str,
    revision: str,
    database: Path,
    database_sha256: str,
    split: Literal["development", "pilot"] = "development",
    admission_file: Path | None = None,
    mutation: Mutation | None = None,
) -> dict[str, JsonValue]:
    # The pilot gate fixes scope and inputs before comparing direct and SBOM-mediated OSV.
    # Preserve partial evidence without treating an incomplete path as a clean result.
    source = source.resolve(strict=True)
    if split == "development" and not source.is_relative_to(
        (project_root / "test_cases/development").resolve()
    ):
        raise ValueError("Development scans require project-authored development case paths")
    workspace_root = workspace_root.resolve()
    if workspace_root.is_relative_to(source) or source.is_relative_to(
        workspace_root / "dependency-runs"
    ):
        raise ValueError("Workspace outputs must be outside the target")
    if split == "pilot":
        if mutation:
            raise ValueError("Mutations are restricted to development fixtures")
        if admission_file is None:
            raise ValueError("Public pilot requires a reviewed admission record")
        admission = json.loads(admission_file.read_bytes())
        if (
            admission.get("status") != "approved"
            or admission.get("revision") != revision
            or admission.get("oracle_review") != "student-confirmed"
            or admission.get("database_sha256") != database_sha256
        ):
            raise ValueError("Public pilot admission/oracle gate is not satisfied")
    run_id = "dep-run-" + uuid.uuid4().hex
    root = workspace_root / "dependency-runs" / run_id
    root.mkdir(parents=True, exist_ok=False)
    report: dict[str, JsonValue] = {
        "contract": "dependency-run-v1",
        "run_id": run_id,
        "recorded_at": utc_now().isoformat(),
        "split": split,
        "label": label,
        "revision": revision,
        "mutation": mutation,
        "semantic_version": SEMANTIC_VERSION,
        "state": "failed",
        "stages": {},
        "limitations": [
            "Development evidence is not student-adjudicated benchmark performance.",
            "Package appearance is not proof of successful per-package vulnerability matching.",
            "No runtime environment is installed or executed.",
            "Output files are polled against a 64 MiB cap; this is not an atomic filesystem quota.",
        ],
    }
    try:
        tools_path = project_root / "configs/dependency/tools.json"
        verify_tool_record(tools_path)
        for file in ("tools.json", "syft.yaml", "osv.toml"):
            _write(
                root,
                "configuration/" + file,
                (project_root / "configs/dependency" / file).read_bytes(),
            )
        prepared = prepare_workspace(
            workspace_root=workspace_root,
            target_source=source,
            source_label=label,
            revision=revision,
            source_kind="project-fixture" if split == "development" else "git",
            license_status="project-authored-private" if split == "development" else "identified",
        )
        snapshot = prepared.snapshot_result
        lock = snapshot.content_root / "uv.lock"
        lock_data = lock.read_bytes()
        lock_stage, scope = parse_lockfile(lock_data)
        if split == "pilot" and admission.get("content_sha256") != snapshot.snapshot.content_sha256:
            raise ValueError("Pilot snapshot does not match its admission record")
        if split == "pilot" and (
            admission.get("lockfile_sha256") != scope.input_sha256
            or admission.get("eligible_unique_identities") != len(scope.eligible)
            or scope.unsupported_pointers
            or scope.ambiguous_projections
        ):
            raise ValueError("Pilot lockfile scope does not match admission")
        if admission_file is not None:
            _write(root, "inputs/admission.json", admission_file.read_bytes())
        _write(
            root,
            "inputs/finite-oracle.json",
            (project_root / "test_cases/development/dependency-basic/expected.json").read_bytes(),
        )
        _write(root, "inputs/uv.lock", lock_data)
        _json(root, "inputs/snapshot.json", snapshot.snapshot.model_dump(mode="json"))
        _json(root, "scope.json", scope.model_dump(mode="json"))
        _json(root, "normalized/lockfile.json", lock_stage.model_dump(mode="json"))
        frozen = inspect_database(database, database_sha256, {name for name, _ in scope.eligible})
        _json(
            root,
            "database/manifest.json",
            {
                "archive_sha256": frozen.sha256,
                "ecosystem": "PyPI",
                "entries": cast(JsonValue, frozen.entries),
                "alias_policy": "transitive-alias-v1",
            },
        )
        for data in frozen.relevant_records.values():
            # Do not use upstream identifiers as filesystem paths.
            _write(root, f"database/records/{sha256_bytes(data)}.json", data)
        sources: list[JsonValue] = [
            {"path": path.relative_to(project_root).as_posix(), "sha256": sha256_file(path)}
            for path in sorted((project_root / "src").rglob("*.py"))
        ]
        _json(
            root,
            "harness-source.json",
            {"files": sources, "uv_lock_sha256": sha256_file(project_root / "uv.lock")},
        )
        docker = resolve_docker(None)
        if docker is None:
            raise ValueError("Docker executable not available")
        stage_results: dict[str, JsonValue] = {}
        stages = [lock_stage]
        started_ns = time.monotonic_ns()
        path_wall: dict[str, int] = {}

        def execute(stage_name: str, producer: str, input_file: Path) -> tuple[Path, int]:
            output = root / "native" / stage_name
            output.mkdir(parents=True, exist_ok=False)
            name = "sonic-dep-" + uuid.uuid4().hex
            config = root / "configuration" / ("syft.yaml" if producer == "syft" else "osv.toml")
            adjacent = snapshot.content_root / "osv-scanner.toml"
            argv = build_dependency_argv(
                docker=docker,
                name=name,
                producer=producer,
                input_file=input_file,
                output=output,
                config=config,
                database=frozen.path,
                adjacent_config=adjacent if adjacent.is_file() and producer == "osv" else None,
            )
            outputs = (
                [output / "syft.json", output / "bom.cdx.json"]
                if producer == "syft"
                else [output / "osv.json"]
            )
            capture = run_bounded_process(
                argv,
                cwd=project_root,
                environment=prepared.environment,
                timeout_seconds=120,
                max_stdout_bytes=2 * 1024**2,
                max_stderr_bytes=2 * 1024**2,
                monitored_files=outputs,
                max_generated_bytes=MAX_NATIVE_BYTES,
            )
            _write(root, f"native/{stage_name}/stdout.bin", capture.stdout)
            _write(root, f"native/{stage_name}/stderr.bin", capture.stderr)
            cleanup_ok: bool | None = None
            if capture.timed_out or capture.output_limited:
                cleanup_ok = cleanup_container(
                    docker=docker,
                    container_name=name,
                    cwd=project_root,
                    environment=prepared.environment,
                )
            evidence: list[JsonValue] = []
            for file in outputs:
                if file.is_symlink():
                    raise ValueError("Scanner output must not be a symbolic link")
                if file.is_file() and file.stat().st_size <= MAX_NATIVE_BYTES:
                    blob = prepared.blob_store.put(file.read_bytes())
                    evidence.append({"file": file.name, "sha256": blob.sha256})
            metadata: dict[str, JsonValue] = {
                "argv": list(capture.argv),
                "exit_code": capture.exit_code,
                "duration_ns": capture.duration_ns,
                "started_at": capture.started_at.isoformat(),
                "ended_at": capture.ended_at.isoformat(),
                "timed_out": capture.timed_out,
                "output_limited": capture.output_limited,
                "cleanup_succeeded": cleanup_ok,
                "environment_names": cast(JsonValue, sorted(prepared.environment)),
                "artifacts": evidence,
                "host_cli_peak_rss_bytes": capture.peak_rss_bytes,
            }
            _json(root, f"native/{stage_name}/execution.json", metadata)
            stage_results[stage_name] = metadata
            if capture.timed_out or capture.output_limited:
                raise ValueError(
                    f"{stage_name} exceeded time/output bounds; partial evidence retained"
                )
            return output, capture.exit_code if capture.exit_code is not None else -1

        for stage_name, producer in (("osv-direct", "osv"), ("syft", "syft"), ("osv-sbom", "osv")):
            path_started = time.monotonic_ns()
            try:
                input_file = (
                    root / ("mutations/bom.cdx.json" if mutation else "native/syft/bom.cdx.json")
                    if stage_name == "osv-sbom"
                    else lock
                )
                # Consume the preserved validated export, not a second discovery.
                if stage_name == "osv-sbom" and not any(
                    stage.stage == "cyclonedx" and stage.state == "complete" for stage in stages
                ):
                    raise ValueError("SBOM path skipped: validated Syft export is unavailable")
                output, code = execute(stage_name, producer, input_file)
                if producer == "syft":
                    stage = parse_syft((output / "syft.json").read_bytes())
                    if code != 0:
                        stage.state = "failed"
                    stages.append(stage)
                    _json(root, "normalized/syft.json", stage.model_dump(mode="json"))
                    cdx_data = (output / "bom.cdx.json").read_bytes()
                    validate_cyclonedx(cdx_data, project_root / "schemas/vendor/cyclonedx/1.6")
                    if mutation:
                        original_sha256 = sha256_bytes(cdx_data)
                        cdx_data = mutate_sbom(cdx_data, mutation)
                        validate_cyclonedx(cdx_data, project_root / "schemas/vendor/cyclonedx/1.6")
                        _write(root, "mutations/bom.cdx.json", cdx_data)
                        _json(
                            root,
                            "mutations/change.json",
                            {
                                "mutation": mutation,
                                "original_sha256": original_sha256,
                                "mutated_sha256": sha256_bytes(cdx_data),
                                "target": "requests@2.31.0",
                                "interpretation": "post-export mutation; not a Syft defect",
                            },
                        )
                    cdx = parse_cyclonedx(cdx_data)
                    if code != 0:
                        cdx.state = "failed"
                    stages.append(cdx)
                    _json(root, "normalized/cyclonedx.json", cdx.model_dump(mode="json"))
                else:
                    osv_stage = parse_osv(
                        (output / "osv.json").read_bytes(),
                        stage_name=cast(Literal["osv-direct", "osv-sbom"], stage_name),
                        exit_code=code,
                        alias_groups=frozen.aliases,
                    )
                    stages.append(osv_stage)
                    _json(root, f"normalized/{stage_name}.json", osv_stage.model_dump(mode="json"))
            except (OSError, ValueError, KeyError, TypeError, ValidationError) as exc:
                stage_results[stage_name + "-error"] = str(exc)[:2000]
            finally:
                path_wall[stage_name] = time.monotonic_ns() - path_started
        stage_map = {stage.stage: stage for stage in stages}
        comparisons: list[JsonValue] = []
        for left, right in (
            ("lockfile", "syft"),
            ("syft", "cyclonedx"),
            ("cyclonedx", "osv-sbom"),
            ("lockfile", "osv-direct"),
            ("osv-direct", "osv-sbom"),
        ):
            if left in stage_map and right in stage_map:
                comparisons.append(
                    compare_stages(stage_map[left], stage_map[right], scope).model_dump(mode="json")
                )
        _json(root, "comparisons.json", comparisons)
        report.update(
            {
                "state": "complete"
                if len(stages) == 5
                and all(stage.state == "complete" for stage in stages)
                and not any(key.endswith("-error") for key in stage_results)
                and not scope.unsupported_pointers
                and not scope.ambiguous_projections
                and all(
                    item.status == "identified" for stage in stages for item in stage.observations
                )
                else "partial",
                "stages": stage_results,
                "semantic_sha256": dependency_semantic_hash(stages, scope),
                "database_sha256": frozen.sha256,
                "snapshot_sha256": snapshot.snapshot.content_sha256,
                "paired_end_to_end_ns": time.monotonic_ns() - started_ns,
                "direct_path_wall_ns": path_wall["osv-direct"],
                "sbom_initial_path_wall_ns": path_wall["syft"] + path_wall["osv-sbom"],
                "sbom_consumer_only_wall_ns": path_wall["osv-sbom"],
                "path_timing_definition": (
                    "Container lifecycle, capture and stage normalization/validation; "
                    "includes Syft generation in initial SBOM path."
                ),
                "timing_boundary": (
                    "Prepared snapshot/config/database index to completed pair and normalization; "
                    "excludes initial downloads and preparation."
                ),
                "comparison_count": len(comparisons),
                "eligible_packages": len(scope.eligible),
                "separate_local_packages": len(scope.separate_local),
                "unsupported_scope_records": len(scope.unsupported_pointers),
                "ambiguous_projections": len(scope.ambiguous_projections),
                "relationship_fidelity": "not scored; native typed records retained",
            }
        )
        if sha256_file(frozen.path) != frozen.sha256 or sha256_file(lock) != scope.input_sha256:
            raise ValueError("Frozen input changed during execution")
    except (OSError, ValueError, KeyError, SnapshotError) as exc:
        report["state"] = "failed"
        report["error"] = str(exc)[:2000]
    _json(root, "report.json", report)
    seal_bundle(root)
    validate_dependency_bundle(root)
    return {**report, "bundle_root": str(root)}
