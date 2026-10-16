"""Replay the paired dependency evidence; visibility and matching claims stay separate."""

import json
import re
from pathlib import Path
from typing import Literal, cast

from pydantic import JsonValue

from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.benchmarks.attempt_models import (
    DependencyAttemptEvidence,
    DependencyStageProgress,
)
from agentsec_evidence.benchmarks.dependency_plan import CASE_ROOTS, ORACLE, dependency_inputs
from agentsec_evidence.benchmarks.evidence import bundle_inventory
from agentsec_evidence.benchmarks.models import DependencyBenchmarkPlan, DependencyCell
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes, sha256_file
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.dependencies.analysis import (
    compare_stages,
    dependency_semantic_hash,
    package_set,
)
from agentsec_evidence.dependencies.database import inspect_database
from agentsec_evidence.dependencies.execution import build_dependency_argv
from agentsec_evidence.dependencies.models import StageEvidence
from agentsec_evidence.dependencies.parsers import (
    parse_cyclonedx,
    parse_lockfile,
    parse_osv,
    parse_syft,
)
from agentsec_evidence.dependencies.pipeline import validate_dependency_bundle
from agentsec_evidence.dependencies.validation import validate_cyclonedx
from agentsec_evidence.models.contracts import InventoryEntry, TargetSnapshot
from agentsec_evidence.research.retained import MAX_ENTRY_BYTES, bounded_file, plain_path

STAGE_ORDER = ("lockfile", "osv-direct", "syft", "cyclonedx", "osv-sbom")
COMPARISONS = (
    ("lockfile", "syft"),
    ("syft", "cyclonedx"),
    ("cyclonedx", "osv-sbom"),
    ("lockfile", "osv-direct"),
    ("osv-direct", "osv-sbom"),
)


def _json(path: Path) -> dict[str, object]:
    return cast(
        dict[str, object],
        load_agent_json(bounded_file(path, MAX_ENTRY_BYTES), max_bytes=MAX_ENTRY_BYTES),
    )


def _snapshot(execution: Path, root: Path, cell: DependencyCell) -> tuple[Path, TargetSnapshot]:
    target = TargetSnapshot.model_validate_json(
        bounded_file(root / "inputs/snapshot.json", MAX_ENTRY_BYTES)
    )
    if not re.fullmatch(r"snapshot_[0-9a-f]{64}", target.snapshot_id):
        raise ValueError("Unsafe dependency snapshot identity")
    snapshot = execution / "targets" / target.snapshot_id
    plain_path(snapshot.parent, directory=True)
    if {p.name for p in snapshot.parent.iterdir()} != {target.snapshot_id}:
        raise ValueError("Ambiguous dependency target snapshot")
    if dependency_inputs(snapshot / "content", cell.case_id) != cell.input_files:
        raise ValueError("Dependency snapshot differs from frozen inputs")
    if _json(snapshot / "snapshot.json") != target.model_dump(mode="json"):
        raise ValueError("Dependency snapshot metadata differs")
    inventory_raw = bounded_file(snapshot / "inventory.jsonl", MAX_ENTRY_BYTES)
    inventory = tuple(
        InventoryEntry.model_validate_json(line)
        for line in inventory_raw.splitlines()
        if line.strip()
    )
    if sorted((i.path, i.byte_length, i.sha256) for i in inventory) != [
        (f.path, f.bytes, f.sha256) for f in cell.input_files
    ]:
        raise ValueError("Dependency inventory differs from admitted case")
    content_sha = semantic_hash(
        [{"byte_length": i.byte_length, "path": i.path, "sha256": i.sha256} for i in inventory]
    )
    if (
        target.content_sha256 != content_sha
        or target.snapshot_id != "snapshot_" + content_sha
        or target.inventory_sha256 != sha256_bytes(inventory_raw)
        or target.file_count != len(cell.input_files)
        or target.total_bytes != sum(f.bytes for f in cell.input_files)
        or target.source_label != "fixture:" + CASE_ROOTS[cell.case_id].rsplit("/", 1)[-1]
        or target.revision != "fixture-v1"
        or target.source_kind != "project-fixture"
        or target.license_status != "project-authored-private"
    ):
        raise ValueError("Dependency snapshot binding differs")
    return snapshot, target


def _execution(
    root: Path,
    snapshot: Path,
    database: Path,
    stage: str,
) -> dict[str, object]:
    record = _json(root / f"native/{stage}/execution.json")
    argv = record.get("argv")
    if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv) or len(argv) < 8:
        raise ValueError("Invalid dependency invocation record")
    command = cast(list[str], argv)
    if Path(command[0]).name.lower() not in {"docker", "docker.exe"} or command[5] != "--name":
        raise ValueError("Unexpected dependency command")
    name = command[6]
    if not re.fullmatch(r"sonic-dep-[0-9a-f]{32}", name):
        raise ValueError("Invalid dependency container identity")
    producer = "syft" if stage == "syft" else "osv"
    input_file = (
        root / "native/syft/bom.cdx.json" if stage == "osv-sbom" else snapshot / "content/uv.lock"
    )
    adjacent = snapshot / "content/osv-scanner.toml"
    expected = build_dependency_argv(
        docker=Path(command[0]),
        name=name,
        producer=producer,
        input_file=input_file,
        output=root / "native" / stage,
        config=root / "configuration" / ("syft.yaml" if producer == "syft" else "osv.toml"),
        database=database,
        adjacent_config=adjacent if adjacent.is_file() and producer == "osv" else None,
    )
    code = record.get("exit_code")
    if (
        command != expected
        or type(code) is not int
        or code not in ({0} if producer == "syft" else {0, 1})
        or record.get("timed_out") is not False
        or record.get("output_limited") is not False
        or record.get("cleanup_succeeded") is not None
        or type(record.get("duration_ns")) is not int
        or cast(int, record["duration_ns"]) < 0
    ):
        raise ValueError("Dependency invocation failed or differs from admitted offline treatment")
    outputs = ("syft.json", "bom.cdx.json") if producer == "syft" else ("osv.json",)
    if record.get("artifacts") != [
        {"file": name, "sha256": sha256_file(root / "native" / stage / name)} for name in outputs
    ]:
        raise ValueError("Dependency execution artifact hashes differ")
    return record


def verify_dependency_attempt(
    project: Path,
    execution: Path,
    run_id: str,
    plan: DependencyBenchmarkPlan,
    cell: DependencyCell,
) -> DependencyAttemptEvidence:
    if not re.fullmatch(r"dep-run-[0-9a-f]{32}", run_id):
        raise ValueError("Invalid dependency run identity")
    root = execution / "dependency-runs" / run_id
    plain_path(root.parent, directory=True)
    if {p.name for p in root.parent.iterdir()} != {run_id}:
        raise ValueError("Dependency attempt requires exactly one paired run")
    before = bundle_inventory(root)
    validate_dependency_bundle(root)
    report = _json(root / "report.json")
    snapshot, target = _snapshot(execution, root, cell)
    snapshot_before = bundle_inventory(snapshot)
    pins = {p.path: p.sha256 for p in plan.pins}
    for name in ("tools.json", "syft.yaml", "osv.toml"):
        if sha256_file(root / "configuration" / name) != pins["configs/dependency/" + name]:
            raise ValueError("Dependency configuration differs from frozen plan")
    if sha256_file(root / "inputs/finite-oracle.json") != pins[ORACLE]:
        raise ValueError("Dependency expectation binding differs")
    if _json(root / "harness-source.json") != {
        "files": [{"path": p.path, "sha256": p.sha256} for p in plan.implementation],
        "uv_lock_sha256": pins["uv.lock"],
    }:
        raise ValueError("Dependency implementation evidence differs")
    lock_raw = bounded_file(root / "inputs/uv.lock", MAX_ENTRY_BYTES)
    if lock_raw != bounded_file(snapshot / "content/uv.lock", MAX_ENTRY_BYTES):
        raise ValueError("Dependency copied lockfile differs")
    lock, scope = parse_lockfile(lock_raw)
    if _json(root / "scope.json") != scope.model_dump(mode="json"):
        raise ValueError("Dependency scope replay differs")
    database = plain_path(project / plan.database.path, directory=False)
    if database.stat().st_size != plan.database.bytes:
        raise ValueError("Frozen dependency database size changed")
    frozen = inspect_database(database, plan.database.sha256, {name for name, _ in scope.eligible})
    # The full archive index exceeds the small agent-document node budget. Compare its
    # canonical producer bytes to reconstructed frozen entries, without relaxing any parser.
    expected_manifest = json_bytes(
        {
            "archive_sha256": frozen.sha256,
            "ecosystem": "PyPI",
            "entries": cast(JsonValue, frozen.entries),
            "alias_policy": "transitive-alias-v1",
        }
    )
    if bounded_file(root / "database/manifest.json", MAX_ENTRY_BYTES) != expected_manifest:
        raise ValueError("Dependency database entry manifest differs")
    records = {f"{sha256_bytes(data)}.json": data for data in frozen.relevant_records.values()}
    record_root = root / "database/records"
    if {p.name for p in record_root.iterdir()} != set(records):
        raise ValueError("Dependency advisory record set differs")
    if any(
        bounded_file(record_root / name, MAX_ENTRY_BYTES) != data for name, data in records.items()
    ):
        raise ValueError("Dependency retained advisory bytes differ")
    executions: dict[str, dict[str, object]] = {
        stage: _execution(root, snapshot, database, stage) for stage in plan.stage_order
    }
    if len({cast(list[str], ex["argv"])[6] for ex in executions.values()}) != 3:
        raise ValueError("Dependency stages require distinct containers")
    syft_raw = bounded_file(root / "native/syft/syft.json", MAX_ENTRY_BYTES)
    cdx_raw = bounded_file(root / "native/syft/bom.cdx.json", MAX_ENTRY_BYTES)
    validate_cyclonedx(cdx_raw, project / "schemas/vendor/cyclonedx/1.6")
    stages = [lock]
    for stage in ("osv-direct", "syft", "cyclonedx", "osv-sbom"):
        if stage == "syft":
            parsed = parse_syft(syft_raw)
        elif stage == "cyclonedx":
            parsed = parse_cyclonedx(cdx_raw)
        else:
            parsed = parse_osv(
                bounded_file(root / f"native/{stage}/osv.json", MAX_ENTRY_BYTES),
                stage_name=cast(Literal["osv-direct", "osv-sbom"], stage),
                exit_code=cast(int, executions[stage]["exit_code"]),
                alias_groups=frozen.aliases,
            )
        stages.append(parsed)
    if {p.name for p in (root / "normalized").iterdir()} != {s + ".json" for s in STAGE_ORDER}:
        raise ValueError("Dependency normalized stage set differs")
    for parsed in stages:
        retained = StageEvidence.model_validate_json(
            bounded_file(root / f"normalized/{parsed.stage}.json", MAX_ENTRY_BYTES)
        )
        if retained != parsed:
            raise ValueError("Dependency native normalization replay differs")
    stage_map: dict[str, StageEvidence] = {s.stage: s for s in stages}
    comparisons = [
        compare_stages(stage_map[left], stage_map[right], scope).model_dump(mode="json")
        for left, right in COMPARISONS
    ]
    if json.loads(bounded_file(root / "comparisons.json", MAX_ENTRY_BYTES)) != comparisons:
        raise ValueError("Dependency comparison replay differs")
    complete = (
        all(s.state == "complete" for s in stages)
        and not scope.unsupported_pointers
        and not scope.ambiguous_projections
        and all(o.status == "identified" for s in stages for o in s.observations)
    )
    terminal: Literal["complete", "partial"] = "complete" if complete else "partial"
    semantic = dependency_semantic_hash(stages, scope)
    expected_report = {
        "contract": "dependency-run-v1",
        "run_id": run_id,
        "split": "development",
        "label": target.source_label,
        "revision": "fixture-v1",
        "mutation": None,
        "semantic_version": "dependency-semantic-v2",
        "state": terminal,
        "stages": executions,
        "semantic_sha256": semantic,
        "database_sha256": frozen.sha256,
        "snapshot_sha256": target.content_sha256,
        "comparison_count": 5,
        "eligible_packages": len(scope.eligible),
        "separate_local_packages": len(scope.separate_local),
        "unsupported_scope_records": len(scope.unsupported_pointers),
        "ambiguous_projections": len(scope.ambiguous_projections),
        "relationship_fidelity": "not scored; native typed records retained",
    }
    if any(report.get(key) != value for key, value in expected_report.items()) or "error" in report:
        raise ValueError("Dependency report differs from replayed evidence")
    if (root / "mutations").exists() or (root / "inputs/admission.json").exists():
        raise ValueError("Dependency benchmark does not admit mutation or public input")
    for key in (
        "paired_end_to_end_ns",
        "direct_path_wall_ns",
        "sbom_initial_path_wall_ns",
        "sbom_consumer_only_wall_ns",
    ):
        if type(report.get(key)) is not int or cast(int, report[key]) < 0:
            raise ValueError("Dependency timing missing or invalid")
    if (
        before != bundle_inventory(root)
        or snapshot_before != bundle_inventory(snapshot)
        or sha256_file(database) != plan.database.sha256
    ):
        raise ValueError("Dependency evidence changed during verification")
    state: Literal["partial-analysis", "completed-with-findings", "completed-without-findings"] = (
        "partial-analysis"
        if not complete
        else (
            "completed-with-findings"
            if any(s.matches for s in stages)
            else "completed-without-findings"
        )
    )
    return DependencyAttemptEvidence(
        run_id=run_id,
        terminal_state=terminal,
        semantic_sha256=semantic,
        bundle_files=before,
        snapshot_files=snapshot_before,
        state=state,
        stages=tuple(
            DependencyStageProgress(
                stage=s.stage,
                state=s.state,
                package_observations=len(s.observations),
                unique_pypi_projections=len(package_set(s)),
                advisory_match_records=len(s.matches) if s.stage.startswith("osv-") else None,
            )
            for s in stages
        ),
        eligible_packages=len(scope.eligible),
        separate_local_packages=len(scope.separate_local),
    )
