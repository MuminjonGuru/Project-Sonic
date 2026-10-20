"""Replay the paired dependency evidence; visibility and matching claims stay separate."""

import json
import re
from pathlib import Path
from typing import Literal, cast

from pydantic import JsonValue

from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.benchmarks.attempt_models import (
    DependencyAttemptEvidence,
    DependencyBoundaryEvidence,
    DependencyBoundaryStage,
    DependencyStageProgress,
)
from agentsec_evidence.benchmarks.dependency_boundary_plan import (
    CASE_ROOTS as BOUNDARY_ROOTS,
)
from agentsec_evidence.benchmarks.dependency_boundary_plan import (
    PARSER_FAILURES,
    boundary_inputs,
)
from agentsec_evidence.benchmarks.dependency_mutation_plan import ADMITTED_MUTATION_PINS, MUTATIONS
from agentsec_evidence.benchmarks.dependency_plan import CASE_ROOTS, ORACLE, dependency_inputs
from agentsec_evidence.benchmarks.evidence import bundle_inventory
from agentsec_evidence.benchmarks.models import (
    DependencyBenchmarkPlan,
    DependencyBoundaryCell,
    DependencyBoundaryPlan,
    DependencyCell,
    DependencyMutationCell,
    DependencyMutationPlan,
)
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
from agentsec_evidence.dependencies.mutations import Mutation, mutate_sbom
from agentsec_evidence.dependencies.parsers import (
    parse_cyclonedx,
    parse_lockfile,
    parse_osv,
    parse_syft,
)
from agentsec_evidence.dependencies.pipeline import validate_dependency_bundle
from agentsec_evidence.dependencies.validation import validate_cyclonedx
from agentsec_evidence.models.contracts import InventoryEntry, TargetSnapshot
from agentsec_evidence.research.retained import (
    MAX_ENTRY_BYTES,
    RetainedManifest,
    bounded_file,
    plain_path,
)

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


def _snapshot(
    execution: Path,
    root: Path,
    cell: DependencyCell | DependencyMutationCell | DependencyBoundaryCell,
) -> tuple[Path, TargetSnapshot]:
    metadata = root / "inputs/snapshot.json"
    if isinstance(cell, DependencyBoundaryCell) and cell.case_id in PARSER_FAILURES:
        # The unchanged producer fails before copying input metadata into its run bundle.
        # Its prepared snapshot still binds the failed input; do not fabricate native output.
        parent = plain_path(execution / "targets", directory=True)
        candidates = list(parent.iterdir())
        if len(candidates) != 1:
            raise ValueError("Ambiguous failed dependency snapshot")
        metadata = candidates[0] / "snapshot.json"
    target = TargetSnapshot.model_validate_json(bounded_file(metadata, MAX_ENTRY_BYTES))
    if not re.fullmatch(r"snapshot_[0-9a-f]{64}", target.snapshot_id):
        raise ValueError("Unsafe dependency snapshot identity")
    snapshot = execution / "targets" / target.snapshot_id
    plain_path(snapshot.parent, directory=True)
    if {p.name for p in snapshot.parent.iterdir()} != {target.snapshot_id}:
        raise ValueError("Ambiguous dependency target snapshot")
    if isinstance(cell, DependencyBoundaryCell):
        inputs = boundary_inputs(snapshot / "content", cell.case_id)
        relative = BOUNDARY_ROOTS[cell.case_id]
    else:
        source_case = (
            "dev-dependency-basic-v1" if isinstance(cell, DependencyMutationCell) else cell.case_id
        )
        inputs = dependency_inputs(snapshot / "content", source_case)
        relative = CASE_ROOTS[source_case]
    if inputs != cell.input_files:
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
        or target.source_label != "fixture:" + relative.rsplit("/", 1)[-1]
        or target.revision != "fixture-v1"
        or target.source_kind != "project-fixture"
        or target.license_status != "project-authored-private"
    ):
        raise ValueError("Dependency snapshot binding differs")
    return snapshot, target


def verify_dependency_execution(
    root: Path,
    snapshot: Path,
    database: Path,
    stage: str,
    mutation: Mutation | None = None,
    allow_no_packages: bool = False,
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
        root / ("mutations/bom.cdx.json" if mutation else "native/syft/bom.cdx.json")
        if stage == "osv-sbom"
        else snapshot / "content/uv.lock"
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
        or code
        not in ({0} if producer == "syft" else ({0, 1, 128} if allow_no_packages else {0, 1}))
        or record.get("timed_out") is not False
        or record.get("output_limited") is not False
        or record.get("cleanup_succeeded") is not None
        or type(record.get("duration_ns")) is not int
        or cast(int, record["duration_ns"]) < 0
    ):
        raise ValueError("Dependency invocation failed or differs from admitted offline treatment")
    outputs: tuple[str, ...] = (
        ("syft.json", "bom.cdx.json") if producer == "syft" else ("osv.json",)
    )
    if code == 128 and producer == "osv":
        if {p.name for p in (root / "native" / stage).iterdir()} != {
            "stdout.bin",
            "stderr.bin",
            "execution.json",
        }:
            raise ValueError(
                "No-package exit requires exactly retained process evidence without a report"
            )
        outputs = ()
    if record.get("artifacts") != [
        {"file": name, "sha256": sha256_file(root / "native" / stage / name)} for name in outputs
    ]:
        raise ValueError("Dependency execution artifact hashes differ")
    return record


def verify_dependency_attempt(
    project: Path,
    execution: Path,
    run_id: str,
    plan: DependencyBenchmarkPlan | DependencyMutationPlan | DependencyBoundaryPlan,
    cell: DependencyCell | DependencyMutationCell | DependencyBoundaryCell,
) -> DependencyAttemptEvidence | DependencyBoundaryEvidence:
    mutation: Mutation | None = None
    if isinstance(plan, DependencyMutationPlan) and isinstance(cell, DependencyMutationCell):
        if MUTATIONS.get(cell.case_id) != cell.mutation:
            raise ValueError("Mutation cell differs from admitted transformation")
        mutation = cell.mutation
    elif not (
        (isinstance(plan, DependencyBenchmarkPlan) and isinstance(cell, DependencyCell))
        or (isinstance(plan, DependencyBoundaryPlan) and isinstance(cell, DependencyBoundaryCell))
    ):
        raise ValueError("Dependency plan and cell contracts differ")
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
    if mutation is not None and any(
        pins.get(p) != digest or sha256_file(project / p) != digest
        for p, digest in ADMITTED_MUTATION_PINS.items()
    ):
        raise ValueError("Mutation replay requires the admitted transformation and expectations")
    for name in ("tools.json", "syft.yaml", "osv.toml"):
        if sha256_file(root / "configuration" / name) != pins["configs/dependency/" + name]:
            raise ValueError("Dependency configuration differs from frozen plan")
    if (
        isinstance(plan, DependencyBoundaryPlan)
        and isinstance(cell, DependencyBoundaryCell)
        and cell.case_id in PARSER_FAILURES
    ):
        return _verify_input_failure(
            project, root, snapshot, target, before, snapshot_before, report, plan, cell
        )
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
    observed_records = (
        {p.name for p in plain_path(record_root, directory=True).iterdir()}
        if record_root.exists()
        else set()
    )
    if observed_records != set(records):
        raise ValueError("Dependency advisory record set differs")
    if any(
        bounded_file(record_root / name, MAX_ENTRY_BYTES) != data for name, data in records.items()
    ):
        raise ValueError("Dependency retained advisory bytes differ")
    executions: dict[str, dict[str, object]] = {
        stage: verify_dependency_execution(
            root,
            snapshot,
            database,
            stage,
            mutation,
            isinstance(plan, DependencyBoundaryPlan)
            and isinstance(cell, DependencyBoundaryCell)
            and cell.case_id == "dev-dependency-empty-v1",
        )
        for stage in plan.stage_order
    }
    if len({cast(list[str], ex["argv"])[6] for ex in executions.values()}) != 3:
        raise ValueError("Dependency stages require distinct containers")
    syft_raw = bounded_file(root / "native/syft/syft.json", MAX_ENTRY_BYTES)
    cdx_raw = bounded_file(root / "native/syft/bom.cdx.json", MAX_ENTRY_BYTES)
    validate_cyclonedx(cdx_raw, project / "schemas/vendor/cyclonedx/1.6")
    if mutation is not None:
        # Replay the admitted transformation from preserved producer bytes; a rehashed
        # change receipt alone cannot establish what was changed or what OSV consumed.
        mutated = mutate_sbom(cdx_raw, mutation)
        mutation_root = plain_path(root / "mutations", directory=True)
        if {p.name for p in mutation_root.iterdir()} != {"bom.cdx.json", "change.json"}:
            raise ValueError("Mutation evidence set differs")
        if bounded_file(mutation_root / "bom.cdx.json", MAX_ENTRY_BYTES) != mutated:
            raise ValueError("Mutated SBOM differs from exact transformation replay")
        if _json(mutation_root / "change.json") != {
            "mutation": mutation,
            "original_sha256": sha256_bytes(cdx_raw),
            "mutated_sha256": sha256_bytes(mutated),
            "target": "requests@2.31.0",
            "interpretation": "post-export mutation; not a Syft defect",
        }:
            raise ValueError("Mutation change record differs from replay")
        validate_cyclonedx(mutated, project / "schemas/vendor/cyclonedx/1.6")
        cdx_raw = mutated
    stages = [lock]
    native_errors: dict[str, object] = {}
    for stage in ("osv-direct", "syft", "cyclonedx", "osv-sbom"):
        if stage == "syft":
            parsed = parse_syft(syft_raw)
        elif stage == "cyclonedx":
            parsed = parse_cyclonedx(cdx_raw)
        else:
            if executions[stage]["exit_code"] == 128:
                # Preserve the producer's missing-output diagnostic, but never invent a
                # zero-count normalized result for a report that OSV did not produce.
                try:
                    (root / f"native/{stage}/osv.json").read_bytes()
                except FileNotFoundError as exc:
                    native_errors[stage + "-error"] = str(exc)[:2000]
                else:
                    raise ValueError("Unexpected output for admitted no-report observation")
                continue
            parsed = parse_osv(
                bounded_file(root / f"native/{stage}/osv.json", MAX_ENTRY_BYTES),
                stage_name=cast(Literal["osv-direct", "osv-sbom"], stage),
                exit_code=cast(int, executions[stage]["exit_code"]),
                alias_groups=frozen.aliases,
            )
        stages.append(parsed)
    if {p.name for p in (root / "normalized").iterdir()} != {s.stage + ".json" for s in stages}:
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
        if left in stage_map and right in stage_map
    ]
    if json.loads(bounded_file(root / "comparisons.json", MAX_ENTRY_BYTES)) != comparisons:
        raise ValueError("Dependency comparison replay differs")
    complete = (
        len(stages) == 5
        and all(s.state == "complete" for s in stages)
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
        "mutation": mutation,
        "semantic_version": "dependency-semantic-v2",
        "state": terminal,
        "stages": {**executions, **native_errors},
        "semantic_sha256": semantic,
        "database_sha256": frozen.sha256,
        "snapshot_sha256": target.content_sha256,
        "comparison_count": len(comparisons),
        "eligible_packages": len(scope.eligible),
        "separate_local_packages": len(scope.separate_local),
        "unsupported_scope_records": len(scope.unsupported_pointers),
        "ambiguous_projections": len(scope.ambiguous_projections),
        "relationship_fidelity": "not scored; native typed records retained",
    }
    if any(report.get(key) != value for key, value in expected_report.items()) or "error" in report:
        raise ValueError("Dependency report differs from replayed evidence")
    if (mutation is None and (root / "mutations").exists()) or (
        root / "inputs/admission.json"
    ).exists():
        raise ValueError("Dependency benchmark contains unadmitted mutation or public input")
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
    if isinstance(plan, DependencyBoundaryPlan):
        return DependencyBoundaryEvidence(
            run_id=run_id,
            terminal_state=terminal,
            semantic_sha256=semantic,
            bundle_files=before,
            snapshot_files=snapshot_before,
            state=state,
            scanner_invocations=3,
            stages=tuple(
                DependencyBoundaryStage(
                    stage=cast(
                        Literal["lockfile", "syft", "cyclonedx", "osv-direct", "osv-sbom"], name
                    ),
                    state=stage_map[name].state if name in stage_map else "not-produced",
                    package_observations=len(stage_map[name].observations)
                    if name in stage_map
                    else None,
                    unique_pypi_projections=len(package_set(stage_map[name]))
                    if name in stage_map
                    else None,
                    advisory_match_records=len(stage_map[name].matches)
                    if name.startswith("osv-") and name in stage_map
                    else None,
                    native_exit_code=cast(int, executions[name]["exit_code"])
                    if name in executions
                    else None,
                    output_status="parsed" if name in stage_map else "no-report-no-packages",
                )
                for name in STAGE_ORDER
            ),
            eligible_packages=len(scope.eligible),
            separate_local_packages=len(scope.separate_local),
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


def _verify_input_failure(
    project: Path,
    root: Path,
    snapshot: Path,
    target: TargetSnapshot,
    before: RetainedManifest,
    snapshot_before: RetainedManifest,
    report: dict[str, object],
    plan: DependencyBoundaryPlan,
    cell: DependencyBoundaryCell,
) -> DependencyBoundaryEvidence:
    raw = bounded_file(snapshot / "content/uv.lock", MAX_ENTRY_BYTES)
    try:
        parse_lockfile(raw)
    except ValueError as exc:
        error = str(exc)[:2000]
    else:
        raise ValueError("Admitted parser-failure input unexpectedly parsed")
    expected: dict[str, object] = {
        "contract": "dependency-run-v1",
        "run_id": root.name,
        "split": "development",
        "label": target.source_label,
        "revision": "fixture-v1",
        "mutation": None,
        "semantic_version": "dependency-semantic-v2",
        "state": "failed",
        "stages": {},
        "error": error,
    }
    if set(report) != set(expected) | {"recorded_at", "limitations"} or any(
        report.get(k) != v for k, v in expected.items()
    ):
        raise ValueError("Pre-scan dependency failure differs from exact input replay")
    if {p.path for p in before.files} != {
        "configuration/tools.json",
        "configuration/syft.yaml",
        "configuration/osv.toml",
        "report.json",
        "manifest.json",
    }:
        raise ValueError("Pre-scan failure has missing or unexpected execution evidence")
    database = plain_path(project / plan.database.path, directory=False)
    if (
        database.stat().st_size != plan.database.bytes
        or sha256_file(database) != plan.database.sha256
    ):
        raise ValueError("Frozen database changed")
    if bundle_inventory(root) != before or bundle_inventory(snapshot) != snapshot_before:
        raise ValueError("Failed input evidence changed during replay")
    return DependencyBoundaryEvidence(
        run_id=root.name,
        terminal_state="failed",
        semantic_sha256=None,
        bundle_files=before,
        snapshot_files=snapshot_before,
        state="execution-failed",
        scanner_invocations=0,
        stages=tuple(
            DependencyBoundaryStage(
                stage=cast(
                    Literal["lockfile", "syft", "cyclonedx", "osv-direct", "osv-sbom"], name
                ),
                state="failed" if name == "lockfile" else "not-produced",
                output_status="input-parse-failed" if name == "lockfile" else "not-run",
            )
            for name in STAGE_ORDER
        ),
        input_failure="malformed-lockfile"
        if cell.case_id == "dev-dependency-malformed-v1"
        else "unsupported-lockfile-version",
    )
