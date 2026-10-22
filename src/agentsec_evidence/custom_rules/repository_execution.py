"""Sequential custom-family execution bound to a fully replayed admitted pilot."""

from __future__ import annotations

import argparse
import json
import time
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any, cast

from pydantic import JsonValue

from agentsec_evidence.agents.execution import AgentAuditToolConfig
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes, sha256_file
from agentsec_evidence.core.io import atomic_write_bytes
from agentsec_evidence.custom_rules.repository_contracts import (
    TARGETS,
    RepositoryCustomPlan,
    current_native,
    prepare_plan,
    validate_plan,
    verify_base,
)
from agentsec_evidence.custom_rules.shared_execution import (
    PROFILE,
    _portable_command,
    _read_capture,
    capture_ok,
    inspect_image,
    run_capture,
    worker_argv,
)
from agentsec_evidence.execution.config import load_toml_config
from agentsec_evidence.orchestration.shared import minimal_environment, resolve_docker
from agentsec_evidence.pilot.runner import evidence_records, save
from agentsec_evidence.reporting.custom_contracts import FAMILIES, IMAGE, Family
from agentsec_evidence.research.retained import (
    RetainedManifest,
    bounded_file,
    plain_path,
    read_retained_research,
)


def argv_for(
    docker: Path, tool: AgentAuditToolConfig, root: Path, batch: int, name: str, family: Family
) -> list[str]:
    argv = worker_argv(docker, tool, root, batch, name, family)
    if family.key == "tool-execution":
        index = argv.index("agentsec_evidence.custom_rules.tool_execution_worker")
        argv[index] = "agentsec_evidence.custom_rules.tool_execution_v2_worker"
    return argv


def schedule(plan: RepositoryCustomPlan) -> list[dict[str, Any]]:
    return [
        {
            "key": f"runs/r{rep:02d}/b{batch:03d}/{family.key}",
            "repetition": rep,
            "batch": batch,
            "family": family.key,
            "state": "not-run",
            "native_state": None,
            "finding_records": None,
            "duration_ns": None,
        }
        for rep in range(1, plan.repetitions + 1)
        for batch in range(len(plan.requests))
        for family in FAMILIES
    ]


def check_prepared(root: Path, plan: RepositoryCustomPlan) -> None:
    validate_plan(plan)
    actual = {
        p.relative_to(root / "implementation").as_posix()
        for p in (root / "implementation").rglob("*")
        if p.is_file()
    }
    if actual != set(plan.source_pins):
        raise ValueError("Trusted implementation membership differs")
    for path, digest in plan.source_pins.items():
        if sha256_bytes(bounded_file(root / "implementation" / path, 1024**2)) != digest:
            raise ValueError("Trusted implementation bytes changed")
    for batch, request in enumerate(plan.requests):
        base = root / f"batches/{batch:03d}"
        if bounded_file(base / "request.json", 256 * 1024) != request.model_dump_json().encode():
            raise ValueError("Worker request changed")
        actual = {
            p.relative_to(base / "target").as_posix()
            for p in (base / "target").rglob("*")
            if p.is_file()
        }
        if actual != set(request.selected):
            raise ValueError("Worker view membership differs")
        for entry in request.inventory:
            raw = bounded_file(base / "target" / entry.path, 256 * 1024)
            if sha256_bytes(raw) != entry.sha256 or len(raw) != entry.byte_length:
                raise ValueError("Worker input changed")


def run_repository_custom(
    project: Path,
    baseline: Path,
    database: Path,
    output: Path,
    *,
    target: str,
    repetitions: int = 3,
    docker: Path | None = None,
) -> dict[str, Any]:
    project, baseline = plain_path(project, directory=True), plain_path(baseline, directory=True)
    output = output.absolute()
    plain_path(output.parent, directory=True)
    if (
        output.exists()
        or output == project / "workspace"
        or not output.is_relative_to(project / "workspace")
    ):
        raise ValueError("Use a fresh ignored workspace attempt; no overwrite or automatic resume")
    plan, inputs, sources = prepare_plan(project, baseline, target, database, output, repetitions)
    validate_plan(plan)
    executable = resolve_docker(docker)
    if executable is None:
        raise ValueError("Docker required; no target parsing on the host")
    tool = load_toml_config(project / "configs/tools/agent-audit.toml", AgentAuditToolConfig)
    output.mkdir()
    start = time.perf_counter_ns()
    result: dict[str, Any] = {
        "contract": "repository-custom-execution-v1",
        "finished": False,
        "error": None,
        "rows": schedule(plan),
        "duration_ns": None,
        "profile": PROFILE.model_dump(mode="json"),
    }
    save(output / "plan.json", plan.model_dump(mode="json"))
    try:
        for path, raw in sources.items():
            atomic_write_bytes(output / "implementation" / path, raw)
        atomic_write_bytes(output / "tool.toml", tool.raw)
        for batch, request in enumerate(plan.requests):
            base = output / f"batches/{batch:03d}"
            atomic_write_bytes(base / "request.json", request.model_dump_json().encode())
            for entry in request.inventory:
                atomic_write_bytes(base / "target" / entry.path, inputs[entry.path])
        environment = minimal_environment(output / "runtime")
        inspect_image(
            run_capture(
                [str(executable), "image", "inspect", IMAGE],
                output / "preflight",
                environment,
                timeout=30,
            )
        )
        check_prepared(output, plan)
        for row in result["rows"]:
            family = next(f for f in FAMILIES if f.key == row["family"])
            name = "repo-custom-" + uuid.uuid4().hex
            argv = argv_for(executable, tool.value, output, row["batch"], name, family)
            directory = output / row["key"]
            row["state"] = "failed"
            save(output / "result.json", result)
            try:
                capture = run_capture(argv, directory, environment)
            finally:
                cleanup = run_capture(
                    [str(executable), "rm", "--force", name],
                    directory / "cleanup",
                    environment,
                    timeout=15,
                )
                if not (
                    capture_ok(cleanup, {0})
                    or (capture_ok(cleanup, {1}) and b"no such container" in cleanup.stderr.lower())
                ):
                    raise ValueError("Container cleanup not confirmed")
            if not capture_ok(capture, {0, 1, 2}):
                raise ValueError("Worker failed or exceeded its resource budget")
            native = current_native(
                capture.stdout,
                (output / f"batches/{row['batch']:03d}/request.json").read_bytes(),
                family,
                capture.exit_code,
            )
            row.update(
                state="validated",
                native_state=native.execution_state,
                finding_records=sum(len(f.findings or []) for f in native.files),
                duration_ns=capture.duration_ns,
            )
            save(output / "result.json", result)
            print(f"{target} {row['key']}: {native.execution_state}", flush=True)
        check_prepared(output, plan)
        if sha256_file(baseline / "evidence-manifest.json") != plan.baseline_manifest_sha256:
            raise ValueError("Parent evidence seal changed during execution")
        result["finished"] = True
    except BaseException as exc:
        result["error"] = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        result["duration_ns"] = time.perf_counter_ns() - start
        save(output / "result.json", result)
        manifest = RetainedManifest.model_validate({"files": evidence_records(output)})
        save(output / "evidence-manifest.json", manifest.model_dump(mode="json"))
    return result


def verify_repository_custom(project: Path, root: Path, database: Path) -> dict[str, Any]:
    retained = read_retained_research(root)
    plan = RepositoryCustomPlan.model_validate_json(retained.read("plan.json"))
    check_prepared(root, plan)
    baseline = Path(plan.baseline_root)
    report = verify_base(project, baseline, plan.target, database)
    _, _, report_path, _ = TARGETS[plan.target]
    if (
        sha256_file(baseline / "evidence-manifest.json") != plan.baseline_manifest_sha256
        or sha256_file(baseline / report_path) != plan.baseline_report_sha256
        or report["content_sha256"] != plan.content_sha256
    ):
        raise ValueError("Parent evidence differs")
    proof = json.loads(bounded_file(baseline / "preparation/git-verification.json", 4 * 1024**2))
    selected = sorted(
        f["source"]["path"] for f in proof["files"] if f["source"]["path"].endswith(".py")
    )
    if selected != [e.path for e in plan.inventory]:
        raise ValueError("Custom selection differs from full pinned Python selection")
    for entry in plan.inventory:
        raw = bounded_file(baseline / "preparation/source" / entry.path, 256 * 1024)
        if (sha256_bytes(raw), len(raw)) != (entry.sha256, entry.byte_length):
            raise ValueError("Custom file differs from admitted parent bytes")
    result = json.loads(retained.read("result.json"))
    if (
        result.get("contract") != "repository-custom-execution-v1"
        or result.get("finished") is not True
        or result.get("error") is not None
        or result.get("profile") != PROFILE.model_dump(mode="json")
    ):
        raise ValueError("Custom attempt incomplete; retain failures, never report them as clean")
    preflight = _read_capture(retained.files, "preflight")
    if list(preflight.argv[1:]) != ["image", "inspect", IMAGE]:
        raise ValueError("Preflight command differs")
    inspect_image(preflight)
    tool = load_toml_config(root / "tool.toml", AgentAuditToolConfig).value
    rows = result["rows"]
    planned = schedule(plan)
    if len(rows) != len(planned):
        raise ValueError("Missing or additional custom rows")
    grouped: dict[tuple[str, int], list[Any]] = defaultdict(list)
    native_records = []
    for row, expected in zip(rows, planned, strict=True):
        if any(row[k] != expected[k] for k in ("key", "family", "repetition", "batch")):
            raise ValueError("Custom schedule differs")
        family = next(f for f in FAMILIES if f.key == row["family"])
        capture = _read_capture(retained.files, row["key"])
        name = capture.argv[capture.argv.index("--name") + 1]
        argv = argv_for(root / "plan.json", tool, root, row["batch"], name, family)
        if _portable_command(
            list(capture.argv), plan.execution_root, row["batch"]
        ) != _portable_command(argv, str(root.absolute()), row["batch"]):
            raise ValueError("Worker command or isolation differs")
        cleanup = _read_capture(retained.files, row["key"] + "/cleanup")
        if (
            cleanup.argv[0] != capture.argv[0]
            or list(cleanup.argv[1:]) != ["rm", "--force", name]
            or not (
                capture_ok(cleanup, {0})
                or (capture_ok(cleanup, {1}) and b"no such container" in cleanup.stderr.lower())
            )
        ):
            raise ValueError("Cleanup not verified")
        if not capture_ok(capture, {0, 1, 2}):
            raise ValueError("Unsuccessful capture")
        native = current_native(
            capture.stdout,
            retained.read(f"batches/{row['batch']:03d}/request.json"),
            family,
            capture.exit_code,
        )
        if (
            row["state"] != "validated"
            or row["native_state"] != native.execution_state
            or row["finding_records"] != sum(len(f.findings or []) for f in native.files)
            or row["duration_ns"] != capture.duration_ns
        ):
            raise ValueError("Custom table differs from native evidence")
        grouped[(family.key, row["repetition"])].extend(native.files)
        native_records.append(
            {
                **row,
                "native_sha256": sha256_bytes(capture.stdout),
                "native_json": capture.stdout.decode("utf-8"),
                "native_exit_code": capture.exit_code,
                "native": native.model_dump(mode="json"),
            }
        )
    summaries = []
    for family in FAMILIES:
        hashes = []
        for rep in range(1, plan.repetitions + 1):
            files = sorted(grouped[family.key, rep], key=lambda f: f.path)
            if [f.path for f in files] != selected:
                raise ValueError("Partition lost or duplicated files")
            hashes.append(
                semantic_hash(cast(JsonValue, [f.model_dump(mode="json") for f in files]))
            )
        first = grouped[family.key, 1]
        summaries.append(
            {
                "family": family.key,
                "selected_files": len(first),
                "analyzed_files": sum(f.state == "analyzed" for f in first),
                "incomplete_files": sum(f.state != "analyzed" for f in first),
                "condition_records": sum(len(f.findings or []) for f in first),
                "inventory_records": sum(len(f.inventory) for f in first),
                "limitation_records": sum(len(f.limitations_observed) for f in first),
                "repeatability": "not-assessed"
                if len(hashes) == 1
                else "equal"
                if len(set(hashes)) == 1
                else "different",
                "semantic_sha256": hashes,
            }
        )
    if sha256_file(root / "evidence-manifest.json") != retained.manifest_sha256:
        raise ValueError("Evidence seal changed during replay")
    return {
        "contract": "repository-custom-verification-v1",
        "passed": True,
        "evidence_manifest_sha256": retained.manifest_sha256,
        "plan": plan.model_dump(mode="json"),
        "baseline_report": report,
        "baseline_report_json": bounded_file(baseline / report_path, 4 * 1024**2).decode("utf-8"),
        "artifact_inventory": json.loads(
            bounded_file(baseline / "preparation/artifact-inventory.json", 4 * 1024**2)
        ),
        "artifact_inventory_sha256": sha256_file(baseline / "preparation/artifact-inventory.json"),
        "families": summaries,
        "rows": native_records,
        "unique_vulnerabilities": None,
        "scanner_invocations_during_replay": 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("run", "verify"))
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--target", choices=tuple(TARGETS))
    parser.add_argument("--repetitions", type=int, default=3)
    args = parser.parse_args()
    if args.mode == "run":
        if args.baseline is None or args.target is None:
            parser.error("run requires --baseline and --target")
        run_repository_custom(
            args.project,
            args.baseline,
            args.database,
            args.output,
            target=args.target,
            repetitions=args.repetitions,
        )
    result = verify_repository_custom(args.project, args.output, args.database)
    print(
        json.dumps(
            {k: result[k] for k in ("contract", "passed", "evidence_manifest_sha256", "families")},
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
