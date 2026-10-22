"""Finite shared-input rehearsal; no public-repository admission or target execution."""

from __future__ import annotations

import argparse
import dataclasses
import json
import time
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any, cast

from pydantic import JsonValue

from agentsec_evidence.agents.execution import AgentAuditToolConfig, build_agent_argv
from agentsec_evidence.agents.records import AgentInputRequest
from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.core.io import atomic_write_bytes
from agentsec_evidence.custom_rules.shared_inputs import (
    REGISTRY_PINS,
    SharedPlan,
    build_plan,
    prepare_shared,
    read_registry,
)
from agentsec_evidence.execution.config import ExecutionProfile, load_toml_config
from agentsec_evidence.execution.process import ProcessCapture, run_bounded_process
from agentsec_evidence.models.contracts import ContractModel
from agentsec_evidence.orchestration.shared import minimal_environment, resolve_docker
from agentsec_evidence.pilot.runner import evidence_records, save
from agentsec_evidence.reporting.custom_contracts import (
    FAMILIES,
    IMAGE,
    NATIVE,
    Family,
    NativeFile,
    NativeReport,
    expected_exit,
    validate_native,
)
from agentsec_evidence.research.retained import (
    RetainedManifest,
    bounded_file,
    plain_path,
    read_retained_research,
)

PROFILE = ExecutionProfile.model_validate(
    {
        "profile_id": "shared-custom-authored-v1",
        "profile_kind": "development",
        "network": "denied",
        "target_mount": "read-only",
        "max_workers": 1,
        "limits": {
            "timeout_seconds": 90,
            "cpu_count": 1,
            "memory_mb": 512,
            "pids": 64,
            "tmpfs_mb": 64,
            "max_stdout_bytes": 2 * 1024**2,
            "max_stderr_bytes": 1024**2,
            "max_native_bytes": 2 * 1024**2,
        },
    }
)


def worker_argv(
    docker: Path, tool: AgentAuditToolConfig, root: Path, batch: int, name: str, family: Family
) -> list[str]:
    if family not in FAMILIES:
        raise ValueError("Unknown shared worker")
    argv = build_agent_argv(
        docker=docker,
        tool=tool,
        profile=PROFILE,
        name=name,
        target=root / f"batches/{batch:03d}/target",
        worker_source=root / "implementation/src",
        request=root / f"batches/{batch:03d}/request.json",
    )
    if argv[-4:] != ["-m", "agentsec_evidence.agents.worker", "/request.json", "/target"]:
        raise ValueError("Base invocation contract changed")
    # Replace only the known trusted module, never a target-supplied command.
    return [
        *argv[:-4],
        "-X",
        "utf8",
        "-m",
        "agentsec_evidence.custom_rules." + family.worker,
        "/request.json",
        "/target",
        "--fail-on",
        family.threshold,
    ]


def capture_ok(capture: ProcessCapture, exits: set[int]) -> bool:
    return capture.exit_code in exits and not any(
        (
            capture.timed_out,
            capture.output_limited,
            capture.stdout_truncated,
            capture.stderr_truncated,
        )
    )


def save_capture(directory: Path, capture: ProcessCapture) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    atomic_write_bytes(directory / "stdout.bin", capture.stdout)
    atomic_write_bytes(directory / "stderr.bin", capture.stderr)
    record = dataclasses.asdict(capture)
    del record["stdout"], record["stderr"]
    save(directory / "process.json", record)


def run_capture(
    argv: list[str], directory: Path, environment: dict[str, str], *, timeout: int = 90
) -> ProcessCapture:
    directory.mkdir(parents=True, exist_ok=False)
    save(directory / "command.json", {"argv": argv})
    try:
        capture = run_bounded_process(
            argv,
            cwd=directory,
            environment=environment,
            timeout_seconds=timeout,
            max_stdout_bytes=PROFILE.limits.max_stdout_bytes,
            max_stderr_bytes=PROFILE.limits.max_stderr_bytes,
        )
        save_capture(directory, capture)
        return capture
    except BaseException as exc:
        save(directory / "failure.json", {"type": type(exc).__name__})
        raise


def inspect_image(capture: ProcessCapture) -> None:
    if not capture_ok(capture, {0}):
        raise ValueError("Pinned image preflight did not finish")
    images = json.loads(capture.stdout)
    if len(images) != 1 or images[0].get("Id") != IMAGE or images[0].get("Os") != "linux":
        raise ValueError("Pinned Linux image not present; no pull or fallback")


def check_native(
    raw: bytes, request_raw: bytes, family: Family, exit_code: int | None
) -> NativeReport:
    request = AgentInputRequest.model_validate(load_agent_json(request_raw, max_bytes=256 * 1024))
    native = NATIVE.validate_python(load_agent_json(raw, max_bytes=PROFILE.limits.max_native_bytes))
    if native.contract != family.contract or native.request_sha256 != sha256_bytes(request_raw):
        raise ValueError("Wrong worker or exact request binding")
    validate_native(native, request)
    if exit_code != expected_exit(native):
        raise ValueError("Process exit and worker state differ")
    return native


def planned_rows(plan: SharedPlan) -> list[dict[str, Any]]:
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
            "error": None,
        }
        for rep in range(1, plan.repetitions + 1)
        for batch in range(len(plan.requests))
        for family in FAMILIES
    ]


def verify_prepared(root: Path, plan: SharedPlan) -> None:
    for path, expected in plan.source_pins.items():
        if sha256_bytes(bounded_file(root / "implementation" / path, 1024**2)) != expected:
            raise ValueError("Frozen implementation changed")
    for family in FAMILIES:
        read_registry(bounded_file(root / "registries" / family.registry, 256 * 1024), family.key)
    for batch, request in enumerate(plan.requests):
        raw = bounded_file(root / f"batches/{batch:03d}/request.json", 256 * 1024)
        if raw != request.model_dump_json().encode():
            raise ValueError("Prepared request changed")
        target = root / f"batches/{batch:03d}/target"
        actual = {p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file()}
        if actual != set(request.selected):
            raise ValueError("Prepared view membership changed")
        for entry in request.inventory:
            data = bounded_file(target / entry.path, 256 * 1024)
            if len(data) != entry.byte_length or sha256_bytes(data) != entry.sha256:
                raise ValueError("Prepared input bytes changed")


def run_shared(
    project: Path,
    output: Path,
    *,
    max_files: int = 64,
    repetitions: int = 2,
    docker: Path | None = None,
) -> dict[str, Any]:
    project = plain_path(project, directory=True)
    output = output.absolute()
    if output == project / "workspace" or not output.is_relative_to(project / "workspace"):
        raise ValueError("New attempt must be inside the ignored project workspace")
    plain_path(output.parent, directory=True)
    if output.exists():
        raise ValueError("Attempt already exists; use a fresh path, never overwrite or resume it")
    prepared = prepare_shared(project, max_files=max_files, repetitions=repetitions)
    plan = prepared.plan
    executable = resolve_docker(docker)
    if executable is None:
        raise ValueError("Docker required; no host-scanning fallback")
    tool = load_toml_config(project / "configs/tools/agent-audit.toml", AgentAuditToolConfig)
    output.mkdir()
    start = time.perf_counter_ns()
    rows = planned_rows(plan)
    result: dict[str, Any] = {
        "contract": "shared-custom-authored-execution-v1",
        "rows": rows,
        "finished": False,
        "error": None,
        "prepared_unchanged": None,
        "duration_ns": None,
        "profile": PROFILE.model_dump(mode="json"),
        "target_execution": False,
        "unique_vulnerabilities": None,
        "execution_root": str(output),
    }
    save(output / "plan.json", plan.model_dump(mode="json"))
    save(output / "result.json", result)
    try:
        for path, raw in prepared.sources.items():
            atomic_write_bytes(output / "implementation" / path, raw)
        for path, raw in prepared.registries.items():
            atomic_write_bytes(output / "registries" / path, raw)
        atomic_write_bytes(output / "tool.toml", tool.raw)
        for batch, request in enumerate(plan.requests):
            base = output / f"batches/{batch:03d}"
            for entry in request.inventory:
                atomic_write_bytes(base / "target" / entry.path, prepared.inputs[entry.path])
            atomic_write_bytes(base / "request.json", request.model_dump_json().encode())
        environment = minimal_environment(output / "runtime")
        preflight = run_capture(
            [str(executable), "image", "inspect", IMAGE],
            output / "preflight",
            environment,
            timeout=30,
        )
        inspect_image(preflight)
        verify_prepared(output, plan)
        for row in rows:
            family = next(f for f in FAMILIES if f.key == row["family"])
            name = "shared-custom-" + uuid.uuid4().hex
            argv = worker_argv(executable, tool.value, output, row["batch"], name, family)
            directory = output / row["key"]
            row["state"] = "failed"
            try:
                capture = run_capture(argv, directory, environment)
            finally:
                cleanup = run_capture(
                    [str(executable), "rm", "--force", name],
                    directory / "cleanup",
                    environment,
                    timeout=15,
                )
                cleaned = capture_ok(cleanup, {0}) or (
                    capture_ok(cleanup, {1}) and b"no such container" in cleanup.stderr.lower()
                )
                if not cleaned:
                    raise ValueError("Container cleanup not confirmed; remaining workers not run")
            row["duration_ns"] = capture.duration_ns
            if not capture_ok(capture, {0, 1, 2}):
                raise ValueError("Worker timed out, failed or exceeded its output budget")
            native = check_native(
                capture.stdout,
                bounded_file(output / f"batches/{row['batch']:03d}/request.json", 256 * 1024),
                family,
                capture.exit_code,
            )
            row.update(
                state="validated",
                native_state=native.execution_state,
                finding_records=sum(len(f.findings or []) for f in native.files),
            )
            save(output / "result.json", result)
            print(f"{row['key']}: {native.execution_state}", flush=True)
        verify_prepared(output, plan)
        result["prepared_unchanged"] = True
        result["finished"] = True
    except BaseException as exc:
        result["error"] = {"type": type(exc).__name__, "message": str(exc)}
        for row in rows:
            if row["state"] == "failed":
                row["error"] = type(exc).__name__
        raise
    finally:
        result["duration_ns"] = time.perf_counter_ns() - start
        save(output / "result.json", result)
        manifest = RetainedManifest.model_validate({"files": evidence_records(output)})
        save(output / "evidence-manifest.json", manifest.model_dump(mode="json"))
    return result


def _read_capture(files: dict[str, bytes], key: str) -> ProcessCapture:
    record = json.loads(files[key + "/process.json"])
    # ProcessCapture's dataclass does not validate JSON types; bind flags and counts here.
    for flag in ("timed_out", "output_limited", "stdout_truncated", "stderr_truncated"):
        if type(record.get(flag)) is not bool:
            raise ValueError("Invalid retained process flag")
    for count in ("duration_ns", "peak_rss_bytes"):
        if type(record.get(count)) is not int or record[count] < 0:
            raise ValueError("Invalid retained process measurement")
    if type(record.get("exit_code")) is not int:
        raise ValueError("Retained worker has no integer exit code")
    command = json.loads(files[key + "/command.json"])["argv"]
    if command != record["argv"]:
        raise ValueError("Retained command and process differ")
    return ProcessCapture(
        **record, stdout=files[key + "/stdout.bin"], stderr=files[key + "/stderr.bin"]
    )


def _portable_command(argv: list[str], root: str, batch: int) -> list[str]:
    """Strip host locations only; retain mount roles and every execution-policy flag."""
    result = list(argv)
    result[0] = "docker"
    mounts = {
        "/target,readonly": f"{root}/batches/{batch:03d}/target",
        "/app/src,readonly": f"{root}/implementation/src",
        "/request.json,readonly": f"{root}/batches/{batch:03d}/request.json",
    }
    for index, part in enumerate(result):
        if part == "--name":
            result[index + 1] = "container-name"
        if part == "--mount":
            mount = result[index + 1]
            if not mount.startswith("type=bind,source=") or mount.count(",target=") != 1:
                raise ValueError("Invalid retained bind mount")
            source, target = mount.removeprefix("type=bind,source=").split(",target=")
            if target not in mounts or source.replace("\\", "/") != mounts[target].replace(
                "\\", "/"
            ):
                raise ValueError("Unexpected retained mount role")
            result[index + 1] = "type=bind,source=HOST,target=" + target
    return result


def verify_shared(root: Path) -> dict[str, Any]:
    """Recompute assertions from sealed native bytes; never run scanners during verification."""
    retained = read_retained_research(root)
    plan = SharedPlan.model_validate(
        load_agent_json(retained.read("plan.json"), max_bytes=4 * 1024**2)
    )
    expected_plan = build_plan(
        plan.inventory, plan.source_pins, max_files=plan.max_files, repetitions=plan.repetitions
    )
    if plan != expected_plan or len(plan.inventory) != 385 or plan.registry_pins != REGISTRY_PINS:
        raise ValueError("Retained plan differs from finite deterministic treatment")
    verify_prepared(root, plan)
    registries = {
        family.key: read_registry(retained.read("registries/" + family.registry), family.key)
        for family in FAMILIES
    }
    authored = {
        f"{family}/{case.id}.py": case.source.encode()
        for family, registry in registries.items()
        for case in registry.cases
    }
    if {e.path: (e.sha256, e.byte_length) for e in plan.inventory} != {
        path: (sha256_bytes(raw), len(raw)) for path, raw in authored.items()
    }:
        raise ValueError("Shared inventory does not equal authored registry union")
    source_paths = {
        path.removeprefix("implementation/")
        for path in retained.files
        if path.startswith("implementation/")
    }
    if source_paths != set(plan.source_pins):
        raise ValueError("Frozen source membership differs")
    result = json.loads(retained.read("result.json"))
    if (
        result.get("contract") != "shared-custom-authored-execution-v1"
        or result.get("finished") is not True
        or result.get("prepared_unchanged") is not True
        or result.get("error") is not None
        or result.get("target_execution") is not False
        or result.get("unique_vulnerabilities") is not None
        or result.get("profile") != PROFILE.model_dump(mode="json")
    ):
        raise ValueError("Attempt is incomplete or its policy differs; no successful validation")
    preflight = _read_capture(retained.files, "preflight")
    if list(preflight.argv[1:]) != ["image", "inspect", IMAGE]:
        raise ValueError("Preflight command differs")
    inspect_image(preflight)
    rows = result["rows"]
    planned = planned_rows(plan)
    if len(rows) != len(planned):
        raise ValueError("Missing or additional worker rows")
    files_by_run: dict[tuple[str, int], list[NativeFile]] = defaultdict(list)
    tool = load_toml_config(root / "tool.toml", AgentAuditToolConfig).value
    for row, expected in zip(rows, planned, strict=True):
        if any(row[k] != expected[k] for k in ("key", "repetition", "batch", "family")):
            raise ValueError("Worker row schedule differs")
        family = next(f for f in FAMILIES if f.key == row["family"])
        capture = _read_capture(retained.files, row["key"])
        argv = list(capture.argv)
        name = argv[argv.index("--name") + 1]
        # Use an existing regular file as a placeholder executable for the pure argv comparison.
        expected_argv = worker_argv(root / "plan.json", tool, root, row["batch"], name, family)
        if _portable_command(argv, result["execution_root"], row["batch"]) != _portable_command(
            expected_argv, str(root.absolute()), row["batch"]
        ):
            raise ValueError("Worker isolation or selected module differs")
        cleanup = _read_capture(retained.files, row["key"] + "/cleanup")
        if (
            cleanup.argv[0] != capture.argv[0]
            or list(cleanup.argv[1:]) != ["rm", "--force", name]
            or not (
                capture_ok(cleanup, {0})
                or (capture_ok(cleanup, {1}) and b"no such container" in cleanup.stderr.lower())
            )
        ):
            raise ValueError("Cleanup was not verified")
        if not capture_ok(capture, {0, 1, 2}):
            raise ValueError("Unsuccessful worker cannot contribute a result")
        native = check_native(
            capture.stdout,
            retained.read(f"batches/{row['batch']:03d}/request.json"),
            family,
            capture.exit_code,
        )
        if (
            row["state"] != "validated"
            or row["error"] is not None
            or row["native_state"] != native.execution_state
            or row["finding_records"] != sum(len(f.findings or []) for f in native.files)
            or row["duration_ns"] != capture.duration_ns
        ):
            raise ValueError("Recorded worker projection differs from native evidence")
        files_by_run[(family.key, row["repetition"])].extend(native.files)
    summary: dict[str, Any] = {
        "contract": "shared-custom-authored-validation-v1",
        "evidence_manifest_sha256": retained.manifest_sha256,
        "snapshot_id": plan.snapshot_id,
        "input_count": len(plan.inventory),
        "worker_invocations": len(rows),
        "repetitions": plan.repetitions,
        "batch_count": len(plan.requests),
        "max_files": plan.max_files,
        "families": [],
        "overlap_candidates": [],
        "unique_vulnerabilities": None,
        "expectation_provenance": {key: r.expectation_provenance for key, r in registries.items()},
        "limitations": [
            "Authored development cases; not held-out labels or public-repository results.",
            "Origin-family assertions only; cross-family hits are unlabelled.",
            "Overlap is co-location, not confirmed duplication; no findings removed.",
            "Research-only policy: no project or inline suppressions applied.",
            "Repeatability compares per-file records, excluding timings and batch envelopes.",
            "Static file-local evidence does not establish runtime reachability or exploitability.",
        ],
    }
    located: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for family in FAMILIES:
        projections: list[str] = []
        origin_mismatches: list[dict[str, Any]] = []
        first: list[NativeFile] = []
        for rep in range(1, plan.repetitions + 1):
            files = sorted(files_by_run[(family.key, rep)], key=lambda f: f.path)
            if [f.path for f in files] != [e.path for e in plan.inventory]:
                raise ValueError("Batch union duplicates or omits shared input")
            if rep == 1:
                first = files
            projections.append(
                semantic_hash(cast(JsonValue, [f.model_dump(mode="json") for f in files]))
            )
            by_path = {f.path: f for f in files}
            for case in registries[family.key].cases:
                file = by_path[f"{family.key}/{case.id}.py"]
                actual_rules = (
                    None
                    if file.findings is None
                    else [
                        getattr(f, "rule_id", None)
                        or cast(ContractModel, f).model_dump()["rule"]["rule_id"]
                        for f in file.findings
                    ]
                )
                actual_inventory = sorted(
                    {rule_id for i in file.inventory if (rule_id := getattr(i, "rule_id", None))}
                )
                if (
                    actual_rules != case.rules
                    or (
                        family.key != "tool-execution"
                        and actual_inventory != sorted(case.inventory)
                    )
                    or file.state != ("malformed" if case.rules is None else "analyzed")
                ):
                    origin_mismatches.append(
                        {
                            "case": case.id,
                            "repetition": rep,
                            "state": file.state,
                            "actual_rules": actual_rules,
                            "actual_inventory": actual_inventory,
                        }
                    )
        for file in first:
            for finding in file.findings or []:
                value = cast(ContractModel, finding).model_dump(mode="json")
                located[file.path].append(
                    {
                        "family": family.key,
                        "record_id": value["record_id"],
                        "rule_id": value.get("rule_id") or value["rule"]["rule_id"],
                        "location": value["location"],
                    }
                )
        summary["families"].append(
            {
                "family": family.key,
                "files": len(first),
                "analyzed": sum(f.state == "analyzed" for f in first),
                "incomplete": sum(f.state != "analyzed" for f in first),
                "finding_records": sum(len(f.findings or []) for f in first),
                "inventory_records": sum(len(f.inventory) for f in first),
                "limitation_records": sum(len(f.limitations_observed) for f in first),
                "origin_cases": len(registries[family.key].cases),
                "origin_mismatches": origin_mismatches,
                "semantic_sha256": projections[0],
                "repeatability": "not-assessed"
                if len(projections) == 1
                else ("equal" if len(set(projections)) == 1 else "different"),
            }
        )
    for path, hits in sorted(located.items()):
        for index, left in enumerate(hits):
            for right in hits[index + 1 :]:
                a, b = left["location"], right["location"]
                if left["family"] != right["family"] and max(
                    a["start_line"], b["start_line"]
                ) <= min(a["end_line"], b["end_line"]):
                    summary["overlap_candidates"].append(
                        {
                            "path": path,
                            "left": left,
                            "right": right,
                            "relationship": "line-overlap-unreviewed",
                        }
                    )
    summary["origin_assertions_passed"] = not any(
        f["origin_mismatches"] for f in summary["families"]
    )
    summary["repeatability_passed"] = (
        all(f["repeatability"] == "equal" for f in summary["families"])
        if plan.repetitions > 1
        else None
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("preview", "run", "verify"))
    parser.add_argument("--project", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    parser.add_argument("--max-files", type=int, default=64)
    parser.add_argument("--repetitions", type=int, default=2)
    args = parser.parse_args()
    if args.mode == "preview":
        plan = prepare_shared(
            args.project, max_files=args.max_files, repetitions=args.repetitions
        ).plan
        print(plan.model_dump_json(indent=2))
    elif args.output is None:
        parser.error("--output required for run or verify")
    elif args.mode == "run":
        run_shared(
            args.project, args.output, max_files=args.max_files, repetitions=args.repetitions
        )
        print(json.dumps(verify_shared(args.output), indent=2))
    else:
        print(json.dumps(verify_shared(args.output), indent=2))


if __name__ == "__main__":
    main()
