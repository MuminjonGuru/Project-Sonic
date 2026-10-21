"""Three sequential, no-install Qdrant repetitions, with read-only local replay."""

from __future__ import annotations

import argparse
import csv
import io
import json
import platform
import time
from pathlib import Path
from typing import Any

from agentsec_evidence.agents.execution import AgentAuditToolConfig
from agentsec_evidence.agents.validation import canonical_artifact_path
from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.core.io import atomic_write_bytes
from agentsec_evidence.dependencies.pipeline import run_dependency_scan
from agentsec_evidence.execution.config import load_toml_config
from agentsec_evidence.execution.process import run_bounded_process
from agentsec_evidence.orchestration.shared import minimal_environment, resolve_docker
from agentsec_evidence.pilot.inputs import PROFILE_PATH, TOOL_PATH
from agentsec_evidence.pilot.qdrant_inputs import (
    CONTENT,
    DATABASE,
    PINS,
    REPOSITORY,
    REVISION,
    SPEC,
    bind,
    prepare_qdrant,
    replay_qdrant_inputs,
    verify_pins,
)
from agentsec_evidence.pilot.qdrant_stages import (
    QdrantRow,
    agent_stage,
    dependency_rows,
    planned_rows,
    repeatability,
    semgrep_stage,
    syntax_gates,
)
from agentsec_evidence.pilot.runner import evidence_records, load, ready_capture, save, seal_attempt
from agentsec_evidence.pilot.validation import verify_seal
from agentsec_evidence.reporting.service import require_new_derivative
from agentsec_evidence.research.models import load_research_profile
from agentsec_evidence.research.retained import plain_path, read_retained_research
from agentsec_evidence.research.semgrep import build_dual_view

REPORT = "repository-pilot-report.json"
LIMITATIONS = [
    "Formative pilot, not held-out evaluation; no complete oracle or accuracy estimate.",
    "Counts are rule reports or package-advisory occurrences, not confirmed vulnerabilities.",
    "Python acceptance does not establish FastMCP, prompt or memory-security coverage.",
    "MCP JSON does not establish effective permissions or safety of the launched package.",
    "The MCP uvx package is unversioned; runtime resolution was not performed "
    "or equated with the Git pin.",
    "Dockerfile and skill file are inventoried but unsupported; KICS was not run.",
    "Implicit Git filtering is disabled in both Semgrep views; policy view is not repository CI.",
    "Per-file detection completion and per-package matching completion remain unknown.",
    "No target execution, installation, live agent, model call or scanner-network access.",
    "Timings include host-cache effects; no performance-superiority claim.",
    "Replay uses original absolute mount paths and frozen database; "
    "this is not clean-machine reproduction.",
    "The new evidence contract is not yet an input to the common HTML reporter.",
]


def table_bytes(rows: list[QdrantRow]) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=list(QdrantRow.model_fields), lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                key: "unknown"
                if value is None
                else json.dumps(value)
                if isinstance(value, list)
                else value
                for key, value in row.model_dump(mode="json").items()
            }
        )
    return buffer.getvalue().encode()


def report_base() -> dict[str, Any]:
    return {
        "contract": "qdrant-repository-pilot-report-v1",
        "approval": "P4-D-2026-10-18-03",
        "repository": REPOSITORY,
        "revision": REVISION,
        "content_sha256": CONTENT,
        "split": "formative-pilot-not-held-out",
        "target_execution": False,
        "target_installation": False,
        "vulnerability_total": None,
        "coverage": {
            "inventory_files": 34,
            "python_files_selected": 19,
            "mcp_json_selected": 1,
            "eligible_lockfile_identities": 111,
            "local_root_separate": 1,
            "skill": "observed-unsupported",
            "Dockerfile": "observed-unsupported",
            "dynamic_FastMCP_registration": "unknown",
            "runtime_exploitability": "not-assessed",
        },
        "limitations": LIMITATIONS,
    }


def guard(root: Path, database: Path, project: Path | None = None) -> None:
    freeze = load(root / "freeze.json")
    if freeze["pins"] != PINS or freeze["database_sha256"] != DATABASE:
        raise ValueError("Freeze configuration differs from the admitted pins")
    if sha256_file(database) != DATABASE or str(database) != freeze["database"]:
        raise ValueError("Database bytes or execution location changed")
    for entry in freeze["input_records"]:
        canonical_artifact_path(entry["path"])
        if sha256_file(root / entry["path"]) != entry["sha256"]:
            raise ValueError("Frozen input changed: " + entry["path"])
    if project is not None:
        verify_pins(project)
        if (project / SPEC).read_bytes() != (root / "frozen" / SPEC).read_bytes():
            raise ValueError("Intake specification changed during run")
        code = {
            p.relative_to(project).as_posix(): sha256_file(p)
            for p in (project / "src").rglob("*.py")
        }
        if code != freeze["code"]:
            raise ValueError("Trusted source changed during run")
    replay_qdrant_inputs(root)


def run_qdrant_pilot(
    *,
    project: Path,
    cache: Path,
    rules: Path,
    database: Path,
    output: Path,
    docker: Path | None = None,
) -> dict[str, Any]:
    project = plain_path(project, directory=True)
    cache, rules = plain_path(cache, directory=True), plain_path(rules, directory=True)
    database = plain_path(database, directory=False)
    output = require_new_derivative(output, [cache, rules, database.parent])
    if output == project / "workspace" or not output.is_relative_to(project / "workspace"):
        raise ValueError("Pilot output must be a fresh ignored workspace child")
    plain_path(output.parent, directory=True)
    executable = resolve_docker(docker)
    if executable is None:
        raise ValueError("Local Docker is required; no fallback or automatic pull")
    output.mkdir(exist_ok=False)
    rows = planned_rows()
    result = {
        **report_base(),
        "instrument_finished": False,
        "input_unchanged": None,
        "repetition_wall_ns": [],
        "manual_recovery_actions_during_attempt": 0,
        "manual_preparation_and_adjudication_time_ns": None,
    }
    started = time.monotonic_ns()
    current = None
    try:
        inputs = prepare_qdrant(project, output, cache=cache, rules=rules, database=database)
        environment = minimal_environment(output / "runtime")
        code = {}
        for path in sorted((project / "src").rglob("*.py")):
            relative = path.relative_to(project).as_posix()
            raw = path.read_bytes()
            atomic_write_bytes(output / "trusted-source" / relative, raw)
            code[relative] = sha256_bytes(raw)
        save(
            output / "host.json",
            {"platform": platform.platform(), "python": platform.python_version()},
        )
        profile = load_research_profile((output / "frozen" / PROFILE_PATH).read_bytes())
        tool = load_toml_config(output / "frozen" / TOOL_PATH, AgentAuditToolConfig).value
        dep_tools = load(output / "frozen/configs/dependency/tools.json")
        for index, image in enumerate(
            (
                profile.image,
                tool.image,
                tool.validator_image,
                dep_tools["syft"]["image"],
                dep_tools["osv"]["image"],
            )
        ):
            capture = run_bounded_process(
                [str(executable), "image", "inspect", image],
                cwd=project,
                environment=environment,
                timeout_seconds=30,
                max_stdout_bytes=1024**2,
                max_stderr_bytes=1024**2,
            )
            atomic_write_bytes(output / f"images/{index}.stdout.bin", capture.stdout)
            atomic_write_bytes(output / f"images/{index}.stderr.bin", capture.stderr)
            if not ready_capture(capture, True, {0}):
                raise ValueError("Required pinned local image unavailable")
        freeze = {
            "execution_root": str(output),
            "database": str(database),
            "database_sha256": DATABASE,
            "docker": str(executable),
            "code": code,
            "pins": PINS,
            "environment_names": sorted(environment),
            "input_records": evidence_records(output),
            "timing": "Preparation outside repetitions; validation, scanners, "
            "normalization and guards inside",
            "retry": "No resume or retry; interrupted attempts remain separate",
        }
        save(output / "freeze.json", freeze)
        result["freeze_sha256"] = sha256_file(output / "freeze.json")

        def accept(row: QdrantRow) -> None:
            index = next(
                i
                for i, r in enumerate(rows)
                if (r.repetition, r.stage) == (row.repetition, row.stage)
            )
            rows[index] = row
            save(output / "progress.json", [r.model_dump(mode="json") for r in rows])
            if row.state == "failed":
                raise ValueError("Failed native stage; no silent retry")

        for repetition in range(1, 4):
            tick = time.monotonic_ns()
            cell = output / f"repetition-{repetition}"
            cell.mkdir()
            guard(output, database, project)
            workers = syntax_gates(
                inputs,
                cell,
                project=project,
                docker=executable,
                environment=environment,
                write=True,
            )
            pair = []
            for role in ("research", "repository-policy"):
                current = (
                    repetition,
                    "semgrep-research" if role == "research" else "semgrep-policy",
                )
                guard(output, database, project)
                row, evidence = semgrep_stage(
                    inputs,
                    cell,
                    repetition,
                    role,
                    project=project,
                    docker=executable,
                    environment=environment,
                    write=True,
                )
                accept(row)
                pair.append(evidence)
            bind(
                cell / "dual-view.json", build_dual_view(*pair).model_dump(mode="json"), write=True
            )
            for stage in ("agent-python", "agent-mcp"):
                current = (repetition, stage)
                guard(output, database, project)
                accept(
                    agent_stage(
                        inputs,
                        cell,
                        repetition,
                        stage,
                        workers[stage],
                        project=project,
                        docker=executable,
                        environment=environment,
                        write=True,
                    )
                )
            current = (repetition, "osv-direct")
            guard(output, database, project)
            dep = run_dependency_scan(
                project_root=project,
                workspace_root=cell / "dependencies",
                source=inputs.source,
                label=REPOSITORY,
                revision=REVISION,
                database=database,
                database_sha256=DATABASE,
                split="pilot",
                admission_file=output / "dependency-admission.json",
            )
            if dep["state"] == "failed":
                raise ValueError(
                    "Dependency pipeline failed; retained native receipts show actual stage"
                )
            for row in dependency_rows(output, cell, repetition, database, write=True):
                accept(row)
            guard(output, database, project)
            result["repetition_wall_ns"].append(time.monotonic_ns() - tick)
            current = None
            print(f"Qdrant repetition {repetition}/3 retained", flush=True)
        result.update(instrument_finished=True, input_unchanged=True)
    except BaseException as exc:
        result["failure"] = {
            "type": type(exc).__name__,
            "message": str(exc)[:1000],
            "cell": current,
        }
        if current:
            rows = [
                r.model_copy(
                    update={
                        "state": "failed",
                        "reasons": (*r.reasons, "attempt-interrupted-see-receipts"),
                    }
                )
                if (r.repetition, r.stage) == current
                else r
                for r in rows
            ]
        raise
    finally:
        result["attempt_wall_ns"] = time.monotonic_ns() - started
        result["rows"] = [r.model_dump(mode="json") for r in rows]
        result["repeatability"] = repeatability(rows)
        save(output / REPORT, result)
        atomic_write_bytes(output / "comparison.csv", table_bytes(rows))
        seal_attempt(output)
    return result


def verify_qdrant_pilot(project: Path, root: Path, database: Path) -> dict[str, Any]:
    project, root = plain_path(project, directory=True), plain_path(root, directory=True)
    database = plain_path(database, directory=False)
    read_retained_research(root, manifest_contract="source-pilot-evidence-v1")
    count = verify_seal(root)
    report = load(root / REPORT)
    if any(report.get(k) != v for k, v in report_base().items()):
        raise ValueError("Report identity, admission, coverage or limitations differ")
    if (
        report.get("instrument_finished") is not True
        or report.get("input_unchanged") is not True
        or "failure" in report
    ):
        raise ValueError(
            "Incomplete attempts retain evidence but do not pass finished-pilot replay"
        )
    freeze = load(root / "freeze.json")
    if freeze["execution_root"] != str(root) or report["freeze_sha256"] != sha256_file(
        root / "freeze.json"
    ):
        raise ValueError("Original local execution location or freeze binding differs")
    guard(root, database)
    inputs = replay_qdrant_inputs(root)
    docker = Path(freeze["docker"])
    if docker.name.lower() not in {"docker", "docker.exe"}:
        raise ValueError("Recorded executable is not Docker")
    environment = {key: "" for key in freeze["environment_names"]}
    rows = []
    for repetition in range(1, 4):
        cell = root / f"repetition-{repetition}"
        workers = syntax_gates(
            inputs, cell, project=project, docker=docker, environment=environment, write=False
        )
        pair = []
        for role in ("research", "repository-policy"):
            row, evidence = semgrep_stage(
                inputs,
                cell,
                repetition,
                role,
                project=project,
                docker=docker,
                environment=environment,
                write=False,
            )
            rows.append(row)
            pair.append(evidence)
        bind(cell / "dual-view.json", build_dual_view(*pair).model_dump(mode="json"), write=False)
        rows.extend(
            agent_stage(
                inputs,
                cell,
                repetition,
                stage,
                workers[stage],
                project=project,
                docker=docker,
                environment=environment,
                write=False,
            )
            for stage in ("agent-python", "agent-mcp")
        )
        rows.extend(dependency_rows(root, cell, repetition, database, write=False))
    if report["rows"] != [r.model_dump(mode="json") for r in rows] or report[
        "repeatability"
    ] != repeatability(rows):
        raise ValueError("Table differs from replayed native evidence")
    if (root / "comparison.csv").read_bytes() != table_bytes(rows):
        raise ValueError("CSV differs from replayed rows")
    verify_seal(root)
    return {
        "contract": "qdrant-pilot-replay-v1",
        "passed": True,
        "files_verified": count,
        "rows_replayed": len(rows),
        "repeatability": repeatability(rows),
        "scanner_invocations": 0,
        "meaning": "Local evidence consistency, not independent attestation "
        "or vulnerability validation",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("run", "verify"))
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--rules", type=Path)
    args = parser.parse_args()
    if args.operation == "run":
        if args.cache is None or args.rules is None:
            parser.error("run requires --cache and --rules")
        result = run_qdrant_pilot(
            project=args.project,
            cache=args.cache,
            rules=args.rules,
            database=args.database,
            output=args.output,
        )
        print(
            json.dumps(
                {
                    k: result[k]
                    for k in ("instrument_finished", "repeatability", "repetition_wall_ns")
                }
            )
        )
    else:
        print(json.dumps(verify_qdrant_pilot(args.project, args.output, args.database)))


if __name__ == "__main__":
    main()
