"""Isolated input validation of prepared candidates; no detectors or target execution."""

from __future__ import annotations

import argparse
import json
import time
import uuid
from pathlib import Path
from typing import Any

from agentsec_evidence.agents.execution import AgentAuditToolConfig, build_agent_argv
from agentsec_evidence.agents.records import AgentInputReport, verify_input_report
from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.core.io import atomic_write_bytes
from agentsec_evidence.custom_rules.shared_execution import PROFILE as SHARED_LIMITS
from agentsec_evidence.custom_rules.shared_execution import (
    _portable_command,
    _read_capture,
    capture_ok,
    inspect_image,
    run_capture,
)
from agentsec_evidence.execution.config import ExecutionProfile, load_toml_config
from agentsec_evidence.intake.corpus_validation import (
    PROTOCOL,
    TOOL,
    CorpusValidationPlan,
    assess_inputs,
    prepare_validation_plan,
    validate_plan_structure,
    verify_validation_parent,
)
from agentsec_evidence.orchestration.shared import minimal_environment, resolve_docker
from agentsec_evidence.pilot.runner import evidence_records, save
from agentsec_evidence.reporting.custom_contracts import IMAGE
from agentsec_evidence.research.retained import (
    RetainedManifest,
    bounded_file,
    plain_path,
    read_retained_research,
)

PROFILE = ExecutionProfile.model_validate(
    {
        **SHARED_LIMITS.model_dump(mode="json"),
        "profile_id": "corpus-input-validation-v1",
        "profile_kind": "pilot",
    }
)


def validation_argv(
    docker: Path, tool: AgentAuditToolConfig, root: Path, batch: int, name: str
) -> list[str]:
    base = root / f"batches/{batch:03d}"
    return build_agent_argv(
        docker=docker,
        tool=tool,
        profile=PROFILE,
        name=name,
        target=base / "target",
        worker_source=root / "implementation/src",
        request=base / "request.json",
    )


def check_frozen(root: Path, plan: CorpusValidationPlan) -> None:
    validate_plan_structure(plan)
    members = {
        p.relative_to(root / "implementation").as_posix()
        for p in (root / "implementation").rglob("*")
        if p.is_file()
    }
    if members != set(plan.source_pins):
        raise ValueError("Trusted source membership differs")
    for p, digest in plan.source_pins.items():
        if sha256_bytes(bounded_file(root / "implementation" / p, 1024**2)) != digest:
            raise ValueError("Trusted source bytes changed")
    for name, digest in (("tool.toml", plan.tool_sha256), ("protocol.md", plan.protocol_sha256)):
        if sha256_bytes(bounded_file(root / name, 1024**2)) != digest:
            raise ValueError("Frozen tool or protocol changed")
    for batch, request in enumerate(plan.requests):
        base = root / f"batches/{batch:03d}"
        if bounded_file(base / "request.json", 256 * 1024) != request.model_dump_json().encode():
            raise ValueError("Exact request bytes changed")
        paths = {
            p.relative_to(base / "target").as_posix()
            for p in (base / "target").rglob("*")
            if p.is_file()
        }
        if paths != set(request.selected):
            raise ValueError("Validation view membership differs")
        for entry in request.inventory:
            raw = bounded_file(base / "target" / entry.path, 256 * 1024)
            if (len(raw), sha256_bytes(raw)) != (entry.byte_length, entry.sha256):
                raise ValueError("Validation source bytes changed")


def run_validation(
    project: Path, candidate_root: Path, output: Path, *, docker: Path | None = None
) -> dict[str, Any]:
    project = plain_path(project, directory=True)
    candidate_root = plain_path(candidate_root, directory=True)
    output = output.absolute()
    plain_path(output.parent, directory=True)
    if (
        output.exists()
        or output == project / "workspace"
        or not output.is_relative_to(project / "workspace")
    ):
        raise ValueError("Use a new ignored workspace attempt; no overwrite or silent retry")
    plan, sources = prepare_validation_plan(project, candidate_root, output)
    executable = resolve_docker(docker)
    if executable is None:
        raise ValueError("Docker required; no host parsing fallback")
    tool = load_toml_config(project / TOOL, AgentAuditToolConfig)
    if sha256_bytes(tool.raw) != plan.tool_sha256:
        raise ValueError("Tool configuration changed before preparation")
    output.mkdir()
    result: dict[str, Any] = {
        "contract": "corpus-input-execution-v1",
        "finished": False,
        "error": None,
        "profile": PROFILE.model_dump(mode="json"),
        "security_scanner_invocations": 0,
        "target_execution": False,
        "duration_ns": None,
        "rows": [
            {"key": f"validation/b{b:03d}", "batch": b, "state": "not-run", "duration_ns": None}
            for b in range(len(plan.requests))
        ],
    }
    start = time.perf_counter_ns()
    save(output / "plan.json", plan.model_dump(mode="json"))
    try:
        for path, raw in sources.items():
            atomic_write_bytes(output / "implementation" / path, raw)
        atomic_write_bytes(output / "tool.toml", tool.raw)
        atomic_write_bytes(output / "protocol.md", bounded_file(project / PROTOCOL, 1024**2))
        for batch, request in enumerate(plan.requests):
            base = output / f"batches/{batch:03d}"
            atomic_write_bytes(base / "request.json", request.model_dump_json().encode())
            for entry in request.inventory:
                raw = bounded_file(candidate_root / "prepared/source" / entry.path, 256 * 1024)
                atomic_write_bytes(base / "target" / entry.path, raw)
        check_frozen(output, plan)
        environment = minimal_environment(output / "runtime")
        inspect_image(
            run_capture(
                [str(executable), "image", "inspect", IMAGE],
                output / "preflight",
                environment,
                timeout=30,
            )
        )
        reports = []
        for row in result["rows"]:
            name = "corpus-input-" + uuid.uuid4().hex
            argv = validation_argv(executable, tool.value, output, row["batch"], name)
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
                    raise ValueError("Validation container cleanup not confirmed")
            if not capture_ok(capture, {0}):
                raise ValueError("Syntax worker failed or exceeded its bounded resources")
            report = AgentInputReport.model_validate(
                load_agent_json(capture.stdout, max_bytes=2 * 1024**2)
            )
            request = plan.requests[row["batch"]]
            verify_input_report(report, request, request.model_dump_json().encode())
            reports.append(report)
            row.update(state="validated", duration_ns=capture.duration_ns)
            save(output / "result.json", result)
        assessment = assess_inputs(plan, reports)
        save(output / "assessment.json", assessment.model_dump(mode="json"))
        check_frozen(output, plan)
        verify_validation_parent(project, plan)
        result["finished"] = True
    except BaseException as exc:
        result["error"] = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        result["duration_ns"] = time.perf_counter_ns() - start
        save(output / "result.json", result)
        seal = RetainedManifest.model_validate({"files": evidence_records(output)})
        save(output / "evidence-manifest.json", seal.model_dump(mode="json"))
    return result


def verify_validation(project: Path, root: Path) -> dict[str, Any]:
    retained = read_retained_research(root)
    plan = CorpusValidationPlan.model_validate_json(retained.read("plan.json"))
    check_frozen(root, plan)
    verify_validation_parent(project, plan)
    result = json.loads(retained.read("result.json"))
    if (
        result.get("contract") != "corpus-input-execution-v1"
        or result.get("finished") is not True
        or result.get("error") is not None
        or result.get("target_execution") is not False
        or type(result.get("security_scanner_invocations")) is not int
        or result["security_scanner_invocations"] != 0
        or result.get("profile") != PROFILE.model_dump(mode="json")
    ):
        raise ValueError("Incomplete validation attempt; not a clean scan")
    preflight = _read_capture(retained.files, "preflight")
    if list(preflight.argv[1:]) != ["image", "inspect", IMAGE]:
        raise ValueError("Image preflight command differs")
    inspect_image(preflight)
    tool = load_toml_config(root / "tool.toml", AgentAuditToolConfig).value
    rows = result["rows"]
    if len(rows) != len(plan.requests):
        raise ValueError("Validation row count differs")
    reports = []
    for batch, (row, request) in enumerate(zip(rows, plan.requests, strict=True)):
        key = f"validation/b{batch:03d}"
        if row["key"] != key or row["batch"] != batch or row["state"] != "validated":
            raise ValueError("Validation schedule differs")
        capture = _read_capture(retained.files, key)
        argv = list(capture.argv)
        name = argv[argv.index("--name") + 1]
        expected = validation_argv(root / "plan.json", tool, root, batch, name)
        if _portable_command(argv, plan.execution_root, batch) != _portable_command(
            expected, str(root.absolute()), batch
        ):
            raise ValueError("Validation isolation or module differs")
        cleanup = _read_capture(retained.files, key + "/cleanup")
        if (
            cleanup.argv[0] != capture.argv[0]
            or list(cleanup.argv[1:]) != ["rm", "--force", name]
            or not (
                capture_ok(cleanup, {0})
                or (capture_ok(cleanup, {1}) and b"no such container" in cleanup.stderr.lower())
            )
        ):
            raise ValueError("Validation cleanup not verified")
        if not capture_ok(capture, {0}) or row["duration_ns"] != capture.duration_ns:
            raise ValueError("Validation process failed or timing differs")
        report = AgentInputReport.model_validate(
            load_agent_json(capture.stdout, max_bytes=2 * 1024**2)
        )
        verify_input_report(report, request, retained.read(f"batches/{batch:03d}/request.json"))
        reports.append(report)
    assessment = assess_inputs(plan, reports)
    if json.loads(retained.read("assessment.json")) != assessment.model_dump(mode="json"):
        raise ValueError("Assessment differs from native input evidence")
    if sha256_file(root / "evidence-manifest.json") != retained.manifest_sha256:
        raise ValueError("Validation evidence seal changed")
    return {
        "contract": "corpus-input-verification-v1",
        "passed": True,
        "evidence_manifest_sha256": retained.manifest_sha256,
        "validation_invocations": len(rows),
        "security_scanner_invocations": 0,
        "assessment": assessment.model_dump(mode="json"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("run", "verify"))
    parser.add_argument("--project", type=Path, default=Path.cwd())
    parser.add_argument("--candidate-root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "run":
        if args.candidate_root is None:
            parser.error("run requires --candidate-root")
        run_validation(args.project, args.candidate_root, args.output)
    verified = verify_validation(args.project, args.output)
    print(json.dumps({k: v for k, v in verified.items() if k != "assessment"}, indent=2))


if __name__ == "__main__":
    main()
