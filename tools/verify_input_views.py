"""Verify four fixed development views; optionally run syntax validation, never a scanner."""

from __future__ import annotations

import argparse
import dataclasses
import json
from pathlib import Path
from typing import Any

from agentsec_evidence.agents.execution import AgentAuditToolConfig, build_agent_argv
from agentsec_evidence.agents.inventory import build_artifact_inventory
from agentsec_evidence.agents.view_validation import (
    assess_agent_view_report,
    build_agent_view_request,
)
from agentsec_evidence.core.identity import semantic_hash, sha256_file
from agentsec_evidence.core.io import (
    atomic_write_bytes,
    atomic_write_model,
    json_bytes,
)
from agentsec_evidence.execution.config import ExecutionProfile, load_toml_config
from agentsec_evidence.execution.process import run_bounded_process
from agentsec_evidence.intake.git_verification import verify_git_source
from agentsec_evidence.intake.input_plan import build_tool_input_plan
from agentsec_evidence.intake.snapshot import create_snapshot
from agentsec_evidence.intake.views import (
    ToolViewContext,
    materialize_tool_view,
    replay_parent_source,
    verify_materialized_tool_view,
)
from agentsec_evidence.orchestration.shared import (
    cleanup_container,
    minimal_environment,
    resolve_docker,
)

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "test_cases/development/input-views/cases.json"
IDS = {"excluded-policy", "python-positive", "mcp-positive", "python-inline-suppression"}


def prepare(case: dict[str, Any], output: Path) -> tuple[ToolViewContext, Path]:
    output.mkdir(exist_ok=False)
    files = {file["path"]: file["text"].encode() for file in case["git"]["files"]}
    raw_commit = case["git"]["raw_commit"].encode()
    raw_tree = json_bytes(case["git"]["tree"])
    verification = verify_git_source(
        raw_commit=raw_commit, raw_tree=raw_tree, revision=case["git"]["revision"], files=files
    )
    source = output / "source"
    for path, data in files.items():
        atomic_write_bytes(source / path, data)
    snapshot = create_snapshot(
        source,
        output / "snapshots",
        source_label="controlled-view:" + case["id"],
        revision=verification.revision,
        source_kind="git",
    )
    inventory = build_artifact_inventory(snapshot.snapshot, snapshot.inventory)
    profile = json_bytes({"profile_id": "controlled-view-v1", "selected": case["selected"]})
    plan = build_tool_input_plan(
        inventory=inventory,
        verification=verification,
        tool_id="agent-audit",
        profile_id="controlled-view-v1",
        profile_bytes=profile,
        selected_paths=list(case["selected"]),
        selected_reason="Explicit controlled validation input",
        exclusions={
            path: "Retained in parent policy context"
            for path in files
            if path not in case["selected"]
        },
    )
    atomic_write_bytes(output / "raw/commit.bin", raw_commit)
    atomic_write_bytes(output / "raw/tree.json", raw_tree)
    atomic_write_bytes(output / "raw/profile.json", profile)
    atomic_write_model(output / "verification.json", verification)
    atomic_write_model(output / "inventory.json", inventory)
    atomic_write_model(output / "plan.json", plan)
    return ToolViewContext(inventory, verification, plan, profile, raw_commit, raw_tree), source


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--docker", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    registry = json.loads(CASES.read_bytes())
    cases = registry["cases"]
    if len(cases) != 4 or {case["id"] for case in cases} != IDS:
        raise ValueError("Only the four controlled integration cases are admitted")
    atomic_write_bytes(output / "cases.json", CASES.read_bytes())
    profile = load_toml_config(ROOT / "configs/profiles/agent-development.toml", ExecutionProfile)
    tool = load_toml_config(ROOT / "configs/tools/agent-audit.toml", AgentAuditToolConfig)
    atomic_write_bytes(output / "execution-profile.toml", profile.raw)
    atomic_write_bytes(output / "tool-config.toml", tool.raw)
    environment = minimal_environment(output / "runtime")
    docker = resolve_docker(args.docker)
    if not args.prepare_only and docker is None:
        raise RuntimeError("Docker required for isolated syntax validation")
    worker_records = []
    for source in sorted((ROOT / "src").rglob("*.py")):
        relative = source.relative_to(ROOT / "src").as_posix()
        atomic_write_bytes(output / "worker-source" / relative, source.read_bytes())
        worker_records.append({"path": relative, "sha256": sha256_file(source)})
    atomic_write_bytes(output / "worker-sources.json", json_bytes(worker_records))
    rows: list[dict[str, Any]] = []
    for repetition in (1, 2):
        for case in cases:
            cell = output / f"{case['id']}-{repetition}"
            context, source = prepare(case, cell)
            view = materialize_tool_view(context, source_root=source, output=cell / "view")
            target = cell / "view/target"
            request = build_agent_view_request(context, view, selected_kinds=case["selected"])
            request_path = cell / "request.json"
            atomic_write_model(request_path, request)
            assessment = None
            if not args.prepare_only:
                assert docker is not None
                name = "agent-input-view-" + semantic_hash({"output": str(cell)})[:20]
                argv = build_agent_argv(
                    docker=docker,
                    tool=tool.value,
                    profile=profile.value,
                    name=name,
                    target=target,
                    worker_source=output / "worker-source",
                    request=request_path,
                )
                try:
                    capture = run_bounded_process(
                        argv,
                        cwd=ROOT,
                        environment=environment,
                        timeout_seconds=profile.value.limits.timeout_seconds,
                        max_stdout_bytes=profile.value.limits.max_stdout_bytes,
                        max_stderr_bytes=profile.value.limits.max_stderr_bytes,
                    )
                    atomic_write_bytes(cell / "worker.stdout.bin", capture.stdout)
                    atomic_write_bytes(cell / "worker.stderr.bin", capture.stderr)
                    receipt = dataclasses.asdict(capture)
                    del receipt["stdout"], receipt["stderr"]
                    atomic_write_bytes(
                        cell / "execution.json",
                        (json.dumps(receipt, indent=2, default=str) + "\n").encode(),
                    )
                finally:
                    cleaned = cleanup_container(
                        docker=docker, container_name=name, cwd=ROOT, environment=environment
                    )
                    atomic_write_bytes(cell / "cleanup.json", json_bytes({"succeeded": cleaned}))
                if (
                    capture.exit_code != 0
                    or capture.timed_out
                    or capture.output_limited
                    or capture.stderr
                    or not cleaned
                ):
                    raise RuntimeError("Validation failed; retained attempt is not a clean result")
                assessment = assess_agent_view_report(context, view, request, capture.stdout)
                atomic_write_model(cell / "assessment.json", assessment)
                if (
                    assessment.input_gate_passed != case["expected_input_gate_passed"]
                    or list(assessment.blockers) != case["expected_blockers"]
                ):
                    raise RuntimeError("Observed gate outcome differs from controlled expectations")
            replay_parent_source(context, source)
            verify_materialized_tool_view(view, context, target)
            rows.append(
                {
                    "case": case["id"],
                    "repetition": repetition,
                    "parent_files": len(context.inventory.records),
                    "selected_files": len(view.files),
                    "excluded_files": len(context.inventory.records) - len(view.files),
                    "view_sha256": semantic_hash(view.model_dump(mode="json")),
                    "assessment_sha256": semantic_hash(assessment.model_dump(mode="json"))
                    if assessment
                    else None,
                    "input_gate_passed": assessment.input_gate_passed if assessment else None,
                    "validation_state": "complete" if assessment else "not-run",
                    "blockers": list(assessment.blockers) if assessment else None,
                    "scanner_executed": False,
                    "execution_authorization": "not-granted",
                    "parent_and_view_reverified": True,
                }
            )
    for name in IDS:
        pair = [row for row in rows if row["case"] == name]
        if any(pair[0][key] != pair[1][key] for key in pair[0] if key != "repetition"):
            raise RuntimeError("Controlled repetitions differ")
    summary = {
        "passed": True,
        "role": "controlled-development-not-held-out",
        "cases": 4,
        "preparations": 8,
        "syntax_worker_invocations": 0 if args.prepare_only else 8,
        "scanner_invocations": 0,
        "target_code_executed": False,
        "repeated_semantics_equal": True,
        "rows": rows,
        "limits": [
            "No public intake, detection benchmark or scanner authorization",
            "Prepare-only mode does not test parsing or policy outcomes",
            "Independent review not performed",
        ],
    }
    atomic_write_bytes(output / "summary.json", json_bytes(summary))
    excluded_roots = {"runtime"}
    records = [
        {
            "path": path.relative_to(output).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.relative_to(output).parts[0] not in excluded_roots
    ]
    atomic_write_bytes(output / "evidence-manifest.json", json_bytes({"files": records}))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
