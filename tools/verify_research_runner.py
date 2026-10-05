"""Exercise the guarded research bridge on registered Git fixtures only, offline."""

from __future__ import annotations

import argparse
import dataclasses
import json
from pathlib import Path
from typing import Any, Literal

from verify_research_semgrep import bounded_read, projection, save

from agentsec_evidence.agents.execution import AgentAuditToolConfig, build_agent_argv
from agentsec_evidence.agents.inventory import build_artifact_inventory
from agentsec_evidence.core.identity import semantic_hash, sha256_file
from agentsec_evidence.core.io import atomic_write_bytes, atomic_write_model, json_bytes
from agentsec_evidence.execution.config import ExecutionProfile, load_toml_config
from agentsec_evidence.execution.process import ProcessCapture, run_bounded_process
from agentsec_evidence.intake.git_verification import verify_git_source
from agentsec_evidence.intake.input_plan import build_tool_input_plan
from agentsec_evidence.intake.snapshot import create_snapshot
from agentsec_evidence.intake.views import ToolViewContext
from agentsec_evidence.orchestration.shared import (
    cleanup_container,
    minimal_environment,
    resolve_docker,
)
from agentsec_evidence.research.execution import assess_research_execution, build_research_argv
from agentsec_evidence.research.inputs import (
    assess_research_syntax,
    materialize_research_inputs,
    replay_research_inputs,
    research_worker_request,
)
from agentsec_evidence.research.models import (
    MAX_FILE_BYTES,
    MAX_REPORT_BYTES,
    load_research_profile,
    verify_rule_bytes,
)
from agentsec_evidence.research.policy import POLICY_LABEL
from agentsec_evidence.research.semgrep import build_dual_view, reconcile_semgrep_pass

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "test_cases/development/research-runner/cases.json"
PROFILE = ROOT / "configs/research/semgrep-python-candidate-v1.json"


def invoke(
    argv: list[str], cell: Path, docker: Path, name: str, environment: dict[str, str]
) -> tuple[ProcessCapture, bool]:
    cell.mkdir(parents=True, exist_ok=True)
    save(cell / "command.json", {"argv": argv, "target_execution": False})
    try:
        capture = run_bounded_process(
            argv,
            cwd=ROOT,
            environment=environment,
            timeout_seconds=120,
            max_stdout_bytes=MAX_REPORT_BYTES,
            max_stderr_bytes=MAX_REPORT_BYTES,
            monitored_files=(cell / "native.json", cell / "native.sarif"),
            max_generated_bytes=2 * MAX_REPORT_BYTES,
        )
        atomic_write_bytes(cell / "stdout.bin", capture.stdout)
        atomic_write_bytes(cell / "stderr.bin", capture.stderr)
        receipt = dataclasses.asdict(capture)
        del receipt["stdout"], receipt["stderr"]
        save(cell / "execution.json", receipt)
    except Exception as exc:
        save(cell / "launch-failure.json", {"type": type(exc).__name__})
        raise
    finally:
        cleaned = cleanup_container(
            docker=docker, container_name=name, cwd=ROOT, environment=environment
        )
        save(cell / "cleanup.json", {"succeeded": cleaned})
    return capture, cleaned


def controlled_context(
    case: dict[str, Any], cell: Path, profile_bytes: bytes
) -> tuple[ToolViewContext, Path]:
    files = {p: text.encode() for p, text in case["files"].items()}
    source = cell / "parent"
    for path, data in files.items():
        atomic_write_bytes(source / path, data)
    raw_commit, raw_tree = case["git"]["raw_commit"].encode(), json_bytes(case["git"]["tree"])
    proof = verify_git_source(
        raw_commit=raw_commit, raw_tree=raw_tree, revision=case["git"]["revision"], files=files
    )
    snapshot = create_snapshot(
        source,
        cell / "snapshots",
        source_label="controlled-research:" + case["id"],
        revision=proof.revision,
        source_kind="git",
    )
    inventory = build_artifact_inventory(snapshot.snapshot, snapshot.inventory)
    profile = load_research_profile(profile_bytes)
    plan = build_tool_input_plan(
        inventory=inventory,
        verification=proof,
        tool_id="semgrep",
        profile_id=profile.profile_id,
        profile_bytes=profile_bytes,
        selected_paths=case["selected"],
        selected_reason="Registered development input",
        exclusions={
            p: "Retain full parent evidence, exclude from scanner selection"
            for p in files
            if p not in case["selected"]
        },
    )
    for name, model in (
        ("inventory", inventory),
        ("git-verification", proof),
        ("input-plan", plan),
    ):
        atomic_write_model(cell / f"{name}.json", model)
    atomic_write_bytes(cell / "commit.raw", raw_commit)
    atomic_write_bytes(cell / "tree.json", raw_tree)
    return ToolViewContext(inventory, proof, plan, profile_bytes, raw_commit, raw_tree), source


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rule-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--docker", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    if output == ROOT / "workspace" or not output.is_relative_to(ROOT / "workspace"):
        raise ValueError("Output must be a fresh ignored workspace child")
    output.mkdir(parents=True, exist_ok=False)
    docker = resolve_docker(args.docker)
    if docker is None:
        raise RuntimeError("Docker unavailable; this helper never downloads images")
    environment = minimal_environment(output / "runtime")
    profile_bytes, registry_bytes = PROFILE.read_bytes(), REGISTRY.read_bytes()
    registry, profile = json.loads(registry_bytes), load_research_profile(profile_bytes)
    if (
        registry["role"] != "development-not-held-out"
        or registry["target_execution"] is not False
        or len(registry["cases"]) != 15
    ):
        raise ValueError("Only the finite registered development corpus is permitted")
    rules = {
        r.source_path: bounded_read(args.rule_source / r.source_path, MAX_FILE_BYTES)
        for r in profile.rules
    }
    license_bytes = bounded_read(args.rule_source / "LICENSE", MAX_FILE_BYTES)
    verify_rule_bytes(profile, rules, license_bytes=license_bytes)
    for path, data in rules.items():
        atomic_write_bytes(output / "rules" / path, data)
    atomic_write_bytes(output / "rules/LICENSE", license_bytes)
    atomic_write_bytes(output / "profile.json", profile_bytes)
    atomic_write_bytes(output / "cases.json", registry_bytes)
    for name in ("verify_research_runner.py", "verify_research_semgrep.py"):
        atomic_write_bytes(output / "harness" / name, (ROOT / "tools" / name).read_bytes())
    for path in sorted((ROOT / "src").rglob("*.py")):
        atomic_write_bytes(
            output / "worker-source" / path.relative_to(ROOT / "src"), path.read_bytes()
        )
    execution = load_toml_config(ROOT / "configs/profiles/agent-development.toml", ExecutionProfile)
    tool = load_toml_config(ROOT / "configs/tools/agent-audit.toml", AgentAuditToolConfig)
    atomic_write_bytes(output / "execution-profile.toml", execution.raw)
    atomic_write_bytes(output / "validator-tool.toml", tool.raw)
    rows = []
    syntax_count = scanner_count = 0
    for case in registry["cases"]:
        cell = output / case["id"]
        context, source = controlled_context(case, cell, profile_bytes)
        preparation, view = materialize_research_inputs(
            context, source=source, output=cell / "view"
        )
        atomic_write_model(cell / "policy.json", preparation.policy)
        row: dict[str, Any] = {
            "case": case["id"],
            "revision": context.verification.revision,
            "selected_files": len(case["selected"]),
            "scanner_passes": [],
            "target_executed": False,
        }
        rows.append(row)
        if preparation.scope is None:
            if case["gate"] != "policy-refused" or case["blocker"] not in {
                b.code for b in preparation.policy.blockers
            }:
                raise RuntimeError("Unexpected policy refusal; evidence retained")
            row.update({"state": "policy-refused", "finding_count": None})
            print(case["id"], row["state"], flush=True)
            continue
        assert view is not None
        scope, target = preparation.scope, cell / "view/target"
        request = research_worker_request(scope)
        request_path = cell / "request.json"
        atomic_write_model(request_path, request)
        name = "research-syntax-" + semantic_hash({"path": str(cell)})[:20]
        argv = build_agent_argv(
            docker=docker,
            tool=tool.value,
            profile=execution.value,
            name=name,
            target=target,
            worker_source=output / "worker-source",
            request=request_path,
        )
        capture, cleaned = invoke(argv, cell / "syntax", docker, name, environment)
        syntax_count += 1
        if capture.exit_code != 0 or capture.timed_out or capture.output_limited or not cleaned:
            raise RuntimeError("Syntax worker failed; scanner not launched")
        syntax_ok = assess_research_syntax(request, request_path.read_bytes(), capture.stdout)
        replay_research_inputs(
            context, source=source, preparation=preparation, view=view, target=target
        )
        if not syntax_ok:
            if case["gate"] != "syntax-refused":
                raise RuntimeError("Unexpected syntax refusal")
            row.update({"state": "syntax-refused", "finding_count": None})
            print(case["id"], row["state"], flush=True)
            continue
        if case["gate"] != "scan":
            raise RuntimeError("Expected refusal did not occur; scanner not launched")
        observations = []
        for repetition in range(1, 3 if case.get("repeat") else 2):
            passes = []
            for role in ("research", "repository-policy"):
                role_value: Literal["research", "repository-policy"] = (
                    "research" if role == "research" else "repository-policy"
                )
                native_cell = cell / f"{role}-{repetition}"
                native_cell.mkdir()
                replay_research_inputs(
                    context, source=source, preparation=preparation, view=view, target=target
                )
                verify_rule_bytes(
                    profile,
                    {p: bounded_read(output / "rules" / p, MAX_FILE_BYTES) for p in rules},
                    license_bytes=bounded_read(output / "rules/LICENSE", MAX_FILE_BYTES),
                )
                name = "research-scan-" + semantic_hash({"path": str(native_cell)})[:20]
                argv = build_research_argv(
                    docker=docker,
                    name=name,
                    profile_bytes=profile_bytes,
                    scope=scope,
                    role=role_value,
                    rules=output / "rules",
                    target=target,
                    output=native_cell,
                )
                capture, cleaned = invoke(argv, native_cell, docker, name, environment)
                scanner_count += 1
                evidence = None
                try:
                    evidence = reconcile_semgrep_pass(
                        profile_bytes=profile_bytes,
                        scope=scope,
                        execution_id=name,
                        role=role_value,
                        native_json=bounded_read(native_cell / "native.json", MAX_REPORT_BYTES),
                        native_sarif=bounded_read(native_cell / "native.sarif", MAX_REPORT_BYTES),
                    )
                    atomic_write_model(native_cell / "evidence.json", evidence)
                except (OSError, ValueError) as exc:
                    save(native_cell / "reconciliation-failure.json", {"type": type(exc).__name__})
                status = assess_research_execution(
                    capture, cleanup_succeeded=cleaned, evidence=evidence
                )
                atomic_write_model(native_cell / "assessment.json", status)
                replay_research_inputs(
                    context, source=source, preparation=preparation, view=view, target=target
                )
                if status.analysis_state == "failed" or evidence is None:
                    raise RuntimeError("Failed native attempt retained; not a clean analysis")
                if capture.exit_code != (2 if case.get("native_issue") else 0):
                    raise RuntimeError("Unexpected native process status")
                if bool(evidence.native_errors) != bool(case.get("native_issue")):
                    raise RuntimeError("Unexpected native analysis issue")
                row["scanner_passes"].append(
                    {
                        "role": role,
                        "repetition": repetition,
                        "status": status.model_dump(mode="json"),
                        "native_findings": len(evidence.findings),
                        "duration_ns": capture.duration_ns,
                    }
                )
                passes.append(evidence)
            dual = build_dual_view(*passes)
            atomic_write_model(cell / f"dual-view-{repetition}.json", dual)
            if sorted(
                f.path for f in passes[1].files if f.native_reason == "semgrepignore_patterns_match"
            ) != sorted(case["policy_excluded"]):
                raise RuntimeError("Policy exclusions differ from controlled expectation")
            if sorted(
                {f.anchor.path for f in passes[1].findings if f.native_suppressions}
            ) != sorted(case["suppressed"]):
                raise RuntimeError("Inline suppression differs from controlled expectation")
            if {f.anchor.path for f in passes[0].findings} != set(case["selected"]):
                raise RuntimeError("Research pass failed to retain selected eval conditions")
            observations.append([projection(p) for p in passes])
        if any(result != observations[0] for result in observations[1:]):
            raise RuntimeError("Repeat semantic observations differ")
        row.update(
            {
                "state": "observed",
                "repeated": bool(case.get("repeat")),
                "semantic_repeat_equal": True if case.get("repeat") else None,
            }
        )
        print(case["id"], "verified", len(row["scanner_passes"]), "scanner passes", flush=True)
    verify_rule_bytes(
        profile,
        {p: bounded_read(output / "rules" / p, MAX_FILE_BYTES) for p in rules},
        license_bytes=bounded_read(output / "rules/LICENSE", MAX_FILE_BYTES),
    )
    save(
        output / "summary.json",
        {
            "assertions_passed": True,
            "role": "controlled-development-not-held-out",
            "policy_label": POLICY_LABEL,
            "syntax_workers": syntax_count,
            "scanner_invocations": scanner_count,
            "cases": rows,
            "public_source_scanned": False,
            "analysis_completeness": "not-established",
            "limitations": [
                "Selected fixture paths, not repository-wide detector coverage",
                "No target execution",
                "No public-source admission or common-report integration",
                "No independent security labels",
            ],
        },
    )
    records = [
        {
            "path": p.relative_to(output).as_posix(),
            "bytes": p.stat().st_size,
            "sha256": sha256_file(p),
        }
        for p in sorted(output.rglob("*"))
        if p.is_file() and p.relative_to(output).parts[0] != "runtime"
    ]
    save(output / "evidence-manifest.json", {"files": records})
    print("Guarded controlled research verification complete", flush=True)


if __name__ == "__main__":
    main()
