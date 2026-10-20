"""Execute one admitted development case without using detector expectations as gates."""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path
from typing import Any, Literal, cast

from agentsec_evidence.agents.execution import AgentAuditToolConfig, build_agent_argv
from agentsec_evidence.agents.inventory import build_artifact_inventory
from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
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
from agentsec_evidence.research.retained import (
    MAX_ENTRY_BYTES,
    MAX_TREE_BYTES,
    RetainedManifest,
    bounded_file,
    plain_path,
)
from agentsec_evidence.research.semgrep import build_dual_view, reconcile_semgrep_pass

REGISTRY_PATH = "test_cases/development/research-runner/cases.json"
PROFILE_PATH = "configs/research/semgrep-python-candidate-v1.json"
EXECUTION_PATH = "configs/profiles/agent-development.toml"
VALIDATOR_PATH = "configs/tools/agent-audit.toml"
ADMITTED_PINS = {
    REGISTRY_PATH: "c2949fc1a1205731473a731ad1a8eb63183fbf899670854e883b45379c510f8c",
    PROFILE_PATH: "ce4b8517a4042bb247ac641250f5d9428e8a5f985db69d36f2d9fef28f09e23c",
    EXECUTION_PATH: "2e133b817c87ce454d7a148da177fda593d0effe639688226e8b24f8600aea77",
    VALIDATOR_PATH: "449980ad953f95802e712d3d397598dafb9afb9601805bb6d51819c34fa8e231",
}


def save(path: Path, value: Any) -> None:
    atomic_write_bytes(path, json_bytes(value))


def controlled_context(
    case: dict[str, Any], cell: Path, profile_bytes: bytes
) -> tuple[ToolViewContext, Path]:
    files = {p: text.encode() for p, text in case["files"].items()}
    raw_commit, raw_tree = case["git"]["raw_commit"].encode(), json_bytes(case["git"]["tree"])
    proof = verify_git_source(
        raw_commit=raw_commit, raw_tree=raw_tree, revision=case["git"]["revision"], files=files
    )
    source = cell / "parent"
    for path, data in files.items():
        atomic_write_bytes(source / path, data)
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


def invoke(
    argv: list[str],
    cell: Path,
    *,
    project: Path,
    docker: Path,
    name: str,
    environment: dict[str, str],
) -> tuple[ProcessCapture, bool]:
    if os.path.lexists(cell):
        plain_path(cell, directory=True)
        if any(cell.iterdir()):
            raise ValueError("Refuse overwriting a process capture")
    else:
        cell.mkdir(exist_ok=False)
    save(cell / "command.json", {"argv": argv, "target_execution": False})
    try:
        capture = run_bounded_process(
            argv,
            cwd=project,
            environment=environment,
            timeout_seconds=120,
            max_stdout_bytes=MAX_REPORT_BYTES,
            max_stderr_bytes=MAX_REPORT_BYTES,
            monitored_files=(cell / "native.json", cell / "native.sarif"),
            max_generated_bytes=2 * MAX_REPORT_BYTES,
        )
        atomic_write_bytes(cell / "stdout.bin", capture.stdout)
        atomic_write_bytes(cell / "stderr.bin", capture.stderr)
        record = dataclasses.asdict(capture)
        del record["stdout"], record["stderr"]
        record["started_at"] = capture.started_at.isoformat()
        record["ended_at"] = capture.ended_at.isoformat()
        save(cell / "execution.json", record)
    except BaseException as exc:
        save(cell / "launch-failure.json", {"type": type(exc).__name__})
        raise
    finally:
        try:
            cleaned = cleanup_container(
                docker=docker, container_name=name, cwd=project, environment=environment
            )
        except OSError:
            cleaned = False
        save(cell / "cleanup.json", {"succeeded": cleaned})
    return capture, cleaned


def seal_controlled_attempt(root: Path) -> None:
    """Seal successful and failed attempts alike; a hash is not an outcome assertion."""
    records: list[dict[str, Any]] = []
    total = 0
    for directory, dirs, names in os.walk(root):
        for name in list(dirs):
            plain_path(Path(directory) / name, directory=True)
            if Path(directory) == root and name == "runtime":
                dirs.remove(name)
        for name in sorted(names):
            path = Path(directory) / name
            if path == root / "evidence-manifest.json":
                raise ValueError("Refuse resealing an existing attempt")
            if len(records) >= 4096:
                raise ValueError("Controlled evidence file budget exceeded")
            raw = bounded_file(path, MAX_ENTRY_BYTES)
            total += len(raw)
            if total > MAX_TREE_BYTES:
                raise ValueError("Controlled evidence byte budget exceeded")
            records.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "bytes": len(raw),
                    "sha256": sha256_bytes(raw),
                }
            )
    atomic_write_model(
        root / "evidence-manifest.json",
        RetainedManifest.model_validate({"files": sorted(records, key=lambda r: r["path"])}),
    )


def _frozen_inputs(project: Path, rule_source: Path) -> dict[str, bytes]:
    protected = {p: bounded_file(project / p, MAX_REPORT_BYTES) for p in ADMITTED_PINS}
    if any(sha256_bytes(raw) != ADMITTED_PINS[p] for p, raw in protected.items()):
        raise ValueError("Controlled admission changed; re-pinning does not grant permission")
    profile = load_research_profile(protected[PROFILE_PATH])
    rules = {
        r.source_path: bounded_file(rule_source / r.source_path, MAX_FILE_BYTES)
        for r in profile.rules
    }
    license_raw = bounded_file(rule_source / "LICENSE", MAX_FILE_BYTES)
    verify_rule_bytes(profile, rules, license_bytes=license_raw)
    frozen = {
        "profile.json": protected[PROFILE_PATH],
        "cases.json": protected[REGISTRY_PATH],
        "execution-profile.toml": protected[EXECUTION_PATH],
        "validator-tool.toml": protected[VALIDATOR_PATH],
        "rules/LICENSE": license_raw,
        **{"rules/" + p: raw for p, raw in rules.items()},
    }
    src = plain_path(project / "src", directory=True)
    for directory, dirs, names in os.walk(src):
        for name in dirs:
            plain_path(Path(directory) / name, directory=True)
        for name in sorted(names):
            if name.endswith(".py"):
                path = Path(directory) / name
                if len(frozen) >= 2048:
                    raise ValueError("Worker source file budget exceeded")
                frozen["worker-source/" + path.relative_to(src).as_posix()] = bounded_file(
                    path, MAX_FILE_BYTES
                )
    if "worker-source/agentsec_evidence/agents/worker.py" not in frozen:
        raise ValueError("Trusted syntax worker is missing")
    if sum(map(len, frozen.values())) > MAX_TREE_BYTES // 2:
        raise ValueError("Controlled frozen inputs exceed byte budget")
    return frozen


def _check_frozen(root: Path, frozen: dict[str, bytes]) -> None:
    for path, raw in frozen.items():
        if bounded_file(root / path, len(raw)) != raw:
            raise ValueError("Frozen controlled input changed during execution")
    for prefix in ("rules", "worker-source"):
        actual = set()
        for directory, dirs, names in os.walk(root / prefix):
            for name in dirs:
                plain_path(Path(directory) / name, directory=True)
            for name in names:
                file_path = plain_path(Path(directory) / name, directory=False)
                actual.add(file_path.relative_to(root).as_posix())
        if actual != {p for p in frozen if p.startswith(prefix + "/")}:
            raise ValueError("Frozen controlled input file set changed")


def run_controlled_research_case(
    *, project: Path, rule_source: Path, output: Path, case_id: str, docker_path: Path | None = None
) -> Path:
    """Run one of the original fifteen cases, with its original one/two dual-view repeats.

    Detector expectations stay in the frozen registry for subsequent evaluation, but do not
    control dispatch or success. Only actual policy, syntax and execution evidence do so.
    """
    project = plain_path(project, directory=True)
    output = Path(os.path.abspath(output))
    workspace = plain_path(project / "workspace", directory=True)
    plain_path(output.parent, directory=True)
    if output == workspace or not output.is_relative_to(workspace) or os.path.lexists(output):
        raise ValueError("Output must be a fresh private workspace child")
    rule_source = plain_path(rule_source, directory=True)
    frozen = _frozen_inputs(project, rule_source)
    registry = cast(
        dict[str, Any], load_agent_json(frozen["cases.json"], max_bytes=MAX_REPORT_BYTES)
    )
    if (
        registry.get("role") != "development-not-held-out"
        or registry.get("target_execution") is not False
        or len(registry.get("cases", [])) != 15
    ):
        raise ValueError("Only the registered controlled development corpus is admitted")
    matches = [case for case in registry["cases"] if case["id"] == case_id]
    if len(matches) != 1:
        raise ValueError("Select exactly one admitted development case")
    case = matches[0]
    output.mkdir(exist_ok=False)
    try:
        for path, raw in frozen.items():
            atomic_write_bytes(output / path, raw)
        save(
            output / "frozen-inputs.json",
            {
                "files": [
                    {"path": p, "bytes": len(raw), "sha256": sha256_bytes(raw)}
                    for p, raw in sorted(frozen.items())
                ]
            },
        )
        _execute_case(project, output, case, frozen, docker_path)
    except BaseException as exc:
        save(output / "failure.json", {"type": type(exc).__name__, "completed": False})
        raise
    finally:
        seal_controlled_attempt(output)
    return output / case_id


def _execute_case(
    project: Path,
    output: Path,
    case: dict[str, Any],
    frozen: dict[str, bytes],
    docker_path: Path | None,
) -> None:
    cell = output / case["id"]
    profile_bytes = frozen["profile.json"]
    context, source = controlled_context(case, cell, profile_bytes)
    preparation, view = materialize_research_inputs(context, source=source, output=cell / "view")
    atomic_write_model(cell / "policy.json", preparation.policy)
    # Policy refusals are real input outcomes and do not require a Docker installation.
    if preparation.scope is None:
        _check_frozen(output, frozen)
        return
    assert view is not None
    scope, target = preparation.scope, cell / "view/target"
    docker = resolve_docker(docker_path)
    if docker is None:
        raise RuntimeError("Docker unavailable; no images are downloaded")
    environment = minimal_environment(output / "runtime")
    request = research_worker_request(scope)
    request_path = cell / "request.json"
    atomic_write_model(request_path, request)
    limits = load_toml_config(output / "execution-profile.toml", ExecutionProfile)
    tool = load_toml_config(output / "validator-tool.toml", AgentAuditToolConfig)
    name = "research-syntax-" + semantic_hash({"path": str(cell)})[:20]
    _check_frozen(output, frozen)
    capture, cleaned = invoke(
        build_agent_argv(
            docker=docker,
            tool=tool.value,
            profile=limits.value,
            name=name,
            target=target,
            worker_source=output / "worker-source",
            request=request_path,
        ),
        cell / "syntax",
        project=project,
        docker=docker,
        name=name,
        environment=environment,
    )
    if (
        capture.exit_code != 0
        or capture.timed_out
        or capture.output_limited
        or capture.stdout_truncated
        or capture.stderr_truncated
        or not cleaned
    ):
        raise RuntimeError("Syntax worker failed; scanner not launched")
    parsed = assess_research_syntax(request, request_path.read_bytes(), capture.stdout)
    replay_research_inputs(
        context, source=source, preparation=preparation, view=view, target=target
    )
    _check_frozen(output, frozen)
    if not parsed:
        return
    for repetition in range(1, 3 if case.get("repeat") is True else 2):
        passes = []
        for role in ("research", "repository-policy"):
            role_value: Literal["research", "repository-policy"] = (
                "research" if role == "research" else "repository-policy"
            )
            native_cell = cell / f"{role}-{repetition}"
            native_cell.mkdir(exist_ok=False)
            replay_research_inputs(
                context, source=source, preparation=preparation, view=view, target=target
            )
            _check_frozen(output, frozen)
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
            capture, cleaned = invoke(
                argv,
                native_cell,
                project=project,
                docker=docker,
                name=name,
                environment=environment,
            )
            evidence = None
            try:
                evidence = reconcile_semgrep_pass(
                    profile_bytes=profile_bytes,
                    scope=scope,
                    execution_id=name,
                    role=role_value,
                    native_json=bounded_file(native_cell / "native.json", MAX_REPORT_BYTES),
                    native_sarif=bounded_file(native_cell / "native.sarif", MAX_REPORT_BYTES),
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
            _check_frozen(output, frozen)
            if status.analysis_state == "failed" or evidence is None:
                raise RuntimeError("Failed native attempt retained; not successful analysis")
            passes.append(evidence)
        atomic_write_model(cell / f"dual-view-{repetition}.json", build_dual_view(*passes))
