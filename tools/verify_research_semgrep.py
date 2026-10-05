"""Offline controlled-case verification only; no arbitrary target or public source scan."""

from __future__ import annotations

import argparse
import dataclasses
import json
from collections import Counter
from pathlib import Path
from typing import Any, Literal

from agentsec_evidence.agents.execution import AgentAuditToolConfig, build_agent_argv
from agentsec_evidence.agents.records import (
    AgentInputReport,
    AgentInputRequest,
    verify_input_report,
)
from agentsec_evidence.agents.validation import canonical_artifact_path, load_agent_json
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes, sha256_file
from agentsec_evidence.core.io import atomic_write_bytes, atomic_write_model, json_bytes
from agentsec_evidence.execution.config import ExecutionProfile, load_toml_config
from agentsec_evidence.execution.process import run_bounded_process
from agentsec_evidence.models.contracts import InventoryEntry
from agentsec_evidence.orchestration.shared import (
    cleanup_container,
    minimal_environment,
    resolve_docker,
)
from agentsec_evidence.research.models import (
    MAX_FILE_BYTES,
    MAX_REPORT_BYTES,
    ResearchInput,
    SemgrepPassEvidence,
    SemgrepResearchScope,
    load_research_profile,
    verify_rule_bytes,
)
from agentsec_evidence.research.semgrep import build_dual_view, reconcile_semgrep_pass

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "configs/research/semgrep-python-candidate-v1.json"
CASES = ROOT / "test_cases/development/semgrep-research/cases.json"


def save(path: Path, value: Any) -> None:
    atomic_write_bytes(
        path, (json.dumps(value, indent=2, sort_keys=True, default=str) + "\n").encode()
    )


def bounded_read(path: Path, limit: int) -> bytes:
    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise ValueError("Expected a regular local evidence file")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Evidence byte budget exceeded")
    return data


def capture(
    argv: list[str],
    output: Path,
    *,
    docker: Path,
    name: str,
    environment: dict[str, str],
    permitted_exit_codes: tuple[int, ...] = (0,),
) -> int:
    output.mkdir(parents=True, exist_ok=True)
    save(output / "command.json", {"argv": argv, "target_execution": False})
    try:
        result = run_bounded_process(
            argv,
            cwd=ROOT,
            environment=environment,
            timeout_seconds=120,
            max_stdout_bytes=MAX_REPORT_BYTES,
            max_stderr_bytes=MAX_REPORT_BYTES,
            monitored_files=(output / "native.json", output / "native.sarif"),
            max_generated_bytes=2 * MAX_REPORT_BYTES,
        )
        atomic_write_bytes(output / "stdout.bin", result.stdout)
        atomic_write_bytes(output / "stderr.bin", result.stderr)
        receipt = dataclasses.asdict(result)
        del receipt["stdout"], receipt["stderr"]
        save(output / "execution.json", receipt)
    finally:
        cleaned = cleanup_container(
            docker=docker, container_name=name, cwd=ROOT, environment=environment
        )
        save(output / "cleanup.json", {"succeeded": cleaned})
    if (
        result.exit_code not in permitted_exit_codes
        or result.timed_out
        or result.output_limited
        or not cleaned
    ):
        raise RuntimeError("Unsuccessful controlled attempt retained; not a clean analysis")
    assert result.exit_code is not None
    return result.exit_code


def mount(path: Path, destination: str, *, readonly: bool = True) -> str:
    source = str(path.resolve(strict=True))
    if any(char in source for char in (",", "\r", "\n", "\0")):
        raise ValueError("Unsafe Docker mount source")
    return f"type=bind,source={source},target={destination}" + (",readonly" if readonly else "")


def projection(evidence: SemgrepPassEvidence) -> dict[str, Any]:
    """Only known run identity/raw-byte fields vary; all observation fields remain compared."""
    return evidence.model_dump(
        mode="json", exclude={"execution_id", "native_json_sha256", "native_sarif_sha256"}
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rule-source",
        type=Path,
        required=True,
        help="Cached upstream root with LICENSE and python/",
    )
    parser.add_argument(
        "--output", type=Path, required=True, help="Fresh directory under workspace/"
    )
    parser.add_argument("--docker", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    if (
        not output.is_relative_to((ROOT / "workspace").resolve())
        or output == (ROOT / "workspace").resolve()
    ):
        raise ValueError("Controlled output must be a new child of the ignored workspace")
    output.mkdir(parents=True, exist_ok=False)
    docker = resolve_docker(args.docker)
    if docker is None:
        raise RuntimeError("Pinned local Docker images are required; this tool never pulls")
    environment = minimal_environment(output / "runtime")
    profile_bytes = PROFILE.read_bytes()
    profile = load_research_profile(profile_bytes)
    case_bytes = CASES.read_bytes()
    registry = json.loads(case_bytes)
    if registry["role"] != "development-not-held-out" or registry["target_execution"] is not False:
        raise ValueError("Only controlled non-executed development inputs are authorized")
    if len(registry["conditions"]) != 30 or len(registry["policy_case"]["files"]) != 12:
        raise ValueError("Unexpected controlled registry scope")
    files = {
        rule.source_path: bounded_read(args.rule_source / rule.source_path, MAX_FILE_BYTES)
        for rule in profile.rules
    }
    license_bytes = bounded_read(args.rule_source / "LICENSE", MAX_FILE_BYTES)
    verify_rule_bytes(profile, files, license_bytes=license_bytes)
    for path, data in files.items():
        atomic_write_bytes(output / "rules" / path, data)
    atomic_write_bytes(output / "rules/LICENSE", license_bytes)
    atomic_write_bytes(output / "profile.json", profile_bytes)
    atomic_write_bytes(output / "cases.json", case_bytes)
    atomic_write_bytes(output / "harness.py", Path(__file__).read_bytes())
    for path in sorted((ROOT / "src").rglob("*.py")):
        atomic_write_bytes(
            output / "worker-source" / path.relative_to(ROOT / "src"), path.read_bytes()
        )
    execution = load_toml_config(ROOT / "configs/profiles/agent-development.toml", ExecutionProfile)
    tool = load_toml_config(ROOT / "configs/tools/agent-audit.toml", AgentAuditToolConfig)
    atomic_write_bytes(output / "execution-profile.toml", execution.raw)
    atomic_write_bytes(output / "validator-tool.toml", tool.raw)
    groups = {
        "conditions": {case["id"] + ".py": case["source"] for case in registry["conditions"]},
        "policy": registry["policy_case"]["files"],
    }
    scopes: dict[str, SemgrepResearchScope] = {}
    for group, sources in groups.items():
        entries = []
        for path, source in sorted(sources.items()):
            canonical_artifact_path(path)
            data = source.encode("utf-8")
            entries.append(
                ResearchInput(
                    path=path,
                    sha256=sha256_bytes(data),
                    byte_length=len(data),
                    media_type="text/x-python" if path.endswith(".py") else "text/plain",
                )
            )
        scope = SemgrepResearchScope(
            target_snapshot_id=f"authored-research-{group}-v1",
            selection_sha256=sha256_bytes(case_bytes),
            profile_sha256=sha256_bytes(profile_bytes),
            selected_files=tuple(entry for entry in entries if entry.path.endswith(".py")),
            policy_files=tuple(entry for entry in entries if not entry.path.endswith(".py")),
        )
        scopes[group] = scope
        for path, source in sources.items():
            atomic_write_bytes(output / group / "source" / path, source.encode("utf-8"))
        atomic_write_model(output / group / "scope.json", scope)
        request = AgentInputRequest(
            target_snapshot_id=scope.target_snapshot_id,
            inventory=[
                InventoryEntry.model_validate(entry.model_dump(mode="json")) for entry in entries
            ],
            selected={entry.path: "python-source" for entry in scope.selected_files},
        )
        request_path = output / group / "request.json"
        atomic_write_model(request_path, request)
        name = "research-syntax-" + semantic_hash({"output": str(output), "group": group})[:20]
        argv = build_agent_argv(
            docker=docker,
            tool=tool.value,
            profile=execution.value,
            name=name,
            target=output / group / "source",
            worker_source=output / "worker-source",
            request=request_path,
        )
        cell = output / group / "syntax"
        capture(argv, cell, docker=docker, name=name, environment=environment)
        report = AgentInputReport.model_validate(
            load_agent_json(
                bounded_read(cell / "stdout.bin", MAX_REPORT_BYTES), max_bytes=MAX_REPORT_BYTES
            )
        )
        verify_input_report(report, request, request_path.read_bytes())
        if any(check.artifact.parse_state != "parsed" for check in report.checks):
            raise RuntimeError("Controlled source syntax failed; no scanner launch")
    runs: dict[str, list[SemgrepPassEvidence]] = {}
    execution_rows = []
    for repetition in (1, 2):
        for group, role in (
            ("conditions", "research"),
            ("policy", "research"),
            ("policy", "repository-policy"),
        ):
            role_value: Literal["research", "repository-policy"] = (
                "research" if role == "research" else "repository-policy"
            )
            scope = scopes[group]
            cell = output / group / f"{role}-{repetition}"
            cell.mkdir()
            name = "research-scan-" + semantic_hash({"output": str(cell)})[:20]
            argv = [
                str(docker),
                "run",
                "--rm",
                "--pull=never",
                "--name",
                name,
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--user",
                "65534:65534",
                "--cpus",
                "2",
                "--memory",
                "2048m",
                "--memory-swap",
                "2048m",
                "--pids-limit",
                "256",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=268435456",
                "--env",
                "HOME=/tmp",
                "--env",
                "SEMGREP_SEND_METRICS=off",
                "--workdir",
                "/src",
                "--mount",
                mount(output / "rules", "/rules"),
                "--mount",
                mount(output / group / "source", "/src"),
                "--mount",
                mount(cell, "/output", readonly=False),
                profile.image,
                "semgrep",
                "scan",
                "--metrics=off",
                "--disable-version-check",
                "--no-rewrite-rule-ids",
                "--jobs=2",
                "--config",
                "/rules/python",
                "--strict",
                "--no-git-ignore",
                "--verbose",
                "--json",
                "--json-output",
                "/output/native.json",
                "--sarif-output",
                "/output/native.sarif",
            ]
            argv += (
                ["--disable-nosem", *["/src/" + entry.path for entry in scope.selected_files]]
                if role == "research"
                else ["/src"]
            )
            # The deliberately unmatched suppression produces native warning exit 2.
            # Accept it only for this registered group, retain its errors and assert them below.
            exit_code = capture(
                argv,
                cell,
                docker=docker,
                name=name,
                environment=environment,
                permitted_exit_codes=(2,) if group == "policy" else (0,),
            )
            evidence = reconcile_semgrep_pass(
                profile_bytes=profile_bytes,
                scope=scope,
                execution_id=name,
                role=role_value,
                native_json=bounded_read(cell / "native.json", MAX_REPORT_BYTES),
                native_sarif=bounded_read(cell / "native.sarif", MAX_REPORT_BYTES),
            )
            atomic_write_model(cell / "evidence.json", evidence)
            if group == "policy":
                if len(evidence.native_errors) != 1:
                    raise RuntimeError("Expected exactly the unmatched-suppression warning")
                warning = evidence.native_errors[0]
                if (
                    not isinstance(warning, dict)
                    or warning.get("path") != "/src/unknown-rule.py"
                    or warning.get("code") != 2
                    or "unrelated.rule" not in str(warning.get("message"))
                ):
                    raise RuntimeError("Unexpected native error retained; not an accepted warning")
            elif evidence.native_errors:
                raise RuntimeError("Unexpected condition-scan errors")
            execution_rows.append(
                {
                    "group": group,
                    "role": role,
                    "repetition": repetition,
                    "exit_code": exit_code,
                    "native_error_count": len(evidence.native_errors),
                    "analysis_state": "incomplete" if evidence.native_errors else "not-established",
                }
            )
            runs.setdefault(f"{group}-{role}", []).append(evidence)
            print(group, role, repetition, "native findings", len(evidence.findings), flush=True)
    for key, pair in runs.items():
        if projection(pair[0]) != projection(pair[1]):
            raise RuntimeError(f"Controlled semantic observations differ: {key}")
    view = build_dual_view(runs["policy-research"][0], runs["policy-repository-policy"][0])
    atomic_write_model(output / "policy/dual-view.json", view)
    policy = runs["policy-repository-policy"][0]
    actual_excluded = sorted(
        f.path for f in policy.files if f.native_reason == "semgrepignore_patterns_match"
    )
    actual_marked = sorted({f.anchor.path for f in policy.findings if f.native_suppressions})
    if actual_excluded != sorted(
        registry["policy_case"]["expected_excluded_paths"]
    ) or actual_marked != sorted(registry["policy_case"]["expected_inline_marked_paths"]):
        raise RuntimeError("Native policy observations differ from controlled assertions")
    findings = runs["conditions-research"][0].findings
    rows = [
        {
            "case": case["id"],
            "condition": case["condition"],
            "condition_present": case["condition_present"],
            "designated_rule": case["rule_id"],
            "designated_rule_reported": any(
                f.anchor.path == case["id"] + ".py" and f.anchor.rule_id == case["rule_id"]
                for f in findings
            ),
            "all_reported_rules": sorted(
                {f.anchor.rule_id for f in findings if f.anchor.path == case["id"] + ".py"}
            ),
        }
        for case in registry["conditions"]
    ]
    for group, scope in scopes.items():
        for entry in (*scope.selected_files, *scope.policy_files):
            if sha256_file(output / group / "source" / entry.path) != entry.sha256:
                raise RuntimeError("Controlled input changed")
    verify_rule_bytes(
        profile,
        {path: bounded_read(output / "rules" / path, MAX_FILE_BYTES) for path in files},
        license_bytes=bounded_read(output / "rules/LICENSE", MAX_FILE_BYTES),
    )
    save(
        output / "summary.json",
        {
            "verification_assertions_passed": True,
            "role": "controlled-development-not-held-out",
            "rule_count": len(profile.rules),
            "syntax_workers": 2,
            "scanner_invocations": 6,
            "condition_files": 30,
            "policy_python_files": 10,
            "semantic_repeats_equal": True,
            "input_hashes_unchanged": True,
            "target_code_executed": False,
            "policy_view_states": dict(Counter(row.state for row in view.findings)),
            "conditions": rows,
            "executions": execution_rows,
            "limitations": [
                "Source-condition labels are not independently adjudicated vulnerabilities",
                "No public source runner or final profile admission",
                "Semgrep file reporting does not establish complete rule execution",
                "No runtime exploitability test or accuracy estimate",
                "Policy treatment is a frozen offline snapshot, not a reconstruction of project CI",
            ],
        },
    )
    records = [
        {
            "path": path.relative_to(output).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.relative_to(output).parts[0] != "runtime"
    ]
    atomic_write_bytes(output / "evidence-manifest.json", json_bytes({"files": records}))
    print("Controlled verification complete; disagreements retained in summary.json", flush=True)


if __name__ == "__main__":
    main()
