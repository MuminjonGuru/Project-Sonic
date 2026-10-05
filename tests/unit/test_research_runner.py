from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from agentsec_evidence.agents.inventory import build_artifact_inventory
from agentsec_evidence.agents.worker import validate_view
from agentsec_evidence.core.io import json_bytes, model_bytes
from agentsec_evidence.execution.process import ProcessCapture
from agentsec_evidence.intake.git_verification import verify_git_source
from agentsec_evidence.intake.input_plan import build_tool_input_plan
from agentsec_evidence.intake.snapshot import create_snapshot
from agentsec_evidence.intake.views import ToolViewContext
from agentsec_evidence.research.execution import assess_research_execution, build_research_argv
from agentsec_evidence.research.inputs import (
    assess_research_syntax,
    materialize_research_inputs,
    prepare_research_inputs,
    replay_research_inputs,
    research_worker_request,
)
from agentsec_evidence.research.models import SemgrepPassEvidence, load_research_profile
from agentsec_evidence.research.policy import assess_semgrep_policy

ROOT = Path(__file__).resolve().parents[2]
CASES = json.loads((ROOT / "test_cases/development/research-runner/cases.json").read_bytes())[
    "cases"
]
PROFILE = (ROOT / "configs/research/semgrep-python-candidate-v1.json").read_bytes()


def context_case(tmp_path: Path, case: dict[str, Any]) -> tuple[ToolViewContext, Path]:
    source = tmp_path / "parent"
    files = {p: text.encode() for p, text in case["files"].items()}
    for path, data in files.items():
        file = source / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(data)
    commit, tree = case["git"]["raw_commit"].encode(), json_bytes(case["git"]["tree"])
    proof = verify_git_source(
        raw_commit=commit, raw_tree=tree, revision=case["git"]["revision"], files=files
    )
    snapshot = create_snapshot(
        source,
        tmp_path / "snapshots",
        source_label="controlled-research-test",
        revision=proof.revision,
        source_kind="git",
    )
    inventory = build_artifact_inventory(snapshot.snapshot, snapshot.inventory)
    plan = build_tool_input_plan(
        inventory=inventory,
        verification=proof,
        tool_id="semgrep",
        profile_id=load_research_profile(PROFILE).profile_id,
        profile_bytes=PROFILE,
        selected_paths=case["selected"],
        selected_reason="Controlled test input",
        exclusions={p: "Retain unselected parent" for p in files if p not in case["selected"]},
    )
    return ToolViewContext(inventory, proof, plan, PROFILE, commit, tree), source


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_git_verified_scope_and_syntax_gates(tmp_path: Path, case: dict[str, Any]) -> None:
    context, source = context_case(tmp_path, case)
    preparation, view = materialize_research_inputs(
        context, source=source, output=tmp_path / "view"
    )
    assert preparation.policy.implicit_gitignore == "disabled"
    if case["gate"] == "policy-refused":
        assert preparation.scope is None and view is None
        assert case["blocker"] in {b.code for b in preparation.policy.blockers}
        assert not (tmp_path / "view").exists()
        return
    assert view is not None and preparation.scope is not None
    scope = preparation.scope
    assert {e.path for e in scope.selected_files} == set(case["selected"])
    assert {e.path for e in scope.policy_files} == {e.path for e in preparation.policy.files}
    target = tmp_path / "view/target"
    assert not (target / "unselected.py").exists()
    request = research_worker_request(scope)
    # Host parsing is restricted to these trusted authored unit fixtures; the runner uses Docker.
    raw = model_bytes(request)
    report = validate_view(target, raw)
    assert assess_research_syntax(request, raw, model_bytes(report)) == (case["gate"] == "scan")
    replay_research_inputs(
        context, source=source, preparation=preparation, view=view, target=target
    )
    assert scope.execution_authorization == "not-granted"


@pytest.mark.parametrize(
    "relative", ["../a", "/etc/passwd", "C:/a", "a\\b", "./a", "a/../b", "CON"]
)
def test_unsafe_policy_include_paths_refused(relative: str) -> None:
    assessment = assess_semgrep_policy({".semgrepignore": f":include {relative}\n".encode()})
    assert [b.code for b in assessment.blockers] == ["unsafe-include"]


@pytest.mark.parametrize(
    "data",
    [b"\xff", b"\xef\xbb\xbf", b"a\0b", b"x\ry", b"x" * (256 * 1024 + 1)],
    ids=["invalid-utf8", "bom", "nul", "bare-cr", "oversize"],
)
def test_invalid_policy_bytes_refused(data: bytes) -> None:
    assert assess_semgrep_policy({".semgrepignore": data}).blockers


def test_explicit_gitignore_import_distinct_from_implicit_git_filter() -> None:
    files = {".gitignore": b"agent.py\n"}
    assert not assess_semgrep_policy(files).files
    assessment = assess_semgrep_policy(files | {".semgrepignore": b":include .gitignore\r\n"})
    assert not assessment.blockers and assessment.includes[0].target == ".gitignore"
    assert assessment.implicit_gitignore == "disabled"
    assert [f.path for f in assessment.files] == [".gitignore", ".semgrepignore"]


def test_python_include_and_nested_directives_refused() -> None:
    result = assess_semgrep_policy(
        {".semgrepignore": b":include policy.py\n", "policy.py": b"*.py\n"}
    )
    assert [b.code for b in result.blockers] == ["python-policy-input"]
    result = assess_semgrep_policy(
        {".semgrepignore": b":include a\n", "a": b":include b\n", "b": b"*.py\n"}
    )
    assert [b.code for b in result.blockers] == ["nested-include"]


@pytest.mark.parametrize("kind", ["lines", "edges", "files", "total"])
def test_policy_work_is_bounded_before_scanner_launch(kind: str) -> None:
    if kind == "lines":
        files = {".semgrepignore": b"a\n" * 4097}
    elif kind == "edges":
        files = {".semgrepignore": b":include a\n" * 129, "a": b"*.py\n"}
    elif kind == "files":
        files = {f"pkg{i}/.semgrepignore": b"" for i in range(65)}
    else:
        files = {f"pkg{i}/.semgrepignore": b"x" * (256 * 1024) for i in range(5)}
    assert "policy-budget" in {b.code for b in assess_semgrep_policy(files).blockers}


@pytest.mark.parametrize(
    "change", ["parent", "mounted", "extra", "receipt", "commit", "profile", "tool", "plan-profile"]
)
def test_research_bridge_rejects_changed_evidence(tmp_path: Path, change: str) -> None:
    context, source = context_case(tmp_path, CASES[0])
    preparation, view = materialize_research_inputs(
        context, source=source, output=tmp_path / "view"
    )
    assert view is not None
    target = tmp_path / "view/target"
    if change == "parent":
        (source / "unselected.py").write_bytes(b"changed")
    elif change == "mounted":
        (target / "agent.py").write_bytes(b"changed")
    elif change == "extra":
        (target / "extra.py").write_bytes(b"x = 1\n")
    elif change == "receipt":
        preparation = replace(
            preparation,
            policy=preparation.policy.model_copy(
                update={"root_defaults": "root-file-overrides-defaults"}
            ),
        )
    elif change == "commit":
        context = replace(context, raw_commit=context.raw_commit + b"changed")
    elif change == "profile":
        context = replace(context, profile_bytes=context.profile_bytes + b" ")
    else:
        key, value = (
            ("tool_id", "agent-audit") if change == "tool" else ("profile_id", "wrong-profile")
        )
        context = replace(context, plan=context.plan.model_copy(update={key: value}))
    with pytest.raises(ValueError):
        replay_research_inputs(
            context, source=source, preparation=preparation, view=view, target=target
        )


def test_worker_request_and_report_cannot_be_rebound(tmp_path: Path) -> None:
    context, source = context_case(tmp_path, CASES[0])
    preparation, _ = materialize_research_inputs(context, source=source, output=tmp_path / "view")
    assert preparation.scope is not None
    request = research_worker_request(preparation.scope)
    raw = model_bytes(request)
    report = validate_view(tmp_path / "view/target", raw)
    with pytest.raises(ValueError):
        assess_research_syntax(
            request.model_copy(update={"target_snapshot_id": "wrong"}), raw, model_bytes(report)
        )
    with pytest.raises(ValueError):
        assess_research_syntax(request, raw, model_bytes(report.model_copy(update={"checks": []})))


def test_argv_keeps_both_git_filters_disabled_and_distinguishes_views(tmp_path: Path) -> None:
    context, source = context_case(tmp_path, CASES[0])
    preparation = prepare_research_inputs(context, source)
    assert preparation.scope is not None
    for role in ("research", "repository-policy"):
        argv = build_research_argv(
            docker=Path("docker"),
            name="research-test",
            profile_bytes=PROFILE,
            scope=preparation.scope,
            role=role,
            rules=source,
            target=source,
            output=tmp_path,
        )
        assert "--no-git-ignore" in argv and "--pull=never" in argv
        assert argv[argv.index("--network") + 1] == "none"
        assert "--read-only" in argv and "--disable-version-check" in argv
        assert ("--disable-nosem" in argv) == (role == "research")
        assert (argv[-1] == "/src") == (role == "repository-policy")
        assert all(
            "readonly" in value
            for value in argv
            if "target=/src" in value or "target=/rules" in value
        )
        assert not any("docker.sock" in value for value in argv)


def capture(**changes: Any) -> ProcessCapture:
    now = datetime.now(UTC)
    return replace(
        ProcessCapture(("docker",), now, now, 1, 0, b"", b"", False, False, False, False, 1),
        **changes,
    )


def minimal_evidence(**changes: Any) -> SemgrepPassEvidence:
    return SemgrepPassEvidence.model_validate(
        {
            "profile_sha256": "a" * 64,
            "scope_sha256": "b" * 64,
            "execution_id": "test",
            "role": "research",
            "native_json_sha256": "c" * 64,
            "native_sarif_sha256": "d" * 64,
            "files": [{"path": "agent.py", "state": "reported"}],
            "findings": [],
            "native_execution_successful": True,
            "native_skip_details_available": True,
            "native_declared_rule_ids": [],
            **changes,
        }
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"timed_out": True},
        {"output_limited": True},
        {"stdout_truncated": True},
        {"stderr_truncated": True},
        {"exit_code": None},
        {"exit_code": 127},
        {"exit_code": 1},
    ],
)
def test_process_failures_never_become_clean(changes: dict[str, Any]) -> None:
    result = assess_research_execution(
        capture(**changes), cleanup_succeeded=True, evidence=minimal_evidence()
    )
    assert result.analysis_state == "failed" and result.vulnerability_total is None


@pytest.mark.parametrize(
    "changes",
    [
        {"native_errors": [{"code": 2}]},
        {"native_skipped_rules": [{}]},
        {"native_notifications": [{}]},
        {"native_execution_successful": None},
        {"files": [{"path": "agent.py", "state": "unreported"}]},
    ],
)
def test_native_issues_do_not_become_successful_complete_analysis(changes: dict[str, Any]) -> None:
    assert (
        assess_research_execution(
            capture(), cleanup_succeeded=True, evidence=minimal_evidence(**changes)
        ).analysis_state
        == "incomplete"
    )


def test_process_and_reports_remain_separate() -> None:
    assert (
        assess_research_execution(
            capture(), cleanup_succeeded=True, evidence=minimal_evidence()
        ).analysis_state
        == "not-established"
    )
    assert (
        assess_research_execution(
            capture(exit_code=2), cleanup_succeeded=True, evidence=minimal_evidence()
        ).analysis_state
        == "incomplete"
    )
    assert (
        assess_research_execution(capture(), cleanup_succeeded=True, evidence=None).analysis_state
        == "failed"
    )
    assert (
        assess_research_execution(
            capture(), cleanup_succeeded=False, evidence=minimal_evidence()
        ).analysis_state
        == "failed"
    )
