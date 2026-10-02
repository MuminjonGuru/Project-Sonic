from __future__ import annotations

import json
import os
import stat
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import JsonValue

from agentsec_evidence.agents.inventory import build_artifact_inventory
from agentsec_evidence.agents.records import AgentInputRequest
from agentsec_evidence.agents.view_validation import (
    AgentViewAssessment,
    assess_agent_view_report,
    build_agent_view_request,
)
from agentsec_evidence.agents.worker import validate_view
from agentsec_evidence.core.identity import sha256_file
from agentsec_evidence.core.io import json_bytes, model_bytes
from agentsec_evidence.intake.git_verification import verify_git_source
from agentsec_evidence.intake.input_plan import build_tool_input_plan
from agentsec_evidence.intake.snapshot import create_snapshot
from agentsec_evidence.intake.views import (
    ToolInputView,
    ToolViewContext,
    materialize_tool_view,
    replay_parent_source,
    verify_materialized_tool_view,
)

ROOT = Path(__file__).resolve().parents[2]
CASES = ROOT / "test_cases/development/input-views/cases.json"


def context_case(
    tmp_path: Path, case_id: str = "python-positive", selected: list[str] | None = None
) -> tuple[ToolViewContext, Path, dict[str, Any]]:
    case = next(c for c in json.loads(CASES.read_bytes())["cases"] if c["id"] == case_id)
    source = tmp_path / "source"
    files = {f["path"]: f["text"].encode() for f in case["git"]["files"]}
    for name, data in files.items():
        file = source / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(data)
    commit = case["git"]["raw_commit"].encode()
    tree = json_bytes(case["git"]["tree"])
    proof = verify_git_source(
        raw_commit=commit, raw_tree=tree, revision=case["git"]["revision"], files=files
    )
    snapshot = create_snapshot(
        source,
        tmp_path / "snapshots",
        source_label="controlled-view:" + case_id,
        revision=proof.revision,
        source_kind="git",
    )
    inventory = build_artifact_inventory(snapshot.snapshot, snapshot.inventory)
    paths = list(case["selected"]) if selected is None else selected
    profile_paths: list[JsonValue] = [str(path) for path in paths]
    profile = json_bytes({"role": "controlled-input-view-only", "selected_paths": profile_paths})
    plan = build_tool_input_plan(
        inventory=inventory,
        verification=proof,
        tool_id="agent-audit",
        profile_id="controlled-view-v1",
        profile_bytes=profile,
        selected_paths=paths,
        selected_reason="Controlled validation input",
        exclusions={path: "Retained in full policy context" for path in files if path not in paths},
    )
    return ToolViewContext(inventory, proof, plan, profile, commit, tree), source, case


@pytest.mark.parametrize(
    "case_id", ["python-positive", "mcp-positive", "python-inline-suppression", "excluded-policy"]
)
def test_controlled_views_bind_requests_and_keep_full_policy_context(
    tmp_path: Path, case_id: str
) -> None:
    context, source, case = context_case(tmp_path, case_id)
    before = {p.relative_to(source): sha256_file(p) for p in source.rglob("*") if p.is_file()}
    view = materialize_tool_view(context, source_root=source, output=tmp_path / "view")
    target = tmp_path / "view/target"
    assert {p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file()} == set(
        case["selected"]
    )
    restored = ToolInputView.model_validate_json((tmp_path / "view/view.json").read_bytes())
    verify_materialized_tool_view(restored, context, target)
    request = build_agent_view_request(context, view, selected_kinds=case["selected"])
    # Unit tests parse only these trusted controlled fixtures. Real target parsing uses Docker.
    report = validate_view(target, model_bytes(request))
    result = assess_agent_view_report(context, view, request, model_bytes(report))
    assert result.input_gate_passed == case["expected_input_gate_passed"]
    assert list(result.blockers) == case["expected_blockers"]
    assert result.execution_authorization == "not-granted" and result.scanner_executed is False
    if case_id == "excluded-policy":
        assert not (target / ".agent-audit.yaml").exists()
        assert result.blocked_policy_paths == (".agent-audit.yaml",)
        assert len(context.inventory.records) == 21 and len(request.inventory) == 1
    repeated = materialize_tool_view(context, source_root=source, output=tmp_path / "repeat")
    assert model_bytes(view) == model_bytes(repeated)
    assert before == {
        p.relative_to(source): sha256_file(p) for p in source.rglob("*") if p.is_file()
    }


@pytest.mark.parametrize("change", ["missing", "changed", "extra", "directory", "hardlink"])
def test_changed_parent_source_never_produces_a_view(tmp_path: Path, change: str) -> None:
    context, source, _case = context_case(tmp_path)
    if change == "missing":
        (source / "agent.py").unlink()
    elif change == "changed":
        (source / "agent.py").write_bytes(b"changed")
    elif change == "extra":
        (source / "extra.py").write_bytes(b"extra")
    elif change == "directory":
        (source / "unexpected").mkdir()
    else:
        os.link(source / "agent.py", tmp_path / "hardlink.py")
    with pytest.raises(ValueError):
        materialize_tool_view(context, source_root=source, output=tmp_path / "view")
    assert not (tmp_path / "view").exists()


@pytest.mark.parametrize("change", ["missing", "changed", "extra", "directory"])
def test_changed_selected_view_is_rejected(tmp_path: Path, change: str) -> None:
    context, source, _case = context_case(tmp_path)
    view = materialize_tool_view(context, source_root=source, output=tmp_path / "view")
    target = tmp_path / "view/target"
    if change == "missing":
        (target / "agent.py").unlink()
    elif change == "changed":
        (target / "agent.py").write_bytes(b"changed")
    elif change == "extra":
        (target / "extra.py").write_bytes(b"extra")
    else:
        (target / "unexpected").mkdir()
    with pytest.raises(ValueError):
        verify_materialized_tool_view(view, context, target)


@pytest.mark.parametrize("part", ["profile", "commit", "tree", "inventory", "plan"])
def test_altered_parent_evidence_is_rejected_before_copy(tmp_path: Path, part: str) -> None:
    context, source, _case = context_case(tmp_path)
    if part == "profile":
        context = replace(context, profile_bytes=b"changed")
    elif part == "commit":
        context = replace(context, raw_commit=context.raw_commit + b"changed")
    elif part == "tree":
        context = replace(context, raw_tree=b"{}")
    elif part == "inventory":
        context.inventory.snapshot.revision = "a" * 40
    else:
        context = replace(context, plan=context.plan.model_copy(update={"selections": ()}))
    with pytest.raises(ValueError):
        materialize_tool_view(context, source_root=source, output=tmp_path / "view")
    assert not (tmp_path / "view").exists()


def test_view_receipt_cannot_rebind_or_grant_execution(tmp_path: Path) -> None:
    context, source, _case = context_case(tmp_path)
    view = materialize_tool_view(context, source_root=source, output=tmp_path / "view")
    with pytest.raises(ValueError, match="parent plan"):
        verify_materialized_tool_view(
            view.model_copy(update={"input_plan_sha256": "a" * 64}),
            context,
            tmp_path / "view/target",
        )
    with pytest.raises(ValueError):
        ToolInputView.model_validate(view.model_dump() | {"execution_authorization": "approved"})


def test_output_overwrite_and_source_overlap_are_refused(tmp_path: Path) -> None:
    context, source, _case = context_case(tmp_path)
    output = tmp_path / "view"
    materialize_tool_view(context, source_root=source, output=output)
    before = {p: sha256_file(p) for p in output.rglob("*") if p.is_file()}
    with pytest.raises(FileExistsError):
        materialize_tool_view(context, source_root=source, output=output)
    assert before == {p: sha256_file(p) for p in output.rglob("*") if p.is_file()}
    with pytest.raises(ValueError, match="overlap"):
        materialize_tool_view(context, source_root=source, output=source / "nested-view")


@pytest.mark.parametrize("kind", ["symlink", "reparse"])
def test_links_and_reparse_ancestors_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    context, source, _case = context_case(tmp_path)
    original = Path.lstat

    def lstat(path: Path, *args: Any, **kwargs: Any) -> Any:
        if path == source:
            return SimpleNamespace(
                st_mode=stat.S_IFLNK if kind == "symlink" else stat.S_IFDIR,
                st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT if kind == "reparse" else 0,
            )
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", lstat)
    with pytest.raises(ValueError, match="Links and reparse"):
        replay_parent_source(context, source)


def test_empty_selection_is_accounted_for_but_not_admitted(tmp_path: Path) -> None:
    context, source, _case = context_case(tmp_path, selected=[])
    view = materialize_tool_view(context, source_root=source, output=tmp_path / "view")
    request = build_agent_view_request(context, view, selected_kinds={})
    report = validate_view(tmp_path / "view/target", model_bytes(request))
    result = assess_agent_view_report(context, view, request, model_bytes(report))
    assert result.input_gate_passed is False and result.blockers == ("no-eligible-inputs",)


@pytest.mark.parametrize("change", ["missing", "extra", "unsupported", "wrong-tool"])
def test_worker_selection_must_exactly_match_supported_tool_view(
    tmp_path: Path, change: str
) -> None:
    context, source, _case = context_case(tmp_path)
    view = materialize_tool_view(context, source_root=source, output=tmp_path / "view")
    selected: dict[str, Any] = {"agent.py": "python-source"}
    if change == "missing":
        selected = {}
    elif change == "extra":
        selected["extra.py"] = "python-source"
    elif change == "unsupported":
        selected["agent.py"] = "unknown"
    else:
        context = replace(context, plan=context.plan.model_copy(update={"tool_id": "semgrep"}))
    with pytest.raises(ValueError):
        build_agent_view_request(context, view, selected_kinds=selected)


@pytest.mark.parametrize("change", ["request", "missing", "hash", "snapshot", "invalid-json"])
def test_worker_report_is_bound_to_exact_view_request(tmp_path: Path, change: str) -> None:
    context, source, case = context_case(tmp_path)
    view = materialize_tool_view(context, source_root=source, output=tmp_path / "view")
    request = build_agent_view_request(context, view, selected_kinds=case["selected"])
    report = validate_view(tmp_path / "view/target", model_bytes(request)).model_dump(mode="json")
    if change == "request":
        report["request_sha256"] = "a" * 64
    elif change == "missing":
        report["checks"] = []
    elif change == "hash":
        report["checks"][0]["artifact"]["source"]["sha256"] = "a" * 64
    elif change == "snapshot":
        request = AgentInputRequest.model_validate(
            request.model_dump() | {"target_snapshot_id": "other"}
        )
    raw = b"{}{}" if change == "invalid-json" else json_bytes(report)
    with pytest.raises(ValueError):
        assess_agent_view_report(context, view, request, raw)


def test_gate_cannot_be_promoted_to_scan_permission(tmp_path: Path) -> None:
    context, source, case = context_case(tmp_path)
    view = materialize_tool_view(context, source_root=source, output=tmp_path / "view")
    request = build_agent_view_request(context, view, selected_kinds=case["selected"])
    report = validate_view(tmp_path / "view/target", model_bytes(request))
    result = assess_agent_view_report(context, view, request, model_bytes(report))
    for update in (
        {"execution_authorization": "approved"},
        {"scanner_executed": True},
        {"blockers": ["blocked"]},
    ):
        with pytest.raises(ValueError):
            AgentViewAssessment.model_validate(result.model_dump() | update)


def test_nested_selection_preserves_exact_bytes_and_paths(tmp_path: Path) -> None:
    registry = json.loads(CASES.read_bytes())
    case = next(c for c in registry["cases"] if c["id"] == "excluded-policy")
    paths = [f["path"] for f in case["git"]["files"] if "/" in f["path"]]
    assert paths
    context, source, _case = context_case(tmp_path, "excluded-policy", selected=paths)
    view = materialize_tool_view(context, source_root=source, output=tmp_path / "view")
    target = tmp_path / "view/target"
    assert {f.source.path for f in view.files} == set(paths)
    for path in paths:
        assert (target / path).read_bytes() == (source / path).read_bytes()


def test_copy_failure_leaves_no_success_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context, source, _case = context_case(tmp_path)
    original = Path.open

    def fail_copy(path: Path, *args: Any, **kwargs: Any) -> Any:
        if path == tmp_path / "view/target/agent.py":
            raise OSError("controlled write failure")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_copy)
    with pytest.raises(OSError, match="controlled write failure"):
        materialize_tool_view(context, source_root=source, output=tmp_path / "view")
    assert (tmp_path / "view/target").is_dir()
    assert not (tmp_path / "view/view.json").exists()
    replay_parent_source(context, source)


def test_changed_excluded_parent_file_is_detected_after_copy(tmp_path: Path) -> None:
    context, source, _case = context_case(tmp_path, "excluded-policy")
    view = materialize_tool_view(context, source_root=source, output=tmp_path / "view")
    (source / ".agent-audit.yaml").write_bytes(b"changed")
    verify_materialized_tool_view(view, context, tmp_path / "view/target")
    with pytest.raises(ValueError):
        replay_parent_source(context, source)


def test_view_bridge_enforces_per_file_worker_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context, source, case = context_case(tmp_path)
    view = materialize_tool_view(context, source_root=source, output=tmp_path / "view")
    monkeypatch.setattr("agentsec_evidence.agents.view_validation.MAX_INPUT_BYTES", 1)
    with pytest.raises(ValueError, match="worker file budget"):
        build_agent_view_request(context, view, selected_kinds=case["selected"])
