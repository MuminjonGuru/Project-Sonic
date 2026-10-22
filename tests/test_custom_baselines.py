from __future__ import annotations

import dataclasses
import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from agentsec_evidence.agents.execution import AgentAuditToolConfig
from agentsec_evidence.agents.inputs import validate_agent_input
from agentsec_evidence.agents.records import AgentInputCheck, AgentInputReport, AgentInputRequest
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.core.io import atomic_write_bytes
from agentsec_evidence.custom_rules import baseline_execution as execution
from agentsec_evidence.custom_rules.baseline_inputs import (
    PROFILE_PATH,
    PROFILE_SHA,
    authored_snapshot_id,
    group_requests,
    planned_rows,
    repeatability,
    select_baseline,
)
from agentsec_evidence.custom_rules.shared_execution import capture_ok
from agentsec_evidence.custom_rules.shared_inputs import prepare_shared
from agentsec_evidence.execution.config import load_toml_config
from agentsec_evidence.execution.process import ProcessCapture
from agentsec_evidence.models.contracts import InventoryEntry
from agentsec_evidence.pilot.runner import save
from agentsec_evidence.reporting.custom_contracts import FAMILIES
from agentsec_evidence.research.models import load_research_profile

PROJECT = Path(__file__).resolve().parents[1]


def report(request: AgentInputRequest, sources: dict[str, bytes]) -> AgentInputReport:
    # Only trusted authored strings are parsed in unit tests; the runner uses isolated validation.
    checks = []
    for path in request.selected:
        checked = validate_agent_input(
            sources[path],
            path=path,
            kind="python-source",
            target_snapshot_id=request.target_snapshot_id,
        )
        checks.append(
            AgentInputCheck(
                artifact=checked.artifact,
                line_count=checked.line_count,
                suppression_lines=list(checked.suppression_lines),
            )
        )
    return AgentInputReport(
        request_sha256=sha256_bytes(request.model_dump_json().encode()), checks=checks
    )


def small_request(sources: dict[str, bytes]) -> AgentInputRequest:
    return AgentInputRequest(
        target_snapshot_id="trusted-authored-unit-test",
        inventory=[
            InventoryEntry(
                path=p, sha256=sha256_bytes(b), byte_length=len(b), media_type="text/x-python"
            )
            for p, b in sorted(sources.items())
        ],
        selected={p: "python-source" for p in sorted(sources)},
    )


def capture(argv: list[str], stdout: bytes = b"", code: int = 0) -> ProcessCapture:
    now = datetime.now(UTC)
    return ProcessCapture(
        tuple(argv), now, now, 1, code, stdout, b"", False, False, False, False, 0
    )


def test_original_groups_and_actual_syntax_policy_denominators() -> None:
    prepared = prepare_shared(PROJECT)
    assert authored_snapshot_id(prepared.inputs) == prepared.plan.snapshot_id
    assert (
        authored_snapshot_id(dict(reversed(list(prepared.inputs.items()))))
        == prepared.plan.snapshot_id
    )
    groups = group_requests(prepared)
    assert sorted(len(r.inventory) for r in groups.values()) == [34, 54, 57, 60, 60, 60, 60]
    eligible = 0
    blocked = []
    for key, request in groups.items():
        selection = select_baseline(
            request, request.model_dump_json().encode(), report(request, prepared.inputs)
        )
        assert len(selection.exclusions) == 1
        assert selection.exclusions[0]["state"] == "malformed"
        assert selection.exclusions[0]["baseline_findings"] is None
        eligible += len(selection.checks)
        if selection.agent_blockers:
            blocked.append(key)
        assert selection.scope is not None
        assert selection.scope.profile_sha256 == PROFILE_SHA
        assert not selection.scope.policy_files
    assert eligible == 378
    assert set(blocked) == {"tool-execution", "network-data"}


@pytest.mark.parametrize("mutation", ["request", "source", "duplicate", "missing", "snapshot"])
def test_selection_binds_worker_observations(mutation: str) -> None:
    sources = {"a.py": b"eval(value)\n"}
    request = small_request(sources)
    result = report(request, sources).model_dump()
    if mutation == "request":
        result["request_sha256"] = "f" * 64
    elif mutation == "source":
        result["checks"][0]["artifact"]["source"]["sha256"] = "f" * 64
    elif mutation == "duplicate":
        result["checks"] *= 2
    elif mutation == "missing":
        result["checks"] = []
    else:
        result["checks"][0]["artifact"]["target_snapshot_id"] = "another"
    with pytest.raises(ValueError):
        select_baseline(
            request, request.model_dump_json().encode(), AgentInputReport.model_validate(result)
        )


def test_all_malformed_is_no_eligible_not_clean() -> None:
    sources = {"a.py": b"def broken(\n"}
    request = small_request(sources)
    selection = select_baseline(
        request, request.model_dump_json().encode(), report(request, sources)
    )
    assert selection.scope is None
    assert selection.agent_blockers == ("no-eligible-inputs",)
    assert selection.exclusions[0]["baseline_findings"] is None


def test_nosemgrep_does_not_trigger_agent_policy_refusal() -> None:
    sources = {"a.py": b"eval(value)  # nosemgrep\n"}
    request = small_request(sources)
    selection = select_baseline(
        request, request.model_dump_json().encode(), report(request, sources)
    )
    assert not selection.agent_blockers
    assert selection.scope is not None


@pytest.mark.parametrize("count", [0, 4, True])
def test_finite_schedule_limit(count: int) -> None:
    with pytest.raises(ValueError):
        planned_rows(count)


def test_not_run_refused_and_different_are_not_equal() -> None:
    rows = planned_rows(2)
    assert len(rows) == 42
    assert all(r["finding_records"] is None for r in rows)
    assert {r["state"] for r in repeatability(rows)} == {"not-assessed"}
    for row in rows:
        row.update(state="observed", semantic_sha256="a" * 64)
    assert {r["state"] for r in repeatability(rows)} == {"equal"}
    rows[0]["semantic_sha256"] = "b" * 64
    assert repeatability(rows)[0]["state"] == "different"
    rows[0]["state"] = "refused"
    assert repeatability(rows)[0]["state"] == "not-assessed"


def test_retained_mounts_do_not_allow_external_source() -> None:
    argv = [
        "docker.exe",
        "run",
        "--name",
        "one",
        "--mount",
        "type=bind,source=D:\\attempt\\groups\\one,target=/target,readonly",
        "image",
    ]
    assert execution.portable(argv, "D:\\attempt")[5].startswith("type=bind,source=ROOT/")
    with pytest.raises(ValueError, match="external mount"):
        execution.portable(argv, "D:\\different")


def test_frozen_guard_detects_bytes_extra_files_and_escape(tmp_path: Path) -> None:
    files = {"implementation/src/code.py": b"pass\n", "rules/rule.yml": b"rule"}
    for p, raw in files.items():
        atomic_write_bytes(tmp_path / p, raw)
    pins = execution.frozen_hashes(files)
    execution.verify_frozen(tmp_path, pins)
    atomic_write_bytes(tmp_path / "implementation/src/new.py", b"new")
    with pytest.raises(ValueError, match="membership"):
        execution.verify_frozen(tmp_path, pins)
    with pytest.raises(ValueError):
        execution.verify_frozen(tmp_path, {"../escape": "f" * 64})
    atomic_write_bytes(tmp_path / "rules/rule.yml", b"changed")
    with pytest.raises(ValueError, match="bytes changed"):
        execution.verify_frozen(tmp_path, pins)


def test_image_preflight_and_cleanup_fail_closed() -> None:
    image = "sha256:" + "a" * 64
    argv = ["docker", "image", "inspect", image]
    execution.check_image(capture(argv, json.dumps([{"Id": image, "Os": "linux"}]).encode()), image)
    with pytest.raises(ValueError):
        execution.check_image(capture(argv, b'[{"Id":"other","Os":"linux"}]'), image)
    assert execution.cleanup_ok(capture(["docker", "rm", "x"]))
    assert not execution.cleanup_ok(capture(["docker", "rm", "x"], code=1))


@pytest.mark.parametrize("fault", ["timeout", "raise", "cleanup"])
def test_invoke_always_records_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    argv = ["docker", "run", "--name", "unit-test"]

    def fake(args: list[str], **kwargs: Any) -> ProcessCapture:
        if args[1] == "rm":
            return capture(args, code=1 if fault == "cleanup" else 0)
        if fault == "raise":
            raise OSError("authored launch failure")
        return dataclasses.replace(capture(args), timed_out=fault == "timeout")

    monkeypatch.setattr(execution, "run_bounded_process", fake)
    monkeypatch.setattr("agentsec_evidence.custom_rules.shared_execution.run_bounded_process", fake)
    if fault == "timeout":
        result = execution.invoke(argv, tmp_path / "process", {})
        assert not capture_ok(result, {0})
    else:
        with pytest.raises((ValueError, OSError)):
            execution.invoke(argv, tmp_path / "process", {})
    assert (tmp_path / "process/cleanup/process.json").is_file()


def test_baseline_commands_preserve_suppression_and_isolation(tmp_path: Path) -> None:
    sources = {"family/a.py": b"eval(value)\n"}
    request = small_request(sources)
    selection = select_baseline(
        request, request.model_dump_json().encode(), report(request, sources)
    )
    atomic_write_bytes(tmp_path / "groups/family/selected/family/a.py", sources["family/a.py"])
    atomic_write_bytes(tmp_path / "profile.json", (PROJECT / PROFILE_PATH).read_bytes())
    atomic_write_bytes(
        tmp_path / "tool.toml", (PROJECT / "configs/tools/agent-audit.toml").read_bytes()
    )
    (tmp_path / "rules").mkdir()
    (tmp_path / "native").mkdir()
    for role in ("research", "repository-policy", "agent-audit"):
        argv = execution.stage_argv(
            tmp_path, tmp_path / "profile.json", "unit-test", "family", role, "native", selection
        )
        assert argv[argv.index("--network") + 1] == "none"
        assert "--read-only" in argv
        assert "--user" in argv
        assert "--disable-nosem" in argv if role == "research" else "--disable-nosem" not in argv
        if role != "agent-audit":
            assert "--no-git-ignore" in argv
    refused = dataclasses.replace(selection, agent_blockers=("suppression-marker:family/a.py",))
    with pytest.raises(ValueError, match="refused"):
        execution.stage_argv(
            tmp_path,
            tmp_path / "profile.json",
            "unit-test",
            "family",
            "agent-audit",
            "native",
            refused,
        )


def test_native_zero_reports_does_not_establish_complete_analysis(tmp_path: Path) -> None:
    sources = {"a.py": b"value = 1\n"}
    request = small_request(sources)
    selection = select_baseline(
        request, request.model_dump_json().encode(), report(request, sources)
    )
    profile_raw = (PROJECT / PROFILE_PATH).read_bytes()
    atomic_write_bytes(tmp_path / "profile.json", profile_raw)
    native = {
        "version": "1.174.0",
        "results": [],
        "errors": [],
        "skipped_rules": [],
        "paths": {"scanned": ["/src/a.py"], "skipped": []},
    }
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Semgrep OSS",
                        "semanticVersion": "1.174.0",
                        "rules": [
                            {"id": r.native_rule_id}
                            for r in load_research_profile(profile_raw).rules
                        ],
                    }
                },
                "invocations": [{"executionSuccessful": True}],
                "results": [],
            }
        ],
    }
    save(tmp_path / "native/native.json", native)
    save(tmp_path / "native/native.sarif", sarif)
    observed, _ = execution.native_observation(
        tmp_path, {"key": "native", "role": "research"}, selection, capture(["docker"])
    )
    assert observed["finding_records"] == 0
    assert observed["assessment"]["analysis_state"] == "not-established"
    assert observed["files"]["a.py"]["state"] == "reported"
    aa = {
        "version": "0.20.0",
        "scan_timestamp": "2026-10-22T00:00:00",
        "scan_path": "/target",
        "scanned_files": 1,
        "findings": [],
        "summary": {
            "total": 0,
            "actionable": 0,
            "suppressed": 0,
            "by_severity": {},
            "by_category": {},
            "by_tier": {"BLOCK": 0, "WARN": 0, "INFO": 0, "SUPPRESSED": 0},
            "risk_score": 0.0,
            "risk_label": "LOW",
        },
    }
    observed, _ = execution.native_observation(
        tmp_path,
        {"key": "native", "role": "agent-audit"},
        selection,
        capture(["docker"], json.dumps(aa).encode()),
    )
    assert observed["finding_records"] == 0
    assert observed["files"]["a.py"]["state"] == "native-per-file-completion-not-observable"
    tool = load_toml_config(PROJECT / "configs/tools/agent-audit.toml", AgentAuditToolConfig).value
    assert tool.network == "denied"


def test_existing_output_never_overwritten(tmp_path: Path) -> None:
    (tmp_path / "workspace/existing").mkdir(parents=True)
    with pytest.raises(ValueError, match="never overwrite"):
        execution.run_baselines(
            tmp_path, tmp_path / "workspace/existing", custom_run=tmp_path, rule_source=tmp_path
        )


def test_comparison_preserves_unknown_refused_and_observed_zero() -> None:
    spec = importlib.util.spec_from_file_location(
        "summarize_custom_baselines", PROJECT / "tools/summarize_custom_baselines.py"
    )
    assert spec is not None and spec.loader is not None
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    path = "tool-execution/example.py"
    reference = {
        "original_manifest_sha256": "a" * 64,
        "observations": {path: {f.key: {"findings": []} for f in FAMILIES}},
    }
    rows = planned_rows(2)
    observations = {}
    for row in rows:
        if row["role"] == "agent-audit":
            row.update(state="refused", reasons=["suppression-marker"])
        else:
            row["state"] = "observed"
            observations[row["key"]] = {"files": {path: {"state": "reported", "findings": []}}}
    validation = {
        "passed": True,
        "manifest_sha256": "b" * 64,
        "rows": rows,
        "excluded": [],
        "observations": observations,
        "limitations": [],
    }
    result = helper.build_comparison(validation, reference, {path: b"pass\n"})
    assert result["accuracy_metrics"] is None
    baseline = result["rows"][0]["baselines"]
    assert baseline["research"]["findings"] == []
    assert baseline["agent-audit"]["findings"] is None
    assert b"refused,unknown" in helper.table_bytes(result)
    validation["excluded"] = [{"path": path, "state": "malformed", "baseline_findings": None}]
    result = helper.build_comparison(validation, reference, {path: b"pass\n"})
    assert all(v["state"] == "input-excluded" for v in result["rows"][0]["baselines"].values())
    assert b"input-excluded,unknown" in helper.table_bytes(result)
    validation["passed"] = False
    with pytest.raises(ValueError):
        helper.build_comparison(validation, reference, {path: b"pass\n"})
