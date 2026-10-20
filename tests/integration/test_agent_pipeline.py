from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from agentsec_evidence.agents.bundle_validation import validate_agent_bundle
from agentsec_evidence.agents.development import APPROVED_CASES
from agentsec_evidence.agents.records import AgentRunDetails
from agentsec_evidence.agents.url_contrast import CASE_IDS as URL_CONTRAST_CASE_IDS
from agentsec_evidence.agents.worker import validate_view
from agentsec_evidence.cli.app import app
from agentsec_evidence.core.time import utc_now
from agentsec_evidence.execution.process import ProcessCapture
from agentsec_evidence.models.contracts import RunState
from agentsec_evidence.operations.offline import (
    load_existing_run,
    normalize_existing_run,
    validate_existing_run,
)
from agentsec_evidence.orchestration import agent_pipeline
from agentsec_evidence.orchestration.agent_pipeline import AgentScanRequest, run_agent_scan
from agentsec_evidence.reporting.service import validate_common_report, write_common_report

PROJECT = Path(__file__).resolve().parents[2]
ADMITTED = {
    "python-positive",
    "python-corrected",
    "python-near-miss",
    "mcp-positive",
    "mcp-corrected",
    "mcp-near-miss",
}


def native_document(
    *, suppressed: bool = False, stamp: str = "2026-10-02T00:00:00"
) -> dict[str, Any]:
    """Authored native report for pipeline plumbing, not a detector-accuracy oracle."""
    return {
        "version": "0.20.0",
        "scan_timestamp": stamp,
        "scan_path": "/target",
        "scanned_files": 1,
        "summary": {
            "total": 1,
            "actionable": 0 if suppressed else 1,
            "suppressed": int(suppressed),
            "by_severity": {"high": 1},
            "by_category": {"tool_misuse": 1},
            "by_tier": {
                "BLOCK": 0,
                "WARN": 0 if suppressed else 1,
                "INFO": 0,
                "SUPPRESSED": int(suppressed),
            },
            "risk_score": 2.0,
            "risk_label": "LOW",
        },
        "findings": [
            {
                "rule_id": "EXAMPLE-001",
                "title": "Authored observation",
                "description": "Test double only",
                "severity": "high",
                "category": "tool_misuse",
                "location": {
                    "file_path": "/target/agent.py",
                    "start_line": 6,
                    "end_line": 6,
                    "start_column": None,
                    "end_column": None,
                    "snippet": "return eval(expression)",
                },
                "confidence": 0.85,
                "tier": "SUPPRESSED" if suppressed else "WARN",
                "suppressed": suppressed,
                "suppressed_reason": "test" if suppressed else None,
                "suppressed_by": None,
                "needs_review": False,
                "cwe_id": "CWE-94",
                "owasp_id": "ASI-05",
                "asi_categories": ["ASI-05"],
                "remediation": {
                    "description": "Review",
                    "code_example": None,
                    "reference_url": None,
                },
                "metadata": {"authored": True},
                "detected_at": stamp,
                "reason": "Example",
            }
        ],
    }


def fake_runner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    native: dict[str, Any] | None = None,
    fault: str | None = None,
) -> list[str]:
    calls: list[str] = []
    docker = tmp_path / "docker.exe"
    docker.write_bytes(b"test double")
    monkeypatch.setattr(agent_pipeline, "resolve_docker", lambda _: docker)
    monkeypatch.setattr(agent_pipeline, "cleanup_container", lambda **_: fault != "cleanup")

    def run(
        argv: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> ProcessCapture:
        del cwd, environment, timeout_seconds, max_stdout_bytes, max_stderr_bytes
        worker = "agentsec_evidence.agents.worker" in argv
        stage = "validation" if worker else "scanner"
        calls.append(stage)
        mounts = {}
        for value in argv:
            if value.startswith("type=bind,"):
                parts = dict(part.split("=", 1) for part in value.split(",") if "=" in part)
                mounts[parts["target"]] = Path(parts["source"])
        assert argv[argv.index("--network") + 1] == "none"
        assert "--read-only" in argv and "--cap-drop" in argv and "--memory-swap" in argv
        assert all("readonly" in value for value in argv if value.startswith("type=bind,"))
        if fault == f"{stage}-launch":
            raise OSError("Authored launch failure")
        if worker:
            report = validate_view(mounts["/target"], mounts["/request.json"].read_bytes())
            raw = report.model_dump_json().encode()
            if fault == "response-binding":
                raw = (
                    report.model_copy(update={"request_sha256": "0" * 64})
                    .model_dump_json()
                    .encode()
                )
        else:
            document = native or native_document()
            if fault == "snapshot-change":
                (mounts["/target"] / "agent.py").write_bytes(b"changed")
            if "mcp" in next(mounts["/target"].iterdir()).name:
                document["findings"][0]["location"]["file_path"] = "/target/mcp.json"
                document["findings"][0]["location"]["start_line"] = 1
                document["findings"][0]["location"]["end_line"] = 1
            raw = json.dumps(document).encode()
        if fault == f"{stage}-malformed":
            raw = b"{"
        instant = utc_now()
        return ProcessCapture(
            argv=tuple(argv),
            started_at=instant,
            ended_at=instant,
            duration_ns=100,
            exit_code=2 if fault == f"{stage}-exit" else 0,
            stdout=raw,
            stderr=b"diagnostic" if fault == f"{stage}-stderr" else b"",
            timed_out=fault == f"{stage}-timeout",
            output_limited=fault == f"{stage}-limit",
            stdout_truncated=fault == f"{stage}-limit",
            stderr_truncated=False,
            peak_rss_bytes=4096,
        )

    monkeypatch.setattr(agent_pipeline, "run_bounded_process", run)
    return calls


@pytest.mark.parametrize("case", sorted(APPROVED_CASES))
def test_bounded_case_admission(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    calls = fake_runner(monkeypatch, tmp_path)
    workspace = tmp_path / "workspace"
    result = run_agent_scan(AgentScanRequest(PROJECT, workspace, case))
    expected = RunState.PARTIAL if case in ADMITTED else RunState.REJECTED
    assert result.terminal_state == expected
    assert calls == (["validation", "scanner"] if case in ADMITTED else ["validation"])
    assert validate_existing_run(
        project_root=PROJECT, workspace_root=workspace, run_id=result.run_id
    ).passed
    details = validate_agent_bundle(load_existing_run(workspace, result.run_id))
    assert details.admitted == (case in ADMITTED)
    assert (
        load_existing_run(workspace, result.run_id).run.semantic_hash_version
        == "agent-run-semantic-v1"
    )
    assert details.native_result_count == (1 if case in ADMITTED else None)
    if case not in ADMITTED:
        assert details.blockers and details.assessments[0].finding_count is None


@pytest.mark.parametrize("case_id", URL_CONTRAST_CASE_IDS)
def test_url_contrasts_reuse_isolation_and_distinct_source_family(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case_id: str
) -> None:
    calls = fake_runner(monkeypatch, tmp_path)
    workspace = tmp_path / "workspace"
    result = run_agent_scan(AgentScanRequest(PROJECT, workspace, case_id))
    existing = load_existing_run(workspace, result.run_id)
    details = validate_agent_bundle(existing)
    assert calls == ["validation", "scanner"]
    assert result.terminal_state == RunState.PARTIAL
    assert details.admitted and details.input_unchanged
    assert existing.target.revision == "agent-url-contrast-development-v1"
    assert details.case_id == case_id
    assert existing.findings[0].rule.native_id == "EXAMPLE-001"


@pytest.mark.parametrize(
    "fault,state",
    [
        *[
            (f"validation-{name}", RunState.REJECTED)
            for name in ("launch", "exit", "timeout", "limit", "stderr", "malformed")
        ],
        ("response-binding", RunState.REJECTED),
        ("cleanup", RunState.REJECTED),
        ("scanner-launch", RunState.EXECUTION_FAILED),
        ("scanner-timeout", RunState.TIMED_OUT),
        ("scanner-limit", RunState.EXECUTION_FAILED),
        ("scanner-malformed", RunState.PARSE_FAILED),
        ("scanner-exit", RunState.PARTIAL),
        ("scanner-stderr", RunState.PARTIAL),
        ("snapshot-change", RunState.VALIDATION_FAILED),
    ],
)
def test_failures_are_finalized_not_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str, state: RunState
) -> None:
    fake_runner(monkeypatch, tmp_path, fault=fault)
    workspace = tmp_path / "workspace"
    result = run_agent_scan(AgentScanRequest(PROJECT, workspace, "python-positive"))
    assert result.terminal_state == state
    assert result.summary.normalized_failure_count > 0
    assert validate_existing_run(
        project_root=PROJECT, workspace_root=workspace, run_id=result.run_id
    ).passed


def test_offline_reporting_suppression_and_repeatability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    fake_runner(monkeypatch, tmp_path, native=native_document(suppressed=True))
    first = run_agent_scan(AgentScanRequest(PROJECT, workspace, "python-positive"))
    fake_runner(
        monkeypatch, tmp_path, native=native_document(suppressed=True, stamp="2026-10-03T00:00:00")
    )
    second = run_agent_scan(AgentScanRequest(PROJECT, workspace, "python-positive"))
    assert first.semantic_sha256 == second.semantic_sha256
    monkeypatch.setattr(
        agent_pipeline,
        "run_bounded_process",
        lambda *a, **kw: pytest.fail("Offline process launch"),
    )
    output = tmp_path / "report"
    report = write_common_report(project_root=PROJECT, bundles=[first.run_root], output=output)
    assert report.contract == "common-report-v2"
    assert report.sources[0].kind == "agent-static"
    assert validate_common_report(PROJECT, output)["passed"] is True
    sarif = json.loads((output / "results.sarif").read_bytes())
    observation = sarif["runs"][0]["results"][0]
    assert observation["kind"] == "review"
    assert observation["suppressions"][0]["status"] == "underReview"
    normalize_existing_run(
        project_root=PROJECT,
        workspace_root=workspace,
        run_id=first.run_id,
        output_root=tmp_path / "derivative",
    )
    for command in ("inspect", "summarize", "validate"):
        result = CliRunner().invoke(
            app,
            [
                command,
                first.run_id,
                "--project-root",
                str(PROJECT),
                "--workspace",
                str(workspace),
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        if command != "validate":
            assert json.loads(result.output)["agent_details"]["native_suppressed_count"] == 1


def test_empty_observation_keeps_per_file_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    document = native_document()
    document["findings"] = []
    document["summary"].update(
        total=0,
        actionable=0,
        by_severity={},
        by_category={},
        by_tier={"BLOCK": 0, "WARN": 0, "INFO": 0, "SUPPRESSED": 0},
    )
    fake_runner(monkeypatch, tmp_path, native=document)
    workspace = tmp_path / "workspace"
    result = run_agent_scan(AgentScanRequest(PROJECT, workspace, "python-corrected"))
    details = validate_agent_bundle(load_existing_run(workspace, result.run_id))
    assert details.native_result_count == 0
    assert details.assessments[0].state == "unknown"
    assert details.assessments[0].finding_count is None


def test_cli_refuses_unregistered_inputs(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "agent-audit",
            "public-repo",
            "--project-root",
            str(PROJECT),
            "--workspace",
            str(tmp_path / "workspace"),
            "--json",
        ],
    )
    assert result.exit_code == 2
    assert not (tmp_path / "workspace").exists()


def test_tampered_agent_details_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_runner(monkeypatch, tmp_path)
    workspace = tmp_path / "workspace"
    result = run_agent_scan(AgentScanRequest(PROJECT, workspace, "python-positive"))
    path = result.run_root / "normalized/agent-details.json"
    details = AgentRunDetails.model_validate_json(path.read_bytes())
    path.write_text(details.model_copy(update={"native_result_count": 99}).model_dump_json())
    with pytest.raises(ValueError, match="integrity"):
        validate_agent_bundle(load_existing_run(workspace, result.run_id))


def test_missing_docker_keeps_unknown_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(agent_pipeline, "resolve_docker", lambda _: None)
    workspace = tmp_path / "workspace"
    result = run_agent_scan(AgentScanRequest(PROJECT, workspace, "python-positive"))
    assert result.terminal_state is RunState.REJECTED
    details = validate_agent_bundle(load_existing_run(workspace, result.run_id))
    assert not details.scanner_launched and details.native_result_count is None
    assert details.validation_state == "not-run"


def test_semantics_detect_nonvolatile_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    fake_runner(monkeypatch, tmp_path)
    first = run_agent_scan(AgentScanRequest(PROJECT, workspace, "python-positive"))
    document = native_document()
    document["novel_metadata"] = {"value": "retained"}
    fake_runner(monkeypatch, tmp_path, native=document)
    second = run_agent_scan(AgentScanRequest(PROJECT, workspace, "python-positive"))
    assert first.semantic_sha256 != second.semantic_sha256


def test_cli_scan_and_refusal_codes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_runner(monkeypatch, tmp_path)
    for case, code in [("python-positive", 8), ("python-malformed", 6)]:
        result = CliRunner().invoke(
            app,
            [
                "scan",
                "agent-audit",
                case,
                "--project-root",
                str(PROJECT),
                "--workspace",
                str(tmp_path / "workspace"),
                "--json",
            ],
        )
        assert result.exit_code == code, result.output
        assert json.loads(result.output)["agent_details"]["scanner_launched"] == (code == 8)
