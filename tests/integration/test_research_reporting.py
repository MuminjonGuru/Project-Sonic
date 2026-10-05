from __future__ import annotations

import dataclasses
import json
import os
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

import pytest
from typer.testing import CliRunner

from agentsec_evidence.agents.execution import AgentAuditToolConfig, build_agent_argv
from agentsec_evidence.agents.inventory import build_artifact_inventory
from agentsec_evidence.agents.worker import validate_view
from agentsec_evidence.cli.app import app
from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.core.io import (
    atomic_write_bytes,
    atomic_write_model,
    json_bytes,
    model_bytes,
)
from agentsec_evidence.execution.config import ExecutionProfile, load_toml_config
from agentsec_evidence.execution.process import ProcessCapture
from agentsec_evidence.intake.git_verification import verify_git_source
from agentsec_evidence.intake.input_plan import build_tool_input_plan
from agentsec_evidence.intake.snapshot import create_snapshot
from agentsec_evidence.intake.views import ToolViewContext
from agentsec_evidence.reporting.models import CommonReport, ResearchSource
from agentsec_evidence.reporting.research import load_research_source
from agentsec_evidence.reporting.service import validate_common_report, write_common_report
from agentsec_evidence.research.execution import assess_research_execution, build_research_argv
from agentsec_evidence.research.inputs import materialize_research_inputs, research_worker_request
from agentsec_evidence.research.models import load_research_profile
from agentsec_evidence.research.retained import RetainedManifest, read_retained_research
from agentsec_evidence.research.semgrep import build_dual_view, reconcile_semgrep_pass

ROOT = Path(__file__).resolve().parents[2]
RULE = "python_eval_rule-eval"


def put(path: Path, value: Any) -> None:
    atomic_write_bytes(
        path, value if isinstance(value, bytes) else json.dumps(value, default=str).encode()
    )


def seal(root: Path) -> None:
    put(
        root / "evidence-manifest.json",
        {
            "files": [
                {
                    "path": p.relative_to(root).as_posix(),
                    "bytes": p.stat().st_size,
                    "sha256": sha256_file(p),
                }
                for p in sorted(root.rglob("*"))
                if p.is_file() and p.name != "evidence-manifest.json"
            ]
        },
    )


def process(
    root: Path, argv: list[str], *, stdout: bytes = b"", exit_code: int = 0
) -> ProcessCapture:
    now = datetime(2026, 10, 6, tzinfo=UTC)
    capture = ProcessCapture(
        tuple(argv), now, now, 1, exit_code, stdout, b"", False, False, False, False, 1
    )
    record = dataclasses.asdict(capture)
    del record["stdout"], record["stderr"]
    put(root / "execution.json", record)
    put(root / "command.json", {"argv": argv, "target_execution": False})
    put(root / "cleanup.json", {"succeeded": True})
    put(root / "stdout.bin", stdout)
    put(root / "stderr.bin", b"")
    return capture


def matrix(tmp_path: Path, case_id: str = "inline", *, warning: bool = False) -> Path:
    """Synthetic native/process evidence; trusted fixture AST only, no Docker or scanner."""
    root = tmp_path / "matrix"
    case = next(
        c
        for c in json.loads(
            (ROOT / "test_cases/development/research-runner/cases.json").read_bytes()
        )["cases"]
        if c["id"] == case_id
    )
    put(
        root / "cases.json",
        {"role": "development-not-held-out", "target_execution": False, "cases": [case]},
    )
    candidate = json.loads(
        (ROOT / "configs/research/semgrep-python-candidate-v1.json").read_bytes()
    )
    candidate["rules"] = [r for r in candidate["rules"] if r["native_rule_id"] == RULE]
    rule_bytes, license_bytes = (
        b"synthetic rule evidence, never executed",
        b"synthetic license evidence",
    )
    candidate["rules"][0]["sha256"] = sha256_bytes(rule_bytes)
    candidate["source_license_sha256"] = sha256_bytes(license_bytes)
    profile_bytes = json.dumps(candidate).encode()
    profile = load_research_profile(profile_bytes)
    put(root / "profile.json", profile_bytes)
    put(root / "rules" / profile.rules[0].source_path, rule_bytes)
    put(root / "rules/LICENSE", license_bytes)
    put(root / "worker-source/placeholder.txt", b"synthetic process receipt; no worker launched")
    cell = root / case_id
    files = {p: value.encode() for p, value in case["files"].items()}
    for name, data in files.items():
        put(cell / "parent" / name, data)
    commit, tree = case["git"]["raw_commit"].encode(), json_bytes(case["git"]["tree"])
    proof = verify_git_source(
        raw_commit=commit, raw_tree=tree, revision=case["git"]["revision"], files=files
    )
    snapshot = create_snapshot(
        cell / "parent",
        cell / "snapshots",
        source_label="synthetic:" + case_id,
        revision=proof.revision,
        source_kind="git",
    )
    inventory = build_artifact_inventory(snapshot.snapshot, snapshot.inventory)
    plan = build_tool_input_plan(
        inventory=inventory,
        verification=proof,
        tool_id="semgrep",
        profile_id=profile.profile_id,
        profile_bytes=profile_bytes,
        selected_paths=case["selected"],
        selected_reason="Trusted controlled unit fixture",
        exclusions={p: "Unselected parent evidence" for p in files if p not in case["selected"]},
    )
    context = ToolViewContext(inventory, proof, plan, profile_bytes, commit, tree)
    for name, value in (
        ("inventory", inventory),
        ("git-verification", proof),
        ("input-plan", plan),
    ):
        atomic_write_model(cell / f"{name}.json", value)
    put(cell / "commit.raw", commit)
    put(cell / "tree.json", tree)
    preparation, _ = materialize_research_inputs(
        context, source=cell / "parent", output=cell / "view"
    )
    atomic_write_model(cell / "policy.json", preparation.policy)
    if preparation.scope is None:
        seal(root)
        return cell
    scope = preparation.scope
    request = research_worker_request(scope)
    atomic_write_model(cell / "request.json", request)
    # Only project-authored trusted fixture syntax is parsed in these unit tests.
    report = validate_view(cell / "view/target", model_bytes(request))
    execution = load_toml_config(ROOT / "configs/profiles/agent-development.toml", ExecutionProfile)
    tool = load_toml_config(ROOT / "configs/tools/agent-audit.toml", AgentAuditToolConfig)
    put(root / "execution-profile.toml", execution.raw)
    put(root / "validator-tool.toml", tool.raw)
    argv = build_agent_argv(
        docker=root / "profile.json",
        tool=tool.value,
        profile=execution.value,
        name="synthetic-syntax",
        target=cell / "view/target",
        worker_source=root / "worker-source",
        request=cell / "request.json",
    )
    process(cell / "syntax", argv, stdout=model_bytes(report))
    if any(c.artifact.parse_state != "parsed" for c in report.checks):
        seal(root)
        return cell
    for repetition in range(1, 3 if case.get("repeat") else 2):
        pair = []
        for role in ("research", "repository-policy"):
            role_value: Literal["research", "repository-policy"] = (
                "research" if role == "research" else "repository-policy"
            )
            prefix = cell / f"{role}-{repetition}"
            prefix.mkdir()
            inline = case_id == "inline"
            excluded = (
                set(case.get("policy_excluded", [])) if role == "repository-policy" else set()
            )
            paths = [p for p in case["selected"] if p not in excluded]
            native = {
                "version": "1.174.0",
                "results": [
                    {
                        "check_id": RULE,
                        "path": "/src/" + p,
                        "start": {"line": 1, "col": 9},
                        "end": {"line": 1, "col": 22},
                        "extra": {"message": "Synthetic eval observation", "severity": "WARNING"},
                    }
                    for p in paths
                    if not (role == "repository-policy" and inline)
                ],
                "errors": [{"code": 2, "message": "synthetic warning"}] if warning else [],
                "skipped_rules": [],
                "paths": {
                    "scanned": ["/src/" + p for p in paths],
                    "skipped": [
                        {"path": "/src/" + p, "reason": "semgrepignore_patterns_match"}
                        for p in sorted(excluded)
                    ],
                },
            }
            sarif = {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "Semgrep OSS",
                                "semanticVersion": "1.174.0",
                                "rules": [{"id": RULE}],
                            }
                        },
                        "invocations": [
                            {"executionSuccessful": True, "toolExecutionNotifications": []}
                        ],
                        "results": [
                            {
                                "ruleId": RULE,
                                "message": {"text": "Synthetic eval observation"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {
                                                "uri": "/src/" + p,
                                                "uriBaseId": "%SRCROOT%",
                                            },
                                            "region": {
                                                "startLine": 1,
                                                "startColumn": 9,
                                                "endLine": 1,
                                                "endColumn": 22,
                                            },
                                        }
                                    }
                                ],
                                **(
                                    {"suppressions": [{"kind": "inSource", "status": "accepted"}]}
                                    if inline
                                    else {}
                                ),
                            }
                            for p in paths
                        ],
                    }
                ],
            }
            put(prefix / "native.json", native)
            put(prefix / "native.sarif", sarif)
            name = f"synthetic-{role}-{repetition}"
            argv = build_research_argv(
                docker=Path("docker"),
                name=name,
                profile_bytes=profile_bytes,
                scope=scope,
                role=role_value,
                rules=root / "rules",
                target=cell / "view/target",
                output=prefix,
            )
            captured = process(prefix, argv, exit_code=2 if warning else 0)
            evidence = reconcile_semgrep_pass(
                profile_bytes=profile_bytes,
                scope=scope,
                execution_id=name,
                role=role_value,
                native_json=(prefix / "native.json").read_bytes(),
                native_sarif=(prefix / "native.sarif").read_bytes(),
            )
            atomic_write_model(prefix / "evidence.json", evidence)
            atomic_write_model(
                prefix / "assessment.json",
                assess_research_execution(captured, cleanup_succeeded=True, evidence=evidence),
            )
            pair.append(evidence)
        atomic_write_model(cell / f"dual-view-{repetition}.json", build_dual_view(*pair))
    seal(root)
    return cell


@pytest.mark.parametrize(
    "case_id,count",
    [("inline", 4), ("defaults", 4), ("missing-include", 1), ("malformed-python", 1)],
)
def test_research_report_keeps_views_repeats_and_refusals(
    tmp_path: Path, case_id: str, count: int
) -> None:
    cell = matrix(tmp_path, case_id)
    before = {p: sha256_file(p) for p in cell.parent.rglob("*") if p.is_file()}
    report = write_common_report(project_root=ROOT, bundles=[cell], output=tmp_path / "report")
    assert report.contract == "common-report-v3" and report.sarif_runs == count
    source = report.sources[0]
    assert isinstance(source, ResearchSource) and source.summary.vulnerability_total is None
    assert validate_common_report(ROOT, tmp_path / "report")["passed"]
    document = json.loads((tmp_path / "report/results.sarif").read_bytes())
    if case_id in {"missing-include", "malformed-python"}:
        assert not source.summary.passes and source.summary.unrun_finding_count is None
        assert document["runs"][0]["invocations"][0]["executionSuccessful"] is False
    if case_id == "inline":
        for run in document["runs"]:
            result = run["results"][0]
            assert result["suppressions"][0]["status"] == "underReview"
            assert (
                result["properties"]["agentsecEvidence/nativeSuppressions"][0]["status"]
                == "accepted"
            )
            assert (
                result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "agent.py"
            )
        assert source.summary.passes[1].evidence.findings[0].json_pointer is None
    write_common_report(project_root=ROOT, bundles=[cell], output=tmp_path / "repeat")
    assert (tmp_path / "report/results.sarif").read_bytes() == (
        tmp_path / "repeat/results.sarif"
    ).read_bytes()
    assert before == {p: sha256_file(p) for p in cell.parent.rglob("*") if p.is_file()}


def test_native_exit_two_stays_incomplete(tmp_path: Path) -> None:
    source, document = load_research_source(matrix(tmp_path, warning=True))
    assert all(p.execution.analysis_state == "incomplete" for p in source.summary.passes)
    runs = cast(list[dict[str, Any]], document["runs"])
    assert all(not r["invocations"][0]["executionSuccessful"] for r in runs)


@pytest.mark.parametrize(
    "change",
    [
        "raw",
        "manifest-duplicate",
        "manifest-traversal",
        "unexpected-file",
        "extra-pass",
        "scope",
        "git",
        "policy",
        "summary",
        "command",
        "request",
        "missing-report",
        "missing-repetition",
    ],
)
def test_corrupt_or_inconsistent_research_evidence_is_refused(tmp_path: Path, change: str) -> None:
    cell = matrix(tmp_path)
    root = cell.parent
    if change == "raw":
        put(cell / "research-1/native.json", {})
    elif change.startswith("manifest-"):
        manifest = json.loads((root / "evidence-manifest.json").read_bytes())
        if change == "manifest-duplicate":
            manifest["files"].append(manifest["files"][0])
        else:
            manifest["files"][0]["path"] = "../outside"
        put(root / "evidence-manifest.json", manifest)
    elif change == "unexpected-file":
        put(root / "extra.txt", b"unexpected")
    else:
        if change == "extra-pass":
            shutil.copytree(cell / "research-1", cell / "research-3")
        elif change == "scope":
            value = json.loads((cell / "view/scope.json").read_bytes())
            value["selection_sha256"] = "a" * 64
            put(cell / "view/scope.json", value)
        elif change == "git":
            put(cell / "commit.raw", b"not a commit")
        elif change == "policy":
            value = json.loads((cell / "policy.json").read_bytes())
            value["root_defaults"] = "root-file-overrides-defaults"
            put(cell / "policy.json", value)
        elif change == "summary":
            value = json.loads((cell / "research-1/evidence.json").read_bytes())
            value["findings"] = []
            put(cell / "research-1/evidence.json", value)
        elif change == "command":
            for filename in ("execution.json", "command.json"):
                value = json.loads((cell / "research-1" / filename).read_bytes())
                value["argv"][value["argv"].index("--network") + 1] = "host"
                put(cell / "research-1" / filename, value)
        elif change == "request":
            value = json.loads((cell / "request.json").read_bytes())
            value["selected"] = {}
            put(cell / "request.json", value)
        elif change == "missing-report":
            (cell / "research-1/native.sarif").unlink()
        else:
            shutil.rmtree(cell / "research-2")
        seal(root)
    with pytest.raises(ValueError):
        write_common_report(project_root=ROOT, bundles=[cell], output=tmp_path / "rejected")
    assert not (tmp_path / "rejected").exists()


def reseal_report(output: Path) -> None:
    manifest = json.loads((output / "report-manifest.json").read_bytes())
    for entry in manifest["entries"]:
        entry.update(
            bytes=(output / entry["path"]).stat().st_size,
            sha256=sha256_file(output / entry["path"]),
        )
    put(output / "report-manifest.json", manifest)


@pytest.mark.parametrize(
    "change",
    [
        "approval",
        "anchor",
        "pointer",
        "pass",
        "status",
        "native-status",
        "fingerprint",
        "invocation",
        "null-count",
        "version",
    ],
)
def test_resealed_derivative_cannot_change_research_meaning(tmp_path: Path, change: str) -> None:
    cell = matrix(tmp_path)
    output = tmp_path / "report"
    write_common_report(project_root=ROOT, bundles=[cell], output=output)
    if change in {"null-count", "version"}:
        report = json.loads((output / "report.json").read_bytes())
        if change == "null-count":
            report["sources"][0]["summary"]["unrun_finding_count"] = 0
        else:
            report["contract"] = "common-report-v1"
        put(output / "report.json", report)
    else:
        document = json.loads((output / "results.sarif").read_bytes())
        run = document["runs"][0]
        result = run["results"][0]
        if change == "approval":
            result["suppressions"][0]["status"] = "accepted"
        elif change == "anchor":
            result["locations"][0]["physicalLocation"]["region"]["startLine"] = 10
        elif change == "pointer":
            result["properties"]["agentsecEvidence/nativeSarifPointer"] = "/runs/0/results/88"
        elif change == "pass":
            run["properties"]["agentsecEvidence/researchPass"] = "repository-policy-1"
        elif change == "native-status":
            run["properties"]["agentsecEvidence/nativeExecutionSuccessful"] = False
        elif change == "fingerprint":
            result["partialFingerprints"] = {}
        elif change == "invocation":
            run["invocations"] = []
        else:
            run["properties"]["agentsecEvidence/analysisState"] = "failed"
        put(output / "results.sarif", document)
    reseal_report(output)
    with pytest.raises(ValueError):
        validate_common_report(ROOT, output)


def test_research_cli_offline_and_protected_destinations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cell = matrix(tmp_path, "missing-include")
    import agentsec_evidence.execution.process as process_module

    def forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("Reporting cannot launch producers")

    monkeypatch.setattr(process_module, "run_bounded_process", forbidden)
    runner = CliRunner()
    output = tmp_path / "report"
    built = runner.invoke(
        app, ["report", "build", str(cell), "--output", str(output), "--project-root", str(ROOT)]
    )
    assert built.exit_code == 0, built.output
    assert (
        runner.invoke(
            app, ["report", "validate", str(output), "--project-root", str(ROOT)]
        ).exit_code
        == 0
    )
    for destination in (cell / "out", cell.parent / "out", output / "nested", output):
        with pytest.raises(ValueError):
            write_common_report(project_root=ROOT, bundles=[cell], output=destination)
    with pytest.raises(ValueError, match="Duplicate"):
        write_common_report(project_root=ROOT, bundles=[cell, cell], output=tmp_path / "duplicate")


def test_research_manifest_refuses_hardlinks_and_budget_abuse(tmp_path: Path) -> None:
    cell = matrix(tmp_path, "missing-include")
    os.link(cell / "policy.json", tmp_path / "linked")
    with pytest.raises(ValueError, match="hard-linked"):
        read_retained_research(cell.parent)
    for path, size in (("a", 17 * 1024 * 1024), ("a/" * 65 + "x", 1)):
        with pytest.raises(ValueError):
            RetainedManifest.model_validate(
                {"files": [{"path": path, "bytes": size, "sha256": "a" * 64}]}
            )


def test_old_reporting_contracts_still_validate_empty_source_models() -> None:
    # Version selection is additive; legacy report model defaults remain unchanged.
    report = CommonReport(generated_at=datetime.now(UTC), sources=[], sarif_runs=0)
    assert report.contract == "common-report-v1"
