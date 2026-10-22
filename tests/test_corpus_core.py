"""Authored corpus contracts and simulated native processes, never public target execution."""

from __future__ import annotations

import ast
import dataclasses
import importlib
import json
import socket
import subprocess
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from test_corpus_validation import run_authored
from test_custom_baselines import capture

from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.core.io import atomic_write_bytes
from agentsec_evidence.corpus import contracts, execution, reporting
from agentsec_evidence.custom_rules.baseline_execution import cleanup_ok
from agentsec_evidence.custom_rules.baseline_inputs import PROFILE_PATH
from agentsec_evidence.custom_rules.shared_execution import save_capture
from agentsec_evidence.execution.process import ProcessCapture
from agentsec_evidence.pilot.runner import evidence_records, save
from agentsec_evidence.reporting.custom_contracts import FAMILIES, expected_exit
from agentsec_evidence.research.models import load_research_profile
from agentsec_evidence.research.retained import read_retained_research

PROJECT = Path(__file__).resolve().parents[1]


def native_document() -> dict[str, Any]:
    """A nonempty authored parser example, not scanner accuracy ground truth."""
    return {
        "version": "0.20.0",
        "scan_timestamp": "2026-10-02T00:00:00",
        "scan_path": "/target",
        "scanned_files": 1,
        "summary": {
            "total": 1,
            "actionable": 1,
            "suppressed": 0,
            "by_severity": {"high": 1},
            "by_category": {"tool_misuse": 1},
            "by_tier": {"BLOCK": 0, "WARN": 1, "INFO": 0, "SUPPRESSED": 0},
            "risk_score": 2.0,
            "risk_label": "LOW",
        },
        "findings": [
            {
                "rule_id": "EXAMPLE-001",
                "title": "Authored example",
                "description": "Example only",
                "severity": "high",
                "category": "tool_misuse",
                "location": {
                    "file_path": "/target/agent.py",
                    "start_line": 2,
                    "end_line": 2,
                    "start_column": None,
                    "end_column": None,
                    "snippet": "return eval(value)",
                },
                "confidence": 0.85,
                "tier": "WARN",
                "suppressed": False,
                "suppressed_reason": None,
                "suppressed_by": None,
                "needs_review": False,
                "cwe_id": "CWE-94",
                "owasp_id": "ASI-05",
                "asi_categories": ["ASI-05"],
                "remediation": {
                    "description": "Review manually",
                    "code_example": None,
                    "reference_url": None,
                },
                "metadata": {"authored": True},
                "detected_at": "2026-10-02T00:00:00",
                "reason": "Example",
            }
        ],
    }


def setup_core(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, files: dict[str, bytes] | None = None
) -> tuple[Path, Path]:
    files = files or {"main.py": b"eval(command)\n"}
    validation, _ = run_authored(
        tmp_path,
        monkeypatch,
        {**files, "LICENSE": b"Authored test license, not a public source license."},
    )
    atomic_write_bytes(tmp_path / contracts.SPEC, (PROJECT / contracts.SPEC).read_bytes())
    # An explicitly authored rule pack keeps unit tests offline, without vendoring upstream YAML.
    rule = b"rules: []\n"
    license_raw = b"Authored rule test license"
    profile = json.loads((PROJECT / PROFILE_PATH).read_bytes())
    profile["rules"] = [
        {
            "source_path": "python/test.yml",
            "sha256": sha256_bytes(rule),
            "native_rule_id": "authored-test",
            "upstream_test_state": "passed",
        }
    ]
    profile["source_license_sha256"] = sha256_bytes(license_raw)
    profile_raw = json.dumps(profile).encode()
    monkeypatch.setattr(contracts, "PROFILE_SHA", sha256_bytes(profile_raw))
    atomic_write_bytes(tmp_path / PROFILE_PATH, profile_raw)
    rules = tmp_path / "workspace/rules"
    atomic_write_bytes(rules / "python/test.yml", rule)
    atomic_write_bytes(rules / "LICENSE", license_raw)
    output = tmp_path / "workspace/core-preparation"
    contracts.prepare_core(tmp_path, validation, rules, output)
    return output, validation


def admission(root: Path, output: Path) -> Path:
    plan = contracts.CorpusCorePlan.model_validate_json((root / "plan.json").read_bytes())
    record = contracts.CorpusCoreAdmission(
        plan_sha256=sha256_file(root / "plan.json"),
        reviewer="Authored test reviewer",
        provenance="student-AI-assisted",
        license_evidence={e.path: e.sha256 for e in plan.validation.preview.license_candidates},
        license_review_note="Authored test inputs only, not a real public license decision.",
        optional_stage_review_note="No optional stages admitted in this authored core test.",
        resource_review_note="Existing fixed core bounds retained for this authored test.",
        treatment_review_note="Three repeats of all seven families and whole eligible baselines.",
    )
    save(output, record.model_dump(mode="json"))
    return output


def mock_processes(monkeypatch: pytest.MonkeyPatch, *, fault: str | None = None) -> list[list[str]]:
    commands: list[list[str]] = []

    def simulate(
        argv: list[str], directory: Path, environment: dict[str, str], **kwargs: Any
    ) -> ProcessCapture:
        commands.append(argv)
        directory.mkdir(parents=True, exist_ok=False)
        save(directory / "command.json", {"argv": argv})
        code, raw = 0, b""
        if argv[1:3] == ["image", "inspect"]:
            raw = json.dumps([{"Id": argv[3], "RepoDigests": [argv[3]], "Os": "linux"}]).encode()
        elif argv[1] == "rm":
            if fault == "cleanup":
                code = 1
        else:
            mounts = {}
            for i, value in enumerate(argv):
                if value == "--mount":
                    source, destination = (
                        argv[i + 1].removeprefix("type=bind,source=").split(",target=")
                    )
                    mounts[destination.removesuffix(",readonly")] = Path(source)
            if "/app/src" in mounts:
                module = argv[argv.index("-m") + 1]
                worker = importlib.import_module(module)
                request_raw = mounts["/request.json"].read_bytes()
                # Only this test's authored strings enter in-process workers.
                native = worker.scan_view(mounts["/target"], request_raw)
                raw = native.model_dump_json().encode()
                family = next(
                    f
                    for f in FAMILIES
                    if f.worker in module
                    or (f.key == "tool-execution" and "tool_execution_v2" in module)
                )
                code = (
                    worker.exit_status(native)
                    if family.key == "tool-execution"
                    else expected_exit(native)
                )
            elif "/rules" in mounts:
                output = mounts["/output"]
                paths = sorted(
                    "/src/" + p.relative_to(mounts["/src"]).as_posix()
                    for p in mounts["/src"].rglob("*.py")
                )
                save(
                    output / "native.json",
                    {
                        "version": "1.174.0",
                        "results": [],
                        "errors": [],
                        "skipped_rules": [],
                        "paths": {"scanned": paths, "skipped": []},
                    },
                )
                save(
                    output / "native.sarif",
                    {
                        "version": "2.1.0",
                        "runs": [
                            {
                                "tool": {
                                    "driver": {
                                        "name": "Semgrep OSS",
                                        "semanticVersion": "1.174.0",
                                        "rules": [{"id": "authored-test"}],
                                    }
                                },
                                "invocations": [{"executionSuccessful": True}],
                                "results": [],
                            }
                        ],
                    },
                )
            else:
                document = native_document()
                python_paths = sorted(mounts["/target"].rglob("*.py"))
                document["scanned_files"] = len(python_paths)
                location = document["findings"][0]["location"]
                location.update(
                    file_path="/target/"
                    + python_paths[0].relative_to(mounts["/target"]).as_posix(),
                    start_line=1,
                    end_line=1,
                )
                raw = json.dumps(document).encode()
            if fault == "invalid":
                raw = b"{}"
        result = dataclasses.replace(
            capture(argv, raw, code),
            duration_ns=123,
            timed_out=fault == "timeout" and argv[1] == "run",
            stdout_truncated=fault == "truncated" and argv[1] == "run",
        )
        save_capture(directory, result)
        return result

    def baseline(
        argv: list[str], directory: Path, environment: dict[str, str], **kwargs: Any
    ) -> ProcessCapture:
        try:
            return simulate(argv, directory, environment)
        finally:
            cleanup = simulate(
                [argv[0], "rm", "--force", argv[argv.index("--name") + 1]],
                directory / "cleanup",
                environment,
            )
            if not cleanup_ok(cleanup):
                raise ValueError("Authored cleanup failure")

    monkeypatch.setattr(execution, "run_capture", simulate)
    monkeypatch.setattr(execution, "invoke", baseline)
    return commands


def run_core(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    files: dict[str, bytes] | None = None,
    *,
    fault: str | None = None,
) -> tuple[Path, list[list[str]]]:
    prepared, _ = setup_core(tmp_path, monkeypatch, files)
    review = admission(prepared, tmp_path / "workspace/review.json")
    commands = mock_processes(monkeypatch, fault=fault)
    root = tmp_path / "workspace/core-run"
    execution.run_core(tmp_path, prepared, review, root, docker=tmp_path / "docker.exe")
    return root, commands


def test_prepare_and_offline_replay_do_not_parse_or_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, _ = setup_core(tmp_path, monkeypatch)

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Offline verification must not parse targets or launch")

    monkeypatch.setattr(ast, "parse", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    plan = contracts.load_preparation(tmp_path, prepared)
    assert contracts.dry_run(plan)["planned_invocations"] == 30
    assert contracts.dry_run(plan)["scanner_invocations"] == 0
    assert plan.execution_authorization == "requires-bound-admission"
    assert not (prepared / "admission.json").exists()


def test_all_producers_three_repeats_replay_and_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, commands = run_core(tmp_path, monkeypatch)
    assert len([c for c in commands if c[1] == "run"]) == 30
    verified = execution.verify_core(tmp_path, root)
    assert verified["execution_finished"]
    report = reporting.build_report(verified)
    assert len(report["summary"]) == 10
    assert {s["repeatability"] for s in report["summary"]} == {"equal"}
    assert report["unique_vulnerabilities"] is None
    assert report["summary"][0]["repetitions"][0]["finding_records"] == 1
    monkeypatch.setattr(
        execution, "run_capture", lambda *a, **kw: pytest.fail("offline report launched")
    )
    output = tmp_path / "report"
    assert reporting.write_report(tmp_path, root, output)["passed"]
    assert reporting.verify_report(tmp_path, root, output)["scanner_invocations"] == 0
    assert set(p.name for p in output.iterdir()) == {
        "report.json",
        "report.html",
        "evidence-manifest.json",
    }
    assert "not confirmed" in (output / "report.html").read_text()


def test_65_files_custom_only_full_accounting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, commands = run_core(
        tmp_path, monkeypatch, {f"file{i:03}.py": b"pass\n" for i in range(65)}
    )
    replay = execution.verify_core(tmp_path, root)
    assert len([c for c in commands if c[1] == "run"]) == 42
    assert len(replay["rows"]) == 51
    blocked = [r for r in replay["rows"] if r["producer"] in contracts.ROLES]
    assert all(r["state"] == "unsupported-size" and r["finding_records"] is None for r in blocked)
    for group in reporting.build_report(replay)["summary"][:7]:
        assert all(
            r["analyzed_files"] == 65 and not r["omitted_paths"] for r in group["repetitions"]
        )


@pytest.mark.parametrize(
    "files, baseline_states",
    [
        ({"good.py": b"pass", "bad.py": b"def broken("}, ["input-refused"] * 3),
        ({"a.py": b"pass # noaudit"}, ["observed", "observed", "policy-refused"]),
        ({"README.md": b"No Python"}, ["no-input"] * 3),
    ],
)
def test_refusals_never_become_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    files: dict[str, bytes],
    baseline_states: list[str],
) -> None:
    root, _ = run_core(tmp_path, monkeypatch, files)
    report = reporting.build_report(execution.verify_core(tmp_path, root))
    assert [s["repetitions"][0]["state"] for s in report["summary"][-3:]] == baseline_states
    for group in report["summary"]:
        for rep in group["repetitions"]:
            if rep["state"] != "observed":
                assert rep["finding_records"] is None


@pytest.mark.parametrize("fault", ["timeout", "truncated", "invalid", "cleanup"])
def test_failed_attempt_sealed_reported_not_reused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    with pytest.raises(ValueError):
        run_core(tmp_path, monkeypatch, fault=fault)
    root = tmp_path / "workspace/core-run"
    assert read_retained_research(root)
    replay = execution.verify_core(tmp_path, root)
    assert not replay["execution_finished"]
    assert replay["rows"][0]["state"] == "failed"
    assert all(r["finding_records"] is None for r in replay["rows"])
    report = reporting.build_report(replay)
    assert all(s["repeatability"] == "not-assessed" for s in report["summary"])
    assert b"Incomplete attempt" in reporting.render(report)
    assert (
        reporting.write_report(tmp_path, root, tmp_path / "failed-report")["execution_finished"]
        is False
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "no-review",
        "wrong-plan",
        "wrong-license",
        "implementation",
        "target",
        "rule",
        "extra-file",
        "repeat",
    ],
)
def test_refuse_mutations_before_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    prepared, _ = setup_core(tmp_path, monkeypatch)
    review = admission(prepared, tmp_path / "workspace/review.json")
    if mutation == "no-review":
        review = tmp_path / "missing.json"
    elif mutation in {"wrong-plan", "wrong-license"}:
        record = json.loads(review.read_bytes())
        record["plan_sha256" if mutation == "wrong-plan" else "license_evidence"] = (
            "f" * 64 if mutation == "wrong-plan" else {"LICENSE": "f" * 64}
        )
        save(review, record)
    elif mutation == "implementation":
        atomic_write_bytes(tmp_path / "src/agentsec_evidence/__init__.py", b"changed")
    elif mutation == "repeat":
        record = json.loads((prepared / "plan.json").read_bytes())
        record["repetitions"] = 1
        save(prepared / "plan.json", record)
        save(prepared / "evidence-manifest.json", {"files": evidence_records(prepared)})
    else:
        path = {
            "target": "batches/000/target/main.py",
            "rule": "rules/python/test.yml",
            "extra-file": "batches/000/target/extra.py",
        }[mutation]
        atomic_write_bytes(prepared / path, b"changed")
    commands = mock_processes(monkeypatch)
    with pytest.raises((ValueError, OSError)):
        execution.run_core(
            tmp_path,
            prepared,
            review,
            tmp_path / "workspace/blocked",
            docker=tmp_path / "docker.exe",
        )
    assert commands == []


@pytest.mark.parametrize(
    "mutation", ["counter", "isolation", "schedule", "observation", "duplicate", "report"]
)
def test_resealed_tampering_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    root, _ = run_core(tmp_path, monkeypatch)
    result = json.loads((root / "result.json").read_bytes())
    first = result["rows"][0]
    if mutation == "counter":
        first["finding_records"] = 999
    elif mutation == "schedule":
        first["batch"] = 10
    elif mutation == "duplicate":
        result["rows"].append(first)
    elif mutation == "isolation":
        for name in ("command.json", "process.json"):
            path = root / first["key"] / "process" / name
            doc = json.loads(path.read_bytes())
            doc["argv"][doc["argv"].index("--network") + 1] = "host"
            save(path, doc)
    elif mutation == "observation":
        path = root / first["key"] / "observation.json"
        doc = json.loads(path.read_bytes())
        doc["finding_records"] = 0
        save(path, doc)
    else:
        path = root / "report"
        path.mkdir()
        atomic_write_bytes(path / "unexpected.txt", b"extra")
    save(root / "result.json", result)
    save(root / "evidence-manifest.json", {"files": evidence_records(root)})
    with pytest.raises(ValueError):
        execution.verify_core(tmp_path, root)


def test_commands_offline_readonly_and_policy_split(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, commands = run_core(tmp_path, monkeypatch)
    for argv in commands:
        if argv[1] != "run":
            continue
        assert argv[argv.index("--network") + 1] == "none"
        assert "--read-only" in argv and "65534:65534" in argv and "no-new-privileges" in argv
        assert all(
            "readonly" in argv[i + 1] or "target=/output" in argv[i + 1]
            for i, arg in enumerate(argv)
            if arg == "--mount"
        )
        assert not any("docker.sock" in arg for arg in argv)
        if "--json-output" in argv:
            assert "--no-git-ignore" in argv
    assert len([a for a in commands if "--disable-nosem" in a]) == 3
    assert execution.verify_core(tmp_path, root)["scanner_invocations_during_replay"] == 0


def test_html_escapes_native_text_and_exports_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _ = run_core(tmp_path, monkeypatch)
    report = reporting.build_report(execution.verify_core(tmp_path, root))
    report["observations"][report["rows"][0]["key"]]["native"]["test-text"] = (
        '<script>alert("unsafe")</script>'
    )
    html_raw = reporting.render(report)
    assert b"<script>" not in html_raw and b"&lt;script&gt;" in html_raw
    assert b"file://" not in html_raw and b"default-src 'none'" in html_raw


def test_original_profile_and_historical_contracts_unchanged() -> None:
    raw = (PROJECT / PROFILE_PATH).read_bytes()
    assert sha256_bytes(raw) == "ce4b8517a4042bb247ac641250f5d9428e8a5f985db69d36f2d9fef28f09e23c"
    assert len(load_research_profile(raw).rules) == 68


def test_nonempty_agent_projection_has_stable_evidence_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, _ = setup_core(
        tmp_path, monkeypatch, {"agent.py": b"def f(x):\n    return eval(x)\n"}
    )
    plan = contracts.load_preparation(tmp_path, prepared)
    row = next(r for r in contracts.schedule(plan) if r["producer"] == "agent-audit-python")
    raw = json.dumps(native_document()).encode()
    first = execution.observe(prepared, plan, row, capture(["authored"], raw))
    second = execution.observe(prepared, plan, row, capture(["authored"], raw))
    assert first == second
    assert first["findings"][0]["record_id"].startswith("finding_corpus_")
    changed = native_document()
    changed["scan_timestamp"] = "2026-10-22T00:00:01"
    changed["findings"][0]["detected_at"] = changed["scan_timestamp"]
    later = execution.observe(
        prepared, plan, row, capture(["authored"], json.dumps(changed).encode())
    )
    assert first["semantic"] == later["semantic"]
    assert first["findings"][0]["record_id"] != later["findings"][0]["record_id"]


def test_published_schemas_match_contracts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    prepared, _ = setup_core(tmp_path, monkeypatch)
    review = admission(prepared, tmp_path / "workspace/review.json")
    for model, name, path in (
        (contracts.CorpusCorePlan, "plan", prepared / "plan.json"),
        (contracts.CorpusCoreAdmission, "admission", review),
    ):
        schema = json.loads((PROJECT / f"schemas/corpus-core-v1/{name}.schema.json").read_bytes())
        expected = model.model_json_schema(mode="serialization")
        expected["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        expected["$id"] = f"urn:agentsec-evidence:schema:corpus-core-{name}-v1"
        assert schema == expected
        Draft202012Validator(schema).validate(json.loads(path.read_bytes()))


def test_existing_attempt_and_changed_parent_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, validation = setup_core(tmp_path, monkeypatch)
    review = admission(prepared, tmp_path / "workspace/review.json")
    commands = mock_processes(monkeypatch)
    output = tmp_path / "workspace/existing"
    output.mkdir()
    with pytest.raises(ValueError, match="fresh ignored attempt"):
        execution.run_core(tmp_path, prepared, review, output, docker=tmp_path / "docker.exe")
    doc = json.loads((validation / "assessment.json").read_bytes())
    doc["potential_paired_comparison"] = False
    save(validation / "assessment.json", doc)
    save(validation / "evidence-manifest.json", {"files": evidence_records(validation)})
    with pytest.raises(ValueError):
        execution.run_core(
            tmp_path, prepared, review, tmp_path / "workspace/new", docker=tmp_path / "docker.exe"
        )
    assert not commands


def test_mid_attempt_failure_keeps_previous_observations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prepared, _ = setup_core(tmp_path, monkeypatch)
    review = admission(prepared, tmp_path / "workspace/review.json")
    mock_processes(monkeypatch)
    original = execution.observe

    def fail_second(
        root: Path, plan: contracts.CorpusCorePlan, row: dict[str, Any], process: ProcessCapture
    ) -> dict[str, Any]:
        if row["producer"] == "network-data":
            raise ValueError("Authored second-stage failure")
        return original(root, plan, row, process)

    monkeypatch.setattr(execution, "observe", fail_second)
    output = tmp_path / "workspace/core-run"
    with pytest.raises(ValueError, match="second-stage"):
        execution.run_core(tmp_path, prepared, review, output, docker=tmp_path / "docker.exe")
    monkeypatch.setattr(execution, "observe", original)
    report = reporting.build_report(execution.verify_core(tmp_path, output))
    assert report["rows"][0]["finding_records"] == 1
    assert report["rows"][1]["state"] == "failed"
    assert report["rows"][2]["state"] == "not-run"
    assert all(s["repeatability"] == "not-assessed" for s in report["summary"])
