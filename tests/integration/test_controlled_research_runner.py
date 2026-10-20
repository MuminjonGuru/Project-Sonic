"""Producer tests use synthetic process/native evidence; no scanner is executed here."""

from __future__ import annotations

import dataclasses
import json
import shutil
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from test_research_reporting import matrix

from agentsec_evidence.agents.worker import validate_view
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.core.io import atomic_write_bytes, model_bytes
from agentsec_evidence.execution.process import ProcessCapture
from agentsec_evidence.reporting.research import load_research_source
from agentsec_evidence.research import controlled
from agentsec_evidence.research.retained import read_retained_research

ROOT = Path(__file__).resolve().parents[2]


def test_production_pins_bind_unchanged_admitted_resources() -> None:
    assert all(
        len(digest) == 64 and sha256_bytes((ROOT / path).read_bytes()) == digest
        for path, digest in controlled.ADMITTED_PINS.items()
    )


def setup_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case_id: str = "inline"
) -> tuple[Path, Path, Path, Path, list[list[str]], list[str]]:
    template = matrix(tmp_path / "synthetic", case_id)
    project = tmp_path / "project"
    (project / "workspace").mkdir(parents=True)
    for path in controlled.ADMITTED_PINS:
        raw = (ROOT / path).read_bytes()
        if path == controlled.PROFILE_PATH:
            raw = (template.parent / "profile.json").read_bytes()
        atomic_write_bytes(project / path, raw)
    # Test-only synthetic profile pin; production admission remains unchanged.
    monkeypatch.setattr(
        controlled,
        "ADMITTED_PINS",
        {p: sha256_bytes((project / p).read_bytes()) for p in controlled.ADMITTED_PINS},
    )
    atomic_write_bytes(
        project / "src/agentsec_evidence/agents/worker.py", b"# Synthetic worker; never executed\n"
    )
    rules = project / "workspace/rules"
    shutil.copytree(template.parent / "rules", rules)
    output = project / "workspace/attempt"
    (project / "docker").write_bytes(b"synthetic executable path; never launched")
    calls: list[list[str]] = []
    cleanups: list[str] = []

    def capture(argv: list[str], **kwargs: Any) -> ProcessCapture:
        calls.append(argv)
        assert "--pull=never" in argv or argv[argv.index("--pull") + 1] == "never"
        assert argv[argv.index("--network") + 1] == "none"
        mounts = {}
        for index, item in enumerate(argv):
            if index and argv[index - 1] == "--mount":
                parts = dict(p.split("=", 1) for p in item.split(",") if "=" in p)
                mounts[parts["target"]] = Path(parts["source"])
        stdout = b""
        if "/request.json" in mounts:
            target = mounts["/target"]
            stdout = model_bytes(validate_view(target, mounts["/request.json"].read_bytes()))
        else:
            native = mounts["/output"]
            for name in ("native.json", "native.sarif"):
                shutil.copyfile(template / native.name / name, native / name)
        now = datetime(2026, 10, 15, tzinfo=UTC)
        return ProcessCapture(
            tuple(argv), now, now, 1, 0, stdout, b"", False, False, False, False, 1
        )

    def cleanup(**kwargs: Any) -> bool:
        cleanups.append(kwargs["container_name"])
        return True

    monkeypatch.setattr(controlled, "resolve_docker", lambda _: project / "docker")
    monkeypatch.setattr(controlled, "run_bounded_process", capture)
    monkeypatch.setattr(controlled, "cleanup_container", cleanup)
    return project, rules, output, template, calls, cleanups


def run(project: Path, rules: Path, output: Path, case_id: str = "inline") -> Path:
    return controlled.run_controlled_research_case(
        project=project, rule_source=rules, output=output, case_id=case_id
    )


@pytest.mark.parametrize(
    "case_id,workers,passes",
    [
        ("inline", 1, 4),
        ("defaults", 1, 4),
        ("empty-root", 1, 2),
        ("missing-include", 0, 0),
        ("malformed-python", 1, 0),
    ],
)
def test_case_outputs_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case_id: str, workers: int, passes: int
) -> None:
    project, rules, output, _, calls, cleanups = setup_case(tmp_path, monkeypatch, case_id)
    cell = run(project, rules, output, case_id)
    source, sarif = load_research_source(cell)
    assert len(source.summary.passes) == passes
    assert len(calls) == len(cleanups) == workers + passes
    assert isinstance(sarif["runs"], list) and len(sarif["runs"]) == max(1, passes)
    assert source.summary.vulnerability_total is None
    before = read_retained_research(output)
    assert load_research_source(cell)[0] == source
    assert read_retained_research(output) == before
    with pytest.raises(ValueError, match="fresh"):
        run(project, rules, output, case_id)


def test_policy_refusal_does_not_require_docker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, rules, output, _, calls, _ = setup_case(tmp_path, monkeypatch, "missing-include")
    monkeypatch.setattr(controlled, "resolve_docker", lambda _: pytest.fail("Docker was requested"))
    source, _ = load_research_source(run(project, rules, output, "missing-include"))
    assert source.state == "policy-refused" and not calls


@pytest.mark.parametrize("field", ["gate", "policy_excluded", "suppressed", "native_issue"])
def test_expectations_do_not_control_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    project, rules, output, _, calls, _ = setup_case(tmp_path, monkeypatch)
    registry_path = project / controlled.REGISTRY_PATH
    registry = json.loads(registry_path.read_bytes())
    case = next(c for c in registry["cases"] if c["id"] == "inline")
    case[field] = {"gate": "syntax-refused", "native_issue": True}.get(field, ["not-observed.py"])
    raw = json.dumps(registry).encode()
    registry_path.write_bytes(raw)
    monkeypatch.setitem(controlled.ADMITTED_PINS, controlled.REGISTRY_PATH, sha256_bytes(raw))
    source, _ = load_research_source(run(project, rules, output))
    assert source.state == "observed" and len(calls) == 5


def test_missing_expected_findings_are_results_not_process_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, rules, output, template, _, _ = setup_case(tmp_path, monkeypatch)
    for prefix in template.glob("*-*"):
        if not prefix.is_dir() or not (prefix / "native.json").exists():
            continue
        native = json.loads((prefix / "native.json").read_bytes())
        sarif = json.loads((prefix / "native.sarif").read_bytes())
        native["results"] = []
        sarif["runs"][0]["results"] = []
        (prefix / "native.json").write_text(json.dumps(native), encoding="utf-8")
        (prefix / "native.sarif").write_text(json.dumps(sarif), encoding="utf-8")
    source, _ = load_research_source(run(project, rules, output))
    assert source.state == "observed"
    assert all(p.native_finding_records == 0 for p in source.summary.passes)


@pytest.mark.parametrize("kind", ["timeout", "truncated", "cleanup", "interrupt", "launch"])
def test_failed_syntax_retains_evidence_and_stops(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    project, rules, output, _, calls, _ = setup_case(tmp_path, monkeypatch)
    original: Callable[..., ProcessCapture] = vars(controlled)["run_bounded_process"]

    def broken(*args: Any, **kwargs: Any) -> ProcessCapture:
        if kind == "interrupt":
            raise KeyboardInterrupt
        if kind == "launch":
            raise OSError("private failure text")
        captured = original(*args, **kwargs)
        if kind == "timeout":
            return dataclasses.replace(captured, timed_out=True)
        if kind == "truncated":
            return dataclasses.replace(captured, stdout_truncated=True)
        return captured

    monkeypatch.setattr(controlled, "run_bounded_process", broken)
    if kind == "cleanup":
        monkeypatch.setattr(controlled, "cleanup_container", lambda **_: False)
    error = (
        KeyboardInterrupt if kind == "interrupt" else OSError if kind == "launch" else RuntimeError
    )
    with pytest.raises(error):
        run(project, rules, output)
    retained = read_retained_research(output)
    assert "failure.json" in retained.files and len(calls) <= 1
    assert b"private failure text" not in retained.read("failure.json")
    assert not any(p.startswith("inline/research-") for p in retained.files)
    assert "inline/syntax/cleanup.json" in retained.files


@pytest.mark.parametrize("change", ["unknown-case", "registry", "profile", "rule", "worker-extra"])
def test_admission_and_frozen_inputs_are_guarded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    project, rules, output, _, calls, _ = setup_case(tmp_path, monkeypatch)
    if change == "unknown-case":
        with pytest.raises(ValueError, match="admitted"):
            run(project, rules, output, "../outside")
    elif change in {"registry", "profile", "rule"}:
        path = project / (
            controlled.REGISTRY_PATH if change == "registry" else controlled.PROFILE_PATH
        )
        if change == "rule":
            path = next(rules.rglob("*.yml"))
        path.write_bytes(path.read_bytes() + b"\n")
        with pytest.raises(ValueError):
            run(project, rules, output)
    else:
        original: Callable[..., ProcessCapture] = vars(controlled)["run_bounded_process"]

        def tamper(*args: Any, **kwargs: Any) -> ProcessCapture:
            capture = original(*args, **kwargs)
            (output / "worker-source/extra.py").write_bytes(b"# extra")
            return capture

        monkeypatch.setattr(controlled, "run_bounded_process", tamper)
        with pytest.raises(ValueError, match="file set changed"):
            run(project, rules, output)
        assert read_retained_research(output).read("failure.json")
    assert len(calls) <= (1 if change == "worker-extra" else 0)


def test_outside_output_and_resealing_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, rules, output, _, _, _ = setup_case(tmp_path, monkeypatch, "missing-include")
    with pytest.raises(ValueError, match="fresh private workspace"):
        run(project, rules, tmp_path / "outside", "missing-include")
    run(project, rules, output, "missing-include")
    before = (output / "evidence-manifest.json").read_bytes()
    with pytest.raises(ValueError, match="resealing"):
        controlled.seal_controlled_attempt(output)
    assert (output / "evidence-manifest.json").read_bytes() == before


@pytest.mark.parametrize("kind", ["missing-report", "invalid-report", "exit", "cleanup"])
def test_native_failure_is_sealed_without_second_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    project, rules, output, _, calls, _ = setup_case(tmp_path, monkeypatch)
    original: Callable[..., ProcessCapture] = vars(controlled)["run_bounded_process"]

    def broken(*args: Any, **kwargs: Any) -> ProcessCapture:
        captured = original(*args, **kwargs)
        if len(calls) == 2:
            native = output / "inline/research-1/native.json"
            if kind == "missing-report":
                native.unlink()
            elif kind == "invalid-report":
                native.write_bytes(b"not JSON")
            elif kind == "exit":
                return dataclasses.replace(captured, exit_code=127)
        return captured

    monkeypatch.setattr(controlled, "run_bounded_process", broken)
    if kind == "cleanup":
        monkeypatch.setattr(controlled, "cleanup_container", lambda **_: len(calls) != 2)
    with pytest.raises(RuntimeError, match="Failed native attempt"):
        run(project, rules, output)
    retained = read_retained_research(output)
    assert len(calls) == 2 and "failure.json" in retained.files
    assert not any(p.startswith("inline/repository-policy-") for p in retained.files)
    assert (
        json.loads(retained.read("inline/research-1/assessment.json"))["analysis_state"] == "failed"
    )


def test_native_warning_is_partial_evidence_not_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, rules, output, template, calls, _ = setup_case(tmp_path, monkeypatch)
    for native in template.glob("*/native.json"):
        document = json.loads(native.read_bytes())
        document["errors"] = [{"code": 2, "message": "Synthetic warning"}]
        native.write_text(json.dumps(document), encoding="utf-8")
    original: Callable[..., ProcessCapture] = vars(controlled)["run_bounded_process"]

    def warning(*args: Any, **kwargs: Any) -> ProcessCapture:
        captured = original(*args, **kwargs)
        return dataclasses.replace(captured, exit_code=2) if len(calls) > 1 else captured

    monkeypatch.setattr(controlled, "run_bounded_process", warning)
    source, _ = load_research_source(run(project, rules, output))
    assert all(p.execution.analysis_state == "incomplete" for p in source.summary.passes)
    assert len(calls) == 5


def test_missing_docker_is_retained_failure_not_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, rules, output, _, calls, _ = setup_case(tmp_path, monkeypatch)
    monkeypatch.setattr(controlled, "resolve_docker", lambda _: None)
    with pytest.raises(RuntimeError, match="Docker unavailable"):
        run(project, rules, output)
    assert read_retained_research(output).read("failure.json")
    assert not calls


def test_hard_linked_input_is_refused_before_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    project, rules, output, _, calls, _ = setup_case(tmp_path, monkeypatch)
    os.link(project / controlled.REGISTRY_PATH, project / "registry-alias.json")
    with pytest.raises(ValueError, match="hard-linked"):
        run(project, rules, output)
    assert not output.exists() and not calls
