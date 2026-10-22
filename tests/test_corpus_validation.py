"""Authored input-gate tests; public syntax is parsed only in the isolated worker."""

from __future__ import annotations

import ast
import json
import socket
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from test_corpus_preflight import prepared

from agentsec_evidence.agents.records import AgentInputReport
from agentsec_evidence.agents.worker import validate_view
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.core.io import atomic_write_model
from agentsec_evidence.custom_rules.shared_execution import save_capture
from agentsec_evidence.execution.process import ProcessCapture
from agentsec_evidence.intake import corpus_validation_execution as execution
from agentsec_evidence.intake.corpus import CorpusCandidates, build_preview, write_preview
from agentsec_evidence.intake.corpus_validation import (
    PROTOCOL,
    REGISTRY,
    TOOL,
    CorpusInputAssessment,
    CorpusValidationPlan,
    assess_inputs,
    prepare_validation_plan,
)
from agentsec_evidence.pilot.runner import evidence_records, save
from agentsec_evidence.reporting.custom_contracts import IMAGE

PROJECT = Path(__file__).resolve().parents[1]


def setup(project: Path, files: dict[str, bytes]) -> tuple[Path, Path]:
    root = project / "workspace/candidates/R03"
    root.parent.mkdir(parents=True)
    candidate, spec, target = prepared(root, files)
    atomic_write_model(root / "intake-spec.json", spec)
    atomic_write_model(project / REGISTRY, CorpusCandidates(candidates=(candidate,)))
    for name in (PROTOCOL, TOOL):
        destination = project / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((PROJECT / name).read_bytes())
    source = project / "src/agentsec_evidence/__init__.py"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"# Authored worker source placeholder, not executed\n")
    write_preview(build_preview(candidate, spec, target), root / "preflight")
    return root, project / "workspace/validation"


def fake_capture(monkeypatch: pytest.MonkeyPatch, *, failure: str | None = None) -> list[list[str]]:
    commands: list[list[str]] = []

    def capture(
        argv: list[str], directory: Path, environment: dict[str, str], *, timeout: int = 90
    ) -> ProcessCapture:
        commands.append(argv)
        directory.mkdir(parents=True)
        save(directory / "command.json", {"argv": argv})
        code, stdout, stderr = 0, b"", b""
        limited = False
        if argv[1:3] == ["image", "inspect"]:
            stdout = json.dumps([{"Id": IMAGE, "Os": "linux"}]).encode()
        elif argv[1] == "rm":
            code, stderr = (
                (1, b"unexpected cleanup error")
                if failure == "cleanup"
                else (1, b"No such container")
            )
        else:
            mounts = {}
            for i, value in enumerate(argv):
                if value == "--mount":
                    source, destination = (
                        argv[i + 1].removeprefix("type=bind,source=").split(",target=")
                    )
                    mounts[destination.removesuffix(",readonly")] = Path(source)
            # This fake parses only the test's own authored bytes, never repository source.
            report = validate_view(mounts["/target"], mounts["/request.json"].read_bytes())
            stdout = report.model_dump_json().encode()
            if failure == "timeout":
                code = 137
            elif failure == "truncated":
                limited = True
            elif failure == "response":
                stdout = b"{}"
        result = ProcessCapture(
            argv=tuple(argv),
            started_at=datetime(2026, 10, 22, tzinfo=UTC),
            ended_at=datetime(2026, 10, 22, tzinfo=UTC),
            exit_code=code,
            stdout=stdout,
            stderr=stderr,
            timed_out=failure == "timeout" and argv[1] == "run",
            output_limited=limited,
            stdout_truncated=limited,
            stderr_truncated=False,
            duration_ns=123,
            peak_rss_bytes=100,
        )
        save_capture(directory, result)
        return result

    monkeypatch.setattr(execution, "run_capture", capture)
    return commands


def run_authored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    files: dict[str, bytes],
    *,
    failure: str | None = None,
) -> tuple[Path, list[list[str]]]:
    root, output = setup(tmp_path, files)
    docker = tmp_path / "docker.exe"
    docker.write_bytes(b"placeholder")
    commands = fake_capture(monkeypatch, failure=failure)
    execution.run_validation(tmp_path, root, output, docker=docker)
    return output, commands


def test_exact_offline_plan_without_target_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, output = setup(tmp_path, {"bad.py": b"def broken(", "LICENSE": b"Authored"})

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Planning cannot parse targets or launch anything")

    monkeypatch.setattr(ast, "parse", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    plan, _ = prepare_validation_plan(tmp_path, root, output)
    assert plan.collection_repetitions == 3
    assert plan.security_scanner_authorization == "not-granted"
    assert plan.requests[0].inventory[0].sha256 == sha256_bytes(b"def broken(")
    assert plan.parent_paths == ("LICENSE", "bad.py")


@pytest.mark.parametrize(
    "files, states",
    [
        ({"a.py": b"pass"}, ["input-eligible"] * 3),
        (
            {"a.py": b"pass", "b.py": b"def broken("},
            ["input-eligible-with-incomplete-files", "input-refused", "input-refused"],
        ),
        ({"a.py": b"pass # noaudit"}, ["input-eligible", "input-eligible", "policy-refused"]),
        ({"venv/a.py": b"pass"}, ["input-eligible", "input-eligible", "policy-refused"]),
        (
            {"a.py": b"pass", ".AGENT-AUDIT.YAML": b"rules: []"},
            ["input-eligible", "input-eligible", "policy-refused"],
        ),
        (
            {"a.py": b"pass", ".semgrepignore": b":include ../outside"},
            ["input-eligible", "policy-refused", "input-eligible"],
        ),
        ({"README.md": b"Authored no-python"}, ["no-input"] * 3),
    ],
)
def test_native_eligibility_and_no_scanning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, files: dict[str, bytes], states: list[str]
) -> None:
    output, commands = run_authored(tmp_path, monkeypatch, files)
    result = execution.verify_validation(tmp_path, output)
    assessment = result["assessment"]
    assert [s["state"] for s in assessment["stages"]] == states
    assert assessment["potential_paired_comparison"] == (states == ["input-eligible"] * 3)
    assert all(
        s["findings"] is None and s["scanner_invocations"] == 0 for s in assessment["stages"]
    )
    for argv in commands:
        if argv[1] != "run":
            continue
        assert "agentsec_evidence.agents.worker" in argv
        assert "scan" not in argv
        assert "--network" in argv and "none" in argv and "--read-only" in argv
        assert "65534:65534" in argv and "no-new-privileges" in argv
        assert argv[argv.index("--memory") + 1] == "512m"
        assert all("readonly" in argv[i + 1] for i, a in enumerate(argv) if a == "--mount")
    root = tmp_path / "workspace/candidates/R03"
    with pytest.raises(ValueError, match="new ignored"):
        execution.run_validation(tmp_path, root, output, docker=tmp_path / "docker.exe")


def test_65_files_not_sharded_for_baselines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output, _ = run_authored(tmp_path, monkeypatch, {f"f{i:03}.py": b"pass" for i in range(65)})
    result = execution.verify_validation(tmp_path, output)
    assert result["validation_invocations"] == 2
    assert len(result["assessment"]["checks"]) == 65
    assert [s["state"] for s in result["assessment"]["stages"]] == [
        "input-eligible",
        "unsupported-size",
        "unsupported-size",
    ]


def test_oversized_input_remains_accounted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output, _ = run_authored(
        tmp_path, monkeypatch, {"large.py": b"#" * (256 * 1024 + 1), "small.py": b"pass"}
    )
    result = execution.verify_validation(tmp_path, output)
    assert [e["path"] for e in result["assessment"]["omitted_from_validation"]] == ["large.py"]
    assert result["assessment"]["stages"][0]["state"] == "input-eligible-with-incomplete-files"


@pytest.mark.parametrize("failure", ["timeout", "truncated", "cleanup", "response"])
def test_failure_sealed_and_not_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    with pytest.raises(ValueError):
        run_authored(tmp_path, monkeypatch, {"a.py": b"pass"}, failure=failure)
    output = tmp_path / "workspace/validation"
    assert (output / "evidence-manifest.json").is_file()
    result = json.loads((output / "result.json").read_bytes())
    assert (
        result["finished"] is False and result["error"] and result["rows"][0]["state"] == "failed"
    )
    with pytest.raises(ValueError, match="Incomplete"):
        execution.verify_validation(tmp_path, output)


@pytest.mark.parametrize(
    "field",
    [
        "source",
        "extra",
        "implementation",
        "request",
        "assessment",
        "command",
        "cleanup",
        "rows",
        "parent",
        "protocol",
        "counts",
    ],
)
def test_tampering_rejected_even_with_resealed_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    output, _ = run_authored(tmp_path, monkeypatch, {"a.py": b"pass"})

    def mutate(path: str, function: Any) -> None:
        value = json.loads((output / path).read_bytes())
        function(value)
        save(output / path, value)

    if field == "source":
        (output / "batches/000/target/a.py").write_bytes(b"changed")
    elif field == "extra":
        (output / "batches/000/target/extra.py").write_bytes(b"pass")
    elif field == "implementation":
        (output / "implementation/src/agentsec_evidence/__init__.py").write_bytes(b"changed")
    elif field == "request":
        (output / "batches/000/request.json").write_bytes(b"{}")
    elif field == "assessment":
        mutate("assessment.json", lambda v: v.update(potential_paired_comparison=False))
    elif field in {"command", "cleanup"}:
        key = "validation/b000" + ("/cleanup" if field == "cleanup" else "")
        for name in ("command.json", "process.json"):
            mutate(key + "/" + name, lambda v: v["argv"].__setitem__(1, "exec"))
    elif field == "rows":
        mutate("result.json", lambda v: v.update(rows=[]))
    elif field == "parent":
        (tmp_path / "workspace/candidates/R03/prepared/source/a.py").write_bytes(b"changed")
    elif field == "protocol":
        (output / "protocol.md").write_bytes(b"changed")
    else:
        mutate("result.json", lambda v: v.update(security_scanner_invocations=1))
    save(output / "evidence-manifest.json", {"files": evidence_records(output)})
    with pytest.raises(ValueError):
        execution.verify_validation(tmp_path, output)


def test_assessment_requires_exact_responses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output, _ = run_authored(tmp_path, monkeypatch, {"a.py": b"pass"})
    plan = CorpusValidationPlan.model_validate_json((output / "plan.json").read_bytes())
    report = AgentInputReport.model_validate_json(
        (output / "validation/b000/stdout.bin").read_bytes()
    )
    for reports in ([], [report, report], [report.model_copy(update={"request_sha256": "f" * 64})]):
        with pytest.raises(ValueError):
            assess_inputs(plan, reports)


@pytest.mark.parametrize(
    "model,name", [(CorpusValidationPlan, "plan"), (CorpusInputAssessment, "assessment")]
)
def test_committed_schema_matches_contract(model: Any, name: str) -> None:
    expected = model.model_json_schema(mode="serialization")
    expected["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    expected["$id"] = f"urn:agentsec-evidence:schema:corpus-input-validation-{name}-v1"
    actual = json.loads(
        (PROJECT / f"schemas/corpus-input-validation-v1/{name}.schema.json").read_bytes()
    )
    assert actual == expected
    Draft202012Validator.check_schema(actual)
