from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from agentsec_evidence.benchmarks.models import (
    MAX_PLAN_BYTES,
    BenchmarkDryRun,
    BenchmarkDryRunV2,
    BenchmarkPlan,
)
from agentsec_evidence.benchmarks.service import (
    ADMITTED_PINS,
    REGISTRY,
    build_development_plan,
    plan_bytes,
    validate_plan,
)
from agentsec_evidence.cli.app import app
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.research.retained import bounded_file

PROJECT = Path(__file__).resolve().parents[2]


def test_current_dry_run_schema_keeps_historical_contract_separate() -> None:
    assert (
        json.loads((PROJECT / "schemas/benchmark-v2/dry-run.schema.json").read_bytes())
        == BenchmarkDryRunV2.model_json_schema()
    )
    assert BenchmarkDryRun.model_fields["resume_implemented"].default is False


@pytest.fixture
def project(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    for path in ADMITTED_PINS:
        destination = project / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(PROJECT / path, destination)
    (project / "src").mkdir()
    (project / "src/never_import.py").write_text("raise RuntimeError('must not execute')\n")
    return project


def sample(project: Path, *ids: str, repeats: int = 1) -> BenchmarkPlan:
    return build_development_plan(
        project,
        plan_id="authored-rehearsal",
        case_ids=ids or ("python-positive",),
        repetitions=repeats,
    )


def write_plan(project: Path, value: BenchmarkPlan | dict[str, Any]) -> Path:
    path = project / "plan.json"
    path.write_bytes(plan_bytes(value) if isinstance(value, BenchmarkPlan) else json_bytes(value))
    return path


def test_all_registered_cases_are_planned_not_executed(project: Path) -> None:
    registry = json.loads((project / REGISTRY).read_bytes())
    plan = sample(project, *(case["id"] for case in registry["cases"]), repeats=3)
    path = write_plan(project, plan)
    before = {p.relative_to(project): p.read_bytes() for p in project.rglob("*") if p.is_file()}
    result = validate_plan(project, path)
    assert len(result.cells) == 39
    assert len({cell.cell_id for cell in result.cells}) == 39
    assert all(
        cell.state == "not-attempted" and cell.finding_records is None for cell in result.cells
    )
    assert sum(cell.producer_invocations for cell in result.cells) == 0
    assert result.execution_authorized is False
    assert result.runtime_readiness == "not-checked"
    assert result.metric_scoring_implemented is False
    assert result.resume_implemented is True
    assert result.contract == "benchmark-dry-run-v2"
    assert result.resume_scope == "verified-terminal-authored-agent-attempts-only-no-retry"
    assert result == validate_plan(project, path)
    assert {
        p.relative_to(project): p.read_bytes() for p in project.rglob("*") if p.is_file()
    } == before


def test_cells_follow_explicit_case_then_repeat_order(project: Path) -> None:
    result = validate_plan(
        project, write_plan(project, sample(project, "mcp-positive", "python-positive", repeats=2))
    )
    assert [(cell.case_id, cell.repetition) for cell in result.cells] == [
        ("mcp-positive", 1),
        ("mcp-positive", 2),
        ("python-positive", 1),
        ("python-positive", 2),
    ]


def test_policy_context_is_inventoried_not_selected_or_dropped(project: Path) -> None:
    result = validate_plan(project, write_plan(project, sample(project, "python-excluded-yaml")))
    cell = result.cells[0]
    assert [file.path for file in cell.input_files] == [".agent-audit.yaml", "agent.py"]
    assert cell.selected_paths == ("agent.py",)
    assert cell.expectation.policy_observation == "target-exclusion"
    assert cell.expectation.expected_condition == "present"
    assert cell.finding_records is None


@pytest.mark.parametrize(
    "case", ["python-malformed", "mcp-malformed", "unsupported-text", "python-inline-suppression"]
)
def test_invalid_or_suppressed_case_is_retained_not_assumed_clean(project: Path, case: str) -> None:
    result = validate_plan(project, write_plan(project, sample(project, case)))
    assert result.cells[0].case_id == case
    assert result.cells[0].finding_records is None
    assert result.cells[0].coverage == "not-measured"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("split", "held-out"),
        ("split", "pilot"),
        ("admission", "approved-by-plan-author"),
        ("treatment", "python-source-pilot-v1"),
        ("purpose", "confirmatory"),
        ("repetitions", 0),
        ("repetitions", 4),
        ("repetitions", True),
        ("max_workers", 2),
        ("max_workers", True),
        ("automatic_retries", 1),
        ("automatic_retries", False),
        ("target_execution", True),
        ("order", "parallel"),
        ("metrics", []),
        ("metrics", ["accuracy-v1"]),
        ("protocol_status", "frozen"),
        ("plan_id", "../escape"),
        ("plan_id", " "),
        ("shell_command", "anything"),
    ],
)
def test_unadmitted_plan_options_refused(project: Path, field: str, value: Any) -> None:
    data = sample(project).model_dump(mode="json")
    data[field] = value
    with pytest.raises(ValueError):
        validate_plan(project, write_plan(project, data))


@pytest.mark.parametrize(
    "kind",
    [
        "empty",
        "duplicate",
        "unknown",
        "family",
        "held-out",
        "property",
        "selection",
        "input-hash",
        "oracle",
        "oracle-review",
    ],
)
def test_case_or_oracle_relabeling_refused(project: Path, kind: str) -> None:
    data = sample(project).model_dump(mode="json")
    case = data["cases"][0]
    if kind == "empty":
        data["cases"] = []
    elif kind == "duplicate":
        data["cases"].append(case)
    elif kind == "unknown":
        case["case_id"] = "my-public-repo"
    elif kind == "family":
        case["source_family"] = "independent-family"
    elif kind == "held-out":
        case["split"] = "held-out"
    elif kind == "property":
        case["property_id"] = "mcp.filesystem-root-declaration"
    elif kind == "selection":
        case["selected_paths"] = ["other.py"]
    elif kind == "input-hash":
        case["files"][0]["sha256"] = "0" * 64
    elif kind == "oracle":
        case["expectation"]["expected_condition"] = "absent"
        case["expectation_sha256"] = semantic_hash(case["expectation"])
    else:
        case["expectation"]["review_status"] = "independently-accepted"
    with pytest.raises(ValueError):
        validate_plan(project, write_plan(project, data))


@pytest.mark.parametrize(
    "path", ["../outside", "/absolute", "C:/absolute", "a\\b", "src/../a", "src//a", "src/./a"]
)
def test_unsafe_pin_path_refused(project: Path, path: str) -> None:
    data = sample(project).model_dump(mode="json")
    data["implementation"][0]["path"] = path
    with pytest.raises(ValueError):
        validate_plan(project, write_plan(project, data))


@pytest.mark.parametrize(
    "kind",
    [
        "pin-hash",
        "pin-size",
        "extra-pin",
        "missing-pin",
        "duplicate-pin",
        "unsorted",
        "missing-source",
        "added-source",
        "changed-source",
    ],
)
def test_pin_and_implementation_mutations_refused(project: Path, kind: str) -> None:
    data = sample(project).model_dump(mode="json")
    if kind == "pin-hash":
        data["pins"][0]["sha256"] = "0" * 64
    elif kind == "pin-size":
        data["pins"][0]["bytes"] += 1
    elif kind == "extra-pin":
        data["pins"].append(data["pins"][0])
    elif kind == "missing-pin":
        data["pins"].pop()
    elif kind == "duplicate-pin":
        data["pins"][1] = data["pins"][0]
    elif kind == "unsorted":
        data["pins"].reverse()
    elif kind == "missing-source":
        (project / "src/never_import.py").unlink()
    elif kind == "added-source":
        (project / "src/extra.py").write_text("# new code\n")
    else:
        (project / "src/never_import.py").write_text("# changed code\n")
    with pytest.raises(ValueError):
        validate_plan(project, write_plan(project, data))


@pytest.mark.parametrize("path", list(ADMITTED_PINS))
def test_changed_protected_file_cannot_be_readmitted_by_rehashing(project: Path, path: str) -> None:
    data = sample(project).model_dump(mode="json")
    changed = (project / path).read_bytes() + b"\n"
    (project / path).write_bytes(changed)
    for pin in data["pins"]:
        if pin["path"] == path:
            pin.update(bytes=len(changed), sha256=sha256_bytes(changed))
    with pytest.raises(ValueError, match="Protected admission input changed"):
        validate_plan(project, write_plan(project, data))


def test_fresh_explicit_plan_changes_identity_after_code_change(project: Path) -> None:
    first = sample(project)
    (project / "src/never_import.py").write_text("# authorized engineering increment\n")
    second = sample(project)
    assert first.implementation != second.implementation
    old_id = semantic_hash(first.model_dump(mode="json"))
    result = validate_plan(project, write_plan(project, second))
    assert result.plan_semantic_sha256 != old_id


@pytest.mark.parametrize(
    "payload",
    [b"{", b'{"plan_id":"a","plan_id":"b"}', b" " * (MAX_PLAN_BYTES + 1)],
    ids=["malformed", "duplicate-key", "oversized"],
)
def test_invalid_duplicate_or_oversized_plan_refused(project: Path, payload: bytes) -> None:
    path = project / "invalid.json"
    path.write_bytes(payload)
    with pytest.raises(ValueError):
        validate_plan(project, path)


def test_hard_linked_plan_refused(project: Path) -> None:
    path = write_plan(project, sample(project))
    alias = project / "alias.json"
    os.link(path, alias)
    with pytest.raises(ValueError, match="non-hard-linked"):
        validate_plan(project, path)


def test_hard_linked_source_refused(project: Path) -> None:
    path = write_plan(project, sample(project))
    os.link(project / "src/never_import.py", project / "source-alias.txt")
    with pytest.raises(ValueError, match="non-hard-linked"):
        validate_plan(project, path)


def test_python_inside_cache_named_directory_is_not_silently_skipped(project: Path) -> None:
    plan = sample(project)
    path = write_plan(project, plan)
    directory = project / "src/__pycache__"
    directory.mkdir()
    (directory / "unexpected.py").write_text("# source despite directory name\n")
    with pytest.raises(ValueError, match="pins differ"):
        validate_plan(project, path)


def test_walk_error_cannot_silently_omit_source(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write_plan(project, sample(project))

    def failed_walk(*args: Any, **kwargs: Any) -> Any:
        kwargs["onerror"](PermissionError("denied source subtree"))
        return iter(())

    monkeypatch.setattr("agentsec_evidence.benchmarks.service.os.walk", failed_walk)
    with pytest.raises(PermissionError, match="denied source subtree"):
        validate_plan(project, path)


def test_plan_change_during_validation_refused(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agentsec_evidence.benchmarks import service

    path = write_plan(project, sample(project))
    original = bounded_file
    reads = 0

    def changing(file: Path, limit: int) -> bytes:
        nonlocal reads
        raw = original(file, limit)
        if file == path:
            reads += 1
            if reads > 1:
                return raw + b"\n"
        return raw

    monkeypatch.setattr(service, "bounded_file", changing)
    with pytest.raises(ValueError, match="changed during validation"):
        validate_plan(project, path)


@pytest.mark.parametrize("command", ["validate", "dry-run"])
def test_cli_does_not_launch_process_or_network(
    project: Path, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    path = write_plan(project, sample(project, "python-positive", "mcp-positive"))

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("Offline plan commands cannot invoke processes or network")

    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("socket.socket", forbidden)
    result = CliRunner().invoke(
        app, ["benchmark", command, str(path), "--project-root", str(project)]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["plan_valid"] is True
    assert payload["execution_authorized"] is False
    if command == "dry-run":
        assert len(payload["cells"]) == 2
    else:
        assert payload["planned_cells"] == 2


@pytest.mark.parametrize("command", ["validate", "dry-run"])
def test_cli_refusal_is_nonzero(project: Path, command: str) -> None:
    path = write_plan(project, sample(project))
    (project / "src/never_import.py").write_text("# changed\n")
    result = CliRunner().invoke(
        app, ["benchmark", command, str(path), "--project-root", str(project)]
    )
    assert result.exit_code == 5
    assert "pins differ" in result.output


@pytest.mark.parametrize(("name", "model"), [("plan", BenchmarkPlan), ("dry-run", BenchmarkDryRun)])
def test_generated_schemas_match(
    name: str, model: type[BenchmarkPlan] | type[BenchmarkDryRun]
) -> None:
    assert (
        json.loads((PROJECT / f"schemas/benchmark-v1/{name}.schema.json").read_bytes())
        == model.model_json_schema()
    )
