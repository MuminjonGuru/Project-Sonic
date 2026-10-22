from __future__ import annotations

import dataclasses
import importlib
import importlib.util
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agentsec_evidence.agents.records import AgentInputRequest
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.core.io import atomic_write_bytes
from agentsec_evidence.custom_rules import shared_execution as execution
from agentsec_evidence.custom_rules.shared_inputs import (
    SharedPlan,
    partition_inputs,
    prepare_shared,
    read_registry,
    view_entries,
)
from agentsec_evidence.execution.process import ProcessCapture
from agentsec_evidence.models.contracts import InventoryEntry
from agentsec_evidence.pilot.runner import evidence_records, save
from agentsec_evidence.reporting.custom_contracts import FAMILIES, IMAGE, Family, expected_exit

PROJECT = Path(__file__).resolve().parents[1]


def entry(path: str, size: int = 1) -> InventoryEntry:
    return InventoryEntry(path=path, byte_length=size, sha256="a" * 64, media_type="text/x-python")


def test_partition_is_order_independent_and_lossless() -> None:
    items = [entry(f"f{i:03d}.py") for i in range(129)]
    batches = partition_inputs(items)
    assert [len(b) for b in batches] == [64, 64, 1]
    assert batches == partition_inputs(list(reversed(items)))
    assert [e for b in batches for e in b] == items
    assert partition_inputs([]) == []


@pytest.mark.parametrize("limit", [0, 65, True])
def test_partition_refuses_invalid_limit(limit: int) -> None:
    with pytest.raises(ValueError):
        partition_inputs([entry("a.py")], max_files=limit)


@pytest.mark.parametrize(
    "items",
    [
        [entry("A.py"), entry("a.py")],
        [entry("a"), entry("a/b.py")],
        [entry("a.py", 256 * 1024 + 1)],
        [entry("/".join(["deep"] * 65) + "/a.py")],
    ],
)
def test_partition_explicitly_refuses_unsupported(items: list[InventoryEntry]) -> None:
    with pytest.raises(ValueError):
        partition_inputs(items)


def test_partition_respects_bytes_and_directory_entry_budget() -> None:
    assert [len(b) for b in partition_inputs([entry(f"{i}.py", 256 * 1024) for i in range(5)])] == [
        4,
        1,
    ]
    deep = [entry(f"{i}/" + "/".join(["d"] * 60) + "/f.py") for i in range(12)]
    batches = partition_inputs(deep)
    assert len(batches) == 2
    assert all(view_entries([e.path for e in b]) <= 512 for b in batches)


def test_pinned_finite_union_and_plan_boundary() -> None:
    prepared = prepare_shared(PROJECT)
    assert len(prepared.inputs) == 385
    assert sum(map(len, prepared.inputs.values())) == 16246
    assert len(prepared.plan.requests) == 7
    assert len(execution.planned_rows(prepared.plan)) == 98
    assert all(r.selected.keys() == {e.path for e in r.inventory} for r in prepared.plan.requests)
    alternate = prepare_shared(PROJECT, max_files=32, repetitions=1)
    assert len(alternate.plan.requests) == 13
    assert alternate.plan.snapshot_id == prepared.plan.snapshot_id
    for family in FAMILIES:
        with pytest.raises(ValueError, match="approved repair bytes"):
            read_registry(prepared.registries[family.registry] + b" ", family.key)
    plan = prepared.plan.model_dump()
    plan["source_pins"] = {"../outside.py": "a" * 64}
    with pytest.raises(ValueError):
        SharedPlan.model_validate(plan)


def test_partition_comparison_requires_unchanged_instrument_and_different_batches() -> None:
    spec = importlib.util.spec_from_file_location(
        "compare_shared_custom", PROJECT / "tools/compare_shared_custom.py"
    )
    assert spec is not None and spec.loader is not None
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    left = prepare_shared(PROJECT).plan
    right = prepare_shared(PROJECT, max_files=32, repetitions=1).plan
    helper.compare_plans(left, right)
    with pytest.raises(ValueError, match="different input partitions"):
        helper.compare_plans(left, left)
    changed = right.model_copy(update={"source_pins": {"src/agentsec_evidence/fake.py": "0" * 64}})
    with pytest.raises(ValueError, match="Only batching"):
        helper.compare_plans(left, changed)
    with pytest.raises(ValueError, match="repeatability"):
        helper.compare_plans(left.model_copy(update={"repetitions": 1}), right)


def capture(argv: list[str], raw: bytes = b"", code: int = 0) -> ProcessCapture:
    now = datetime.now(UTC)
    return ProcessCapture(tuple(argv), now, now, 1, code, raw, b"", False, False, False, False, 0)


@pytest.mark.parametrize(
    "flag", ["timed_out", "output_limited", "stdout_truncated", "stderr_truncated"]
)
def test_process_incompleteness_is_not_success(flag: str) -> None:
    value = dataclasses.replace(
        capture(["docker"]),
        timed_out=flag == "timed_out",
        output_limited=flag == "output_limited",
        stdout_truncated=flag == "stdout_truncated",
        stderr_truncated=flag == "stderr_truncated",
    )
    assert not execution.capture_ok(value, {0})


@pytest.mark.parametrize("family", FAMILIES, ids=lambda f: f.key)
def test_exact_request_exit_and_no_suppression_policy(tmp_path: Path, family: Family) -> None:
    # These are authored test strings, never imported or executed as target programs.
    raw = b"import os\neval(value); os.system(command)  # nosemgrep: TOOL-EXEC-001\n"
    atomic_write_bytes(tmp_path / "case.py", raw)
    request = AgentInputRequest(
        target_snapshot_id="shared-unit",
        inventory=[
            InventoryEntry(
                path="case.py",
                sha256=sha256_bytes(raw),
                byte_length=len(raw),
                media_type="text/x-python",
            )
        ],
        selected={"case.py": "python-source"},
    )
    worker = importlib.import_module("agentsec_evidence.custom_rules." + family.worker)
    native = worker.scan_view(tmp_path, request.model_dump_json().encode())
    assert native.policy == "research-only-no-suppressions-applied"
    execution.check_native(
        native.model_dump_json().encode(),
        request.model_dump_json().encode(),
        family,
        expected_exit(native),
    )
    with pytest.raises(ValueError, match="request binding"):
        execution.check_native(
            native.model_dump_json().encode(),
            request.model_dump_json().encode() + b" ",
            family,
            expected_exit(native),
        )
    with pytest.raises(ValueError, match="exit"):
        execution.check_native(
            native.model_dump_json().encode(), request.model_dump_json().encode(), family, 127
        )
    if family.key == "tool-execution":
        assert {f.rule.rule_id for f in native.files[0].findings} == {
            "TOOL-EXEC-001",
            "TOOL-EXEC-003",
        }
        assert len({f.record_id for f in native.files[0].findings}) == 2


def fake_docker(argv: list[str], **kwargs: object) -> ProcessCapture:
    if argv[1:3] == ["image", "inspect"]:
        return capture(argv, json.dumps([{"Id": IMAGE, "Os": "linux"}]).encode())
    if argv[1] == "rm":
        return capture(argv)
    mounts = [argv[i + 1] for i, part in enumerate(argv) if part == "--mount"]
    paths = {
        mount.split(",target=")[1].split(",")[0]: Path(
            mount.split("source=")[1].split(",target=")[0]
        )
        for mount in mounts
    }
    module = argv[argv.index("-m") + 1]
    worker = importlib.import_module(module)
    native = worker.scan_view(paths["/target"], paths["/request.json"].read_bytes())
    return capture(argv, native.model_dump_json().encode() + b"\n", expected_exit(native))


@pytest.fixture(scope="module")
def shared_bundle(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    root = tmp_path_factory.mktemp("shared-custom")
    (root / "workspace").mkdir()
    atomic_write_bytes(
        root / "configs/tools/agent-audit.toml",
        (PROJECT / "configs/tools/agent-audit.toml").read_bytes(),
    )
    prepared = prepare_shared(PROJECT)
    output = root / "workspace/attempt"
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(execution, "prepare_shared", lambda *a, **k: prepared)
        patch.setattr(execution, "resolve_docker", lambda p: PROJECT / "pyproject.toml")
        patch.setattr(execution, "run_bounded_process", fake_docker)
        execution.run_shared(root, output)
    yield output


def test_shared_replay_expectations_repeats_and_overlap(shared_bundle: Path) -> None:
    summary = execution.verify_shared(shared_bundle)
    assert summary["input_count"] == 385
    assert summary["worker_invocations"] == 98
    assert summary["origin_assertions_passed"]
    assert summary["repeatability_passed"]
    assert all(f["files"] == 385 and f["incomplete"] == 7 for f in summary["families"])
    assert summary["unique_vulnerabilities"] is None
    assert summary["overlap_candidates"]
    assert all(
        o["relationship"] == "line-overlap-unreviewed" for o in summary["overlap_candidates"]
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-row",
        "wrong-count",
        "unfinished",
        "unsafe-command",
        "timeout",
        "bad-cleanup",
        "changed-native",
        "unlisted-input",
    ],
)
def test_resealed_semantic_tampering_is_rejected(shared_bundle: Path, mutation: str) -> None:
    key = "runs/r01/b000/tool-execution"
    changes: dict[str, bytes] = {}

    def change(path: str, edit: object) -> None:
        changes[path] = (shared_bundle / path).read_bytes()
        save(shared_bundle / path, edit)

    try:
        if mutation in ("missing-row", "wrong-count", "unfinished"):
            result = json.loads((shared_bundle / "result.json").read_bytes())
            if mutation == "missing-row":
                result["rows"].pop()
            elif mutation == "wrong-count":
                result["rows"][0]["finding_records"] += 1
            else:
                result["finished"] = False
            change("result.json", result)
        elif mutation == "changed-native":
            native = json.loads((shared_bundle / key / "stdout.bin").read_bytes())
            native["files"][0]["source_sha256"] = "0" * 64
            change(key + "/stdout.bin", native)
        elif mutation == "unlisted-input":
            atomic_write_bytes(shared_bundle / "batches/000/target/unlisted.py", b"pass\n")
        else:
            process_key = key + ("/cleanup" if mutation == "bad-cleanup" else "")
            process = json.loads((shared_bundle / process_key / "process.json").read_bytes())
            if mutation == "unsafe-command":
                process["argv"][process["argv"].index("--network") + 1] = "host"
                change(process_key + "/command.json", {"argv": process["argv"]})
            elif mutation == "timeout":
                process["timed_out"] = True
            else:
                process["exit_code"] = 1
            change(process_key + "/process.json", process)
        save(shared_bundle / "evidence-manifest.json", {"files": evidence_records(shared_bundle)})
        with pytest.raises(ValueError):
            execution.verify_shared(shared_bundle)
    finally:
        for path, raw in changes.items():
            atomic_write_bytes(shared_bundle / path, raw)
        (shared_bundle / "batches/000/target/unlisted.py").unlink(missing_ok=True)
        save(shared_bundle / "evidence-manifest.json", {"files": evidence_records(shared_bundle)})


def test_existing_attempt_is_never_overwritten(shared_bundle: Path) -> None:
    with pytest.raises(ValueError, match="already exists"):
        execution.run_shared(shared_bundle.parents[1], shared_bundle)


def test_worker_failure_preserves_attempt_and_leaves_remaining_not_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "workspace").mkdir()
    atomic_write_bytes(
        tmp_path / "configs/tools/agent-audit.toml",
        (PROJECT / "configs/tools/agent-audit.toml").read_bytes(),
    )
    prepared = prepare_shared(PROJECT)
    monkeypatch.setattr(execution, "prepare_shared", lambda *a, **k: prepared)
    monkeypatch.setattr(execution, "resolve_docker", lambda p: PROJECT / "pyproject.toml")

    def fail(argv: list[str], **kwargs: object) -> ProcessCapture:
        if argv[1] == "run":
            return dataclasses.replace(capture(argv, code=137), timed_out=True)
        return fake_docker(argv, **kwargs)

    monkeypatch.setattr(execution, "run_bounded_process", fail)
    output = tmp_path / "workspace/failed-attempt"
    with pytest.raises(ValueError, match="timed out"):
        execution.run_shared(tmp_path, output)
    result = json.loads((output / "result.json").read_bytes())
    assert result["finished"] is False
    assert result["rows"][0]["state"] == "failed"
    assert result["rows"][0]["finding_records"] is None
    assert all(r["state"] == "not-run" for r in result["rows"][1:])
    assert (output / "evidence-manifest.json").exists()
    assert (output / "runs/r01/b000/tool-execution/cleanup/process.json").exists()
    with pytest.raises(ValueError, match="incomplete"):
        execution.verify_shared(output)
