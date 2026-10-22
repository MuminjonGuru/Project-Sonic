"""Authored contracts; real Docker rehearsal is recorded separately."""

from __future__ import annotations

import copy
import importlib
import json
from pathlib import Path
from typing import Any

import pytest

from agentsec_evidence.agents.execution import AgentAuditToolConfig
from agentsec_evidence.agents.records import AgentInputRequest
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.custom_rules.repository_contracts import (
    TARGETS,
    RepositoryCustomPlan,
    current_native,
    validate_plan,
)
from agentsec_evidence.custom_rules.repository_execution import argv_for, schedule
from agentsec_evidence.custom_rules.tool_execution_v2_worker import exit_status, scan_view
from agentsec_evidence.execution.config import load_toml_config
from agentsec_evidence.models.contracts import InventoryEntry
from agentsec_evidence.reporting.custom_contracts import FAMILIES, expected_exit
from agentsec_evidence.reporting.repository import (
    LIMITATIONS,
    custom_runs,
    render,
    validate_custom_projection,
)

ROOT = Path(__file__).resolve().parents[1]


def sample(tmp_path: Path) -> tuple[bytes, bytes]:
    source = b"from __future__ import annotations\nx: eval(memory)\neval(code)\n"
    (tmp_path / "case.py").write_bytes(source)
    request = (
        AgentInputRequest(
            target_snapshot_id="a" * 64,
            inventory=[
                InventoryEntry(
                    path="case.py",
                    sha256=sha256_bytes(source),
                    byte_length=len(source),
                    media_type="text/x-python",
                )
            ],
            selected={"case.py": "python-source"},
        )
        .model_dump_json()
        .encode()
    )
    return request, scan_view(tmp_path, request).model_dump_json().encode() + b"\n"


def test_current_native_bound_and_versioned(tmp_path: Path) -> None:
    request, raw = sample(tmp_path)
    native = current_native(raw, request, FAMILIES[0], 1)
    assert native.version == "1.1.0"
    assert len(native.files[0].findings or []) == 1
    assert native.files[0].limitations_observed


@pytest.mark.parametrize(
    "mutation",
    ["request", "catalog", "identity", "source", "state", "rule", "null", "duplicate", "exit"],
)
def test_reject_native_tampering(tmp_path: Path, mutation: str) -> None:
    request, raw = sample(tmp_path)
    payload = json.loads(raw)
    file = payload["files"][0]
    if mutation == "request":
        payload["request_sha256"] = "b" * 64
    elif mutation == "catalog":
        payload["catalog_sha256"] = "b" * 64
    elif mutation == "identity":
        file["findings"][0]["record_id"] = "b" * 64
    elif mutation == "source":
        file["source_sha256"] = "b" * 64
    elif mutation == "state":
        payload["execution_state"] = "partial"
    elif mutation == "rule":
        file["findings"][0]["rule"]["title"] = "Invented vulnerability"
    elif mutation == "null":
        file["findings"] = None
    elif mutation == "duplicate":
        file["findings"].append(copy.deepcopy(file["findings"][0]))
    with pytest.raises(ValueError):
        current_native(
            json.dumps(payload).encode(), request, FAMILIES[0], 0 if mutation == "exit" else 1
        )


def test_native_empty_and_malformed(tmp_path: Path) -> None:
    raw = b"def broken("
    (tmp_path / "bad.py").write_bytes(raw)
    request = (
        AgentInputRequest(
            target_snapshot_id="a" * 64,
            inventory=[
                InventoryEntry(
                    path="bad.py",
                    sha256=sha256_bytes(raw),
                    byte_length=len(raw),
                    media_type="text/x-python",
                )
            ],
            selected={"bad.py": "python-source"},
        )
        .model_dump_json()
        .encode()
    )
    native = scan_view(tmp_path, request)
    assert exit_status(native) == 2 and native.files[0].findings is None
    current_native(native.model_dump_json().encode(), request, FAMILIES[0], 2)


def test_isolation_and_only_trusted_module_switch(tmp_path: Path) -> None:
    tool = load_toml_config(ROOT / "configs/tools/agent-audit.toml", AgentAuditToolConfig).value
    executable = tmp_path / "docker.exe"
    executable.write_bytes(b"placeholder")
    (tmp_path / "batches/000/target").mkdir(parents=True)
    (tmp_path / "batches/000/request.json").write_bytes(b"{}")
    (tmp_path / "implementation/src").mkdir(parents=True)
    argv = argv_for(executable, tool, tmp_path, 0, "test", FAMILIES[0])
    assert "agentsec_evidence.custom_rules.tool_execution_v2_worker" in argv
    assert "--read-only" in argv and "--network" in argv and "none" in argv
    assert "--cap-drop" in argv and "ALL" in argv
    assert not any("docker.sock" in p for p in argv)


def test_html_escapes_and_preserves_nonclaims(tmp_path: Path) -> None:
    request, raw = sample(tmp_path)
    native = current_native(raw, request, FAMILIES[0], 1).model_dump(mode="json")
    row = {
        "family": "tool-execution",
        "key": "runs/r01/b000/tool-execution",
        "batch": 0,
        "repetition": 1,
        "native_sha256": sha256_bytes(raw),
        "native": native,
    }
    run = custom_runs([row], "b" * 64)[0]
    assert len(run["results"]) == 1
    assert run["results"][0]["level"] == "warning"
    assert "startColumn" not in run["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert run["properties"]["uniqueVulnerabilities"] is None
    target = "<script>alert(1)</script>"
    report = {
        "custom": {
            "plan": {
                "target": target,
                "repository": target,
                "revision": "a" * 40,
                "inventory": [1],
                "repetitions": 1,
                "baseline_manifest_sha256": "c" * 64,
                "content_sha256": "d" * 64,
            },
            "baseline_report": {"rows": []},
            "rows": [row],
            "families": [],
            "evidence_manifest_sha256": "e" * 64,
        },
        "baseline_sarif": {"runs": []},
        "limitations": LIMITATIONS,
    }
    document = render(report).decode()
    assert "<script>" not in document and "&lt;script&gt;" in document
    assert "Content-Security-Policy" in document
    assert "No overall risk score" in document
    assert "annotation-not-ordinary-execution" in document
    # JSON persistence sorts mapping keys; rendering must not depend on insertion order.
    assert document == render(json.loads(json.dumps(report, sort_keys=True))).decode()


def test_only_two_formative_targets() -> None:
    assert set(TARGETS) == {"langgraph-cicd", "qdrant-mcp"}


@pytest.fixture
def embedded_projection(tmp_path: Path) -> dict[str, Any]:
    # Artificial bytes for contract tests only; not repository or research evidence.
    raw = b"eval(code)\n"
    inventory = []
    for i in range(26):
        path = f"authored{i:02d}.py"
        (tmp_path / path).write_bytes(raw)
        inventory.append(
            InventoryEntry(
                path=path,
                sha256=sha256_bytes(raw),
                byte_length=len(raw),
                media_type="text/x-python",
            )
        )
    request = AgentInputRequest(
        target_snapshot_id="a" * 64,
        inventory=inventory,
        selected={e.path: "python-source" for e in inventory},
    )
    repo, revision, _, _ = TARGETS["langgraph-cicd"]
    baseline = json.dumps({"rows": [], "repository": repo, "revision": revision})
    plan = RepositoryCustomPlan(
        target="langgraph-cicd",
        repository=repo,
        revision=revision,
        content_sha256="a" * 64,
        baseline_root=str(tmp_path / "baseline"),
        baseline_manifest_sha256="b" * 64,
        baseline_report_sha256=sha256_bytes(baseline.encode()),
        source_pins={"src/agentsec_evidence/__init__.py": "c" * 64},
        catalog_pins={f.key: f.catalog_sha256 for f in FAMILIES},
        inventory=inventory,
        requests=[request],
        repetitions=1,
        execution_root=str(tmp_path / "attempt"),
    )
    validate_plan(plan)
    rows = schedule(plan)
    summaries = []
    for row, family in zip(rows, FAMILIES, strict=True):
        if family.key == "tool-execution":
            native = scan_view(tmp_path, request.model_dump_json().encode())
            code = exit_status(native)
        else:
            module = importlib.import_module("agentsec_evidence.custom_rules." + family.worker)
            native = module.scan_view(tmp_path, request.model_dump_json().encode())
            code = expected_exit(native)
        raw_native = native.model_dump_json().encode() + b"\n"
        row.update(
            state="validated",
            native_state=native.execution_state,
            finding_records=sum(len(f.findings or []) for f in native.files),
            duration_ns=1,
            native_json=raw_native.decode(),
            native_sha256=sha256_bytes(raw_native),
            native_exit_code=code,
            native=native.model_dump(mode="json"),
        )
        summaries.append(
            {
                "family": family.key,
                "selected_files": 26,
                "analyzed_files": 26,
                "incomplete_files": 0,
                "condition_records": row["finding_records"],
                "inventory_records": sum(len(f.inventory) for f in native.files),
                "limitation_records": sum(len(f.limitations_observed) for f in native.files),
                "repeatability": "not-assessed",
                "semantic_sha256": [
                    semantic_hash([f.model_dump(mode="json") for f in native.files])
                ],
            }
        )
    return {
        "plan": plan.model_dump(mode="json"),
        "baseline_report_json": baseline,
        "baseline_report": {**json.loads(baseline), "retained_manifest_sha256": "b" * 64},
        "rows": rows,
        "families": summaries,
        "unique_vulnerabilities": None,
    }


def test_embedded_projection(embedded_projection: dict[str, Any]) -> None:
    validate_custom_projection(embedded_projection)


@pytest.mark.parametrize(
    "part", ["count", "baseline", "native", "request", "repeat", "hash", "inventory", "total"]
)
def test_embedded_projection_rejects_changes(
    embedded_projection: dict[str, Any], part: str
) -> None:
    value = copy.deepcopy(embedded_projection)
    if part == "count":
        value["families"][0]["condition_records"] = 0
    elif part == "baseline":
        value["baseline_report"]["rows"] = ["invented"]
    elif part == "native":
        value["rows"][0]["native"]["files"][0]["findings"] = []
    elif part == "request":
        value["plan"]["requests"][0]["selected"].pop("authored00.py")
    elif part == "repeat":
        value["rows"][0]["repetition"] = 2
    elif part == "hash":
        value["rows"][0]["native_sha256"] = "f" * 64
    elif part == "inventory":
        value["families"][0]["inventory_records"] = 999
    else:
        value["unique_vulnerabilities"] = 26
    with pytest.raises(ValueError):
        validate_custom_projection(value)
