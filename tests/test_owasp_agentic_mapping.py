"""Authored mapping cases: classification integrity, not detector accuracy or human review."""

from __future__ import annotations

import copy
import importlib.util
import json
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from test_corpus_sarif import PROJECT
from test_corpus_sarif import authored as authored

from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.pilot.runner import save
from agentsec_evidence.research.retained import read_retained_research

spec = importlib.util.spec_from_file_location(
    "owasp_agentic_mapping", PROJECT / "tools/owasp_agentic_mapping.py"
)
assert spec is not None and spec.loader is not None
mapper = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mapper
spec.loader.exec_module(mapper)
reports = sys.modules["corpus_report_v2"]


@pytest.fixture
def registry() -> Any:
    return mapper.Registry.model_validate_json(mapper.DEFAULT_REGISTRY.read_bytes())


@pytest.fixture
def document(authored: Any, registry: Any) -> dict[str, Any]:
    report: dict[str, Any] = copy.deepcopy(authored[0])
    report.update(
        contract="corpus-core-report-v1",
        summary=[],
        limitations=[],
        execution_finished=True,
        error=None,
        full_inventory_files=2,
        attempt_duration_ns=12,
        optional_candidates=[],
    )
    for obs in report["observations"].values():
        if obs["kind"] == "custom":
            for file in obs["native"]["files"]:
                for record in file["inventory"]:
                    record["location"] = {"start_line": 1, "end_line": 1}
    for key in ("runs/r01/tool-execution/b000", "runs/r02/tool-execution/b000"):
        native = report["observations"][key]["native"]
        m = registry.mappings[0]
        native.update(
            producer=m.producer, version=m.producer_version, rules=[copy.deepcopy(m.native_rule)]
        )
        native["files"][0]["findings"][0]["rule"]["rule_id"] = m.rule_id
    template = report["observations"]["runs/r01/tool-execution/b000"]
    for m in registry.mappings[1:]:
        obs = copy.deepcopy(template)
        obs["native"].update(
            producer=m.producer, version=m.producer_version, rules=[copy.deepcopy(m.native_rule)]
        )
        obs["native"]["files"] = [obs["native"]["files"][0]]
        file = obs["native"]["files"][0]
        file["inventory"] = []
        if m.record_kind == "condition":
            file["findings"][0].pop("rule")
            file["findings"][0]["rule_id"] = m.rule_id
        else:
            file["findings"] = []
            file["inventory"] = [
                {"rule_id": m.rule_id, "location": {"start_line": 1}, "detail": "ordinary call"}
            ]
            obs["finding_records"] = 0
        key = f"runs/r01/{m.family}/b000"
        report["observations"][key] = obs
        report["rows"].append(
            {
                "key": key,
                "producer": m.family,
                "repetition": 1,
                "batch": 0,
                "state": "observed",
                "finding_records": obs["finding_records"],
                "reasons": [],
            }
        )
    native_rule = report["observations"]["runs/r01/agent-audit-python"]["findings"][0]["rule"]
    native_rule["mappings"] = [{"taxonomy": "OWASP", "value": "ASI01", "origin": "native-observed"}]
    return report


def seal(root: Path, files: dict[str, bytes]) -> str:
    root.mkdir()
    for name, raw in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    save(root / "evidence-manifest.json", reports.manifest_for(files))
    return sha256_bytes((root / "evidence-manifest.json").read_bytes())


@pytest.fixture
def inputs(tmp_path: Path, document: dict[str, Any]) -> dict[str, Any]:
    source = tmp_path / "source"
    sha = seal(source, reports.package(document))
    return {
        "report": source,
        "report_sha256": sha,
        "registry": mapper.DEFAULT_REGISTRY,
        "registry_sha256": sha256_bytes(mapper.DEFAULT_REGISTRY.read_bytes()),
        "output": tmp_path / "mapping",
    }


def test_relationships_do_not_become_coverage(document: Any, registry: Any) -> None:
    before = copy.deepcopy(document)
    files = mapper.project(document, registry, "6" * 64)
    result = json.loads(files["mapping.json"])
    assert document == before
    categories = {c["id"]: c for c in result["categories"]}
    assert categories["ASI05"]["first_repetition_condition_records"] == 1
    assert categories["ASI01"]["first_repetition_condition_records"] == 1
    assert categories["ASI07"]["first_repetition_condition_records"] == 0
    assert categories["ASI07"]["first_repetition_inventory_records"] == 1
    assert categories["ASI07"]["related_evidence"] == "inventory-only"
    assert {c["category_assessment"] for c in categories.values()} == {"not-assessed"}
    assert categories["ASI06"]["related_evidence"] == "no-related-records"
    assert result["scanner_invocations"] == 0 and result["human_acceptance"] is False
    unsupported = next(c for c in result["cells"] if c["state"] == "unsupported-size")
    assert unsupported["conditions"] is None and unsupported["mapped_conditions"] is None
    assert result["cells"][0]["mapped_conditions"] == 1
    assert json.loads(files["cells/0001.json"])["producer_context"]["analysis_state"] == "partial"


def test_native_tags_policy_and_ids_remain_opaque(document: Any, registry: Any) -> None:
    files = mapper.project(document, registry, "6" * 64)
    agent = json.loads(files["cells/0003.json"])["records"][0]
    assert agent["mapping"]["status"] == "unmapped"
    assert agent["native_taxonomy_tags_unreviewed"][0]["value"] == "ASI01"
    assert agent["native_policy"]["tier"] == "SUPPRESSED"
    assert agent["native_policy"]["suppressed"] is False
    assert agent["native_id"]["json_pointer"] == "/findings/0"
    assert len(agent["native_rule_sha256"]) == 64
    assert agent["native_priority"] == "high"
    sg = json.loads(files["cells/0002.json"])["records"][0]
    assert sg["native_policy"]["native_suppressions"][0]["status"] == "accepted"
    assert sg["mapping"]["status"] == "unmapped"
    cells = json.loads(files["mapping.json"])["cells"]
    assert cells[1]["inventory"] is None and cells[2]["inventory"] is None


@pytest.mark.parametrize("field", ["version", "producer", "rule"])
def test_binding_drift_is_unmapped_not_silently_accepted(
    document: Any, registry: Any, field: str
) -> None:
    native = document["observations"]["runs/r01/tool-execution/b000"]["native"]
    if field == "rule":
        native["rules"][0]["title"] = "Different semantics"
    else:
        native[field] = "different"
    files = mapper.project(document, registry, "6" * 64)
    record = json.loads(files["cells/0001.json"])["records"][0]
    assert record["mapping"]["reason"] == "producer-version-rule-or-kind-mismatch"
    if field == "producer":
        rules = json.loads(files["mapping.json"])["custom_rule_accounting"]
        variants = [r for r in rules if r["rule_id"] == "TOOL-EXEC-004"]
        assert len(variants) == 2
        assert {r["producer"] for r in variants} == {"different", "student-tool-execution"}


@pytest.mark.parametrize(
    "fault", ["edition", "category", "duplicate", "inventory", "deferred", "extra"]
)
def test_registry_refuses_bad_semantics(registry: Any, fault: str) -> None:
    value = registry.model_dump()
    if fault == "edition":
        value["taxonomy"]["edition"] = "2025"
    elif fault == "category":
        value["mappings"][0]["category"] = "LLM01"
    elif fault == "duplicate":
        value["mappings"].append(value["mappings"][0])
    elif fault == "inventory":
        value["mappings"][2]["relationship"] = "conditional-static-relevance"
    elif fault == "deferred":
        value["mappings"][0]["native_rule"]["status"] = "deferred"
    else:
        value["approved"] = True
    with pytest.raises(ValueError):
        mapper.Registry.model_validate(value)


@pytest.mark.parametrize(
    "fault", ["key", "count", "duplicate", "kind", "unknown-state", "unobserved-count"]
)
def test_inconsistent_execution_evidence_refused(document: Any, registry: Any, fault: str) -> None:
    if fault == "key":
        document["rows"][0]["repetition"] = 2
    elif fault == "count":
        document["rows"][0]["finding_records"] = 2
    elif fault == "duplicate":
        document["rows"].append(document["rows"][0])
    elif fault == "kind":
        document["observations"][document["rows"][0]["key"]]["kind"] = "semgrep"
    elif fault == "unknown-state":
        document["rows"][5]["state"] = "safe"
    else:
        document["rows"][5]["finding_records"] = 0
    with pytest.raises(ValueError):
        mapper.project(document, registry, "6" * 64)


def test_offline_write_verify_and_repeatable_bytes(inputs: Any, monkeypatch: Any) -> None:
    before = read_retained_research(inputs["report"]).files

    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("Mapping attempted execution or network access")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    result = mapper.execute("write", **inputs)
    assert result["passed"] and result["scanner_invocations"] == 0
    assert mapper.execute("verify", **inputs) == result
    with pytest.raises(ValueError, match="fresh"):
        mapper.execute("write", **inputs)
    other = {**inputs, "output": inputs["output"].with_name("mapping-second")}
    mapper.execute("write", **other)
    assert (
        read_retained_research(inputs["output"]).files
        == read_retained_research(other["output"]).files
    )
    assert read_retained_research(inputs["report"]).files == before


@pytest.mark.parametrize("field", ["report_sha256", "registry_sha256"])
def test_external_hash_required(inputs: Any, field: str) -> None:
    inputs[field] = "0" * 64
    with pytest.raises(ValueError, match="hash differs"):
        mapper.execute("write", **inputs)
    assert not inputs["output"].exists()


@pytest.mark.parametrize("fault", ["extra", "tamper", "resealed", "missing", "runtime"])
def test_output_corruption_refused(inputs: Any, fault: str) -> None:
    mapper.execute("write", **inputs)
    path = inputs["output"] / "mapping.json"
    if fault == "extra":
        (inputs["output"] / "extra.txt").write_text("extra")
    elif fault == "runtime":
        (inputs["output"] / "runtime").mkdir()
    elif fault == "missing":
        path.unlink()
    else:
        value = json.loads(path.read_bytes())
        value["categories"][0]["category_assessment"] = "passed"
        save(path, value)
        if fault == "resealed":
            files = {
                p.relative_to(inputs["output"]).as_posix(): p.read_bytes()
                for p in inputs["output"].rglob("*")
                if p.is_file() and p.name != "evidence-manifest.json"
            }
            save(inputs["output"] / "evidence-manifest.json", reports.manifest_for(files))
    with pytest.raises(ValueError):
        mapper.execute("verify", **inputs)


@pytest.mark.parametrize("fault", ["extra", "tamper", "wrong-contract"])
def test_input_corruption_refused(inputs: Any, fault: str) -> None:
    root = inputs["report"]
    if fault == "extra":
        (root / "extra.txt").write_text("extra")
    elif fault == "tamper":
        (root / "report.json").write_bytes(b"{}")
    else:
        files = read_retained_research(root).files
        value = json.loads(files["report.json"])
        value["contract"] = "common-report-v5"
        files["report.json"] = reports.encoded(value)
        (root / "report.json").write_bytes(files["report.json"])
        save(root / "evidence-manifest.json", reports.manifest_for(files))
        inputs["report_sha256"] = sha256_bytes((root / "evidence-manifest.json").read_bytes())
    with pytest.raises(ValueError):
        mapper.execute("write", **inputs)
    assert not inputs["output"].exists()


@pytest.mark.parametrize("where", ["source", "child", "ancestor", "project-source"])
def test_output_boundary(inputs: Any, where: str) -> None:
    outputs = {
        "source": inputs["report"],
        "child": inputs["report"] / "new",
        "ancestor": inputs["report"].parent,
        "project-source": PROJECT / "src/no-write",
    }
    inputs["output"] = outputs[where]
    with pytest.raises(ValueError, match=r"overlaps|Project output"):
        mapper.execute("write", **inputs)


@pytest.mark.parametrize(
    "field,value",
    [
        ("repository", "![tracking](https://example.invalid)"),
        ("repository", "valid/repo\n<script>"),
        ("revision", "not-pinned"),
        ("candidate_id", "R01\n[link](https://example.invalid)"),
        ("repository", None),
    ],
)
def test_markdown_identity_injection_refused(
    document: Any, registry: Any, field: str, value: Any
) -> None:
    document["candidate"][field] = value
    with pytest.raises(ValueError, match="repository identity"):
        mapper.project(document, registry, "6" * 64)
