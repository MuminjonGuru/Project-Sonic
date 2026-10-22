"""Authored export tests, not public-corpus outcomes or target execution."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, cast

import pytest

from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.pilot.runner import save

PROJECT = Path(__file__).resolve().parents[1]
for name in ("corpus_report_v2", "corpus_review_sampling", "corpus_review_report", "corpus_sarif"):
    spec = importlib.util.spec_from_file_location(name, PROJECT / "tools" / (name + ".py"))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
exporter = sys.modules["corpus_sarif"]
P = "agentsecEvidence/"
SCHEMA_PATH = PROJECT / "schemas/vendor/oasis/sarif-schema-2.1.0.json"
SCHEMA = json.loads(SCHEMA_PATH.read_bytes())
type Authored = tuple[dict[str, Any], dict[str, Any]]


@pytest.fixture
def authored() -> Authored:
    span = {"start_line": 2, "end_line": 2, "start_utf8_byte_column": 4, "end_utf8_byte_column": 12}
    record = {
        "rule": {"rule_id": "TOOL-EXEC-001", "severity": "high"},
        "record_id": "r1",
        "location": span,
    }
    file = {
        "path": "space #/inert.py",
        "source_sha256": "a" * 64,
        "state": "analyzed",
        "reason": "Authored case",
        "findings": [record],
        "inventory": [{"kind": "ordinary-call"}],
        "limitations_observed": [{"kind": "unsupported-scope"}],
    }
    custom: dict[str, Any] = {
        "kind": "custom",
        "finding_records": 1,
        "native_sha256": "b" * 64,
        "native": {
            "producer": "authored-tool",
            "version": "1.1.0",
            "policy": "research-only-no-suppressions-applied",
            "execution_state": "partial",
            "rules": [{"rule_id": "TOOL-EXEC-001", "title": "Authored condition"}],
            "files": [
                file,
                {
                    **copy.deepcopy(file),
                    "path": "malformed.py",
                    "state": "parse-error",
                    "findings": None,
                },
            ],
        },
    }
    anchor = {
        "path": file["path"],
        "rule_id": "sg-001",
        "start_line": 2,
        "end_line": 2,
        "start_column": 5,
        "end_column": 13,
    }
    sg = {
        "kind": "semgrep",
        "finding_records": 1,
        "assessment": {"analysis_state": "partial-analysis"},
        "evidence": {
            "findings": [
                {
                    "anchor": anchor,
                    "message": "Authored baseline claim",
                    "json_pointer": "/results/0",
                    "sarif_pointer": "/runs/0/results/0",
                    "native_suppressions": [{"kind": "inSource", "status": "accepted"}],
                }
            ],
            "native_json_sha256": "c" * 64,
            "native_sarif_sha256": "d" * 64,
            "role": "research",
            "profile_sha256": "e" * 64,
            "files": [{"path": file["path"], "state": "reported", "native_reason": None}],
            "native_errors": [],
            "native_skipped_rules": ["not-run-rule"],
            "native_execution_successful": True,
        },
    }
    agent = {
        "kind": "agent-audit",
        "finding_records": 1,
        "analysis_completeness": "not-established",
        "native_sha256": "f" * 64,
        "native_scanned_files": 1,
        "per_file_completion": "not-observable",
        "findings": [
            {
                "producer": {"tool_version": "0.20.0"},
                "locations": [{"artifact_path": file["path"], "start_line": 2, "end_line": 2}],
                "evidence": [{"json_pointer": "/findings/0", "blob_sha256": "f" * 64}],
                "rule": {"native_id": "AA-001"},
                "message": {"title": "Authored agent claim"},
                "severity": {"native_label": "high"},
                "confidence": {"native_label": "0.2"},
                "native_extension": {
                    "agent_audit": {
                        "tier": "SUPPRESSED",
                        "suppressed": False,
                        "suppressed_by": None,
                        "suppressed_reason": None,
                        "needs_review": False,
                        "location": {
                            "start_line": 2,
                            "end_line": 2,
                            "start_column": 4,
                            "end_column": 12,
                            "snippet": "not copied",
                            "file_path": "/target/inert.py",
                        },
                    }
                },
            }
        ],
    }
    inventory = copy.deepcopy(custom)
    inventory["finding_records"] = 0
    inventory["native"]["rules"] = [
        {"rule_id": "ORG-001", "title": "Ordinary handoff", "status": "inventory-only"}
    ]
    for f in inventory["native"]["files"]:
        f["findings"] = [] if f["state"] == "analyzed" else None
    observations = {
        "runs/r01/tool-execution/b000": custom,
        "runs/r01/semgrep-research": sg,
        "runs/r01/agent-audit-python": agent,
        "runs/r01/orchestration/b000": inventory,
        "runs/r02/tool-execution/b000": copy.deepcopy(custom),
    }
    rows = [
        {
            "key": key,
            "producer": key.split("/")[2],
            "repetition": int(key.split("/")[1][1:]),
            "batch": 0 if key.endswith("b000") else None,
            "state": "observed",
            "finding_records": obs["finding_records"],
            "reasons": [],
        }
        for key, obs in observations.items()
    ]
    rows.append(
        {
            "key": "runs/r02/semgrep-policy",
            "producer": "semgrep-policy",
            "repetition": 2,
            "batch": None,
            "state": "unsupported-size",
            "finding_records": None,
            "reasons": ["input too large"],
        }
    )
    report = {
        "candidate": {
            "candidate_id": "R03",
            "repository": "authored/example",
            "revision": "1" * 40,
            "role": "authored-development",
        },
        "selected_inputs": [
            {"source": {"path": p, "sha256": "a" * 64}} for p in (file["path"], "malformed.py")
        ],
        "source_manifest_sha256": "2" * 64,
        "source_content_sha256": "3" * 64,
        "selection_sha256": "4" * 64,
        "rows": rows,
        "observations": observations,
    }
    identity = {
        "candidate_id": "R03",
        "revision": "1" * 40,
        "producer": "tool-execution",
        "source_path": file["path"],
        "rule_id": "TOOL-EXEC-001",
        "location": span,
        "native_record_identity": {"record_id": "r1", "blob_sha256": "b" * 64},
    }
    proposal = {
        "review_id": "Q01",
        "frozen_record": {
            "identity": identity,
            "evidence_key": rows[0]["key"],
            "identity_sha256": "5" * 64,
        },
        "review_status": "ai-proposed-student-review-pending",
        "human_decision": None,
        "independent_review": None,
        "authorship": "AI-drafted; student review pending",
        "proposal": {"proposed_outcome": "supported-static-condition"},
    }
    return report, {"rows": [proposal]}


def build(authored: Authored) -> tuple[dict[str, Any], dict[str, Any]]:
    report, projection = authored
    return cast(
        tuple[dict[str, Any], dict[str, Any]],
        exporter.build_repository(report, "6" * 64, exporter.review_index(projection)),
    )


def test_preserves_records_and_scope(authored: Authored) -> None:
    before = copy.deepcopy(authored)
    log, accounting = build(authored)
    exporter.validate_log(log, SCHEMA)
    assert authored == before
    assert len(log["runs"]) == 5
    assert accounting["exported_observations_all_repetitions_and_views"] == 4
    assert accounting["unique_vulnerabilities"] is None
    assert accounting["draft_review_ids"] == ["Q01"]
    assert accounting["cells"][0]["inventory_records_not_exported_as_results"] == 2
    assert accounting["cells"][0]["limitation_records_externalized"] == 2
    assert log["runs"][3]["results"] == []  # Inventory-only is not a detection result.
    assert accounting["cells"][-1]["exported_results"] is None
    assert log["properties"][P + "unobservedCells"][0]["state"] == "unsupported-size"
    assert log["runs"][0]["properties"][P + "coverage"]["analysis_state"] == "partial"
    for run in log["runs"]:
        assert "invocations" not in run
        for result in run["results"] or []:
            assert (result["kind"], result["level"]) == ("review", "none")
            assert set(result["locations"][0]["physicalLocation"]["region"]) == {
                "startLine",
                "endLine",
            }
            assert "suppressions" not in result


def test_native_policy_and_priority_remain_separate(authored: Authored) -> None:
    log, _ = build(authored)
    custom, sg, agent = [r["results"][0] for r in log["runs"][:3]]
    assert custom["properties"][P + "nativePriority"] == "high"
    assert sg["properties"][P + "nativePriority"] is None
    assert "version" not in log["runs"][1]["tool"]["driver"]
    assert sg["properties"][P + "nativePolicy"]["native_suppressions"][0]["status"] == "accepted"
    assert agent["properties"][P + "nativePolicy"]["tier"] == "SUPPRESSED"
    assert agent["properties"][P + "nativePolicy"]["suppressed"] is False
    assert agent["properties"][P + "nativeConfidence"] == "0.2"
    assert "snippet" not in agent["properties"][P + "nativeCoordinates"]
    assert (
        agent["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "space%20%23/inert.py"
    )


def test_reviews_do_not_propagate_to_repetitions(authored: Authored) -> None:
    log, _ = build(authored)
    first = log["runs"][0]["results"][0]
    repeated = log["runs"][4]["results"][0]
    assert first["properties"][P + "review"]["review_id"] == "Q01"
    assert repeated["properties"][P + "review"] is None
    assert first["partialFingerprints"] != repeated["partialFingerprints"]


@pytest.mark.parametrize("state", sorted(exporter.UNOBSERVED))
def test_unobserved_states_stay_null(authored: Authored, state: str) -> None:
    authored[0]["rows"][-1]["state"] = state
    log, _ = build(authored)
    exporter.validate_log(log, SCHEMA)
    assert log["properties"][P + "unobservedCells"][0]["exported_results"] is None
    assert log["properties"][P + "unobservedCells"][0]["state"] == state


@pytest.mark.parametrize(
    "fault",
    [
        "count",
        "foreign-path",
        "source-hash",
        "inactive-rule",
        "duplicate-cell",
        "duplicate-finding",
        "unknown-kind",
        "unknown-producer",
        "unknown-state",
        "unobserved-zero",
        "review-source",
        "approval",
        "independent",
        "zero-line",
        "boolean-line",
        "reverse-range",
    ],
)
def test_bad_inputs_are_refused(authored: Authored, fault: str) -> None:
    report, projection = authored
    custom = report["observations"][report["rows"][0]["key"]]
    file = custom["native"]["files"][0]
    record = file["findings"][0]
    if fault == "count":
        custom["finding_records"] = 99
    elif fault == "foreign-path":
        file["path"] = "../outside.py"
    elif fault == "source-hash":
        file["source_sha256"] = "9" * 64
    elif fault == "inactive-rule":
        custom["native"]["rules"][0]["status"] = "inventory-only"
    elif fault == "duplicate-cell":
        report["rows"].append(copy.deepcopy(report["rows"][0]))
    elif fault == "duplicate-finding":
        file["findings"].append(copy.deepcopy(record))
        custom["finding_records"] = report["rows"][0]["finding_records"] = 2
    elif fault == "unknown-kind":
        custom["kind"] = "invented"
    elif fault == "unknown-producer":
        report["rows"][0]["producer"] = "invented"
    elif fault == "unknown-state":
        report["rows"][-1]["state"] = "success"
    elif fault == "unobserved-zero":
        report["rows"][-1]["finding_records"] = 0
    elif fault == "review-source":
        projection["rows"][0]["frozen_record"]["identity"]["revision"] = "9" * 40
    elif fault == "approval":
        projection["rows"][0]["human_decision"] = "accepted"
    elif fault == "independent":
        projection["rows"][0]["independent_review"] = "approved"
    elif fault == "zero-line":
        record["location"]["start_line"] = 0
    elif fault == "boolean-line":
        record["location"]["start_line"] = True
    else:
        record["location"]["end_line"] = 1
    with pytest.raises(ValueError):
        build(authored)


@pytest.mark.parametrize(
    "fault", ["severity", "kind", "columns", "suppression", "index", "invocation", "null-state"]
)
def test_schema_is_not_the_only_gate(authored: Authored, fault: str) -> None:
    log, _ = build(authored)
    run = log["runs"][0]
    result = run["results"][0]
    if fault == "severity":
        result["level"] = "warning"
    elif fault == "kind":
        result["kind"] = "fail"
    elif fault == "columns":
        result["locations"][0]["physicalLocation"]["region"]["startColumn"] = 5
    elif fault == "suppression":
        result["suppressions"] = [{"kind": "external", "status": "accepted"}]
    elif fault == "index":
        run["tool"]["driver"]["rules"][0]["id"] = "another-rule"
    elif fault == "invocation":
        run["invocations"] = [{"executionSuccessful": True}]
    else:
        run["properties"][P + "executionState"] = "not-run"
    with pytest.raises(ValueError):
        exporter.validate_log(log, SCHEMA)


def setup_io(tmp_path: Path, authored: Authored, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    report, projection = authored
    for name in ("review", "queue", "reports", "sources"):
        (tmp_path / name).mkdir()
    (tmp_path / "reports/R03").mkdir()
    manifest = tmp_path / "reports/R03/evidence-manifest.json"
    manifest.write_bytes(b"authored manifest\n")
    projection.update(
        report_manifests={"R03": sha256_bytes(manifest.read_bytes())},
        review_source_sha256="7" * 64,
        protocol_sha256="8" * 64,
    )
    monkeypatch.setattr(
        exporter,
        "review_inputs",
        lambda *_: (projection, {"inputs/reviews.json": b'{"authored":true}\n'}),
    )
    monkeypatch.setattr(exporter, "read_report", lambda _: copy.deepcopy(report))
    return {
        **{k: tmp_path / k for k in ("review", "queue", "reports", "sources")},
        "protocol": tmp_path / "protocol.md",
        "schema": SCHEMA_PATH,
        "output": tmp_path / "out",
    }


def test_write_verify_roundtrip(
    authored: Authored, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = setup_io(tmp_path, authored, monkeypatch)
    result = exporter.execute("write", **args)
    assert result["passed"] and result["scanner_invocations"] == 0
    assert (args["output"] / "inputs/reviews.json").read_bytes() == b'{"authored":true}\n'
    assert exporter.execute("verify", **args) == result
    with pytest.raises(ValueError, match="fresh"):
        exporter.execute("write", **args)
    log = json.loads((args["output"] / "R03/results.sarif").read_bytes())
    log["runs"][0]["results"][0]["message"]["text"] = "Changed claim"
    save(args["output"] / "R03/results.sarif", log)
    members = {
        p.relative_to(args["output"]).as_posix(): p.read_bytes()
        for p in args["output"].rglob("*")
        if p.is_file() and p.name != "evidence-manifest.json"
    }
    save(args["output"] / "evidence-manifest.json", exporter.manifest_for(members))
    with pytest.raises(ValueError, match="projection"):
        exporter.execute("verify", **args)


@pytest.mark.parametrize("fault", ["schema", "overlap", "manifest", "missing-review"])
def test_package_boundaries(
    authored: Authored, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    args = setup_io(tmp_path, authored, monkeypatch)
    if fault == "schema":
        schema = tmp_path / "schema.json"
        schema.write_text("{}", encoding="utf-8")
        args["schema"] = schema
    elif fault == "overlap":
        args["output"] = args["reports"] / "new"
    elif fault == "manifest":
        (args["reports"] / "R03/evidence-manifest.json").write_bytes(b"changed")
    else:
        authored[1]["rows"][0]["frozen_record"]["evidence_key"] = "not-an-existing-cell"
    with pytest.raises(ValueError):
        exporter.execute("write", **args)
    assert not args["output"].exists()
