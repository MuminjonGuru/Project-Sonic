"""Authored review/report contracts; no public source, scanner or target execution."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from agentsec_evidence.core.identity import canonical_json_bytes, sha256_bytes
from agentsec_evidence.pilot.runner import save

PROJECT = Path(__file__).resolve().parents[1]
type Authored = tuple[dict[str, Any], dict[str, Any], dict[str, Any], Path]
for name in ("corpus_report_v2", "corpus_review_sampling", "corpus_review_report"):
    spec = importlib.util.spec_from_file_location(name, PROJECT / "tools" / (name + ".py"))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
companion = sys.modules["corpus_review_report"]
sampling = sys.modules["corpus_review_sampling"]


def seal(root: Path, files: dict[str, bytes]) -> None:
    root.mkdir()
    entries = []
    for name, data in sorted(files.items()):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        entries.append({"path": name, "bytes": len(data), "sha256": sha256_bytes(data)})
    save(root / "checksums.json", {"files": entries})


@pytest.fixture
def authored(tmp_path: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], Path]:
    sources = tmp_path / "sources"
    content = b"# authored inert source\nexec(user_input)\n"
    selected = []
    for name in ("tool.py", "baseline.py", "agent.py"):
        path = sources / "R03/prepared/source" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        selected.append(
            {"source": {"path": name, "sha256": sha256_bytes(content)}, "path_role": "tests"}
        )
    custom = {
        "record_id": "authored-custom",
        "rule": {"rule_id": "TOOL-EXEC-001"},
        "location": {"start_line": 2, "end_line": 2},
    }
    baseline = {
        "anchor": {
            "path": "baseline.py",
            "rule_id": "authored-rule",
            "start_line": 2,
            "end_line": 2,
        },
        "json_pointer": "/results/0",
        "message": "Authored baseline claim",
    }
    native = {
        "tier": "SUPPRESSED",
        "confidence": 0.01,
        "suppressed": False,
        "suppressed_by": None,
        "suppressed_reason": None,
        "needs_review": False,
    }
    agent = {
        "locations": [{"artifact_path": "agent.py", "start_line": 2, "end_line": 2}],
        "evidence": [{"blob_sha256": "e" * 64, "json_pointer": "/findings/0"}],
        "rule": {"native_id": "AUTHORED-001"},
        "native_extension": {"agent_audit": native},
        "message": {"title": "<script>alert(1)</script>", "description": "Authored condition"},
    }
    observations = {
        "runs/r01/tool-execution/b000": {
            "kind": "custom",
            "native_sha256": "a" * 64,
            "native": {
                "rules": [{"rule_id": "TOOL-EXEC-001"}],
                "files": [
                    {
                        "path": "tool.py",
                        "source_sha256": sha256_bytes(content),
                        "findings": [custom],
                    }
                ],
            },
        },
        "runs/r01/semgrep-research": {
            "kind": "semgrep",
            "evidence": {"findings": [baseline], "native_json_sha256": "b" * 64},
        },
        "runs/r01/semgrep-policy": {
            "kind": "semgrep",
            "evidence": {
                "findings": [baseline],
                "native_json_sha256": "c" * 64,
                "files": [{"path": "baseline.py", "state": "reported", "native_reason": None}],
            },
        },
        "runs/r01/agent-audit-python": {"kind": "agent-audit", "findings": [agent]},
    }
    report = {
        "candidate": {
            "candidate_id": "R03",
            "repository": "authored/example",
            "revision": "1" * 40,
            "role": "authored-development",
        },
        "selected_inputs": selected,
        "observations": observations,
        "rows": [
            {
                "key": key,
                "producer": key.split("/")[2],
                "repetition": 1,
                "state": "observed",
                "finding_records": 1,
            }
            for key in observations
        ],
        "core_input_gates": [
            {"stage": "custom-seven", "state": "input-eligible", "reasons": []},
            {"stage": "agent-audit-python", "state": "input-eligible", "reasons": []},
        ],
    }
    population = sampling.records(report)
    queue = {
        "contract": "local-descriptive-review-queue-v1",
        "records": sampling.select(population),
    }
    rows = []
    for number, record in enumerate(queue["records"], 1):
        identity = record["identity"]
        path = identity["source_path"]
        rows.append(
            {
                "review_id": f"Q{number:02}",
                "frozen_record": copy.deepcopy(record),
                "proposal": {
                    "proposed_outcome": "supported-static-condition",
                    "contextual_relevance": "test-only",
                    "assessment": "Authored static condition, not a vulnerability.",
                    "observed_controls": "Authored test context.",
                    "uncertainty": "No runtime evidence.",
                    "suggested_action": "Review context.",
                    "supplementary_ranges": [],
                },
                "citations": [
                    {
                        "candidate_id": "R03",
                        "repository": "authored/example",
                        "revision": "1" * 40,
                        "path": path,
                        "source_sha256": sha256_bytes(content),
                        "start_line": 1,
                        "end_line": 2,
                        "excerpt": content.decode().rstrip("\n"),
                        "url": f"https://github.com/authored/example/blob/{'1' * 40}/{path}#L1-L2",
                    }
                ],
                "policy_context": {
                    **companion.policy_fields(record, report),
                    "interpretation": "Authored context.",
                },
                "overlap": {
                    "candidates": [],
                    "relation": "no-positional-candidate",
                    "rationale": "No overlapping authored input.",
                    "merge_applied": False,
                    "suppression_applied": False,
                },
                "review_status": "ai-proposed-student-review-pending",
                "authorship": companion.AUTHORSHIP,
                "human_decision": None,
                "independent_review": None,
                "external_context_ids": [],
            }
        )
    document = {
        "contract": "corpus-source-context-review-v1",
        "authorship": companion.AUTHORSHIP,
        "rows": rows,
        "metrics": {**companion.derive_counts(rows), "population_records": len(population)},
    }
    return document, queue, {"R03": report}, sources


def test_bind_preserves_policy_and_has_no_approval(authored: Authored) -> None:
    document, queue, reports, sources = authored
    before = copy.deepcopy(document)
    counts = companion.bind_reviews(document, queue, reports, sources)
    assert counts["review_proposals"] == 3
    assert counts["agent_audit_native_tiers"] == {"SUPPRESSED": 1}
    assert counts["student_accepted"] == 0 and counts["unique_vulnerabilities"] is None
    assert document == before


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "duplicate",
        "claim",
        "approval",
        "independent",
        "outcome",
        "source-hash",
        "excerpt",
        "range",
        "source-link",
        "source-traversal",
        "policy",
        "merge",
        "suppression",
        "overlap",
        "metrics",
        "queue",
    ],
)
def test_mutations_are_refused(authored: Authored, fault: str) -> None:
    document, queue, reports, sources = copy.deepcopy(authored)
    first = document["rows"][0]
    if fault == "missing":
        document["rows"].pop()
    elif fault == "duplicate":
        document["rows"][1] = copy.deepcopy(first)
    elif fault == "claim":
        first["frozen_record"]["claim_record"]["rule"]["title"] = "Changed claim"
    elif fault == "approval":
        first["human_decision"] = "accepted"
    elif fault == "independent":
        first["independent_review"] = "approved"
    elif fault == "outcome":
        first["proposal"]["proposed_outcome"] = "confirmed-vulnerability"
    elif fault == "source-hash":
        first["citations"][0]["source_sha256"] = "0" * 64
    elif fault == "excerpt":
        first["citations"][0]["excerpt"] = "invented source"
    elif fault == "range":
        first["citations"][0]["end_line"] = 99
    elif fault == "source-link":
        first["citations"][0]["url"] = "javascript:alert(1)"
    elif fault == "source-traversal":
        first["citations"][0]["path"] = "../outside.py"
    elif fault == "policy":
        document["rows"][2]["policy_context"]["tier"] = "BLOCK"
    elif fault == "merge":
        first["overlap"]["merge_applied"] = True
    elif fault == "suppression":
        first["overlap"]["suppression_applied"] = True
    elif fault == "overlap":
        first["overlap"]["candidates"] = [{"identity_sha256": "0" * 64}]
    elif fault == "metrics":
        document["metrics"]["precision"] = 1.0
    elif fault == "queue":
        queue["records"] = list(reversed(queue["records"]))
    with pytest.raises(ValueError):
        companion.bind_reviews(document, queue, reports, sources)


def test_changed_source_bytes_refused(authored: Authored) -> None:
    document, queue, reports, sources = authored
    (sources / "R03/prepared/source/tool.py").write_bytes(b"# changed\n")
    with pytest.raises(ValueError, match="source bytes"):
        companion.bind_reviews(document, queue, reports, sources)


def test_sampling_repeats_and_policy_do_not_add_cases(authored: Authored) -> None:
    _, queue, reports, _ = authored
    report = copy.deepcopy(reports["R03"])
    repeat = copy.deepcopy(report["rows"][0])
    repeat["repetition"] = 2
    report["rows"].append(repeat)
    assert sampling.select(sampling.records(report)) == queue["records"]


def test_rendering_is_escaped_and_does_not_upgrade_verdicts(authored: Authored) -> None:
    document, _, _, _ = authored
    row = copy.deepcopy(document["rows"][2])
    row["proposal"]["assessment"] = '<img src="https://bad.test/secret" onerror="alert(1)">'
    output = companion.detail(row).decode()
    assert "<script" not in output and "<img" not in output
    assert "&lt;script&gt;" in output and "&lt;img" in output
    assert "SUPPRESSED" in output and "explicit suppressed=False" in output
    assert "student review pending" in output and "No independent approval" in output
    assert "default-src &#x27;none&#x27;" not in output
    assert "default-src 'none'" in output


@pytest.fixture
def prepared(
    tmp_path: Path, authored: Authored, monkeypatch: pytest.MonkeyPatch
) -> dict[str, Path]:
    document, queue, reports, sources = copy.deepcopy(authored)
    reports_root = tmp_path / "reports"
    reports_root.mkdir()
    (reports_root / "R03").mkdir()
    save(
        reports_root / "R03/evidence-manifest.json",
        {"authored": "report reader isolated by fixture"},
    )
    for name in ("status", "results"):
        save(reports_root / f"{name}.json", {"authored": name})
        queue[f"source_{name}_sha256"] = sha256_bytes((reports_root / f"{name}.json").read_bytes())
    queue["source_manifests"] = {
        "R03": sha256_bytes((reports_root / "R03/evidence-manifest.json").read_bytes())
    }
    protocol = tmp_path / "protocol.md"
    protocol.write_text("Authored frozen protocol", encoding="utf-8")
    queue["protocol_sha256"] = sha256_bytes(protocol.read_bytes())
    population = sampling.records(reports["R03"])
    queue_files = {
        "queue.json": companion.encoded(queue),
        "population.json": companion.encoded({"records": population}),
        "README.md": b"Authored queue",
    }
    queue_root = tmp_path / "queue"
    seal(queue_root, queue_files)
    document["frozen_inputs"] = {
        "queue_sha256": sha256_bytes(queue_files["queue.json"]),
        "population_sha256": sha256_bytes(queue_files["population.json"]),
        "protocol_sha256": queue["protocol_sha256"],
    }
    review = tmp_path / "review"
    review_files = {name: b"Authored auxiliary text" for name in companion.REVIEW_FILES}
    review_files["reviews.json"] = companion.encoded(document)
    review_files["metrics.json"] = companion.encoded(document["metrics"])
    seal(review, review_files)
    monkeypatch.setattr(companion, "read_report", lambda path: copy.deepcopy(reports[path.name]))
    return dict(
        review=review,
        queue=queue_root,
        reports=reports_root,
        sources=sources,
        protocol=protocol,
        output=tmp_path / "companion",
    )


def test_write_verify_roundtrip_is_portable_and_deterministic(prepared: dict[str, Path]) -> None:
    before = {
        path: path.read_bytes()
        for name in ("review", "queue", "reports", "sources")
        for path in prepared[name].rglob("*")
        if path.is_file()
    }
    receipt = companion.execute("write", **prepared)
    assert receipt["passed"] and receipt["scanner_invocations"] == 0
    assert companion.execute("verify", **prepared) == receipt
    output = prepared["output"]
    assert (output / "inputs/reviews.json").read_bytes() == (
        prepared["review"] / "reviews.json"
    ).read_bytes()
    assert all(path.read_bytes() == data for path, data in before.items())
    with pytest.raises(ValueError, match="fresh companion"):
        companion.execute("write", **prepared)
    projection = json.loads((output / "report.json").read_bytes())
    assert projection["verification"]["human_approval"] == "not-recorded"
    assert projection["verification"]["native_replay"] == "not-performed"


@pytest.mark.parametrize(
    "fault",
    [
        "extra-input",
        "tampered-input",
        "extra-output",
        "tampered-output",
        "resealed-output",
        "overlap-output",
    ],
)
def test_package_and_path_failures(prepared: dict[str, Path], fault: str) -> None:
    if fault == "extra-input":
        (prepared["review"] / "extra.txt").write_text("extra")
    elif fault == "tampered-input":
        (prepared["review"] / "reviews.json").write_bytes(b"{}")
    elif fault == "overlap-output":
        prepared["output"] = prepared["review"] / "new-report"
    else:
        companion.execute("write", **prepared)
        path = prepared["output"] / ("extra.txt" if fault == "extra-output" else "reviews/Q01.html")
        path.write_text("changed")
        if fault == "resealed-output":
            files = {
                p.relative_to(prepared["output"]).as_posix(): p.read_bytes()
                for p in prepared["output"].rglob("*")
                if p.is_file() and p.name != "evidence-manifest.json"
            }
            save(prepared["output"] / "evidence-manifest.json", companion.manifest_for(files))
    with pytest.raises(ValueError):
        companion.execute(
            "write" if fault in {"extra-input", "tampered-input", "overlap-output"} else "verify",
            **prepared,
        )


def test_invalid_citation_boolean_coordinate(authored: Authored) -> None:
    document, queue, reports, sources = authored
    document["rows"][0]["citations"][0]["start_line"] = True
    with pytest.raises(ValueError):
        companion.bind_reviews(document, queue, reports, sources)


def test_identity_stays_bound_to_native_record(authored: Authored) -> None:
    document, queue, reports, sources = copy.deepcopy(authored)
    original = document["rows"][0]["frozen_record"]
    original["identity"]["native_record_identity"]["blob_sha256"] = "f" * 64
    original["identity_sha256"] = sha256_bytes(canonical_json_bytes(original["identity"]))
    with pytest.raises(ValueError, match="Original record"):
        companion.bind_reviews(document, queue, reports, sources)
