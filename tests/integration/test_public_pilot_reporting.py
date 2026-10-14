from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import JsonValue

from agentsec_evidence.agents.inventory import (
    artifact_inventory_semantic_sha256,
    build_artifact_inventory,
)
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes, sha256_file
from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.intake.input_plan import ToolInputPlan
from agentsec_evidence.intake.snapshot import create_snapshot
from agentsec_evidence.models.contracts import Finding
from agentsec_evidence.pilot.inputs import PLAN_PATH
from agentsec_evidence.pilot.models import STAGES, PilotPlan
from agentsec_evidence.reporting import service
from agentsec_evidence.reporting.models import CommonReport, PublicPilotSource
from agentsec_evidence.reporting.pilot import load_pilot_source, validate_pilot_runs
from agentsec_evidence.research.models import SemgrepResearchScope
from agentsec_evidence.research.retained import read_retained_research
from agentsec_evidence.research.semgrep import build_dual_view, reconcile_semgrep_pass

ROOT = Path(__file__).resolve().parents[2]
HASH = "a" * 64


def synthetic_projection(tmp_path: Path) -> tuple[PublicPilotSource, dict[str, Any]]:
    """Authored read-model data, never a replacement for the real public admission/replay."""
    target = tmp_path / "authored"
    target.mkdir()
    (target / "agent.py").write_bytes(b"value = 1\n")
    (target / "README.md").write_bytes(b"Authored report-contract fixture\n")
    snapshot = create_snapshot(
        target,
        tmp_path / "snapshots",
        source_label="authored:report-contract",
        revision="0" * 40,
        source_kind="project-fixture",
    )
    inventory = build_artifact_inventory(snapshot.snapshot, snapshot.inventory)
    profile = (ROOT / "configs/research/semgrep-python-candidate-v1.json").read_bytes()
    plan = json.loads((ROOT / PLAN_PATH).read_bytes())
    plan.update(
        repository="https://example.invalid/authored-report-contract",
        revision="0" * 40,
        content_sha256=snapshot.snapshot.content_sha256,
        expected_files=2,
        python_paths=["agent.py"],
        approval="synthetic metadata only; no scanner admission",
    )
    selections = [
        {
            "path": entry.path,
            "source_sha256": entry.sha256,
            "disposition": "selected" if entry.path == "agent.py" else "excluded",
            "reason": "Authored read-model fixture",
        }
        for entry in sorted(snapshot.inventory, key=lambda e: e.path)
    ]
    plans = [
        ToolInputPlan.model_validate(
            {
                "target_snapshot_id": snapshot.snapshot.snapshot_id,
                "artifact_inventory_semantic_sha256": artifact_inventory_semantic_sha256(inventory),
                "git_verification_sha256": HASH,
                "tool_id": tool,
                "profile_id": "authored",
                "profile_sha256": sha256_bytes(profile),
                "selections": selections,
            }
        )
        for tool in ("semgrep", "agent-audit")
    ]
    scope = SemgrepResearchScope.model_validate(
        {
            "target_snapshot_id": snapshot.snapshot.snapshot_id,
            "selection_sha256": HASH,
            "profile_sha256": sha256_bytes(profile),
            "selected_files": [
                e.model_dump(mode="json") for e in snapshot.inventory if e.path == "agent.py"
            ],
            "policy_files": [],
        }
    )
    native = {
        "version": "1.174.0",
        "results": [],
        "errors": [],
        "skipped_rules": [],
        "paths": {"scanned": ["/src/agent.py"], "skipped": []},
    }
    native_sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {"name": "Semgrep OSS", "semanticVersion": "1.174.0", "rules": []}
                },
                "invocations": [{"executionSuccessful": True}],
                "results": [],
            }
        ],
    }
    rows, reps, bindings, runs = [], [], [], []
    references: set[str] = set()
    source_id = "public-pilot-" + semantic_hash({"manifest": HASH})[:32]
    for i in range(1, 4):
        pair = [
            reconcile_semgrep_pass(
                profile_bytes=profile,
                scope=scope,
                execution_id=f"example-{role}-{i}",
                role=role,
                native_json=json_bytes(cast(JsonValue, native)),
                native_sarif=json_bytes(cast(JsonValue, native_sarif)),
            )
            for role in ("research", "repository-policy")
        ]
        finding = Finding.model_validate(
            {
                "record_id": f"finding-{i}",
                "run_id": f"agent-{i}",
                "execution_id": f"exec-{i}",
                "target_snapshot_id": snapshot.snapshot.snapshot_id,
                "producer": {
                    "tool_id": "agent-audit",
                    "tool_version": "0.20.0",
                    "adapter_id": "authored",
                    "adapter_version": "1",
                },
                "rule": {"native_id": "AUTHORED-001"},
                "message": {"title": "Authored example"},
                "severity": {"normalized": "unknown", "mapping_id": "authored"},
                "confidence": {},
                "locations": [{"artifact_path": "agent.py", "start_line": 1}],
                "evidence": [
                    {
                        "origin": "native-observed",
                        "blob_sha256": HASH,
                        "json_pointer": "/findings/0",
                    }
                ],
                "assessment": {
                    "verification_state": "unreviewed",
                    "exposure_statement": "static-observable-condition",
                },
                "fingerprints": {"record_v1": HASH, "candidate_equivalence_v1": HASH},
            }
        )
        dep_stages = [
            {
                "stage": stage,
                "state": "complete",
                "observations": 1,
                "identified_unique_packages": 1,
                "eligible_reported_packages": 1,
                "reported_package_advisory_matches": 0,
                "reported_match_occurrences": 0,
                "eligible_package_advisory_matches": 0,
                "unsupported_observations": 0,
                "relationships": 0,
            }
            for stage in ("osv-direct", "syft", "osv-sbom")
        ]
        reps.append(
            {
                "repetition": i,
                "semgrep": build_dual_view(*pair).model_dump(mode="json"),
                "directory_skips": {"research": [], "repository-policy": []},
                "agent_run_id": f"agent-{i}",
                "agent_execution_id": f"exec-{i}",
                "agent_native_scanned_files": 1,
                "agent_findings": [finding.model_dump(mode="json")],
                "dependency": {
                    "run_id": f"dependency-{i}",
                    "state": "complete",
                    "scope_available": True,
                    "eligible_unique_packages": 1,
                    "separate_local_packages": 0,
                    "unsupported_scope_records": 0,
                    "ambiguous_projections": 0,
                    "database_sha256": plan["database_sha256"],
                    "stages": dep_stages,
                    "comparisons": [],
                    "timing_ns": {},
                    "limitations": ["Authored fixture"],
                },
            }
        )
        for stage in STAGES:
            path = f"repetition-{i}/{stage}/native.json"
            references.add(path)
            count = 1 if stage == "agent-audit" else None if stage == "syft" else 0
            rows.append(
                {
                    "repetition": i,
                    "stage": stage,
                    "state": "complete"
                    if stage in {"osv-direct", "syft", "osv-sbom"}
                    else "partial",
                    "finding_records": count,
                    "package_identities": 1
                    if stage in {"osv-direct", "syft", "osv-sbom"}
                    else None,
                    "unit": "package-identities"
                    if stage == "syft"
                    else "package-advisory-occurrences"
                    if stage.startswith("osv-")
                    else "native-rule-reports",
                    "duration_ns": 1,
                    "exit_code": 0,
                    "semantic_sha256": HASH,
                    "evidence": [path],
                    "reasons": ["Authored fixture"],
                }
            )
            if stage == "syft":
                continue
            run = {
                "tool": {"driver": {"name": "Authored example"}},
                "results": [
                    {
                        "ruleId": "AUTHORED-001",
                        "kind": "review",
                        "message": {"text": "Authored example"},
                        "partialFingerprints": {"authored/v1": HASH},
                    }
                ]
                if count
                else [],
                "invocations": [{"executionSuccessful": True}],
                "properties": {
                    "agentsecEvidence/sourceRunId": source_id,
                    "agentsecEvidence/sourceManifestSha256": HASH,
                    "agentsecEvidence/repetition": i,
                    "agentsecEvidence/pilotStage": stage,
                    "agentsecEvidence/evidenceRole": "formative-pilot-not-held-out",
                    "agentsecEvidence/revision": plan["revision"],
                    "agentsecEvidence/targetContentSha256": plan["content_sha256"],
                },
            }
            runs.append(run)
            bindings.append(
                {
                    "repetition": i,
                    "stage": stage,
                    "result_count": count,
                    "run_sha256": semantic_hash(cast(JsonValue, run)),
                }
            )
    source = PublicPilotSource.model_validate(
        {
            "run_id": source_id,
            "label": plan["repository"],
            "revision": plan["revision"],
            "target_content_sha256": plan["content_sha256"],
            "source_manifest_sha256": HASH,
            "summary": {
                "plan": plan,
                "inventory": inventory.model_dump(mode="json"),
                "input_plans": [p.model_dump(mode="json") for p in plans],
                "rows": rows,
                "repetitions": reps,
                "repeatability": dict.fromkeys(STAGES, True),
                "repetition_wall_ns": [10, 10, 10],
                "attempt_wall_ns": 35,
                "manual_recovery_actions_during_attempt": 0,
                "retained_coverage": [{"surface": f"authored-{i}"} for i in range(10)],
                "references": [{"path": p, "sha256": HASH} for p in sorted(references)],
                "sarif_bindings": bindings,
                "limitations": ["Authored read-model data, not public admission"],
            },
        }
    )
    return source, {"version": "2.1.0", "runs": runs}


@pytest.fixture
def projection(tmp_path: Path) -> tuple[PublicPilotSource, dict[str, Any]]:
    return synthetic_projection(tmp_path)


def test_public_read_model_keeps_views_units_and_repeats(
    projection: tuple[PublicPilotSource, dict[str, Any]],
) -> None:
    source, document = projection
    validate_pilot_runs(source, document["runs"])
    assert len(source.summary.rows) == 18
    assert len(document["runs"]) == 15
    assert source.summary.vulnerability_total is None
    assert all(
        r.agent_findings[0].assessment.verification_state == "unreviewed"
        for r in source.summary.repetitions
    )
    # Read-model metadata does not weaken the fixed executable admission contract.
    with pytest.raises(ValueError):
        PilotPlan.model_validate(source.summary.plan.model_dump(mode="json"))


@pytest.mark.parametrize(
    "mutation",
    [
        "version",
        "revision",
        "target",
        "inventory",
        "input-tools",
        "selection",
        "missing-row",
        "repeatability",
        "repetition",
        "missing-reference",
        "unsafe-reference",
        "duplicate-binding",
        "unit",
        "syft-finding",
        "finding-location",
        "finding-id",
        "review-state",
        "agent-count",
        "dependency-count",
        "dependency-database",
        "dependency-database-missing",
        "dependency-stage-missing",
        "dependency-stage-duplicate",
        "duplicate-agent-run",
        "duplicate-agent-execution",
        "duplicate-dependency-run",
        "duplicate-semgrep-execution",
        "timing",
        "total",
        "evidence-role",
        "source-state",
        "complete-coverage",
    ],
)
def test_public_summary_rejects_inconsistent_claims(
    projection: tuple[PublicPilotSource, dict[str, Any]], mutation: str
) -> None:
    source, _ = projection
    data = source.model_dump(mode="json")
    summary = data["summary"]
    if mutation == "version":
        data["kind"] = "semgrep-research"
    elif mutation == "revision":
        data["revision"] = "1" * 40
    elif mutation == "target":
        data["target_content_sha256"] = "b" * 64
    elif mutation == "inventory":
        summary["plan"]["expected_files"] += 1
    elif mutation == "input-tools":
        summary["input_plans"][1] = summary["input_plans"][0]
    elif mutation == "selection":
        summary["plan"]["python_paths"] = ["other.py"]
    elif mutation == "missing-row":
        summary["rows"].pop()
    elif mutation == "repeatability":
        summary["repeatability"]["agent-audit"] = False
    elif mutation == "repetition":
        summary["repetitions"][1]["repetition"] = 1
    elif mutation == "missing-reference":
        summary["references"].pop()
    elif mutation == "unsafe-reference":
        summary["references"][0]["path"] = "../escape"
    elif mutation == "duplicate-binding":
        summary["sarif_bindings"][1] = summary["sarif_bindings"][0]
    elif mutation == "unit":
        summary["rows"][0]["unit"] = "package-identities"
    elif mutation == "syft-finding":
        summary["rows"][4]["finding_records"] = 0
    elif mutation == "finding-location":
        summary["repetitions"][0]["agent_findings"][0]["locations"][0]["artifact_path"] = (
            "unselected.py"
        )
    elif mutation == "finding-id":
        summary["repetitions"][0]["agent_findings"] *= 2
    elif mutation == "review-state":
        summary["repetitions"][0]["agent_findings"][0]["assessment"]["verification_state"] = (
            "confirmed"
        )
    elif mutation == "agent-count":
        summary["rows"][2]["finding_records"] = 0
    elif mutation == "dependency-count":
        summary["rows"][3]["package_identities"] = 2
    elif mutation == "dependency-database":
        summary["repetitions"][0]["dependency"]["database_sha256"] = "b" * 64
    elif mutation == "dependency-database-missing":
        summary["repetitions"][0]["dependency"]["database_sha256"] = None
    elif mutation == "dependency-stage-missing":
        summary["repetitions"][0]["dependency"]["stages"].pop(0)
    elif mutation == "dependency-stage-duplicate":
        stages = summary["repetitions"][0]["dependency"]["stages"]
        stages.append(copy.deepcopy(stages[0]))
    elif mutation == "duplicate-agent-run":
        first, second = summary["repetitions"][:2]
        second["agent_run_id"] = first["agent_run_id"]
        for finding in second["agent_findings"]:
            finding["run_id"] = first["agent_run_id"]
    elif mutation == "duplicate-agent-execution":
        first, second = summary["repetitions"][:2]
        second["agent_execution_id"] = first["agent_execution_id"]
        for finding in second["agent_findings"]:
            finding["execution_id"] = first["agent_execution_id"]
    elif mutation == "duplicate-dependency-run":
        first, second = summary["repetitions"][:2]
        second["dependency"]["run_id"] = first["dependency"]["run_id"]
    elif mutation == "duplicate-semgrep-execution":
        first, second = summary["repetitions"][:2]
        second["semgrep"]["research"]["execution_id"] = first["semgrep"]["research"]["execution_id"]
    elif mutation == "timing":
        summary["attempt_wall_ns"] = 1
    elif mutation == "total":
        summary["vulnerability_total"] = 3
    elif mutation == "evidence-role":
        summary["evidence_role"] = "held-out"
    elif mutation == "source-state":
        data["state"] = "complete"
    elif mutation == "complete-coverage":
        summary["analysis_completeness"] = "complete"
    with pytest.raises(ValueError):
        PublicPilotSource.model_validate(data)


@pytest.mark.parametrize(
    "mutation", ["content", "omission", "order", "repeat", "stage", "role", "severity"]
)
def test_public_sarif_rejects_changed_projection(
    projection: tuple[PublicPilotSource, dict[str, Any]], mutation: str
) -> None:
    source, document = projection
    runs = copy.deepcopy(document["runs"])
    if mutation == "content":
        runs[2]["results"][0]["message"]["text"] = "Changed"
    elif mutation == "omission":
        runs.pop()
    elif mutation == "order":
        runs[0], runs[1] = runs[1], runs[0]
    elif mutation == "repeat":
        runs[0]["properties"]["agentsecEvidence/repetition"] = 2
    elif mutation == "stage":
        runs[0]["properties"]["agentsecEvidence/pilotStage"] = "syft"
    elif mutation == "role":
        runs[0]["properties"]["agentsecEvidence/evidenceRole"] = "held-out"
    elif mutation == "severity":
        runs[2]["results"][0]["level"] = "error"
    with pytest.raises(ValueError):
        validate_pilot_runs(source, runs)


def test_common_v4_roundtrip_and_legacy_version_rules(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    projection: tuple[PublicPilotSource, dict[str, Any]],
) -> None:
    source, document = projection
    bundle = tmp_path / "mock-source"
    bundle.mkdir()
    monkeypatch.setattr(service, "load_report_source", lambda *_: (source, document))
    output = tmp_path / "report"
    report = service.write_common_report(project_root=ROOT, bundles=[bundle], output=output)
    assert report.contract == "common-report-v4"
    assert service.validate_common_report(ROOT, output)["sarif_runs"] == 15
    for version in ("common-report-v1", "common-report-v2", "common-report-v3"):
        with pytest.raises(ValueError):
            CommonReport.model_validate({**report.model_dump(mode="json"), "contract": version})
    second = tmp_path / "copy-of-source"
    second.mkdir()
    with pytest.raises(ValueError, match="Duplicate source run"):
        service.write_common_report(
            project_root=ROOT, bundles=[bundle, second], output=tmp_path / "duplicate"
        )
    nested = bundle / "constituent"
    nested.mkdir()
    with pytest.raises(ValueError, match="nested constituents"):
        service.write_common_report(
            project_root=ROOT, bundles=[bundle, nested], output=tmp_path / "nested"
        )


def test_retained_pilot_allows_only_known_empty_scratch(tmp_path: Path) -> None:
    (tmp_path / "data.json").write_bytes(b"{}")
    manifest: dict[str, Any] = {
        "contract": "source-pilot-evidence-v1",
        "files": [{"path": "data.json", "bytes": 2, "sha256": sha256_file(tmp_path / "data.json")}],
    }
    (tmp_path / "evidence-manifest.json").write_bytes(json.dumps(manifest).encode())
    scratch = tmp_path / "repetition-1/dependencies/runtime/home"
    scratch.mkdir(parents=True)
    # The parent directories are not manifest entries for this minimal authored fixture.
    for parent in ("repetition-1", "repetition-1/dependencies"):
        (tmp_path / parent / "receipt.json").write_bytes(b"{}")
        manifest["files"].append(
            {"path": parent + "/receipt.json", "bytes": 2, "sha256": sha256_bytes(b"{}")}
        )
    (tmp_path / "evidence-manifest.json").write_bytes(json.dumps(manifest).encode())
    assert (
        len(read_retained_research(tmp_path, manifest_contract="source-pilot-evidence-v1").files)
        == 3
    )
    with pytest.raises(ValueError):
        read_retained_research(tmp_path)
    (scratch / "unlisted.txt").write_bytes(b"unexpected")
    with pytest.raises(ValueError, match="Unmanifested evidence file"):
        read_retained_research(tmp_path, manifest_contract="source-pilot-evidence-v1")


def test_public_loader_replays_before_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agentsec_evidence.pilot import validation
    from agentsec_evidence.reporting import pilot
    from agentsec_evidence.research.retained import RetainedResearch

    order: list[str] = []

    def stop(*_: Any) -> dict[str, Any]:
        order.append("replay")
        raise ValueError("unfinished pilot")

    monkeypatch.setattr(
        pilot, "read_retained_research", lambda *a, **k: RetainedResearch(tmp_path, HASH, {})
    )
    monkeypatch.setattr(validation, "validate_source_pilot", stop)
    monkeypatch.setattr(
        pilot, "_project_pilot", lambda *_: pytest.fail("Projection preceded replay")
    )
    with pytest.raises(ValueError, match="unfinished pilot"):
        load_pilot_source(ROOT, tmp_path)
    assert order == ["replay"]
