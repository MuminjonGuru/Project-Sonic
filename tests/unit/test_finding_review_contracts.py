from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from agentsec_evidence.core.identity import semantic_hash
from agentsec_evidence.models.contracts import Finding
from agentsec_evidence.reviews.models import (
    ReviewAnnotation,
    ReviewBatch,
    ReviewManifest,
    ReviewSidecar,
    annotation_sha256,
)

ROOT = Path(__file__).resolve().parents[2]
HASH = "a" * 64


@pytest.fixture
def annotation_data() -> dict[str, Any]:
    finding = Finding.model_validate(
        {
            "record_id": "finding-1",
            "run_id": "agent-1",
            "execution_id": "exec-1",
            "target_snapshot_id": "snapshot_" + HASH,
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
                {"origin": "native-observed", "blob_sha256": HASH, "json_pointer": "/findings/0"}
            ],
            "assessment": {
                "verification_state": "unreviewed",
                "exposure_statement": "static-observable-condition",
            },
            "fingerprints": {"record_v1": HASH, "candidate_equivalence_v1": HASH},
            "native_extension": {"suppressed": False, "tier": "SUPPRESSED"},
        }
    ).model_dump(mode="json")
    return {
        "review_id": "authored-1",
        "subject": {
            "source_run_id": "authored",
            "source_manifest_sha256": HASH,
            "finding_sha256": semantic_hash(finding),
            "finding_snapshot": finding,
        },
        "reviewer": {
            "identity": "Authored test proposal",
            "role": "ai-assistant",
            "authorship": "ai-drafted",
        },
        "created_at": "2026-10-13T00:00:00Z",
        "decision": "proposed",
        "conclusion": "claim-not-substantiated",
        "observed_condition": "Authored test context.",
        "rationale": "No source-controlled input in this authored example.",
        "uncertainty": "No runtime test; not a real adjudication.",
        "contexts": [{"artifact_path": "agent.py", "source_sha256": HASH, "start_line": 1}],
    }


def human_change(data: dict[str, Any], decision: str = "accepted") -> dict[str, Any]:
    changed = copy.deepcopy(data)
    changed.update(
        reviewer={"identity": "Authored reviewer", "role": "student", "authorship": "ai-assisted"},
        created_at="2026-10-13T00:01:00Z",
        decision=decision,
        supersedes_sha256=annotation_sha256(ReviewAnnotation.model_validate(data)),
    )
    return changed


def test_proposals_preserve_native_fields(annotation_data: dict[str, Any]) -> None:
    annotation = ReviewAnnotation.model_validate(annotation_data)
    assert annotation.measured_review_duration_ns is None
    assert annotation.subject.finding_snapshot.assessment.verification_state == "unreviewed"
    assert annotation.subject.finding_snapshot.native_extension == {
        "suppressed": False,
        "tier": "SUPPRESSED",
    }
    sidecar = ReviewSidecar(report_manifest_sha256=HASH, annotations=(annotation,))
    assert sidecar.vulnerability_total is None
    assert sidecar.reviewer_identity_assurance == "declared-not-authenticated"


@pytest.mark.parametrize(
    "mutation",
    [
        "ai-accept",
        "authorship",
        "snapshot",
        "blank",
        "naive-date",
        "path",
        "range",
        "end-only",
        "negative-time",
        "boolean-time",
        "runtime-claim",
        "unresolved-conclusion",
        "extra-field",
    ],
)
def test_annotation_rejects_invalid_claims(annotation_data: dict[str, Any], mutation: str) -> None:
    data = copy.deepcopy(annotation_data)
    if mutation == "ai-accept":
        data["decision"] = "accepted"
    elif mutation == "authorship":
        data["reviewer"]["authorship"] = "human-authored"
    elif mutation == "snapshot":
        data["subject"]["finding_snapshot"]["native_extension"]["suppressed"] = True
    elif mutation == "blank":
        data["uncertainty"] = "  "
    elif mutation == "naive-date":
        data["created_at"] = "2026-10-13T00:00:00"
    elif mutation == "path":
        data["contexts"][0]["artifact_path"] = "../agent.py"
    elif mutation == "range":
        data["contexts"][0].update(start_line=4, end_line=2)
    elif mutation == "end-only":
        data["contexts"][0].update(start_line=None, end_line=2)
    elif mutation == "negative-time":
        data["measured_review_duration_ns"] = -1
    elif mutation == "boolean-time":
        data["measured_review_duration_ns"] = True
    elif mutation == "runtime-claim":
        data["runtime_exploitability"] = "confirmed"
    elif mutation == "unresolved-conclusion":
        data = human_change(data, "unresolved")
    else:
        data["precision"] = 1.0
    with pytest.raises(ValueError):
        ReviewAnnotation.model_validate(data)


@pytest.mark.parametrize("decision", ["accepted", "changed", "unresolved"])
def test_human_history_is_separate_from_native(
    annotation_data: dict[str, Any], decision: str
) -> None:
    data = human_change(annotation_data, decision)
    if decision != "accepted":
        data["conclusion"] = "unresolved"
    sidecar = ReviewSidecar.model_validate(
        {
            "report_manifest_sha256": HASH,
            "annotations": [annotation_data, data],
        }
    )
    assert len(sidecar.annotations) == 2
    assert sidecar.annotations[0].subject == sidecar.annotations[1].subject
    assert (
        sidecar.annotations[1].subject.finding_snapshot.assessment.verification_state
        == "unreviewed"
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "first-human",
        "wrong-supersedes",
        "changed-subject",
        "earlier-date",
        "changed-accept",
        "duplicate-subject",
        "proposal-after-human",
        "wrong-prefix",
        "missing-prefix",
        "empty-revision",
    ],
)
def test_history_rejects_silent_replacement(annotation_data: dict[str, Any], mutation: str) -> None:
    first = copy.deepcopy(annotation_data)
    second = human_change(first)
    data: dict[str, Any] = {"report_manifest_sha256": HASH, "annotations": [first, second]}
    if mutation == "first-human":
        data["annotations"] = [second]
    elif mutation == "wrong-supersedes":
        second["supersedes_sha256"] = "b" * 64
    elif mutation == "changed-subject":
        second["subject"]["source_run_id"] = "different"
    elif mutation == "earlier-date":
        second["created_at"] = "2026-10-12T00:00:00Z"
    elif mutation == "changed-accept":
        second["conclusion"] = "condition-supported"
    elif mutation == "duplicate-subject":
        second = copy.deepcopy(first)
        second["review_id"] = "another-name"
        data["annotations"] = [first, second]
    elif mutation == "proposal-after-human":
        third = copy.deepcopy(first)
        third.update(
            created_at="2026-10-13T00:02:00Z",
            supersedes_sha256=annotation_sha256(ReviewAnnotation.model_validate(second)),
        )
        data["annotations"].append(third)
    elif mutation == "wrong-prefix":
        data["previous_annotation_count"] = 1
    elif mutation == "missing-prefix":
        data["previous_review_sha256"] = HASH
    else:
        data.update(previous_review_sha256=HASH, previous_annotation_count=2)
    with pytest.raises(ValueError):
        ReviewSidecar.model_validate(data)


@pytest.mark.parametrize(
    "name,model",
    [
        ("review-batch", ReviewBatch),
        ("review-sidecar", ReviewSidecar),
        ("review-manifest", ReviewManifest),
    ],
)
def test_review_schemas_match_models(
    name: str, model: type[ReviewBatch | ReviewSidecar | ReviewManifest]
) -> None:
    schema = json.loads((ROOT / "schemas/review-v1" / f"{name}.schema.json").read_bytes())
    assert schema == model.model_json_schema()
    Draft202012Validator.check_schema(schema)
