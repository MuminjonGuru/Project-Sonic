from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import TypeAdapter, ValidationError

from agentsec_evidence.agents.models import AgentArtifact, AgentAssessment, AgentProperty
from agentsec_evidence.agents.schema_export import schema_documents
from agentsec_evidence.core.io import model_bytes

ROOT = Path(__file__).resolve().parents[2]


def artifact_payload() -> dict[str, Any]:
    return {
        "target_snapshot_id": "snapshot-authored",
        "source": {
            "path": "agent.py",
            "sha256": "a" * 64,
            "byte_length": 20,
            "media_type": "text/x-python",
        },
        "kind": "python-source",
        "format_id": "python-3.13-source",
        "parse_state": "parsed",
        "reason": "Synthetic model-validation example, not scanner output",
    }


def assessment_payload() -> dict[str, Any]:
    return {
        "run_id": "run-authored",
        "execution_id": "execution-authored",
        "artifact": artifact_payload(),
        "property_id": "python.tool-argument-to-eval",
        "producer": {
            "tool_id": "synthetic-producer",
            "tool_version": "fixture",
            "adapter_id": "synthetic-contract-test",
            "adapter_version": "fixture",
        },
        "support": "supported",
        "state": "complete",
        "finding_count": 0,
        "native_exit_code": 0,
        "evidence": [
            {"origin": "native-observed", "blob_sha256": "b" * 64, "json_pointer": "/findings"}
        ],
        "reason": "Synthetic complete evidence; zero findings is not proof of safety",
    }


def test_agent_schemas_are_current_and_valid() -> None:
    documents = schema_documents()
    directory = ROOT / "schemas/agent-v1"
    assert {path.name for path in directory.glob("*.json")} == set(documents)
    for name, schema in documents.items():
        Draft202012Validator.check_schema(schema)
        assert json.loads((directory / name).read_bytes()) == schema


def test_complete_record_roundtrips_without_changing_existing_contracts() -> None:
    record = AgentAssessment.model_validate(assessment_payload())
    assert AgentAssessment.model_validate_json(model_bytes(record)) == record
    assert record.artifact.source.schema_version == "0.1.0"
    Draft202012Validator(schema_documents()["assessment.schema.json"]).validate(
        record.model_dump(mode="json")
    )


@pytest.mark.parametrize("state", ["not-run", "malformed", "unsupported", "failed"])
def test_unparsed_artifact_cannot_be_complete(state: str) -> None:
    payload = assessment_payload()
    payload["artifact"]["parse_state"] = state
    with pytest.raises(ValidationError, match="requires parsed input"):
        AgentAssessment.model_validate(payload)


@pytest.mark.parametrize("support", ["partial", "unsupported", "unknown"])
def test_incomplete_support_cannot_be_complete(support: str) -> None:
    payload = assessment_payload()
    payload["support"] = support
    with pytest.raises(ValidationError):
        AgentAssessment.model_validate(payload)


@pytest.mark.parametrize("state", ["not-run", "skipped", "unsupported", "unknown"])
def test_missing_analysis_is_null_not_zero(state: str) -> None:
    payload = assessment_payload()
    payload.update(state=state, limitations=["Not analyzed"])
    if state == "unsupported":
        payload["support"] = "unsupported"
    with pytest.raises(ValidationError, match="no finding count"):
        AgentAssessment.model_validate(payload)
    payload["finding_count"] = None
    payload["evidence"] = []
    assert AgentAssessment.model_validate(payload).finding_count is None


@pytest.mark.parametrize("state", ["complete", "partial", "failed"])
def test_counts_require_evidence(state: str) -> None:
    payload = assessment_payload()
    payload.update(state=state, finding_count=2, evidence=[], limitations=["Example limitation"])
    with pytest.raises(ValidationError, match="evidence"):
        AgentAssessment.model_validate(payload)


def test_partial_observations_are_retained_without_becoming_complete() -> None:
    payload = assessment_payload()
    payload.update(state="partial", finding_count=2, limitations=["One input could not be parsed"])
    assert AgentAssessment.model_validate(payload).finding_count == 2


@pytest.mark.parametrize(
    ("support", "state"), [("unsupported", "partial"), ("supported", "unsupported")]
)
def test_unsupported_states_and_capabilities_must_agree(support: str, state: str) -> None:
    payload = assessment_payload()
    payload.update(support=support, state=state, finding_count=None, limitations=["Not supported"])
    with pytest.raises(ValidationError, match="Unsupported"):
        AgentAssessment.model_validate(payload)


def test_complete_requires_count() -> None:
    payload = assessment_payload()
    payload["finding_count"] = None
    with pytest.raises(ValidationError, match="requires a count"):
        AgentAssessment.model_validate(payload)


@pytest.mark.parametrize("field", ["native_exit_code", "finding_count"])
def test_observations_require_execution_identity(field: str) -> None:
    payload = assessment_payload()
    payload.update(state="partial", execution_id=None, limitations=["Synthetic observation"])
    payload["native_exit_code"] = None
    payload["finding_count"] = None
    payload[field] = 0
    with pytest.raises(ValidationError, match="execution identifier"):
        AgentAssessment.model_validate(payload)


@pytest.mark.parametrize("count", [True, False, -1, "0", 1.2])
def test_finding_count_is_a_nonnegative_integer(count: object) -> None:
    payload = assessment_payload()
    payload["finding_count"] = count
    with pytest.raises(ValidationError):
        AgentAssessment.model_validate(payload)


@pytest.mark.parametrize("state", ["partial", "failed", "skipped", "unsupported", "unknown"])
def test_incomplete_analysis_requires_a_limitation(state: str) -> None:
    payload = assessment_payload()
    payload.update(state=state, finding_count=None, evidence=[])
    if state == "unsupported":
        payload["support"] = "unsupported"
    with pytest.raises(ValidationError, match="limitations"):
        AgentAssessment.model_validate(payload)


def test_exit_code_is_not_a_security_verdict() -> None:
    positive = assessment_payload()
    positive.update(finding_count=1, native_exit_code=1)
    assert AgentAssessment.model_validate(positive).state == "complete"
    malformed = assessment_payload()
    malformed["artifact"]["parse_state"] = "malformed"
    malformed.update(state="failed", finding_count=None, limitations=["Native parse warning"])
    assert AgentAssessment.model_validate(malformed).native_exit_code == 0


@pytest.mark.parametrize("path", ["../agent.py", "/agent.py", "C:/agent.py", "."])
def test_artifact_rejects_non_file_or_escaping_paths(path: str) -> None:
    payload = artifact_payload()
    payload["source"]["path"] = path
    with pytest.raises(ValidationError):
        AgentArtifact.model_validate(payload)


@pytest.mark.parametrize("state", ["parsed", "malformed"])
def test_parse_observation_requires_format(state: str) -> None:
    payload = artifact_payload()
    payload.update(format_id=None, parse_state=state)
    with pytest.raises(ValidationError, match="identified input format"):
        AgentArtifact.model_validate(payload)


def test_unknown_artifact_can_be_recorded_without_support_claims() -> None:
    payload = artifact_payload()
    payload.update(kind="other", format_id=None, parse_state="unsupported")
    assert AgentArtifact.model_validate(payload).format_id is None


def test_extra_fields_and_made_up_contracts_are_rejected() -> None:
    for changes in ({"safe": True}, {"contract": "agent-assessment-v2"}):
        with pytest.raises(ValidationError):
            AgentAssessment.model_validate({**assessment_payload(), **changes})


def test_property_registry_is_finite_and_serializable() -> None:
    records = TypeAdapter(list[AgentProperty]).validate_json(
        (ROOT / "configs/agent-artifacts/properties.json").read_bytes()
    )
    assert {record.property_id for record in records} == {
        "python.tool-argument-to-eval",
        "mcp.filesystem-root-declaration",
    }
    validator = Draft202012Validator(schema_documents()["property.schema.json"])
    for record in records:
        validator.validate(record.model_dump(mode="json"))
    assert records[1].candidate_native_rules == ["AGENT-029"]
    duplicate = records[1].model_dump()
    duplicate["candidate_native_rules"] = ["AGENT-029", "AGENT-029"]
    with pytest.raises(ValidationError, match="unique"):
        AgentProperty.model_validate(duplicate)
