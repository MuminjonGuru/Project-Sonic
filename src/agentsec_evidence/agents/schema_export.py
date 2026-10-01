from __future__ import annotations

from pydantic import BaseModel, JsonValue

from agentsec_evidence.agents.models import AgentArtifact, AgentAssessment, AgentProperty

SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "artifact": AgentArtifact,
    "assessment": AgentAssessment,
    "property": AgentProperty,
}


def schema_documents() -> dict[str, dict[str, JsonValue]]:
    documents: dict[str, dict[str, JsonValue]] = {}
    for name, model in SCHEMA_MODELS.items():
        schema = model.model_json_schema(mode="serialization")
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schema["$id"] = f"urn:agentsec-evidence:schema:agent-v1:{name}"
        documents[f"{name}.schema.json"] = schema
    return documents
