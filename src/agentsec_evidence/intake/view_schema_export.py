from pydantic import JsonValue

from agentsec_evidence.agents.view_validation import AgentViewAssessment
from agentsec_evidence.intake.views import ToolInputView


def schema_documents() -> dict[str, dict[str, JsonValue]]:
    documents: dict[str, dict[str, JsonValue]] = {}
    for name, model in (
        ("tool-input-view", ToolInputView),
        ("agent-view-assessment", AgentViewAssessment),
    ):
        schema = model.model_json_schema(mode="serialization")
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schema["$id"] = f"urn:agentsec-evidence:schema:repository-view-v1:{name}"
        documents[f"{name}.schema.json"] = schema
    return documents
