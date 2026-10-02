from pydantic import JsonValue

from agentsec_evidence.intake.git_verification import GitSourceVerification
from agentsec_evidence.intake.input_plan import ToolInputPlan


def schema_documents() -> dict[str, dict[str, JsonValue]]:
    documents: dict[str, dict[str, JsonValue]] = {}
    for name, model in (
        ("git-source-verification", GitSourceVerification),
        ("tool-input-plan", ToolInputPlan),
    ):
        schema = model.model_json_schema(mode="serialization")
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schema["$id"] = f"urn:agentsec-evidence:schema:repository-input-v1:{name}"
        documents[f"{name}.schema.json"] = schema
    return documents
