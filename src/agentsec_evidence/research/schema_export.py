from pydantic import JsonValue

from agentsec_evidence.research.execution import ResearchExecutionAssessment
from agentsec_evidence.research.models import (
    SemgrepDualView,
    SemgrepPassEvidence,
    SemgrepResearchProfile,
    SemgrepResearchScope,
)
from agentsec_evidence.research.policy import SemgrepPolicyAssessment


def schema_documents() -> dict[str, dict[str, JsonValue]]:
    documents: dict[str, dict[str, JsonValue]] = {}
    for name, model in (
        ("candidate-profile", SemgrepResearchProfile),
        ("scope", SemgrepResearchScope),
        ("pass-evidence", SemgrepPassEvidence),
        ("dual-view", SemgrepDualView),
        ("policy-assessment", SemgrepPolicyAssessment),
        ("execution-assessment", ResearchExecutionAssessment),
    ):
        schema = model.model_json_schema(mode="serialization")
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schema["$id"] = f"urn:agentsec-evidence:schema:semgrep-research-v1:{name}"
        documents[f"{name}.schema.json"] = schema
    return documents
