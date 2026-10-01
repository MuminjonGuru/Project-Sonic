from pathlib import Path

from agentsec_evidence.agents.schema_export import schema_documents
from agentsec_evidence.core.io import json_bytes

root = Path(__file__).resolve().parents[1] / "schemas/agent-v1"
root.mkdir(parents=True, exist_ok=True)
for name, schema in schema_documents().items():
    (root / name).write_bytes(json_bytes(schema))
