from pathlib import Path

from agentsec_evidence.core.io import atomic_write_bytes, json_bytes
from agentsec_evidence.research.schema_export import schema_documents

root = Path(__file__).resolve().parents[1] / "schemas/semgrep-research-v1"
for name, schema in schema_documents().items():
    atomic_write_bytes(root / name, json_bytes(schema))
