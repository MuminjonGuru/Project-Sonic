import json
from pathlib import Path

from jsonschema import Draft202012Validator

from agentsec_evidence.intake.schema_export import schema_documents

ROOT = Path(__file__).resolve().parents[2]


def test_repository_input_schemas_are_separate_current_and_valid() -> None:
    directory = ROOT / "schemas/repository-input-v1"
    schemas = schema_documents()
    assert {p.name for p in directory.glob("*.json")} == set(schemas)
    for name, schema in schemas.items():
        Draft202012Validator.check_schema(schema)
        assert json.loads((directory / name).read_bytes()) == schema
