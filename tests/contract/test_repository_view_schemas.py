import json
from pathlib import Path

from jsonschema import Draft202012Validator

from agentsec_evidence.intake.view_schema_export import schema_documents

ROOT = Path(__file__).resolve().parents[2]


def test_view_schemas_are_separate_current_and_valid() -> None:
    directory = ROOT / "schemas/repository-view-v1"
    expected = schema_documents()
    assert {path.name for path in directory.glob("*.json")} == set(expected)
    for name, schema in expected.items():
        Draft202012Validator.check_schema(schema)
        assert json.loads((directory / name).read_bytes()) == schema
