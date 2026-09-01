from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from agentsec_evidence.models.schema_export import schema_documents


def test_generated_schemas_are_current() -> None:
    schema_root = Path(__file__).resolve().parents[2] / "schemas" / "v0.1.0"
    documents = schema_documents()

    assert {path.name for path in schema_root.glob("*.json")} == set(documents)
    for file_name, expected in documents.items():
        actual = json.loads((schema_root / file_name).read_text(encoding="utf-8"))
        assert actual == expected


def test_all_generated_schemas_are_valid_draft_2020_12() -> None:
    for schema in schema_documents().values():
        Draft202012Validator.check_schema(schema)
