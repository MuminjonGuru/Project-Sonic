from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, JsonValue

from agentsec_evidence.models.contracts import (
    BlobIndex,
    BundleManifest,
    CoverageRecord,
    ExecutionRecord,
    FailureRecord,
    Finding,
    InventoryEntry,
    ParserReport,
    RunEvent,
    RunRecord,
    Summary,
    TargetSnapshot,
    ValidationReport,
)

SCHEMA_BASE = "urn:agentsec-evidence:schema:v0.1.0"

SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "blob-index": BlobIndex,
    "bundle-manifest": BundleManifest,
    "coverage": CoverageRecord,
    "execution": ExecutionRecord,
    "failure": FailureRecord,
    "finding": Finding,
    "inventory-entry": InventoryEntry,
    "parser-report": ParserReport,
    "run-event": RunEvent,
    "run": RunRecord,
    "summary": Summary,
    "target-snapshot": TargetSnapshot,
    "validation-report": ValidationReport,
}


def schema_documents() -> dict[str, dict[str, JsonValue]]:
    documents: dict[str, dict[str, JsonValue]] = {}
    for name, model in SCHEMA_MODELS.items():
        schema = model.model_json_schema(mode="serialization")
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schema["$id"] = f"{SCHEMA_BASE}:{name}"
        documents[f"{name}.schema.json"] = schema
    return documents


def write_schemas(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for file_name, schema in schema_documents().items():
        content = json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        (destination / file_name).write_text(content, encoding="utf-8", newline="\n")
