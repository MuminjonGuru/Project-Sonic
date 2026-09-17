from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft7Validator
from referencing import Registry, Resource

from agentsec_evidence.dependencies.parsers import array_value, object_value, text_value


def validate_cyclonedx(data: bytes, schema_root: Path) -> None:
    resources = []
    schema = None
    for name in ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"):
        value = json.loads((schema_root / name).read_bytes())
        resources.append((value["$id"], Resource.from_contents(value)))
        if name == "bom-1.6.schema.json":
            schema = value
    registry = Registry().with_resources(resources)
    document = object_value(json.loads(data))
    assert schema is not None
    Draft7Validator(schema, registry=registry).validate(document)
    references: set[str] = set()
    components = list(array_value(document.get("components", [])))
    metadata = object_value(document.get("metadata", {}))
    if "component" in metadata:
        components.append(metadata["component"])
    while components:
        component = object_value(components.pop())
        reference = component.get("bom-ref")
        if reference is not None:
            reference = text_value(reference)
            if reference in references:
                raise ValueError("Duplicate CycloneDX bom-ref")
            references.add(reference)
        components.extend(array_value(component.get("components", [])))
    for item in array_value(document.get("dependencies", [])):
        edge = object_value(item)
        endpoints = [edge.get("ref"), *array_value(edge.get("dependsOn", []))]
        if any(endpoint not in references for endpoint in endpoints):
            raise ValueError("Dangling CycloneDX dependency reference")
