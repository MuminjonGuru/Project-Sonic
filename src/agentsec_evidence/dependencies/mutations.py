from __future__ import annotations

import json
from typing import Literal

from packageurl import PackageURL

from agentsec_evidence.core.io import json_bytes
from agentsec_evidence.dependencies.parsers import array_value, object_value, text_value

type Mutation = Literal["remove-component", "remove-purl", "change-version"]


def mutate_sbom(
    data: bytes,
    mutation: Mutation,
    *,
    name: str = "requests",
    version: str = "2.31.0",
) -> bytes:
    document = object_value(json.loads(data))
    components = array_value(document.get("components"))
    selected = [
        object_value(item)
        for item in components
        if object_value(item).get("name") == name and object_value(item).get("version") == version
    ]
    if len(selected) != 1:
        raise ValueError("Mutation requires exactly one selected component")
    component = selected[0]
    old_reference = text_value(component.get("bom-ref"))
    dependencies = array_value(document.get("dependencies", []))
    if mutation == "remove-component":
        document["components"] = [item for item in components if item is not component]
        document["dependencies"] = [
            item for item in dependencies if object_value(item).get("ref") != old_reference
        ]
        for item in array_value(document["dependencies"]):
            edge = object_value(item)
            edge["dependsOn"] = [
                ref for ref in array_value(edge.get("dependsOn", [])) if ref != old_reference
            ]
    elif mutation == "remove-purl":
        if "purl" not in component:
            raise ValueError("Selected component already has no purl")
        del component["purl"]
    elif mutation == "change-version":
        new_version = "2.32.5"
        parsed = PackageURL.from_string(text_value(component.get("purl")))
        component["version"] = new_version
        component["purl"] = parsed._replace(version=new_version).to_string()
        new_reference = "sonic-mutation:requests-2.32.5"
        component["bom-ref"] = new_reference
        # CPEs are an alternative version-bearing identity; remove them instead of leaving a lie.
        component.pop("cpe", None)
        component["properties"] = [
            item
            for item in array_value(component.get("properties", []))
            if object_value(item).get("name") != "syft:cpe23"
        ]
        for item in dependencies:
            edge = object_value(item)
            if edge.get("ref") == old_reference:
                edge["ref"] = new_reference
            edge["dependsOn"] = [
                new_reference if ref == old_reference else ref
                for ref in array_value(edge.get("dependsOn", []))
            ]
    else:
        raise ValueError("Unsupported mutation")
    return json_bytes(document)
