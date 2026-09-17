from __future__ import annotations

import json
import tomllib
from collections import defaultdict
from typing import Literal, cast

from packageurl import PackageURL
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version
from pydantic import JsonValue

from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.dependencies.models import (
    AdvisoryMatch,
    DependencyScope,
    PackageObservation,
    Relationship,
    StageEvidence,
)


def object_value(value: object) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return cast(dict[str, JsonValue], value)


def array_value(value: object) -> list[JsonValue]:
    if not isinstance(value, list):
        raise ValueError("Expected a JSON array")
    return cast(list[JsonValue], value)


def text_value(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("Expected a nonempty string")
    return value


def _observation(
    *,
    name: object,
    version: object,
    pointer: str,
    native_id: str,
    ecosystem: str | None = "PyPI",
    purl: object = None,
    qualifiers: dict[str, str] | None = None,
    context: dict[str, JsonValue] | None = None,
) -> PackageObservation:
    raw_name = text_value(name)
    raw_version = version if isinstance(version, str) and version else None
    normalized_name: str | None = None
    normalized_version: str | None = None
    status = "identified"
    limitations: list[str] = []
    try:
        normalized_name = str(canonicalize_name(raw_name, validate=True))
        normalized_version = str(Version(raw_version)) if raw_version else None
    except (ValueError, InvalidVersion):
        limitations.append("Name or exact version cannot be normalized under PyPI rules.")
    if normalized_name is None or normalized_version is None:
        status = "unresolved"
    if ecosystem != "PyPI":
        status = "unsupported"
        limitations.append("Ecosystem is outside the first PyPI treatment.")
    purl_text = purl if isinstance(purl, str) and purl else None
    source = dict(qualifiers or {})
    if purl_text:
        try:
            parsed = PackageURL.from_string(purl_text)
            source.update({"purl:" + k: v for k, v in (parsed.qualifiers or {}).items()})
            if parsed.namespace or parsed.subpath:
                status = "unsupported"
                limitations.append("Namespaced/subpath PyPI identity requires separate support.")
            if parsed.type != "pypi":
                status = "unsupported"
            elif (
                canonicalize_name(parsed.name) != normalized_name
                or not parsed.version
                or str(Version(parsed.version)) != normalized_version
            ):
                status = "conflicting"
                limitations.append("Package URL and component name/version disagree.")
        except ValueError:
            status = "conflicting"
            limitations.append("Invalid package URL.")
    return PackageObservation(
        native_pointer=pointer,
        native_id=native_id,
        native_name=raw_name,
        native_version=raw_version,
        name=normalized_name,
        version=normalized_version,
        ecosystem=ecosystem,
        purl=purl_text,
        source_qualifiers=source,
        status=cast("LiteralStatus", status),
        context=context or {},
        limitations=limitations,
    )


type LiteralStatus = Literal["identified", "unresolved", "unsupported", "conflicting"]


def parse_lockfile(data: bytes) -> tuple[StageEvidence, DependencyScope]:
    document = tomllib.loads(data.decode("utf-8"))
    if document.get("version") != 1:
        raise ValueError("Unsupported uv lockfile format version")
    packages = array_value(document.get("package", []))
    stage = StageEvidence(stage="lockfile", raw_sha256=sha256_bytes(data))
    eligible: set[tuple[str, str]] = set()
    local: set[tuple[str, str]] = set()
    sources: dict[tuple[str, str], set[str]] = defaultdict(set)
    unsupported: list[str] = []
    for index, value in enumerate(packages):
        package = object_value(value)
        source = object_value(package.get("source", {}))
        pointer = f"/package/{index}"
        record = _observation(
            name=package.get("name"),
            version=package.get("version"),
            pointer=pointer,
            native_id=pointer,
            qualifiers={k: str(v) for k, v in source.items()},
            context={k: v for k, v in package.items() if k not in {"name", "version", "source"}},
        )
        stage.observations.append(record)
        key = record.projection
        if key:
            sources[key].add(json.dumps(source, sort_keys=True))
        if key and source.get("registry") in {
            "https://pypi.org/simple",
            "https://pypi.org/simple/",
        }:
            eligible.add(key)
        elif key and any(k in source for k in ("editable", "virtual", "directory")):
            local.add(key)
        else:
            unsupported.append(pointer)
        dependency_groups: dict[str, tuple[str, JsonValue]] = {
            "runtime": ("dependencies", package.get("dependencies", []))
        }
        for field in ("dev-dependencies", "optional-dependencies"):
            for group, dependencies in object_value(package.get(field, {})).items():
                escaped = group.replace("~", "~0").replace("/", "~1")
                dependency_groups[f"{field}:{group}"] = (f"{field}/{escaped}", dependencies)
        for group, (native_path, dependencies) in dependency_groups.items():
            for edge_index, dependency in enumerate(array_value(dependencies)):
                edge = object_value(dependency)
                stage.relationships.append(
                    Relationship(
                        native_pointer=f"{pointer}/{native_path}/{edge_index}",
                        source_ref=pointer,
                        destination_ref=text_value(edge.get("name")),
                        kind="declared-dependency",
                        context={"group": group, "declaration": edge},
                    )
                )
    ambiguous = {key for key, variants in sources.items() if len(variants) > 1}
    stage.limitations.append("Declared relationships retain qualifiers; not an installed graph.")
    return stage, DependencyScope(
        input_sha256=stage.raw_sha256,
        eligible=sorted(eligible - ambiguous),
        separate_local=sorted(local),
        unsupported_pointers=unsupported,
        ambiguous_projections=sorted(ambiguous),
    )


def parse_syft(data: bytes) -> StageEvidence:
    document = object_value(json.loads(data))
    if object_value(document.get("schema")).get("version") != "16.1.10":
        raise ValueError("Unsupported Syft native schema")
    stage = StageEvidence(stage="syft", raw_sha256=sha256_bytes(data))
    for index, value in enumerate(array_value(document.get("artifacts"))):
        artifact = object_value(value)
        metadata = object_value(artifact.get("metadata", {}))
        qualifiers = {}
        if isinstance(metadata.get("index"), str):
            qualifiers["registry_or_local_index"] = text_value(metadata["index"])
        stage.observations.append(
            _observation(
                name=artifact.get("name"),
                version=artifact.get("version"),
                pointer=f"/artifacts/{index}",
                native_id=text_value(artifact.get("id")),
                ecosystem="PyPI" if artifact.get("type") == "python" else None,
                purl=artifact.get("purl"),
                qualifiers=qualifiers,
                context={
                    k: artifact[k] for k in ("locations", "foundBy", "metadata") if k in artifact
                },
            )
        )
    for index, value in enumerate(array_value(document.get("artifactRelationships", []))):
        edge = object_value(value)
        stage.relationships.append(
            Relationship(
                native_pointer=f"/artifactRelationships/{index}",
                source_ref=text_value(edge.get("parent")),
                destination_ref=text_value(edge.get("child")),
                kind=text_value(edge.get("type")),
                context=object_value(edge.get("metadata", {})),
            )
        )
    return stage


def parse_cyclonedx(data: bytes) -> StageEvidence:
    document = object_value(json.loads(data))
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.6":
        raise ValueError("Expected CycloneDX 1.6")
    stage = StageEvidence(stage="cyclonedx", raw_sha256=sha256_bytes(data))
    for index, value in enumerate(array_value(document.get("components", []))):
        component = object_value(value)
        if component.get("type") == "file":
            continue
        purl = component.get("purl")
        ecosystem = "PyPI" if isinstance(purl, str) and purl.startswith("pkg:pypi/") else None
        record = _observation(
            name=component.get("name"),
            version=component.get("version"),
            pointer=f"/components/{index}",
            native_id=text_value(component.get("bom-ref", f"component-{index}")),
            ecosystem=ecosystem,
            purl=purl,
            context={k: component[k] for k in ("properties", "evidence", "type") if k in component},
        )
        if not purl:
            record.limitations.append(
                "Missing purl: component presence does not prove matching identity."
            )
        stage.observations.append(record)
    for index, value in enumerate(array_value(document.get("dependencies", []))):
        edge = object_value(value)
        for target in array_value(edge.get("dependsOn", [])):
            stage.relationships.append(
                Relationship(
                    native_pointer=f"/dependencies/{index}",
                    source_ref=text_value(edge.get("ref")),
                    destination_ref=text_value(target),
                    kind="depends-on",
                )
            )
    stage.limitations.append("Source registry and dependency group semantics may be absent.")
    return stage


def parse_osv(
    data: bytes,
    *,
    stage_name: Literal["osv-direct", "osv-sbom"],
    exit_code: int,
    alias_groups: dict[str, tuple[str, ...]],
) -> StageEvidence:
    document = object_value(json.loads(data))
    stage = StageEvidence(stage=stage_name, raw_sha256=sha256_bytes(data))
    if exit_code == 128:
        stage.state = "unsupported"
    elif exit_code not in (0, 1):
        stage.state = "failed"
    for source_index, value in enumerate(array_value(document.get("results"))):
        result = object_value(value)
        for index, item in enumerate(array_value(result.get("packages"))):
            package_result = object_value(item)
            package = object_value(package_result.get("package"))
            pointer = f"/results/{source_index}/packages/{index}"
            record = _observation(
                name=package.get("name"),
                version=package.get("version"),
                ecosystem=str(package.get("ecosystem", "unknown")),
                pointer=pointer,
                native_id=pointer,
                context={
                    "source": result.get("source"),
                    "native_groups": package_result.get("groups"),
                },
            )
            stage.observations.append(record)
            groups: dict[tuple[str, ...], set[str]] = defaultdict(set)
            for advisory_value in array_value(package_result.get("vulnerabilities", [])):
                advisory = object_value(advisory_value)
                advisory_id = text_value(advisory.get("id"))
                if advisory_id not in alias_groups:
                    if stage.state == "complete":
                        stage.state = "partial"
                    stage.limitations.append(
                        f"Advisory absent from frozen alias index: {advisory_id}"
                    )
                aliases = alias_groups.get(advisory_id, (advisory_id,))
                groups[aliases].add(advisory_id)
            if record.projection:
                for aliases, original in groups.items():
                    cves = [item for item in aliases if item.startswith("CVE-")]
                    stage.matches.append(
                        AdvisoryMatch(
                            package_pointer=pointer,
                            name=record.projection[0],
                            version=record.projection[1],
                            canonical_advisory=min(cves or list(aliases)),
                            original_ids=sorted(original),
                            aliases=list(aliases),
                        )
                    )
    if (exit_code == 0 and stage.matches) or (exit_code == 1 and not stage.matches):
        stage.state = "partial"
        stage.limitations.append("Native exit and reported findings contradict each other.")
    if exit_code == 0 and not stage.observations:
        stage.state = "partial"
        stage.limitations.append("Successful all-package output contains no reported packages.")
    stage.limitations.extend(
        [
            "All-package output proves reporting, not per-package matching completion.",
            "OSV does not retain source-registry, marker, group or dependency-edge context here.",
        ]
    )
    return stage
