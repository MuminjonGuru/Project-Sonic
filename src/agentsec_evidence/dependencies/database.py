from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass
from pathlib import Path

from pydantic import JsonValue

from agentsec_evidence.core.identity import sha256_bytes, sha256_file
from agentsec_evidence.dependencies.parsers import array_value, object_value, text_value


@dataclass(frozen=True)
class FrozenDatabase:
    path: Path
    sha256: str
    aliases: dict[str, tuple[str, ...]]
    entries: list[dict[str, JsonValue]]
    relevant_records: dict[str, bytes]


def inspect_database(path: Path, expected_sha256: str, names: set[str]) -> FrozenDatabase:
    if not path.is_file() or path.is_symlink() or sha256_file(path) != expected_sha256:
        raise ValueError("Missing or hash-mismatched frozen database; no download is attempted")
    # Union-find joins aliases transitively across records so connected CVE/GHSA/OSV IDs
    # form one advisory group instead of inflating the comparison's vulnerability count.
    parent: dict[str, str] = {}

    def root(value: str) -> str:
        parent.setdefault(value, value)
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    entries: list[dict[str, JsonValue]] = []
    records: dict[str, bytes] = {}
    seen: set[str] = set()
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > 200_000 or sum(item.file_size for item in members) > 2 * 1024**3:
            raise ValueError("Database archive exceeds declared metadata limits")
        for member in members:
            if member.is_dir():
                continue
            if member.file_size > 8 * 1024**2 or member.filename in seen:
                raise ValueError("Oversized or duplicate database entry")
            seen.add(member.filename)
            data = archive.read(member)
            entries.append(
                {"path": member.filename, "sha256": sha256_bytes(data), "bytes": len(data)}
            )
            document = object_value(json.loads(data))
            identifier = text_value(document.get("id"))
            group = [
                identifier,
                *(text_value(item) for item in array_value(document.get("aliases", []))),
            ]
            for alias in group:
                left, right = root(identifier), root(alias)
                parent[max(left, right)] = min(left, right)
            if any(
                object_value(object_value(item).get("package")).get("name") in names
                for item in array_value(document.get("affected", []))
            ):
                records[identifier] = data
    groups: dict[str, list[str]] = {}
    for identifier in parent:
        groups.setdefault(root(identifier), []).append(identifier)
    aliases = {identifier: tuple(sorted(groups[root(identifier)])) for identifier in parent}
    return FrozenDatabase(path.resolve(), expected_sha256, aliases, entries, records)
