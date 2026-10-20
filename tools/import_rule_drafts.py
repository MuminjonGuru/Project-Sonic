"""Extract byte-pinned Markdown spans as inert review data, never as loaded Python."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

LIMIT = 256 * 1024
ID_PATTERN = re.compile(r"""["']id["']\s*:\s*["']([A-Z][A-Z0-9-]*-\d+)["']""")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_plain(path: Path) -> bytes:
    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise ValueError(f"Not a regular unlinked file: {path.name}")
    with path.open("rb") as stream:
        data = stream.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError(f"File exceeds import limit: {path.name}")
    data.decode("utf-8")
    return data


def leaf(value: str) -> str:
    if not value or not re.fullmatch(r"[A-Za-z0-9_.-]+", value) or value in {".", ".."}:
        raise ValueError("Expected a plain leaf filename")
    return value


def text_inventory(data: bytes) -> dict[str, Any]:
    """Lexical inspection only: these are not parsed or reachable detector counts."""
    text = data.decode("utf-8")
    ids = ID_PATTERN.findall(text)
    functions = Counter(re.findall(r"^def ([A-Za-z_]\w*)\(", text, re.MULTILINE))
    categories: list[str] = []
    in_category = False
    for line in text.splitlines():
        if line == "class Category(Enum):":
            in_category = True
        elif in_category and line and not line[0].isspace():
            in_category = False
        elif in_category:
            member = re.match(r"\s+([A-Z][A-Z0-9_]*)\s*=", line)
            if member:
                categories.append(member[1])
    return {
        "method": "lexical inspection; not syntax validation or active-rule coverage",
        "lines": len(text.splitlines()),
        "nonbreaking_spaces": text.count("\u00a0"),
        "literal_id_entries": ids,
        "unique_literal_id_count": len(set(ids)),
        "category_members": categories,
        "duplicate_function_definitions": {
            name: count for name, count in sorted(functions.items()) if count > 1
        },
        "misspelled_future_import": "from _future_ import" in text,
        "misspelled_main_guard": 'if _name_ == "_main_"' in text,
    }


def prepare(plan_path: Path, source: Path) -> tuple[dict[str, bytes], dict[str, Any]]:
    plan_bytes = read_plain(plan_path)
    plan = json.loads(plan_bytes)
    if plan["contract"] != "rule-draft-extraction-plan-v1":
        raise ValueError("Unsupported extraction plan")
    if source.is_symlink() or source.is_junction() or not source.is_dir():
        raise ValueError("Source must be an unlinked directory")
    payloads: dict[str, bytes] = {}
    records = []
    seen_sources: set[str] = set()
    for document in plan["documents"]:
        name = leaf(document["source"])
        if name.casefold() in seen_sources:
            raise ValueError("Duplicate source")
        seen_sources.add(name.casefold())
        raw = read_plain(source / name)
        if digest(raw) != document["sha256"]:
            raise ValueError(f"Source digest mismatch: {name}")
        # Byte-based slices retain original line endings and all code characters.
        lines = raw.splitlines(keepends=True)
        for output in document["outputs"]:
            filename = leaf(output["file"])
            if not filename.endswith((".py.txt", ".yaml.txt")):
                raise ValueError("Only inert source payload extensions are permitted")
            if filename.casefold() in {item.casefold() for item in payloads}:
                raise ValueError("Duplicate output")
            parts: list[bytes] = []
            previous_end = 0
            spans = []
            for start, end in output["ranges"]:
                if (
                    type(start) is not int
                    or type(end) is not int
                    or not previous_end < start <= end <= len(lines)
                ):
                    raise ValueError(f"Invalid or overlapping line span: {name}")
                part = b"".join(lines[start - 1 : end])
                if any(line.strip().startswith(b"```") for line in part.splitlines()):
                    raise ValueError(f"Markdown fence in selected source: {name}")
                if parts and not parts[-1].endswith(b"\n"):
                    raise ValueError("Cannot join parts without inserting source bytes")
                spans.append({"first_line": start, "last_line": end, "sha256": digest(part)})
                parts.append(part)
                previous_end = end
            if not parts:
                raise ValueError("Empty extraction")
            data = b"".join(parts)
            payloads[filename] = data
            records.append(
                {
                    "file": filename,
                    "source_document": name,
                    "source_sha256": digest(raw),
                    "source_ranges": spans,
                    "bytes": len(data),
                    "sha256": digest(data),
                    "inspection": text_inventory(data),
                }
            )
    manifest = {
        "contract": "rule-draft-extraction-v1",
        "status": "inactive-unvalidated-submission",
        "plan_sha256": digest(plan_bytes),
        "importer_sha256": digest(read_plain(Path(__file__))),
        "transformation": "Concatenate selected original line spans; no source fixes or execution.",
        "provenance": {
            "authorship": "Original code, as declared by the student on 2026-10-20.",
            "independently_verified": False,
            "license": "Not assigned by this import.",
        },
        "scanner_execution": False,
        "records": records,
    }
    return payloads, manifest


def materialize(plan: Path, source: Path, destination: Path, *, verify: bool = False) -> None:
    payloads, manifest = prepare(plan, source)
    expected = {
        **payloads,
        "manifest.json": (json.dumps(manifest, indent=2, ensure_ascii=True) + "\n").encode(),
    }
    if verify:
        if destination.is_symlink() or destination.is_junction() or not destination.is_dir():
            raise ValueError("Verification destination must be an unlinked directory")
        if {p.name for p in destination.iterdir()} != set(expected):
            raise ValueError("Unexpected payload membership")
        for name, content in expected.items():
            if read_plain(destination / name) != content:
                raise ValueError(f"Payload differs: {name}")
        return
    destination.mkdir(exist_ok=False)
    for name, content in expected.items():
        with (destination / name).open("xb") as stream:
            stream.write(content)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    materialize(args.plan, args.source, args.output, verify=args.verify)
    print("Source spans verified." if args.verify else "Inactive source payloads extracted.")


if __name__ == "__main__":
    main()
