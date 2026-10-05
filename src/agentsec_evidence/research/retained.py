"""Bounded, read-only verification of a research helper's sealed evidence tree."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from pydantic import Field, StrictInt, model_validator

from agentsec_evidence.agents.validation import canonical_artifact_path, load_agent_json
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.models.contracts import Sha256
from agentsec_evidence.research.models import ResearchModel

MAX_ENTRY_BYTES = 16 * 1024 * 1024
MAX_TREE_BYTES = 128 * 1024 * 1024


class RetainedEntry(ResearchModel):
    path: str = Field(min_length=1, max_length=4096)
    bytes: StrictInt = Field(ge=0, le=MAX_ENTRY_BYTES)
    sha256: Sha256


class RetainedManifest(ResearchModel):
    files: tuple[RetainedEntry, ...] = Field(min_length=1, max_length=4096)

    @model_validator(mode="after")
    def validate_entries(self) -> RetainedManifest:
        paths = [canonical_artifact_path(e.path) for e in self.files]
        if any(len(p.split("/")) > 64 for p in paths):
            raise ValueError("Retained evidence path depth exceeded")
        if len(set(p.casefold() for p in paths)) != len(paths):
            raise ValueError("Duplicate retained evidence path")
        if sum(e.bytes for e in self.files) > MAX_TREE_BYTES:
            raise ValueError("Retained matrix exceeds evidence budget")
        if any(p == "evidence-manifest.json" or p.split("/")[0] == "runtime" for p in paths):
            raise ValueError("Manifest cannot include itself or runtime scratch")
        return self


def plain_path(path: Path, *, directory: bool) -> Path:
    absolute = Path(os.path.abspath(path))
    for component in (*reversed(absolute.parents), absolute):
        info = component.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise ValueError("Evidence links and reparse points are refused")
        if component != absolute or directory:
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("Expected plain evidence directory")
        elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("Expected a regular non-hard-linked evidence file")
    return absolute


def bounded_file(path: Path, limit: int) -> bytes:
    path = plain_path(path, directory=False)
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Retained evidence file exceeds byte limit")
    return data


@dataclass(frozen=True)
class RetainedResearch:
    root: Path
    manifest_sha256: str
    files: dict[str, bytes]

    def read(self, path: str) -> bytes:
        canonical_artifact_path(path)
        try:
            return self.files[path]
        except KeyError as exc:
            raise ValueError("Required retained evidence is missing: " + path) from exc


def read_retained_research(root: Path) -> RetainedResearch:
    root = plain_path(root, directory=True)
    raw = bounded_file(root / "evidence-manifest.json", 4 * 1024 * 1024)
    manifest = RetainedManifest.model_validate(load_agent_json(raw, max_bytes=4 * 1024 * 1024))
    expected = {e.path for e in manifest.files}
    allowed_dirs = {
        str(parent) for name in expected for parent in Path(name).parents if str(parent) != "."
    }
    allowed_dirs = {p.replace("\\", "/") for p in allowed_dirs}
    actual: set[str] = set()
    for directory, dirs, names in os.walk(root):
        for name in list(dirs):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            plain_path(path, directory=True)
            if relative == "runtime":
                dirs.remove(name)
            elif relative not in allowed_dirs:
                raise ValueError("Unmanifested evidence directory")
        for name in names:
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if relative == "evidence-manifest.json":
                continue
            if relative not in expected:
                raise ValueError("Unmanifested evidence file")
            actual.add(relative)
    if actual != expected:
        raise ValueError("Retained evidence file set differs")
    files: dict[str, bytes] = {}
    for entry in manifest.files:
        data = bounded_file(root / entry.path, entry.bytes)
        if len(data) != entry.bytes or sha256_bytes(data) != entry.sha256:
            raise ValueError("Retained research integrity failure")
        files[entry.path] = data
    return RetainedResearch(root, sha256_bytes(raw), files)
