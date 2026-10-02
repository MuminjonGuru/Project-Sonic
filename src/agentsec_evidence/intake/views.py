from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from agentsec_evidence.agents.inventory import ArtifactInventory
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.core.io import atomic_write_model
from agentsec_evidence.intake.git_verification import (
    MAX_TREE_ENTRIES,
    GitEvidenceModel,
    GitSourceVerification,
    VerifiedGitFile,
    replay_git_verification,
)
from agentsec_evidence.intake.input_plan import ToolInputPlan, verify_tool_input_plan
from agentsec_evidence.models.contracts import NonEmpty, Sha256


@dataclass(frozen=True)
class ToolViewContext:
    inventory: ArtifactInventory
    verification: GitSourceVerification
    plan: ToolInputPlan
    profile_bytes: bytes
    raw_commit: bytes
    raw_tree: bytes


def _content_identity(files: tuple[VerifiedGitFile, ...]) -> str:
    return semantic_hash(
        [{"path": f.source.path, "bytes": f.source.size, "sha256": f.sha256} for f in files]
    )


class ToolInputView(GitEvidenceModel):
    contract: Literal["tool-input-view-v1"] = "tool-input-view-v1"
    parent_snapshot_id: NonEmpty
    input_plan_sha256: Sha256
    git_verification_sha256: Sha256
    selected_content_sha256: Sha256
    files: tuple[VerifiedGitFile, ...] = Field(max_length=10_000)
    policy_context: Literal["full-parent-inventory-required"] = "full-parent-inventory-required"
    execution_authorization: Literal["not-granted"] = "not-granted"

    @model_validator(mode="after")
    def validate_files(self) -> ToolInputView:
        paths = [file.source.path for file in self.files]
        if paths != sorted(paths) or len({p.casefold() for p in paths}) != len(paths):
            raise ValueError("View file records must be sorted and unique")
        if _content_identity(self.files) != self.selected_content_sha256:
            raise ValueError("View content identity differs from file records")
        return self


def expected_tool_view(context: ToolViewContext) -> ToolInputView:
    """Rebuild the derivative from its full parent context, not a caller's claimed subset."""
    verify_tool_input_plan(
        context.plan,
        context.inventory,
        context.verification,
        profile_bytes=context.profile_bytes,
    )
    selected = {s.path for s in context.plan.selections if s.disposition == "selected"}
    files = tuple(f for f in context.verification.files if f.source.path in selected)
    return ToolInputView(
        parent_snapshot_id=context.inventory.snapshot.snapshot_id,
        input_plan_sha256=semantic_hash(context.plan.model_dump(mode="json")),
        git_verification_sha256=context.plan.git_verification_sha256,
        selected_content_sha256=_content_identity(files),
        files=files,
    )


def _plain_stat(path: Path) -> os.stat_result:
    result = path.lstat()
    if stat.S_ISLNK(result.st_mode) or (
        getattr(result, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise ValueError("Links and reparse points are outside the local view boundary")
    return result


def _plain_root(path: Path) -> Path:
    # Do not resolve links first: that would hide a junction/symlink in an ancestor.
    absolute = Path(os.path.abspath(path))
    for component in (*reversed(absolute.parents), absolute):
        if not stat.S_ISDIR(_plain_stat(component).st_mode):
            raise ValueError("View roots require plain directories")
    return absolute


def _read_files(root: Path, expected: tuple[VerifiedGitFile, ...]) -> dict[str, bytes]:
    base = _plain_root(root)
    by_path = {file.source.path: file for file in expected}
    allowed_directories: set[str] = set()
    for name in by_path:
        parts = name.split("/")
        allowed_directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
    if len(by_path) + len(allowed_directories) > MAX_TREE_ENTRIES:
        raise ValueError("Filesystem entry budget exceeded")
    pending = [base]
    result: dict[str, bytes] = {}
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                relative = path.relative_to(base).as_posix()
                metadata = _plain_stat(path)
                if stat.S_ISDIR(metadata.st_mode):
                    if relative not in allowed_directories:
                        raise ValueError("Unexpected directory in input view")
                    pending.append(path)
                elif stat.S_ISREG(metadata.st_mode):
                    if metadata.st_nlink != 1 or relative not in by_path:
                        raise ValueError("Hard-linked or unexpected input file")
                    expected_file = by_path[relative]
                    size = expected_file.source.size
                    assert size is not None
                    if metadata.st_size != size:
                        raise ValueError("Input file size changed")
                    with path.open("rb") as stream:
                        data = stream.read(size + 1)
                    if len(data) != size or sha256_bytes(data) != expected_file.sha256:
                        raise ValueError("Input file bytes changed")
                    result[relative] = data
                else:
                    raise ValueError("Nonregular filesystem entry rejected")
    if set(result) != set(by_path):
        raise ValueError("Input file set differs from verified inventory")
    return result


def replay_parent_source(context: ToolViewContext, source_root: Path) -> dict[str, bytes]:
    expected_tool_view(context)
    files = _read_files(source_root, context.verification.files)
    replay_git_verification(
        context.verification,
        raw_commit=context.raw_commit,
        raw_tree=context.raw_tree,
        files=files,
    )
    return files


def verify_materialized_tool_view(
    view: ToolInputView, context: ToolViewContext, target_root: Path
) -> None:
    checked = ToolInputView.model_validate(view.model_dump(mode="json"))
    if checked != expected_tool_view(context):
        raise ValueError("View receipt does not match its parent plan")
    _read_files(target_root, checked.files)


def materialize_tool_view(
    context: ToolViewContext, *, source_root: Path, output: Path
) -> ToolInputView:
    """Copy only verified bytes into a fresh view; leave original inputs and policy intact."""
    view = expected_tool_view(context)
    destination = Path(os.path.abspath(output))
    _plain_root(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("View destination must be new")
    source = _plain_root(source_root)
    if destination.is_relative_to(source) or source.is_relative_to(destination):
        raise ValueError("Source and view destinations must not overlap")
    files = replay_parent_source(context, source)
    destination.mkdir(exist_ok=False)
    target = destination / "target"
    target.mkdir()
    # A failed copy stays inspectable without a success receipt; retry in a new directory.
    for file in view.files:
        path = target / file.source.path
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(files[file.source.path])
    verify_materialized_tool_view(view, context, target)
    atomic_write_model(destination / "view.json", view)
    return view
