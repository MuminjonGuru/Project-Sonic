from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import Final, Literal

from pydantic import Field, model_validator

from agentsec_evidence.agents.validation import canonical_artifact_path
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.models.contracts import NonEmpty
from agentsec_evidence.research.models import (
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_TOTAL_BYTES,
    ResearchInput,
    ResearchModel,
)

POLICY_LABEL: Final = "Semgrep ignore files and inline suppressions; Git ignore filtering disabled"
_INCLUDE = re.compile(r"[ \t]*:include[ \t]*([^ \t]+)[ \t]*")
MAX_POLICY_LINES = 4096
MAX_INCLUDE_EDGES = 128


class PolicyIssue(ResearchModel):
    path: NonEmpty
    code: Literal[
        "policy-budget",
        "policy-encoding",
        "unsupported-directive",
        "unsafe-include",
        "missing-include",
        "nested-include",
        "python-policy-input",
    ]
    line: int | None = Field(default=None, ge=1)


class PolicyInclude(ResearchModel):
    owner: NonEmpty
    line: int = Field(ge=1)
    target: NonEmpty


class SemgrepPolicyAssessment(ResearchModel):
    contract: Literal["semgrep-policy-assessment-v1"] = "semgrep-policy-assessment-v1"
    label: Literal[
        "Semgrep ignore files and inline suppressions; Git ignore filtering disabled"
    ] = POLICY_LABEL
    implicit_gitignore: Literal["disabled"] = "disabled"
    root_defaults: Literal["pinned-native-defaults", "root-file-overrides-defaults"]
    semgrepignore_paths: tuple[str, ...]
    files: tuple[ResearchInput, ...]
    includes: tuple[PolicyInclude, ...]
    blockers: tuple[PolicyIssue, ...]
    pattern_evaluation: Literal["delegated-to-pinned-semgrep"] = "delegated-to-pinned-semgrep"
    execution_authorization: Literal["not-granted"] = "not-granted"

    @model_validator(mode="after")
    def validate_paths(self) -> SemgrepPolicyAssessment:
        paths = [entry.path for entry in self.files]
        if paths != sorted(set(paths)):
            raise ValueError("Policy files must be sorted and unique")
        for path in (*paths, *self.semgrepignore_paths):
            canonical_artifact_path(path)
        if tuple(sorted(set(self.semgrepignore_paths))) != self.semgrepignore_paths:
            raise ValueError("Ignore paths must be sorted and unique")
        if not set(self.semgrepignore_paths).issubset(paths):
            raise ValueError("Every ignore file requires retained identity")
        return self


def assess_semgrep_policy(files: Mapping[str, bytes]) -> SemgrepPolicyAssessment:
    """Bound local policy reads; never implement Semgrep's pattern matching on the host.

    The caller supplies the complete Git-verified parent. All ignore files are considered,
    even outside selected scanner paths. This conservative guard can refuse irrelevant policy.
    """
    for path in files:
        canonical_artifact_path(path)
    roots = tuple(sorted(p for p in files if PurePosixPath(p).name == ".semgrepignore"))
    retained = set(roots)
    includes: list[PolicyInclude] = []
    blockers: list[PolicyIssue] = []
    decoded_lines: dict[str, list[str]] = {}

    def issue(path: str, code: str, line: int | None = None) -> None:
        blockers.append(PolicyIssue.model_validate({"path": path, "code": code, "line": line}))

    def lines(path: str) -> list[str]:
        if path in decoded_lines:
            return decoded_lines[path]
        decoded_lines[path] = []
        data = files[path]
        if len(data) > MAX_FILE_BYTES:
            issue(path, "policy-budget")
            return []
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            issue(path, "policy-encoding")
            return []
        if (
            text.startswith("\ufeff")
            or any((ord(c) < 32 and c not in "\t\r\n") or ord(c) == 127 for c in text)
            or "\r" in text.replace("\r\n", "")
        ):
            issue(path, "policy-encoding")
            return []
        result = text.replace("\r\n", "\n").split("\n")
        if len(result) > MAX_POLICY_LINES:
            issue(path, "policy-budget")
            return []
        decoded_lines[path] = result
        return result

    initial_over_budget = (
        len(roots) > MAX_FILES or sum(len(files[p]) for p in roots) > MAX_TOTAL_BYTES
    )
    for owner in () if initial_over_budget else roots:
        for number, line in enumerate(lines(owner), 1):
            if not line.lstrip(" \t").startswith(":"):
                continue
            match = _INCLUDE.fullmatch(line)
            if match is None:
                issue(owner, "unsupported-directive", number)
                continue
            if len(includes) >= MAX_INCLUDE_EDGES:
                issue(owner, "policy-budget", number)
                break
            relative = match.group(1)
            try:
                # No absolute, drive, escape, dot-component or ambiguous platform syntax.
                canonical_artifact_path(relative)
                target = str(PurePosixPath(owner).parent / relative)
                canonical_artifact_path(target)
            except ValueError:
                issue(owner, "unsafe-include", number)
                continue
            includes.append(PolicyInclude(owner=owner, line=number, target=target))
            if target not in files:
                issue(owner, "missing-include", number)
                continue
            retained.add(target)
            if len(retained) > MAX_FILES or sum(len(files[p]) for p in retained) > MAX_TOTAL_BYTES:
                issue(owner, "policy-budget", number)
                break
            if PurePosixPath(target).suffix.lower() in {".py", ".pyi", ".pyw"}:
                issue(owner, "python-policy-input", number)
            # Pinned Semgrep expands once. Refuse nested directives rather than pretending
            # to follow them, including self-includes and cycles through other ignore files.
            for nested_number, nested_line in enumerate(lines(target), 1):
                if nested_line.lstrip(" \t").startswith(":"):
                    issue(target, "nested-include", nested_number)
    if len(retained) > MAX_FILES or sum(len(files[p]) for p in retained) > MAX_TOTAL_BYTES:
        issue(".semgrepignore", "policy-budget")
    return SemgrepPolicyAssessment(
        root_defaults=(
            "root-file-overrides-defaults"
            if ".semgrepignore" in files
            else "pinned-native-defaults"
        ),
        semgrepignore_paths=roots,
        files=tuple(
            ResearchInput(
                path=p,
                sha256=sha256_bytes(files[p]),
                byte_length=len(files[p]),
                media_type="text/plain",
            )
            for p in sorted(retained)
        ),
        includes=tuple(includes),
        blockers=tuple(blockers),
    )
