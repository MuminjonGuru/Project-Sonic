from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.models.contracts import ExecutionLimits

NonEmpty = Annotated[str, StringConstraints(min_length=1)]


class StrictConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ToolExitCodes(StrictConfigModel):
    clean_or_findings: tuple[int, ...]
    failure: tuple[int, ...]


class ToolLicense(StrictConfigModel):
    software: NonEmpty
    rules: NonEmpty


class SemgrepToolConfig(StrictConfigModel):
    tool_id: Literal["semgrep"]
    tool_version: NonEmpty
    adapter_id: Literal["semgrep-json"]
    adapter_version: NonEmpty
    execution_mode: Literal["container"]
    image: Annotated[str, StringConstraints(pattern=r"^[^@]+@sha256:[0-9a-f]{64}$")]
    native_format: Literal["semgrep-json"]
    network: Literal["denied"]
    target_mount: Literal["read-only"]
    executes_target_code: Literal[False]
    may_emit_secrets: bool
    uses_external_service: Literal[False]
    exit_codes: ToolExitCodes
    license: ToolLicense


class ExecutionProfile(StrictConfigModel):
    profile_id: NonEmpty
    profile_kind: Literal["development", "pilot", "confirmatory", "demo"]
    network: Literal["denied"]
    target_mount: Literal["read-only"]
    max_workers: int = Field(ge=1)
    limits: ExecutionLimits


class LoadedConfig[ModelT: BaseModel](BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    value: ModelT
    sha256: str
    source: Path


def load_toml_config[ModelT: BaseModel](path: Path, model: type[ModelT]) -> LoadedConfig[ModelT]:
    raw = path.read_bytes()
    parsed = tomllib.loads(raw.decode("utf-8"))
    return LoadedConfig(value=model.model_validate(parsed), sha256=sha256_bytes(raw), source=path)
