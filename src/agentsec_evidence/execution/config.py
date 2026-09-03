from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.models.contracts import ExecutionLimits

NonEmpty = Annotated[str, StringConstraints(min_length=1)]
Sha256Text = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
CommitSha = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
QueryId = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
]


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


class KicsToolConfig(StrictConfigModel):
    tool_id: Literal["kics"]
    tool_version: NonEmpty
    adapter_id: Literal["kics-json"]
    adapter_version: NonEmpty
    execution_mode: Literal["container"]
    image: Annotated[str, StringConstraints(pattern=r"^[^@]+@sha256:[0-9a-f]{64}$")]
    image_source_revision: CommitSha
    native_format: Literal["kics-json"]
    network: Literal["denied"]
    target_mount: Literal["read-only"]
    executes_target_code: Literal[False]
    may_emit_secrets: bool
    uses_external_service: Literal[False]
    query_selection_id: NonEmpty
    query_pack_sha256: Sha256Text
    query_pack_file_count: int = Field(gt=0)
    query_pack_total_bytes: int = Field(gt=0)
    platforms: tuple[Literal["Terraform", "Kubernetes"], ...] = Field(min_length=1)
    include_queries: tuple[QueryId, ...] = Field(min_length=1)
    report_formats: tuple[Literal["json", "sarif"], ...] = Field(min_length=2)
    query_timeout_seconds: int = Field(gt=0)
    max_file_size_mb: int = Field(gt=0)
    max_resolver_depth: int = Field(gt=0)
    parallel: int = Field(ge=1)
    disable_secrets: Literal[True]
    disable_full_descriptions: Literal[True]
    exclude_gitignore: Literal[True]
    ignore_on_exit: Literal["results"]
    exit_codes: ToolExitCodes
    license: ToolLicense

    @model_validator(mode="after")
    def validate_frozen_selection(self) -> Self:
        if len(set(self.platforms)) != len(self.platforms):
            raise ValueError("KICS platforms must be unique")
        if len(set(self.include_queries)) != len(self.include_queries):
            raise ValueError("KICS query IDs must be unique")
        if tuple(self.report_formats) != ("json", "sarif"):
            raise ValueError("KICS report formats must be frozen as json then sarif")
        return self


type StaticToolConfig = SemgrepToolConfig | KicsToolConfig


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
    raw: bytes


def load_toml_config[ModelT: BaseModel](path: Path, model: type[ModelT]) -> LoadedConfig[ModelT]:
    raw = path.read_bytes()
    return load_toml_bytes(raw, model, source=path)


def load_toml_bytes[ModelT: BaseModel](
    raw: bytes, model: type[ModelT], *, source: Path
) -> LoadedConfig[ModelT]:
    parsed = tomllib.loads(raw.decode("utf-8"))
    return LoadedConfig(
        value=model.model_validate(parsed),
        sha256=sha256_bytes(raw),
        source=source,
        raw=raw,
    )
