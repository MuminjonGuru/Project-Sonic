"""Deterministic bounded inputs for the finite, authored cross-family validation set."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal, cast

from pydantic import Field, JsonValue, model_validator

from agentsec_evidence.agents.records import AgentInputRequest
from agentsec_evidence.agents.validation import canonical_artifact_path, load_agent_json
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.models.contracts import ContractModel, InventoryEntry, Sha256
from agentsec_evidence.reporting.custom_contracts import FAMILIES, IMAGE
from agentsec_evidence.research.retained import bounded_file, plain_path

# These are the existing repair inputs, not newly selected public evaluation data.
REGISTRY_PINS = {
    "tool-execution": "47ee01e315aca2ddae16a5f08153e043f2219bbc5706fc975fe9cb7bf8da1503",
    "network-data": "646d0d093239d0a044eebd6cd40c9684535b0704a8aaf40bdc7d59021f500e12",
    "filesystem": "41bc6d6df7750a4bb366b713af87224e1a16e00d847f3459a62e349b0426d75a",
    "memory-state": "7f8660db4cc695c6a48e04ba4449693932dad7df890417716b60794865e4a216",
    "self-modification": "87c9d0954c56c836ae3b3309310093a0c3716a23e1b7d9a3bb3cb64457e9c60d",
    "orchestration": "2898ef9badf102dcf88676817d132bbbc2d64b74dc32806ae7606955a7dad4c8",
    "agent-to-agent": "91c923733d018a93e055d3645ce9954d449aba86a06af1c71d12adb0e854b2b9",
}


class RepairCase(ContractModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$", max_length=100)
    source: str
    rules: list[str] | None
    inventory: list[str] = Field(default_factory=list)


class RepairRegistry(ContractModel):
    contract: str
    role: str | None = None
    scope: str | None = None
    expectation_provenance: str
    cases: list[RepairCase] = Field(min_length=1, max_length=100)


def read_registry(raw: bytes, family: str) -> RepairRegistry:
    if sha256_bytes(raw) != REGISTRY_PINS[family]:
        raise ValueError("Authored registry differs from its approved repair bytes")
    registry = RepairRegistry.model_validate(load_agent_json(raw, max_bytes=256 * 1024))
    if registry.contract != family + "-repair-cases-v1":
        raise ValueError("Wrong authored registry contract")
    ids = [case.id for case in registry.cases]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate authored case identity")
    return registry


def view_entries(paths: list[str]) -> int:
    """Workers bound both files and directories, not just selected file count."""
    return len(
        {str(p) for path in paths for p in PurePosixPath(path).parents if str(p) != "."}
    ) + len(paths)


def partition_inputs(
    inventory: list[InventoryEntry], *, max_files: int = 64
) -> list[list[InventoryEntry]]:
    if isinstance(max_files, bool) or not 1 <= max_files <= 64:
        raise ValueError("Batch file limit must be between 1 and 64")
    paths = [canonical_artifact_path(e.path) for e in inventory]
    if len(paths) != len(set(p.casefold() for p in paths)):
        raise ValueError("Ambiguous shared input paths")
    folded = {p.casefold() for p in paths}
    for path, entry in zip(paths, inventory, strict=True):
        if (
            entry.byte_length > 256 * 1024
            or len(path.split("/")) > 64
            or any(str(p).casefold() in folded for p in PurePosixPath(path).parents)
        ):
            raise ValueError("Unsupported file size, depth or file/directory collision")
    batches: list[list[InventoryEntry]] = []
    current: list[InventoryEntry] = []
    for entry in sorted(inventory, key=lambda item: item.path):
        proposed = [*current, entry]
        if current and (
            len(proposed) > max_files
            or sum(item.byte_length for item in proposed) > 1024 * 1024
            or view_entries([item.path for item in proposed]) > 512
        ):
            batches.append(current)
            current = []
        current.append(entry)
    if current:
        batches.append(current)
    return batches


class SharedPlan(ContractModel):
    contract: Literal["shared-custom-authored-plan-v1"] = "shared-custom-authored-plan-v1"
    split: Literal["development-only"] = "development-only"
    policy: Literal["research-only-no-suppressions-applied"] = (
        "research-only-no-suppressions-applied"
    )
    executes_target_code: Literal[False] = False
    image: str = IMAGE
    registry_pins: dict[str, Sha256]
    source_pins: dict[str, Sha256]
    catalog_pins: dict[str, Sha256]
    inventory: list[InventoryEntry]
    snapshot_id: Sha256
    max_files: int = Field(ge=1, le=64)
    repetitions: int = Field(ge=1, le=3)
    requests: list[AgentInputRequest]

    @model_validator(mode="after")
    def validate_source_paths(self) -> SharedPlan:
        for path in self.source_pins:
            canonical_artifact_path(path)
            if not path.startswith("src/agentsec_evidence/") or not path.endswith(".py"):
                raise ValueError("Implementation pin is outside the package")
        if len({p.casefold() for p in self.source_pins}) != len(self.source_pins):
            raise ValueError("Ambiguous implementation paths")
        return self


def build_plan(
    inventory: list[InventoryEntry],
    source_pins: dict[str, str],
    *,
    max_files: int,
    repetitions: int,
) -> SharedPlan:
    inventory = sorted(inventory, key=lambda item: item.path)
    snapshot = semantic_hash(cast(JsonValue, [item.model_dump(mode="json") for item in inventory]))
    batches = partition_inputs(inventory, max_files=max_files)
    return SharedPlan(
        registry_pins=REGISTRY_PINS,
        source_pins=source_pins,
        catalog_pins={family.key: family.catalog_sha256 for family in FAMILIES},
        inventory=inventory,
        snapshot_id=snapshot,
        max_files=max_files,
        repetitions=repetitions,
        requests=[
            AgentInputRequest(
                target_snapshot_id=snapshot,
                inventory=batch,
                selected={entry.path: "python-source" for entry in batch},
            )
            for batch in batches
        ],
    )


@dataclass(frozen=True)
class PreparedShared:
    plan: SharedPlan
    inputs: dict[str, bytes]
    sources: dict[str, bytes]
    registries: dict[str, bytes]


def prepare_shared(project: Path, *, max_files: int = 64, repetitions: int = 2) -> PreparedShared:
    project = plain_path(project, directory=True)
    inputs: dict[str, bytes] = {}
    registries: dict[str, bytes] = {}
    for family in FAMILIES:
        raw = bounded_file(project / family.registry, 256 * 1024)
        registry = read_registry(raw, family.key)
        registries[family.registry] = raw
        for case in registry.cases:
            inputs[f"{family.key}/{case.id}.py"] = case.source.encode("utf-8")
    sources = {
        path.relative_to(project).as_posix(): bounded_file(path, 1024 * 1024)
        for path in sorted((project / "src").rglob("*.py"))
    }
    if not sources or len(inputs) != 385:
        raise ValueError("Finite repair source set is incomplete")
    inventory = [
        InventoryEntry(
            path=path, sha256=sha256_bytes(raw), byte_length=len(raw), media_type="text/x-python"
        )
        for path, raw in inputs.items()
    ]
    plan = build_plan(
        inventory,
        {path: sha256_bytes(raw) for path, raw in sources.items()},
        max_files=max_files,
        repetitions=repetitions,
    )
    for request in plan.requests:
        if len(request.model_dump_json().encode()) > 256 * 1024:
            raise ValueError("Bounded request exceeds worker limit")
    return PreparedShared(plan, inputs, sources, registries)
