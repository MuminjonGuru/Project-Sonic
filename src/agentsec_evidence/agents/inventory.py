from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Literal, Self, cast

from pydantic import ConfigDict, Field, JsonValue, StrictInt, field_validator, model_validator

from agentsec_evidence.agents.artifact_catalog import (
    CATALOG_VERSION,
    FAMILIES,
    RECOGNIZERS,
    ArtifactFamily,
    PathRecognizer,
    match_path,
)
from agentsec_evidence.agents.validation import canonical_artifact_path
from agentsec_evidence.core.identity import semantic_hash, sha256_bytes
from agentsec_evidence.core.io import jsonl_bytes
from agentsec_evidence.models.contracts import (
    ContractModel,
    InventoryEntry,
    NonEmpty,
    Sha256,
    TargetSnapshot,
)

MAX_INVENTORY_FILES = 10_000
CATALOG_SHA256 = semantic_hash([rule.model_dump(mode="json") for rule in RECOGNIZERS])


class InventoryModel(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ArtifactCandidate(InventoryModel):
    artifact_id: NonEmpty
    source: InventoryEntry
    recognizer_ids: tuple[NonEmpty, ...]
    evidence_origin: Literal["path-metadata"] = "path-metadata"
    parse_state: Literal["not-run"] = "not-run"
    analysis_state: Literal["not-run"] = "not-run"
    finding_count: None = None

    @field_validator("source", mode="before")
    @classmethod
    def require_canonical_source_path(cls, value: object) -> object:
        # The legacy InventoryEntry normalizes paths. Derivatives must instead
        # reject altered spellings before that normalization can hide a change.
        if isinstance(value, dict) and isinstance(value.get("path"), str):
            canonical_artifact_path(value["path"])
        elif isinstance(value, InventoryEntry):
            canonical_artifact_path(value.path)
        return value


class FamilyInventory(InventoryModel):
    family: ArtifactFamily
    recognition_support: Literal["filename-candidates", "no-recognizer"]
    candidate_file_count: StrictInt | None = Field(ge=0)
    interpretation: Literal["candidates-observed", "no-candidate-recognized", "unknown"]


def _validate_metadata(snapshot: TargetSnapshot, inventory: tuple[InventoryEntry, ...]) -> None:
    if len(inventory) > MAX_INVENTORY_FILES:
        raise ValueError("Artifact inventory file-count limit exceeded")
    paths = [canonical_artifact_path(entry.path) for entry in inventory]
    if len({path.casefold() for path in paths}) != len(paths):
        raise ValueError("Duplicate or case-colliding inventory paths")
    if (
        snapshot.source_kind == "git"
        and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", snapshot.revision) is None
    ):
        raise ValueError("Git snapshot requires a full revision hash, not a branch or tag")
    if snapshot.file_count != len(inventory) or snapshot.total_bytes != sum(
        entry.byte_length for entry in inventory
    ):
        raise ValueError("Snapshot inventory counts do not match")
    if sha256_bytes(jsonl_bytes(inventory)) != snapshot.inventory_sha256:
        raise ValueError("Snapshot inventory hash does not match")
    # Preserve intake's original ordering when validating its hashes. Sorting here
    # would silently change the legacy snapshot contract.
    content = [
        {"byte_length": entry.byte_length, "path": entry.path, "sha256": entry.sha256}
        for entry in inventory
    ]
    if semantic_hash(cast(JsonValue, content)) != snapshot.content_sha256:
        raise ValueError("Snapshot content identity does not match inventory metadata")
    if snapshot.snapshot_id != f"snapshot_{snapshot.content_sha256}":
        raise ValueError("Snapshot ID does not match content identity")


def _candidates(
    snapshot: TargetSnapshot, inventory: tuple[InventoryEntry, ...]
) -> tuple[ArtifactCandidate, ...]:
    return tuple(
        ArtifactCandidate(
            artifact_id="artifact_"
            + semantic_hash(
                {
                    "snapshot_id": snapshot.snapshot_id,
                    "path": entry.path,
                    "sha256": entry.sha256,
                    "catalog_sha256": CATALOG_SHA256,
                }
            ),
            source=entry,
            recognizer_ids=match_path(entry.path),
        )
        for entry in inventory
    )


def _family_inventory(records: tuple[ArtifactCandidate, ...]) -> tuple[FamilyInventory, ...]:
    summaries: list[FamilyInventory] = []
    for family in FAMILIES:
        rule_ids = {rule.recognizer_id for rule in RECOGNIZERS if rule.family == family}
        if not rule_ids:
            summaries.append(
                FamilyInventory(
                    family=family,
                    recognition_support="no-recognizer",
                    candidate_file_count=None,
                    interpretation="unknown",
                )
            )
            continue
        count = sum(bool(rule_ids.intersection(record.recognizer_ids)) for record in records)
        summaries.append(
            FamilyInventory(
                family=family,
                recognition_support="filename-candidates",
                candidate_file_count=count,
                interpretation="candidates-observed" if count else "no-candidate-recognized",
            )
        )
    return tuple(summaries)


class ArtifactInventory(InventoryModel):
    contract_version: Literal["artifact-inventory-v1"] = "artifact-inventory-v1"
    snapshot: TargetSnapshot
    scope: Literal["all-provided-snapshot-files"] = "all-provided-snapshot-files"
    repository_completeness: Literal["not-verified"] = "not-verified"
    content_reverification: Literal["not-performed"] = "not-performed"
    scan_authorization: Literal["not-granted"] = "not-granted"
    catalog_version: Literal["artifact-path-candidates-v1"] = CATALOG_VERSION
    catalog_sha256: Sha256 = CATALOG_SHA256
    recognizers: tuple[PathRecognizer, ...] = RECOGNIZERS
    records: tuple[ArtifactCandidate, ...] = Field(max_length=MAX_INVENTORY_FILES)
    families: tuple[FamilyInventory, ...]

    @model_validator(mode="after")
    def validate_derivative(self) -> Self:
        if self.catalog_sha256 != CATALOG_SHA256 or self.recognizers != RECOGNIZERS:
            raise ValueError(
                "Unrecognized inventory catalog; do not reuse this contract for new rules"
            )
        inventory = tuple(record.source for record in self.records)
        _validate_metadata(self.snapshot, inventory)
        if self.records != _candidates(self.snapshot, inventory):
            raise ValueError("Artifact candidates do not match deterministic path recognition")
        if self.families != _family_inventory(self.records):
            raise ValueError("Artifact family accounting does not match records")
        return self


def build_artifact_inventory(
    snapshot: TargetSnapshot, inventory: Sequence[InventoryEntry]
) -> ArtifactInventory:
    """Derive candidates from supplied metadata; never open or parse target files."""
    if len(inventory) > MAX_INVENTORY_FILES:
        raise ValueError("Artifact inventory file-count limit exceeded")
    # Nested legacy models are mutable. Revalidate and detach at the boundary so
    # caller mutation cannot retroactively change this derivative's evidence.
    checked_snapshot = TargetSnapshot.model_validate(snapshot.model_dump(mode="json"))
    entries: list[InventoryEntry] = []
    for entry in inventory:
        canonical_artifact_path(entry.path)
        entries.append(InventoryEntry.model_validate(entry.model_dump(mode="json")))
    checked_inventory = tuple(entries)
    _validate_metadata(checked_snapshot, checked_inventory)
    records = _candidates(checked_snapshot, checked_inventory)
    return ArtifactInventory(
        snapshot=checked_snapshot, records=records, families=_family_inventory(records)
    )


def artifact_inventory_semantic_sha256(report: ArtifactInventory) -> str:
    """Revalidate and exclude only acquisition time; all evidence and scope stay bound."""
    checked = ArtifactInventory.model_validate(report.model_dump(mode="json"))
    document = checked.model_dump(mode="json")
    document["snapshot"].pop("retrieved_at")
    return semantic_hash({"projection": "artifact-inventory-semantic-v1", "inventory": document})


def inventory_schema() -> dict[str, JsonValue]:
    schema = ArtifactInventory.model_json_schema(mode="serialization")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = "urn:agentsec-evidence:schema:artifact-inventory-v1"
    return schema
