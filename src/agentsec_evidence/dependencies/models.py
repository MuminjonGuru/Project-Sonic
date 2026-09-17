from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from agentsec_evidence.models.contracts import Sha256


class DependencyModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class PackageObservation(DependencyModel):
    native_pointer: str
    native_id: str
    native_name: str
    native_version: str | None
    name: str | None = None
    version: str | None = None
    ecosystem: str | None = None
    purl: str | None = None
    source_qualifiers: dict[str, str] = Field(default_factory=dict)
    status: Literal["identified", "unresolved", "unsupported", "conflicting"]
    context: dict[str, JsonValue] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)

    @property
    def projection(self) -> tuple[str, str] | None:
        if self.status == "identified" and self.ecosystem == "PyPI" and self.name and self.version:
            return self.name, self.version
        return None


class Relationship(DependencyModel):
    native_pointer: str
    source_ref: str
    destination_ref: str
    kind: str
    context: dict[str, JsonValue] = Field(default_factory=dict)


class AdvisoryMatch(DependencyModel):
    package_pointer: str
    name: str
    version: str
    canonical_advisory: str
    original_ids: list[str]
    aliases: list[str]


class StageEvidence(DependencyModel):
    contract: Literal["dependency-stage-v1"] = "dependency-stage-v1"
    stage: Literal["lockfile", "syft", "cyclonedx", "osv-direct", "osv-sbom"]
    raw_sha256: Sha256
    state: Literal["complete", "partial", "failed", "unsupported"] = "complete"
    observations: list[PackageObservation] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    matches: list[AdvisoryMatch] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class DependencyScope(DependencyModel):
    contract: Literal["dependency-scope-v1"] = "dependency-scope-v1"
    scope: Literal["lockfile-wide-no-install"] = "lockfile-wide-no-install"
    input_file: Literal["uv.lock"] = "uv.lock"
    input_sha256: Sha256
    eligible: list[tuple[str, str]]
    separate_local: list[tuple[str, str]]
    unsupported_pointers: list[str]
    ambiguous_projections: list[tuple[str, str]]
    marker_policy: str = "retain all recorded branches; no runtime filtering"
    group_policy: str = "retain all recorded groups; no runtime filtering"
    comparison_policy: str = (
        "PyPI name/version projection; report source-qualifier loss separately; "
        "never claim complete identity or relationship preservation from this ratio"
    )


class Fraction(DependencyModel):
    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    value: float | None


class StageComparison(DependencyModel):
    contract: Literal["dependency-comparison-v1"] = "dependency-comparison-v1"
    left: str
    right: str
    comparable: bool
    package_projection_retention: Fraction | None
    missing: list[tuple[str, str]]
    added: list[tuple[str, str]]
    left_out_of_scope: list[tuple[str, str]]
    right_out_of_scope: list[tuple[str, str]]
    source_qualifier_losses: list[tuple[str, str]]
    missing_identifiers: list[str]
    limitations: list[str]
