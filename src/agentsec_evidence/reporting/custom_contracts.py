"""Read-only contracts for repaired workers; importing these never scans target source."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Literal, cast

from pydantic import Field, JsonValue, StrictInt, TypeAdapter, model_validator

from agentsec_evidence.agents.records import AgentInputRequest
from agentsec_evidence.agents.validation import load_agent_json
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.custom_rules import (
    agent_to_agent_catalog,
    filesystem_catalog,
    memory_catalog,
    network_catalog,
    orchestration_catalog,
    self_modification_catalog,
    tool_execution,
)
from agentsec_evidence.custom_rules.agent_to_agent import AgentToAgentFileResult
from agentsec_evidence.custom_rules.agent_to_agent_worker import AgentToAgentReport
from agentsec_evidence.custom_rules.filesystem import FilesystemFileResult
from agentsec_evidence.custom_rules.filesystem_worker import FilesystemReport
from agentsec_evidence.custom_rules.memory_state import MemoryFileResult
from agentsec_evidence.custom_rules.memory_worker import MemoryReport
from agentsec_evidence.custom_rules.network_data import NetworkFileResult
from agentsec_evidence.custom_rules.network_worker import NetworkReport
from agentsec_evidence.custom_rules.orchestration import OrchestrationFileResult
from agentsec_evidence.custom_rules.orchestration_worker import OrchestrationReport
from agentsec_evidence.custom_rules.python_static import SourceRange
from agentsec_evidence.custom_rules.self_modification import SelfModificationFileResult
from agentsec_evidence.custom_rules.self_modification_worker import SelfModificationReport
from agentsec_evidence.custom_rules.tool_execution_worker import ToolExecutionReport
from agentsec_evidence.models.contracts import ContractModel, Sha256

type NativeReport = Annotated[
    ToolExecutionReport
    | NetworkReport
    | FilesystemReport
    | MemoryReport
    | SelfModificationReport
    | OrchestrationReport
    | AgentToAgentReport,
    Field(discriminator="contract"),
]
type NativeFile = (
    tool_execution.FileResult
    | NetworkFileResult
    | FilesystemFileResult
    | MemoryFileResult
    | SelfModificationFileResult
    | OrchestrationFileResult
    | AgentToAgentFileResult
)
type TreatmentKey = Literal["all-repeat-1", "all-repeat-2", "valid-only", "corrected-controls"]
NATIVE: TypeAdapter[NativeReport] = TypeAdapter(NativeReport)
TREATMENTS: tuple[TreatmentKey, ...] = (
    "all-repeat-1",
    "all-repeat-2",
    "valid-only",
    "corrected-controls",
)
IMAGE = "sha256:3bfa1ba1294f1c4683ebbbbff98921e67b8230299fe35e0f5e82deefc6a73080"


@dataclass(frozen=True)
class Family:
    key: str
    worker: str
    module: str
    catalog: str | None
    rules: tuple[ContractModel, ...]
    catalog_sha256: str
    legacy: dict[str, str]
    helper: str
    threshold: str = "low"

    @property
    def contract(self) -> str:
        # The retained memory worker predates the longer registry/family label.
        return ("memory" if self.key == "memory-state" else self.key) + "-development-v1"

    @property
    def registry(self) -> str:
        return f"test_cases/development/{self.key}-v1/cases.json"

    @property
    def critical_sources(self) -> set[str]:
        names = {self.worker, self.module, "python_static"}
        if self.catalog:
            names.add(self.catalog)
        return {f"src/agentsec_evidence/custom_rules/{n}.py" for n in names} | {
            "src/agentsec_evidence/agents/inputs.py",
            "src/agentsec_evidence/agents/records.py",
            "src/agentsec_evidence/agents/validation.py",
            "src/agentsec_evidence/agents/worker.py",
            "src/agentsec_evidence/core/identity.py",
            "src/agentsec_evidence/models/contracts.py",
        }


FAMILIES = (
    Family(
        "tool-execution",
        "tool_execution_worker",
        "tool_execution",
        None,
        tool_execution.RULES,
        tool_execution.CATALOG_SHA256,
        {},
        "verify_tool_execution_repair.py",
        "high",
    ),
    Family(
        "network-data",
        "network_worker",
        "network_data",
        "network_catalog",
        network_catalog.RULES,
        network_catalog.CATALOG_SHA256,
        {},
        "verify_network_data_repair.py",
    ),
    Family(
        "filesystem",
        "filesystem_worker",
        "filesystem",
        "filesystem_catalog",
        filesystem_catalog.RULES,
        filesystem_catalog.CATALOG_SHA256,
        filesystem_catalog.LEGACY_MARKERS,
        "verify_filesystem_repair.py",
    ),
    Family(
        "memory-state",
        "memory_worker",
        "memory_state",
        "memory_catalog",
        memory_catalog.RULES,
        memory_catalog.CATALOG_SHA256,
        memory_catalog.LEGACY_MARKERS,
        "verify_memory_state_repair.py",
    ),
    Family(
        "self-modification",
        "self_modification_worker",
        "self_modification",
        "self_modification_catalog",
        self_modification_catalog.RULES,
        self_modification_catalog.CATALOG_SHA256,
        self_modification_catalog.LEGACY_MARKERS,
        "verify_self_modification_repair.py",
    ),
    Family(
        "orchestration",
        "orchestration_worker",
        "orchestration",
        "orchestration_catalog",
        orchestration_catalog.RULES,
        orchestration_catalog.CATALOG_SHA256,
        orchestration_catalog.LEGACY_MARKERS,
        "verify_orchestration_repair.py",
    ),
    Family(
        "agent-to-agent",
        "agent_to_agent_worker",
        "agent_to_agent",
        "agent_to_agent_catalog",
        agent_to_agent_catalog.RULES,
        agent_to_agent_catalog.CATALOG_SHA256,
        agent_to_agent_catalog.LEGACY_MARKERS,
        "verify_agent_to_agent_repair.py",
    ),
)
BY_CONTRACT = {family.contract: family for family in FAMILIES}
BY_VERIFICATION = {family.key + "-repair-verification-v1": family for family in FAMILIES}


def catalog(native: NativeReport) -> list[dict[str, JsonValue]]:
    """Add an explicit status to the older tool-execution catalog, without altering its bytes."""
    return [
        cast(dict[str, JsonValue], rule.model_dump(mode="json"))
        | ({"status": "active-condition"} if isinstance(native, ToolExecutionReport) else {})
        for rule in native.rules
    ]


def expected_exit(native: NativeReport) -> int:
    if native.execution_state != "complete":
        return 2
    threshold = BY_CONTRACT[native.contract].threshold
    levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    for file in native.files:
        for finding in file.findings or []:
            value = cast(ContractModel, finding).model_dump(mode="json")
            priority = value["rule"]["severity"] if "rule" in value else value["priority"]
            if levels[priority] >= levels[threshold]:
                return 1
    return 0


def validate_native(native: NativeReport, request: AgentInputRequest) -> None:
    family = BY_CONTRACT[native.contract]
    if (
        list(native.rules) != list(family.rules)
        or native.catalog_sha256 != family.catalog_sha256
        or getattr(native, "legacy_markers", {}) != family.legacy
        or native.target_snapshot_id != request.target_snapshot_id
        or native.input_inventory != sorted(request.inventory, key=lambda item: item.path)
        or native.not_selected
        != sorted({item.path for item in request.inventory} - request.selected.keys())
        or [file.path for file in native.files] != sorted(request.selected)
    ):
        raise ValueError("Repaired worker catalog, target or input accounting differs")
    entries = {item.path: item for item in request.inventory}
    rules = {item["rule_id"]: item for item in catalog(native)}
    seen: set[str] = set()
    for file in native.files:
        entry = entries[file.path]
        if (file.source_sha256, file.byte_length) != (entry.sha256, entry.byte_length):
            raise ValueError("Native file hash or length differs from request")
        if (file.findings is None) != (file.state != "analyzed"):
            raise ValueError("Incomplete file cannot carry a successful finding list")
        if file.state != "analyzed" and (file.inventory or file.limitations_observed):
            raise ValueError("Unanalyzed file cannot carry successful observations")
        if len(file.findings or []) + len(file.inventory) + len(file.limitations_observed) > 1000:
            raise ValueError("Native record budget exceeded")
        for finding in file.findings or []:
            value = cast(ContractModel, finding).model_dump(mode="json")
            rule_id = value["rule"]["rule_id"] if "rule" in value else value["rule_id"]
            rule = rules.get(rule_id)
            if not rule or rule["status"] != "active-condition":
                raise ValueError("Nonactive rule cannot become a condition finding")
            if isinstance(native, ToolExecutionReport):
                if value["rule"] != {k: v for k, v in rule.items() if k != "status"}:
                    raise ValueError("Embedded finding rule differs from catalog")
            elif value["priority"] != rule["priority"]:
                raise ValueError("Native priority differs from its rule")
            span = SourceRange.model_validate(value["location"])
            if (span.end_line, span.end_utf8_byte_column) < (
                span.start_line,
                span.start_utf8_byte_column,
            ):
                raise ValueError("Reversed native source range")
            expected = sha256_bytes(
                f"{native.version}:{file.path}:{file.source_sha256}:{rule_id}:"
                f"{span.model_dump_json()}".encode()
            )
            if value["record_id"] != expected or expected in seen:
                raise ValueError("Duplicate or incorrect native condition identity")
            seen.add(expected)
        for observation in file.inventory:
            rule_id = getattr(observation, "rule_id", None)
            if rule_id is not None and (
                rule_id not in rules or rules[rule_id]["status"] != "inventory-only"
            ):
                raise ValueError("Inventory rule status differs")
    state = (
        "empty"
        if not native.files
        else ("partial" if any(file.state != "analyzed" for file in native.files) else "complete")
    )
    if native.execution_state != state:
        raise ValueError("Native execution state differs from file states")


class CustomTreatment(ContractModel):
    key: TreatmentKey
    request: AgentInputRequest
    native: NativeReport
    request_json: str = Field(max_length=256 * 1024)
    native_json: str = Field(max_length=16 * 1024**2)
    stdout_sha256: Sha256
    invocation_sha256: Sha256
    duration_ns: StrictInt = Field(ge=0)
    exit_code: StrictInt
    analysis_completeness: Literal["not-established"] = "not-established"
    suppression_application: Literal["not-applied"] = "not-applied"
    review_grouping: Literal["not-performed"] = "not-performed"
    unique_vulnerabilities: None = None

    @model_validator(mode="after")
    def validate_treatment(self) -> CustomTreatment:
        validate_native(self.native, self.request)
        if (
            self.native.request_sha256 != sha256_bytes(self.request_json.encode())
            or self.stdout_sha256 != sha256_bytes(self.native_json.encode())
            or self.request
            != AgentInputRequest.model_validate(
                load_agent_json(self.request_json.encode(), max_bytes=256 * 1024)
            )
            or self.native
            != NATIVE.validate_python(
                load_agent_json(self.native_json.encode(), max_bytes=16 * 1024**2)
            )
        ):
            raise ValueError("Repair native/request exact bytes or parsed projection differs")
        if self.exit_code != expected_exit(self.native):
            raise ValueError("Native exit status differs from bounded worker semantics")
        return self


class CustomSummary(ContractModel):
    contract: Literal["custom-repair-summary-v1"] = "custom-repair-summary-v1"
    family: str
    evidence_role: Literal["authored-development-not-held-out"] = (
        "authored-development-not-held-out"
    )
    registry_sha256: Sha256
    implementation_sha256: Sha256
    image_id: str = Field(default=IMAGE, pattern="^" + IMAGE + "$")
    treatments: tuple[CustomTreatment, ...] = Field(min_length=4, max_length=4)
    vulnerability_total: None = None
    limitations: tuple[str, ...] = (
        "Different repair families use different authored inputs; not a same-repository scan.",
        "Conditions, inventory, deferred IDs and incomplete analysis are separate evidence units.",
        "Overlapping findings retain every native identity; no automatic issue merging.",
        "Research-only policy: local ignores and suppression comments are not applied.",
        "No accuracy, independent labels, complete coverage or runtime exploitability established.",
        "Tool-execution reports can contain source expressions; internal/unredacted evidence.",
        "SARIF exports conditions only; inventory/catalog/limitations remain in report JSON.",
        "SARIF omits source snippets and columns; original UTF-8 byte ranges stay in properties.",
    )

    @model_validator(mode="after")
    def validate_summary(self) -> CustomSummary:
        if tuple(row.key for row in self.treatments) != TREATMENTS:
            raise ValueError("Repair treatments must remain separate and ordered")
        if any(BY_CONTRACT[row.native.contract].key != self.family for row in self.treatments):
            raise ValueError("Repair family differs between treatments")
        first, second = self.treatments[:2]
        if (
            first.stdout_sha256 != second.stdout_sha256
            or first.native != second.native
            or first.request != second.request
        ):
            raise ValueError("Retained full repetitions differ")
        return self
