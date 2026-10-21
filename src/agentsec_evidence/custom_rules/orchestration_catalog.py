"""Inventory-first interpretation of the 22 supplied orchestration IDs."""

from typing import Literal

from pydantic import Field

from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.models.contracts import ContractModel


class OrchestrationRule(ContractModel):
    rule_id: str
    status: Literal["inventory-only", "deferred"]
    title: str
    boundary: str
    related_ids: list[str] = Field(default_factory=list)


def _rule(
    suffix: str,
    status: Literal["inventory-only", "deferred"],
    title: str,
    boundary: str,
    related: tuple[str, ...] = (),
) -> OrchestrationRule:
    return OrchestrationRule(
        rule_id=f"ORG-{suffix}",
        status=status,
        title=title,
        boundary=boundary,
        related_ids=list(related),
    )


RULES = (
    _rule(
        "001",
        "inventory-only",
        "Handoff-named call syntax",
        "Receiver/method spelling and argument shapes, not hijacking or an actual agent handoff.",
    ),
    _rule(
        "002",
        "inventory-only",
        "Routing-named call syntax",
        "Literal/nonliteral arguments do not establish model control or unsafe routing.",
    ),
    _rule(
        "003",
        "inventory-only",
        "State-operation call syntax",
        "No shared storage, ownership, integrity, persistence or injection established.",
    ),
    _rule(
        "004",
        "inventory-only",
        "Memory-like expression in handoff payload syntax",
        "Names and direct expressions, not actual confidential content or cross-agent leakage.",
    ),
    _rule(
        "005",
        "inventory-only",
        "Routing-policy update naming cue",
        "No unauthorized modification or absent validation established.",
    ),
    _rule(
        "006",
        "deferred",
        "Model-driven orchestration",
        "Requires independently established model-output provenance and decision flow.",
    ),
    _rule(
        "007",
        "inventory-only",
        "LangChain-family import declaration",
        "Import spelling only; not installed/runtime framework or compatible API.",
    ),
    _rule(
        "008",
        "inventory-only",
        "AutoGen-family import declaration",
        "Import spelling only; not a verified orchestrator implementation.",
    ),
    _rule(
        "009",
        "deferred",
        "MCP orchestration security",
        "Existing MCP analyzer owns configuration checks; no assumed state/permission schema.",
    ),
    _rule(
        "010",
        "inventory-only",
        "Orchestration persistence naming cue",
        "No actual write, storage location, confidentiality or durable state established.",
    ),
    _rule(
        "011",
        "inventory-only",
        "Immediate call expression in an orchestration argument",
        "AST nesting, not executed call graph, handoff count or dangerous composition.",
    ),
    _rule(
        "012",
        "deferred",
        "Duplicate handoff hijacking claim",
        "No hijacking verdict; basic call shape is 001.",
        ("ORG-001",),
    ),
    _rule(
        "013",
        "deferred",
        "Duplicate dynamic routing claim",
        "No model-controlled routing verdict; basic call shape is 002.",
        ("ORG-002",),
    ),
    _rule(
        "014",
        "deferred",
        "Duplicate shared-state injection claim",
        "No injection verdict; basic state-operation shape is 003.",
        ("ORG-003",),
    ),
    _rule(
        "015",
        "deferred",
        "Duplicate cross-agent leakage claim",
        "No confidentiality/authorization policy; memory-like payload syntax is 004.",
        ("ORG-004",),
    ),
    _rule(
        "016",
        "deferred",
        "Duplicate policy modification claim",
        "No second observation or unauthorized-update verdict.",
        ("ORG-005",),
    ),
    _rule(
        "017",
        "deferred",
        "Duplicate model-driven claim",
        "Same unresolved provenance requirement as 006.",
        ("ORG-006",),
    ),
    _rule(
        "018",
        "deferred",
        "Duplicate LangChain concept",
        "No duplicate import observation or guessed API.",
        ("ORG-007",),
    ),
    _rule(
        "019",
        "deferred",
        "Duplicate AutoGen concept",
        "No duplicate import observation or guessed API.",
        ("ORG-008",),
    ),
    _rule(
        "020",
        "deferred",
        "Duplicate MCP concept",
        "Same unsupported schema boundary as 009.",
        ("ORG-009",),
    ),
    _rule(
        "021",
        "deferred",
        "Duplicate persistence concept",
        "No duplicate observation or inferred storage behavior.",
        ("ORG-010",),
    ),
    _rule(
        "022",
        "deferred",
        "Duplicate leakage concept",
        "Same unresolved confidentiality/authorization boundary as 004.",
        ("ORG-004",),
    ),
)
BY_ID = {rule.rule_id: rule for rule in RULES}
CATALOG_SHA256 = sha256_bytes(("\n".join(rule.model_dump_json() for rule in RULES)).encode())
LEGACY_MARKERS = {
    "ORG-099": "retired diagnostic; parse/resource failure is a state, not a finding",
    "ORG-MCP-001": "deferred ad hoc state-store marker; no assumed MCP schema",
}
