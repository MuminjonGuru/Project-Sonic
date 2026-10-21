"""Versioned interpretation of the 18 submitted memory/state rule IDs."""

from typing import Literal

from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.models.contracts import ContractModel


class MemoryRule(ContractModel):
    rule_id: str
    status: Literal["active-condition", "inventory-only", "deferred"]
    title: str
    boundary: str
    priority: Literal["low", "medium"] | None = None


def _rule(
    suffix: str,
    status: Literal["active-condition", "inventory-only", "deferred"],
    title: str,
    boundary: str,
    priority: Literal["low", "medium"] | None = None,
) -> MemoryRule:
    return MemoryRule(
        rule_id=f"MEM-SEC-{suffix}",
        status=status,
        title=title,
        boundary=boundary,
        priority=priority,
    )


RULES = (
    _rule(
        "001",
        "inventory-only",
        "Memory persistence naming cue",
        "Name only; no proven persistence, file destination or framework semantics.",
    ),
    _rule(
        "002",
        "deferred",
        "Shared-state tampering",
        "Needs actual storage, writer provenance and isolation/access policy.",
    ),
    _rule(
        "003",
        "deferred",
        "Context injection",
        "Variable names cannot establish trust, influence or successful injection.",
    ),
    _rule(
        "004",
        "active-condition",
        "Credential-like value in serialization input",
        "Identifier heuristic only; no confirmed secret, storage or exposure.",
        "low",
    ),
    _rule(
        "005",
        "inventory-only",
        "LangChain-family import declaration",
        "Import spelling, not installed version, framework execution or memory security.",
    ),
    _rule(
        "006",
        "inventory-only",
        "AutoGen-family import declaration",
        "Import spelling, not runtime support or memory security.",
    ),
    _rule(
        "007",
        "deferred",
        "MCP state-store security",
        "No assumed MCP state/permission schema; existing analyzer retains MCP ownership.",
    ),
    _rule(
        "008",
        "inventory-only",
        "Memory-like input to stream serialization",
        "Name heuristic and stream argument; not full-history content or disk persistence.",
    ),
    _rule(
        "009",
        "inventory-only",
        "Memory/context reference in assignment",
        "Syntactic reference, not actual cross-turn influence or injection.",
    ),
    _rule(
        "010",
        "inventory-only",
        "Memory-like input to serialization",
        "Serialization format is not a vulnerability or evidence of later unsafe loading.",
    ),
    _rule(
        "101",
        "inventory-only",
        "Memory slice or bounded-context setting",
        "No token counts, model capacity or overflow measurement.",
    ),
    _rule(
        "102",
        "inventory-only",
        "Summarization/compression naming cue",
        "No content-fidelity, confidentiality or poisoning verdict.",
    ),
    _rule(
        "103",
        "active-condition",
        "Memory-like expression passed to eval/exec",
        "Name-based direct expression only; no provenance, taint or exploitability.",
        "medium",
    ),
    _rule(
        "104",
        "active-condition",
        "Memory-like expression at output/body sink",
        "Direct print/log/HTTP-body syntax; no confidentiality or exfiltration proof.",
        "low",
    ),
    _rule(
        "105",
        "inventory-only",
        "Memory/state attribute assignment or update naming cue",
        "No proof the receiver is an agent or the update is unauthorized.",
    ),
    _rule(
        "106",
        "inventory-only",
        "Memory version/snapshot naming cue",
        "Versioning is not evidence of risk, integrity or rollback protection.",
    ),
    _rule(
        "107",
        "active-condition",
        "Nonliteral content in declared system message",
        "Literal role/content shape or resolved SystemMessage; no model use or poisoning proof.",
        "medium",
    ),
    _rule(
        "108",
        "inventory-only",
        "Session/user identifier naming cue",
        "No cross-session reuse, tenancy or authorization conclusion.",
    ),
)
BY_ID = {rule.rule_id: rule for rule in RULES}
CATALOG_SHA256 = sha256_bytes(("\n".join(rule.model_dump_json() for rule in RULES)).encode())
LEGACY_MARKERS = {
    "MEM-SEC-099": "retired diagnostic; malformed/failed input is state, not a finding",
    "MEM-SEC-MCP-001": "deferred ad hoc MCP state-store marker; no assumed schema",
}
