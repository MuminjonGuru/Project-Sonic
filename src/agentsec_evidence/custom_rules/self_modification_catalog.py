"""All 27 supplied IDs, including duplicate concepts that do not emit twice."""

from typing import Literal

from pydantic import Field

from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.models.contracts import ContractModel


class SelfModificationRule(ContractModel):
    rule_id: str
    status: Literal["active-condition", "inventory-only", "deferred"]
    title: str
    boundary: str
    priority: Literal["low", "medium"] | None = None
    related_ids: list[str] = Field(default_factory=list)


def _rule(
    suffix: str,
    status: Literal["active-condition", "inventory-only", "deferred"],
    title: str,
    boundary: str,
    priority: Literal["low", "medium"] | None = None,
    related: tuple[str, ...] = (),
) -> SelfModificationRule:
    return SelfModificationRule(
        rule_id=f"SELF-MOD-{suffix}",
        status=status,
        title=title,
        boundary=boundary,
        priority=priority,
        related_ids=list(related),
    )


RULES = (
    _rule(
        "001",
        "active-condition",
        "Nonliteral prompt-like attribute assignment",
        "Attribute spelling and value syntax only; no agent identity, trust or injection proof.",
        "low",
    ),
    _rule(
        "002",
        "inventory-only",
        "Tool update or generation naming cue",
        "No verified tool mutation, model involvement or unsafe generated code.",
    ),
    _rule(
        "003",
        "inventory-only",
        "Memory strategy assignment naming cue",
        "No backend, security policy or effective storage change established.",
    ),
    _rule(
        "004",
        "inventory-only",
        "Context-limit setting syntax",
        "No token count, model limit, overflow or production safety conclusion.",
    ),
    _rule(
        "005",
        "inventory-only",
        "Self-evaluation naming cue",
        "No proof of autonomous evaluation or absent external review.",
    ),
    _rule(
        "006",
        "inventory-only",
        "Self/state persistence naming cue",
        "No actual write, storage destination or durable modification established.",
    ),
    _rule("007", "deferred", "Model-driven modification", "Requires model-output provenance."),
    _rule(
        "008",
        "inventory-only",
        "LangChain-family import declaration",
        "Import spelling only; no installed framework or supported mutation API.",
    ),
    _rule(
        "009",
        "inventory-only",
        "AutoGen-family import declaration",
        "Import spelling only; no installed framework or supported mutation API.",
    ),
    _rule(
        "010",
        "deferred",
        "MCP self-modification",
        "Existing analyzer owns MCP; no assumed self/state/permission schema.",
    ),
    _rule(
        "011",
        "active-condition",
        "Response-like expression passed to eval/exec",
        "Direct name heuristic; no proof that the value is model output or attacker controlled.",
        "medium",
        ("TOOL-EXEC-001", "TOOL-EXEC-002"),
    ),
    _rule(
        "012",
        "inventory-only",
        "Validation or approval-hook naming cue",
        "Presence does not prove correctness; absence does not prove missing authorization.",
    ),
    _rule(
        "013",
        "inventory-only",
        "Version, diff or rollback naming cue",
        "Not a validated integrity control or evidence of drift.",
    ),
    _rule(
        "014",
        "inventory-only",
        "Update-named call lexically inside a loop",
        "No loop termination, recursion, reachability or runtime execution conclusion.",
    ),
    _rule(
        "015",
        "deferred",
        "Context overflow during modification",
        "Requires actual model/context accounting; settings remain inventory under 004.",
        related=("SELF-MOD-004",),
    ),
    _rule(
        "101",
        "active-condition",
        "Memory-like expression passed to eval/exec",
        "Overlaps MEM-SEC-103; not an independent detection or proof of self-modification.",
        "medium",
        ("MEM-SEC-103", "TOOL-EXEC-001"),
    ),
    _rule(
        "102",
        "deferred",
        "Duplicate validation concept",
        "Retained, non-emitting; bounded naming observation is 012.",
        related=("SELF-MOD-012",),
    ),
    _rule(
        "103",
        "deferred",
        "Duplicate drift concept",
        "Retained, non-emitting; bounded naming observation is 013.",
        related=("SELF-MOD-013",),
    ),
    _rule(
        "104",
        "deferred",
        "Duplicate loop concept",
        "Retained, non-emitting; bounded loop observation is 014.",
        related=("SELF-MOD-014",),
    ),
    _rule(
        "105",
        "deferred",
        "Duplicate overflow concept",
        "No token/model evidence; do not emit a second settings alert.",
        related=("SELF-MOD-015", "SELF-MOD-004"),
    ),
    _rule(
        "106",
        "deferred",
        "Duplicate injection concept",
        "Direct prompt and code syntax only under 001/011; no injection verdict.",
        related=("SELF-MOD-001", "SELF-MOD-011"),
    ),
    _rule(
        "107",
        "deferred",
        "Cross-framework mismatch",
        "Coexisting imports do not establish incompatible behavior; needs API/version contracts.",
    ),
    _rule(
        "108",
        "deferred",
        "Duplicate persistence concept",
        "Retained, non-emitting; bounded naming observation is 006.",
        related=("SELF-MOD-006",),
    ),
    _rule(
        "109",
        "deferred",
        "Duplicate model-driven concept",
        "Same unresolved provenance requirement as 007.",
        related=("SELF-MOD-007",),
    ),
    _rule(
        "110",
        "deferred",
        "Duplicate LangChain concept",
        "No second import observation or guessed mutation API.",
        related=("SELF-MOD-008",),
    ),
    _rule(
        "111",
        "deferred",
        "Duplicate AutoGen concept",
        "No second import observation or guessed mutation API.",
        related=("SELF-MOD-009",),
    ),
    _rule(
        "112",
        "deferred",
        "Duplicate MCP concept",
        "Same unsupported schema boundary as 010.",
        related=("SELF-MOD-010",),
    ),
)
BY_ID = {rule.rule_id: rule for rule in RULES}
CATALOG_SHA256 = sha256_bytes(("\n".join(rule.model_dump_json() for rule in RULES)).encode())
LEGACY_MARKERS = {
    "SELF-MOD-099": "retired parse diagnostic; failure is a file state, not a finding",
    "SELF-MOD-MCP-001": "deferred ad hoc MCP store marker; no assumed schema",
}
