"""All 26 supplied A2A IDs, without treating ordinary agent features as vulnerabilities."""

from typing import Literal

from pydantic import Field

from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.models.contracts import ContractModel


class AgentToAgentRule(ContractModel):
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
) -> AgentToAgentRule:
    return AgentToAgentRule(
        rule_id=f"A2A-{suffix}",
        status=status,
        title=title,
        boundary=boundary,
        related_ids=list(related),
    )


RULES = (
    _rule(
        "001",
        "inventory-only",
        "Agent-like call or routing syntax",
        "Receiver spelling and argument shape; not actual agent invocation or safe routing.",
    ),
    _rule(
        "002",
        "inventory-only",
        "Prompt-update or identity-operation naming",
        "No impersonation, spoofing, model control or unauthorized prompt change established.",
    ),
    _rule(
        "003",
        "inventory-only",
        "Trust or authorization operation naming",
        "No trust graph, transitive grant, trust score or authorization defect established.",
    ),
    _rule(
        "004",
        "inventory-only",
        "State-sharing call or direct property-copy syntax",
        "No distinct principals, confidential content, executed sharing or leakage established.",
    ),
    _rule(
        "005",
        "inventory-only",
        "Signing or verification operation naming",
        "A verify/sign call is not a vulnerability or proof of valid cryptographic protection.",
    ),
    _rule(
        "006",
        "deferred",
        "Model-driven A2A decisions",
        "Requires independently established model-output provenance and decision flow.",
    ),
    _rule(
        "007",
        "inventory-only",
        "LangChain-family import declaration",
        "Import spelling only, not installed/runtime framework or actual multi-agent behavior.",
    ),
    _rule(
        "008",
        "inventory-only",
        "AutoGen-family import declaration",
        "Import spelling only; no API compatibility or runtime agent identity.",
    ),
    _rule(
        "009",
        "deferred",
        "MCP A2A security",
        "Existing MCP analyzer owns config checks; no guessed trust/state-sharing schema.",
    ),
    _rule(
        "010",
        "inventory-only",
        "A2A persistence naming",
        "No storage location, actual write, durable trust state or security verdict.",
    ),
    _rule(
        "011",
        "deferred",
        "Model-driven impersonation",
        "Duplicate naming cue; neither model origin nor impersonation established.",
        ("A2A-002",),
    ),
    _rule(
        "012",
        "deferred",
        "Model-determined trust",
        "Duplicate trust call; no model provenance or trust-graph semantics.",
        ("A2A-003",),
    ),
    _rule(
        "013",
        "deferred",
        "Duplicate cross-agent state claim",
        "No second observation or leakage verdict.",
        ("A2A-004",),
    ),
    _rule(
        "014",
        "deferred",
        "Duplicate signing/authorization claim",
        "Partition authorize into 003 and sign/verify into 005; do not double count.",
        ("A2A-003", "A2A-005"),
    ),
    _rule(
        "015",
        "deferred",
        "Duplicate agent-call claim",
        "No second observation for the same call.",
        ("A2A-001",),
    ),
    _rule(
        "016",
        "deferred",
        "Duplicate impersonation claim",
        "Naming is not impersonation.",
        ("A2A-002",),
    ),
    _rule(
        "017",
        "deferred",
        "Duplicate trust-chain claim",
        "Naming is not a trust-chain graph.",
        ("A2A-003",),
    ),
    _rule(
        "018",
        "deferred",
        "Duplicate state-sharing claim",
        "No confidentiality or authorization policy.",
        ("A2A-004",),
    ),
    _rule(
        "101",
        "inventory-only",
        "Immediate agent-like call nested in an agent-like call",
        "AST expression nesting, not executed call graph, independent agents or a trust chain.",
    ),
    _rule(
        "102",
        "deferred",
        "Duplicate model-driven identity claim",
        "No model origin or security policy established.",
        ("A2A-002", "A2A-006"),
    ),
    _rule(
        "103",
        "deferred",
        "Duplicate model-driven trust claim",
        "No model origin or trust policy established.",
        ("A2A-003", "A2A-006"),
    ),
    _rule(
        "104",
        "deferred",
        "Duplicate cross-agent state claim",
        "No second observation; Unicode arrows in comments are not Python data flow.",
        ("A2A-004",),
    ),
    _rule(
        "105",
        "inventory-only",
        "Direct role/permissions property-copy syntax",
        "No privilege change, effective authorization, temporal drift or distinct identity proved.",
    ),
    _rule("106", "deferred", "Duplicate agent-call claim", "No second observation.", ("A2A-001",)),
    _rule("107", "deferred", "Duplicate identity claim", "No second observation.", ("A2A-002",)),
    _rule("108", "deferred", "Duplicate trust claim", "No second observation.", ("A2A-003",)),
)
BY_ID = {rule.rule_id: rule for rule in RULES}
CATALOG_SHA256 = sha256_bytes(("\n".join(rule.model_dump_json() for rule in RULES)).encode())
LEGACY_MARKERS = {
    "A2A-099": "retired diagnostic; malformed/resource failure is a state, not a finding",
    "A2A-MCP-001": "deferred ad hoc trust/state-sharing marker; no assumed MCP schema",
}
