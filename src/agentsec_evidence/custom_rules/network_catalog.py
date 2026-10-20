"""Versioned coverage registry: an ID does not imply an implemented vulnerability check."""

from typing import Literal

from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.models.contracts import ContractModel


class NetworkRule(ContractModel):
    rule_id: str
    status: Literal["active-condition", "inventory-only", "deferred"]
    title: str
    boundary: str
    priority: Literal["low", "medium"] | None
    remediation: str | None


def _rule(
    suffix: str,
    title: str,
    boundary: str,
    *,
    status: Literal["active-condition", "inventory-only", "deferred"] = "active-condition",
    priority: Literal["low", "medium"] | None = "medium",
    remediation: str
    | None = "Review the recorded argument and its permitted use at this call site.",
) -> NetworkRule:
    return NetworkRule(
        rule_id=f"NET-DATA-{suffix}",
        status=status,
        title=title,
        boundary=boundary,
        priority=priority if status == "active-condition" else None,
        remediation=remediation if status == "active-condition" else None,
    )


RULES = (
    _rule("001", "Nonliteral HTTP destination expression", "Not proof of caller control or SSRF."),
    _rule(
        "002",
        "Credential-shaped material in a URL or query",
        "Not verified secret validity or flow.",
        remediation="Avoid credentials in URLs; review authenticated channels and log exposure.",
    ),
    _rule(
        "003",
        "Interpolated URL authority",
        "Authority includes user information and port, not just host.",
    ),
    _rule(
        "004",
        "Explicit response streaming",
        "Does not establish a leak or unsafe buffering.",
        status="inventory-only",
    ),
    _rule(
        "005",
        "Credential-like identifier in logging or print",
        "Name heuristic, not secret tracing.",
        priority="low",
        remediation="Review data classification; omit sensitive values from logs.",
    ),
    _rule(
        "006",
        "Agent-specific external-service dispatch",
        "Needs an admitted framework/API contract.",
        status="deferred",
    ),
    _rule(
        "101",
        "Nonliteral WebSocket URI",
        "Not proof of hijacking, hostile origin or caller control.",
    ),
    _rule("102", "Nonliteral gRPC channel target", "Not proof of unauthorized service access."),
    _rule(
        "103",
        "Nonliteral S3 bucket or key",
        "Inline boto3 S3 client get/put_object only; no IAM claim.",
    ),
    _rule(
        "104",
        "Streaming chunk tampering",
        "Needs response typing, framing and an integrity protocol.",
        status="deferred",
    ),
    _rule(
        "105",
        "Explicit TLS verification setting",
        "Records true/false/other; no fingerprinting claim.",
        status="inventory-only",
    ),
    _rule(
        "106",
        "Request replay resistance",
        "Requires operation semantics and server-side guarantees.",
        status="deferred",
    ),
    _rule(
        "107",
        "Interpolated DNS query name",
        "Not evidence of covert exfiltration.",
        priority="low",
        remediation="Review which data enters DNS names and approved resolvers.",
    ),
    _rule(
        "108",
        "SPIFFE_ID environment read",
        "Not proof of service-mesh membership or effective mTLS.",
        status="inventory-only",
    ),
    _rule(
        "109", "Nonliteral explicit proxy configuration", "Not proof of MITM or an untrusted proxy."
    ),
    _rule(
        "110",
        "Credential-like environment read in URL/query expression",
        "Syntactic containment only; no cross-file flow or verified credential.",
        remediation="Keep credentials out of URLs; do not obfuscate or encode them as a defense.",
    ),
    _rule(
        "111",
        "Chunk framing integrity",
        "Requires typed stream and framing-protocol context.",
        status="deferred",
    ),
    _rule(
        "112",
        "LLM-selected service routing",
        "Needs actual routing APIs, source provenance and policy.",
        status="deferred",
    ),
)
BY_ID = {rule.rule_id: rule for rule in RULES}
CATALOG_SHA256 = sha256_bytes(("\n".join(rule.model_dump_json() for rule in RULES) + "\n").encode())
