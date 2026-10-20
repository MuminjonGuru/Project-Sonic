"""Coverage registry for the supplied filesystem draft, not an inferred 24-rule catalog."""

from typing import Literal

from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.models.contracts import ContractModel


class FilesystemRule(ContractModel):
    rule_id: str
    status: Literal["active-condition", "inventory-only", "deferred"]
    title: str
    boundary: str
    priority: Literal["low", "medium"] | None


def _rule(
    suffix: str,
    title: str,
    boundary: str,
    *,
    status: Literal["active-condition", "inventory-only", "deferred"] = "active-condition",
    priority: Literal["low", "medium"] = "medium",
) -> FilesystemRule:
    return FilesystemRule(
        rule_id=f"FS-ACCESS-{suffix}",
        title=title,
        boundary=boundary,
        status=status,
        priority=priority if status == "active-condition" else None,
    )


RULES = (
    _rule("001", "Nonliteral filesystem path expression", "No claim of user/LLM control."),
    _rule(
        "002",
        "MCP filesystem write permissions",
        "Existing MCP analyzer owns admitted configs; no generic ACL schema inferred.",
        status="deferred",
    ),
    _rule(
        "003",
        "Nonliteral destination at a write-capable operation",
        "Not proof of arbitrary write, overwrite or missing validation.",
    ),
    _rule(
        "004",
        "Code/config suffix at a read operation",
        "Suffix is inventory, not execution or unsafe parsing.",
        status="inventory-only",
    ),
    _rule(
        "005",
        "Literal parent component at filesystem I/O",
        "Lexical POSIX/Windows interpretation; not proof of escape from an authorized root.",
    ),
    _rule(
        "006",
        "Credential-like identifier in a direct file write",
        "Name heuristic only; no secret validity, contents tracing or log duplication.",
        priority="low",
    ),
    _rule(
        "007",
        "Literal temporary/runtime path prefix",
        "Normal activity; neither safe-path exemption nor unexpected-write verdict.",
        status="inventory-only",
    ),
    _rule(
        "008",
        "Interpolated filesystem path syntax",
        "Counts formatted expressions; no entropy, volatility or LLM-origin score.",
        status="inventory-only",
    ),
    _rule(
        "009",
        "Literal write-path component counts",
        "Lexical structure only; depth does not establish risk.",
        status="inventory-only",
    ),
    _rule(
        "010",
        "MCP implicit permission interpretation",
        "Absent fields do not prove permissions; existing MCP boundary retained.",
        status="deferred",
    ),
    _rule(
        "011",
        "Direct file-read expression passed to eval/exec",
        "Syntax only; no proof of untrusted contents, reachability or exploitability.",
    ),
    _rule(
        "012",
        "State-like filename at a write operation",
        "Name heuristic, not verified agent memory or poisoning.",
        status="inventory-only",
    ),
)
BY_ID = {rule.rule_id: rule for rule in RULES}
LEGACY_MARKERS = {
    "FS-ACCESS-099": "Retired diagnostic: parsing failures are analysis state, not findings.",
    "FS-ACCESS-MCP-001": "Deferred legacy trust-score marker; no emission or inferred ACL.",
}
CATALOG_SHA256 = sha256_bytes(("\n".join(rule.model_dump_json() for rule in RULES) + "\n").encode())
