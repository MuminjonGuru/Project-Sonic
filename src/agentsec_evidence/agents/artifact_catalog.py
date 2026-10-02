from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict

from agentsec_evidence.models.contracts import ContractModel, NonEmpty

ArtifactFamily = Literal[
    "python-source",
    "mcp-config",
    "agent-config",
    "instructions",
    "skill",
    "memory-context",
    "identity-permissions",
    "dependencies",
    "iac",
]

FAMILIES: tuple[ArtifactFamily, ...] = (
    "python-source",
    "mcp-config",
    "agent-config",
    "instructions",
    "skill",
    "memory-context",
    "identity-permissions",
    "dependencies",
    "iac",
)


class PathRecognizer(ContractModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    recognizer_id: NonEmpty
    version: Literal["1"] = "1"
    family: ArtifactFamily
    selector: Literal["basename", "suffix"]
    pattern: NonEmpty
    candidate_format: NonEmpty
    framework_hint: str | None = None
    reference: NonEmpty
    reference_kind: Literal["official-documentation", "project-convention"]
    checked_on: Literal["2026-10-02"] = "2026-10-02"
    limitation: NonEmpty


CATALOG_VERSION: Literal["artifact-path-candidates-v1"] = "artifact-path-candidates-v1"
RECOGNIZERS: tuple[PathRecognizer, ...] = (
    PathRecognizer(
        recognizer_id="python-source-suffix",
        family="python-source",
        selector="suffix",
        pattern=".py",
        candidate_format="python-source",
        reference="https://docs.python.org/3.13/tutorial/modules.html",
        reference_kind="official-documentation",
        limitation="No syntax, tool binding, framework or data-flow analysis.",
    ),
    PathRecognizer(
        recognizer_id="langgraph-config-name",
        family="agent-config",
        selector="basename",
        pattern="langgraph.json",
        candidate_format="langgraph-config-json",
        framework_hint="LangGraph filename convention only",
        reference="https://docs.langchain.com/langsmith/cli",
        reference_kind="official-documentation",
        limitation="No schema validation or evidence that a deployment uses this file.",
    ),
    PathRecognizer(
        recognizer_id="claude-desktop-config-name",
        family="mcp-config",
        selector="basename",
        pattern="claude_desktop_config.json",
        candidate_format="claude-desktop-config-json",
        reference="https://modelcontextprotocol.io/docs/2026-07-28/develop/connect-local-servers",
        reference_kind="official-documentation",
        limitation="Client filename only; no mcpServers validation or protocol-wide convention.",
    ),
    PathRecognizer(
        recognizer_id="project-mcp-config-name",
        family="mcp-config",
        selector="basename",
        pattern="mcp.json",
        candidate_format="project-mcp-json-candidate",
        reference="docs/agent-artifact-contracts.md",
        reference_kind="project-convention",
        limitation="Authored fixture convention, not a universal MCP configuration filename.",
    ),
    PathRecognizer(
        recognizer_id="agents-instructions-name",
        family="instructions",
        selector="basename",
        pattern="AGENTS.md",
        candidate_format="agents-md",
        reference="https://agents.md/",
        reference_kind="official-documentation",
        limitation="No instruction interpretation, precedence resolution or safety judgment.",
    ),
    PathRecognizer(
        recognizer_id="skill-manifest-name",
        family="skill",
        selector="basename",
        pattern="SKILL.md",
        candidate_format="agent-skill-md",
        reference="https://agentskills.io/specification",
        reference_kind="official-documentation",
        limitation="No frontmatter validation, permission inference or script execution.",
    ),
    PathRecognizer(
        recognizer_id="uv-lock-name",
        family="dependencies",
        selector="basename",
        pattern="uv.lock",
        candidate_format="uv-lock",
        reference="https://docs.astral.sh/uv/concepts/projects/layout/",
        reference_kind="official-documentation",
        limitation="No package parsing or vulnerability matching; other lock formats unrecognized.",
    ),
    PathRecognizer(
        recognizer_id="terraform-hcl-suffix",
        family="iac",
        selector="suffix",
        pattern=".tf",
        candidate_format="terraform-hcl",
        reference="https://developer.hashicorp.com/terraform/language/files",
        reference_kind="official-documentation",
        limitation="No HCL parsing, module resolution or effective infrastructure assessment.",
    ),
    PathRecognizer(
        recognizer_id="terraform-json-suffix",
        family="iac",
        selector="suffix",
        pattern=".tf.json",
        candidate_format="terraform-json",
        reference="https://developer.hashicorp.com/terraform/language/files",
        reference_kind="official-documentation",
        limitation="No JSON parsing, module resolution or effective infrastructure assessment.",
    ),
)


def match_path(path: str) -> tuple[str, ...]:
    """Match literal, case-sensitive names anywhere in the supplied inventory."""
    name = path.rsplit("/", 1)[-1]
    return tuple(
        rule.recognizer_id
        for rule in RECOGNIZERS
        if (name == rule.pattern if rule.selector == "basename" else name.endswith(rule.pattern))
    )
