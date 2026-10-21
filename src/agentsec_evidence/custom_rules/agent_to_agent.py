"""Bounded agent-to-agent inventory; no vulnerability verdict from ordinary agent features."""

from __future__ import annotations

import ast
import re
from pathlib import PurePosixPath
from typing import Final, Literal

from pydantic import Field

from agentsec_evidence.agents.inputs import MAX_AST_NODES, MAX_INPUT_BYTES
from agentsec_evidence.agents.validation import canonical_artifact_path
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.custom_rules.agent_to_agent_catalog import BY_ID
from agentsec_evidence.custom_rules.python_static import SourceRange, location, raw_name
from agentsec_evidence.models.contracts import ContractModel, Sha256

VERSION: Final = "1.0.0"
MAX_RECORDS = 1000
MAX_ARGUMENTS = 128
LIMITATIONS = (
    "Inventory-only development producer; no active vulnerability or security-condition rules.",
    "No target execution/imports, network, model calls, storage access or runtime call graph.",
    "Receiver/method/import spellings are heuristics, not verified framework or agent identity.",
    "No object/assignment alias resolution, interprocedural flow or model-output provenance.",
    "Argument shapes do not establish accepted parameters, trust, permissions or actual values.",
    "No impersonation, leakage, injection, authorization drift or safe-routing conclusion.",
    "A2A means generic naming inventory here, not support for the Agent2Agent protocol.",
    "Immediate call nesting is not actual agent-to-agent invocation or a trust/handoff graph.",
    "Property-copy syntax does not prove distinct objects/principals, values or privileges.",
    "Lambda/comprehension bodies, annotations, type aliases and dynamic reflection unsupported.",
    "MCP remains with the existing analyzer; no assumed state/permission schema.",
    "No suppression handling, risk/confidence score, snippets, identifier or value export.",
)

ArgumentSlot = Literal[
    "positional",
    "agent",
    "task",
    "prompt",
    "data",
    "context",
    "memory",
    "state",
    "response",
    "to",
    "trust",
    "role",
    "permissions",
    "other-keyword",
    "keyword-expansion",
]


class ArgumentShape(ContractModel):
    slot: ArgumentSlot
    ordinal: int = Field(ge=0)
    shape: Literal["literal-syntax", "nonliteral-syntax", "expanded"]
    immediate_call: bool


class AgentToAgentObservation(ContractModel):
    record_id: Sha256
    kind: str
    location: SourceRange
    detail: str
    rule_id: str | None = None
    argument_shapes: list[ArgumentShape] = Field(default_factory=list)


class AgentToAgentFileResult(ContractModel):
    path: str
    source_sha256: Sha256
    byte_length: int = Field(ge=0)
    state: Literal["analyzed", "malformed", "unsupported", "failed"]
    reason: str
    # The inventory-only v1 contract cannot carry invented vulnerability records.
    findings: list[object] | None = Field(max_length=0)
    inventory: list[AgentToAgentObservation]
    limitations_observed: list[AgentToAgentObservation]


_CALL = {"call", "route", "forward", "select"}
_IDENTITY = {"rewrite_system_prompt", "impersonate"}
_TRUST = {"authorize", "trust", "trust_chain"}
_SIGN = {"sign", "verify"}
_PERSIST = {"save_a2a", "persist_a2a", "write_a2a_config"}
_CANDIDATES = _CALL | _IDENTITY | _TRUST | _SIGN | {"share_memory", "update"}
_FRAMEWORKS = {
    "007": {"langchain", "langchain_core", "langchain_classic", "langchain_community", "langgraph"},
    "008": {"autogen", "autogen_core", "autogen_agentchat", "autogen_ext"},
}
_SLOTS: dict[str, ArgumentSlot] = {
    "agent": "agent",
    "task": "task",
    "prompt": "prompt",
    "data": "data",
    "context": "context",
    "memory": "memory",
    "state": "state",
    "response": "response",
    "to": "to",
    "trust": "trust",
    "role": "role",
    "permissions": "permissions",
}


def _literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(item, ast.Constant) for item in node.values)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_literal(item) for item in node.elts)
    if isinstance(node, ast.Dict):
        return all(key is not None and _literal(key) for key in node.keys) and all(
            _literal(value) for value in node.values
        )
    return False


def _receiver(node: ast.AST) -> bool:
    name = raw_name(node)
    return (
        name is not None and re.fullmatch(r"agent(?:[1-9][0-9]*)?", name.split(".")[-1]) is not None
    )


def _agent_call(node: ast.AST) -> bool:
    if isinstance(node, ast.Await):
        node = node.value
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and _receiver(node.func.value)
        and node.func.attr in _CALL
    )


def _property(node: ast.AST, names: set[str]) -> bool:
    return isinstance(node, ast.Attribute) and node.attr in names and _receiver(node.value)


def _immediate_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) or (
        isinstance(node, ast.Await) and isinstance(node.value, ast.Call)
    )


def _shapes(node: ast.Call) -> list[ArgumentShape]:
    if len(node.args) + len(node.keywords) > MAX_ARGUMENTS:
        raise ValueError("Argument-shape budget exceeded")
    shapes: list[ArgumentShape] = []
    for index, value in enumerate(node.args):
        shapes.append(
            ArgumentShape(
                slot="positional",
                ordinal=index,
                shape="expanded"
                if isinstance(value, ast.Starred)
                else ("literal-syntax" if _literal(value) else "nonliteral-syntax"),
                immediate_call=_immediate_call(value),
            )
        )
    for index, item in enumerate(node.keywords):
        shapes.append(
            ArgumentShape(
                slot="keyword-expansion"
                if item.arg is None
                else _SLOTS.get(item.arg, "other-keyword"),
                ordinal=index,
                shape="expanded"
                if item.arg is None
                else ("literal-syntax" if _literal(item.value) else "nonliteral-syntax"),
                immediate_call=_immediate_call(item.value),
            )
        )
    return shapes


class _Analyzer(ast.NodeVisitor):
    def __init__(self, path: str, digest: str) -> None:
        self.path, self.digest = path, digest
        self.inventory: list[AgentToAgentObservation] = []
        self.issues: list[AgentToAgentObservation] = []
        self.seen: set[str] = set()

    def observe(
        self,
        node: ast.AST,
        kind: str,
        detail: str,
        *,
        rule: str | None = None,
        issue: bool = False,
        shapes: list[ArgumentShape] | None = None,
    ) -> None:
        rule_id = f"A2A-{rule}" if rule else None
        if rule_id and BY_ID[rule_id].status != "inventory-only":
            raise ValueError("Deferred rule cannot emit an inventory observation")
        span = location(node)
        arguments_json = "\n".join(item.model_dump_json() for item in shapes or [])
        digest = sha256_bytes(
            f"{VERSION}:{self.path}:{self.digest}:{rule_id}:{kind}:{issue}:"
            f"{span.model_dump_json()}:{arguments_json}".encode()
        )
        if digest in self.seen:
            return
        if len(self.seen) >= MAX_RECORDS:
            raise ValueError("Observation budget exceeded")
        self.seen.add(digest)
        (self.issues if issue else self.inventory).append(
            AgentToAgentObservation(
                record_id=digest,
                kind=kind,
                detail=detail,
                location=span,
                rule_id=rule_id,
                argument_shapes=shapes or [],
            )
        )

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for value in [*node.decorator_list, *node.args.defaults, *node.args.kw_defaults]:
            if value is not None:
                self.visit(value)
        for statement in node.body:
            self.visit(statement)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for value in [*node.decorator_list, *node.bases, *node.keywords]:
            self.visit(value)
        for statement in node.body:
            self.visit(statement)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._copy(node, [node.target], node.value)
        self.visit(node.target)
        if node.value is not None:
            self.visit(node.value)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._copy(node, node.targets, node.value)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if _property(node.target, {"context", "memory", "state", "input", "role", "permissions"}):
            self.observe(
                node,
                "unsupported-property-flow",
                "Augmented assignment is outside the direct-copy treatment",
                issue=True,
            )
        self.generic_visit(node)

    def _copy(self, node: ast.AST, targets: list[ast.expr], value: ast.expr) -> None:
        # Only direct property copies; no tuple unpacking, aliases or inferred temporal drift.
        for target in targets:
            rule = None
            if _property(target, {"context", "memory", "state", "input"}) and _property(
                value, {"context", "memory", "state", "input"}
            ):
                rule = "004"
            elif (
                isinstance(target, ast.Attribute)
                and _property(target, {"role", "permissions"})
                and _property(value, {target.attr})
            ):
                rule = "105"
            if rule:
                self.observe(
                    target,
                    "direct-property-copy",
                    "Assignment syntax only; identity, value and authorization unverified",
                    rule=rule,
                )
                self.observe(
                    node,
                    "unresolved-property-semantics",
                    "No receiver identity, descriptor behavior or policy established",
                    issue=True,
                )
            elif any(
                _property(item, {"context", "memory", "state", "input", "role", "permissions"})
                for item in ast.walk(target)
            ):
                self.observe(
                    node,
                    "unsupported-property-flow",
                    "Source outside the direct property-copy treatment",
                    issue=True,
                )

    def visit_TypeAlias(self, node: ast.TypeAlias) -> None:
        self.observe(node, "unsupported-scope", "Type alias expression not analyzed", issue=True)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self.observe(node, "unsupported-scope", "Lambda body not analyzed", issue=True)
        for value in [*node.args.defaults, *node.args.kw_defaults]:
            if value is not None:
                self.visit(value)

    def visit_ListComp(self, node: ast.AST) -> None:
        self.observe(node, "unsupported-scope", "Comprehension not analyzed", issue=True)

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp

    def _import(self, node: ast.AST, modules: list[str]) -> None:
        for suffix, roots in _FRAMEWORKS.items():
            if any(module.split(".")[0] in roots for module in modules):
                self.observe(node, "import-declaration", "Framework-family spelling", rule=suffix)

    def visit_Import(self, node: ast.Import) -> None:
        self._import(node, [item.name for item in node.names])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if not node.level and node.module:
            self._import(node, [node.module])
        if any(item.name == "*" for item in node.names):
            self.observe(node, "unresolved-import", "Wildcard APIs not resolved", issue=True)

    def visit_Call(self, node: ast.Call) -> None:
        leaf = (
            node.func.id
            if isinstance(node.func, ast.Name)
            else (node.func.attr if isinstance(node.func, ast.Attribute) else "")
        )
        direct = isinstance(node.func, ast.Attribute) and _receiver(node.func.value)
        rule: str | None = None
        kind = "call-naming"
        if leaf in _PERSIST:
            rule, kind = "010", "persistence-naming"
        elif direct:
            if leaf in _CALL:
                rule, kind = "001", "agent-call-naming"
            elif leaf in _IDENTITY or (
                leaf == "update" and any(item.arg == "prompt" for item in node.keywords)
            ):
                rule, kind = "002", "identity-update-naming"
            elif leaf in _TRUST:
                rule, kind = "003", "trust-operation-naming"
            elif leaf == "share_memory":
                rule, kind = "004", "state-sharing-naming"
            elif leaf in _SIGN:
                rule, kind = "005", "signing-verification-naming"
        if rule:
            shapes = _shapes(node)
            self.observe(
                node,
                kind,
                "Call syntax only; receiver/API semantics unverified",
                rule=rule,
                shapes=shapes,
            )
            self.observe(
                node,
                "unresolved-api",
                "No established receiver type or callable signature",
                issue=True,
            )
            keys = [item.arg for item in node.keywords if item.arg is not None]
            expanded = any(item.shape == "expanded" for item in shapes)
            ambiguous = expanded or len(keys) != len(set(keys))
            if ambiguous:
                self.observe(
                    node,
                    "unresolved-arguments",
                    "Expansion/duplicate keys prevent value attribution",
                    issue=True,
                )
            if (
                direct
                and leaf in _CALL
                and any(
                    _agent_call(value)
                    for value in [*node.args, *(item.value for item in node.keywords)]
                )
            ):
                self.observe(
                    node,
                    "immediate-agent-like-nested-call",
                    "Immediate expression nesting only; no executed graph or principal identity",
                    rule="101",
                    shapes=shapes,
                )
        elif direct or leaf in _CANDIDATES:
            self.observe(
                node,
                "unsupported-agent-candidate",
                "Method/receiver spelling outside supported inventory treatment",
                issue=True,
            )
        self.generic_visit(node)


def scan_source(data: bytes, *, path: str) -> AgentToAgentFileResult:
    """Inspect explicit bytes; untrusted source must use the isolated worker."""
    canonical_artifact_path(path)
    digest = sha256_bytes(data)
    state: Literal["analyzed", "malformed", "unsupported", "failed"] = "analyzed"
    reason = "Bounded agent-to-agent inventory only; no security detector is enabled"
    findings: list[object] | None = None
    inventory: list[AgentToAgentObservation] = []
    issues: list[AgentToAgentObservation] = []
    if PurePosixPath(path).suffix != ".py":
        state, reason = "unsupported", "Only Python source; no MCP or live state parsing"
    elif len(data) > MAX_INPUT_BYTES:
        state, reason = "failed", "Input exceeds 256 KiB"
    else:
        try:
            tree = ast.parse(
                data.decode("utf-8", errors="strict"), filename="<agent-to-agent-input>"
            )
            if sum(1 for _ in ast.walk(tree)) > MAX_AST_NODES:
                raise ValueError("AST budget exceeded")
            analyzer = _Analyzer(path, digest)
            analyzer.visit(tree)
            findings = []

            def key(item: AgentToAgentObservation) -> tuple[int, int, str, str]:
                return (
                    item.location.start_line,
                    item.location.start_utf8_byte_column,
                    item.rule_id or "",
                    item.kind,
                )

            inventory = sorted(analyzer.inventory, key=key)
            issues = sorted(analyzer.issues, key=key)
        except (SyntaxError, UnicodeError):
            state, reason = "malformed", "Invalid Python syntax or UTF-8"
        except (ValueError, RecursionError, MemoryError):
            state, reason = "failed", "Parser or observation resource guard reached"
    return AgentToAgentFileResult(
        path=path,
        source_sha256=digest,
        byte_length=len(data),
        state=state,
        reason=reason,
        findings=findings,
        inventory=inventory,
        limitations_observed=issues,
    )
