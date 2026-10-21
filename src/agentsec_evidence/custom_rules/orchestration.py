"""Bounded orchestration inventory; no vulnerability verdict from ordinary agent features."""

from __future__ import annotations

import ast
import re
from pathlib import PurePosixPath
from typing import Final, Literal

from pydantic import Field

from agentsec_evidence.agents.inputs import MAX_AST_NODES, MAX_INPUT_BYTES
from agentsec_evidence.agents.validation import canonical_artifact_path
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.custom_rules.orchestration_catalog import BY_ID
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
    "No hijacking, leakage, injection, authorization or safe-routing conclusion.",
    "Immediate call nesting is not actual agent-to-agent invocation or a handoff count.",
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
    "other-keyword",
    "keyword-expansion",
]


class ArgumentShape(ContractModel):
    slot: ArgumentSlot
    ordinal: int = Field(ge=0)
    shape: Literal["literal-syntax", "nonliteral-syntax", "expanded"]
    immediate_call: bool


class OrchestrationObservation(ContractModel):
    record_id: Sha256
    kind: str
    location: SourceRange
    detail: str
    rule_id: str | None = None
    argument_shapes: list[ArgumentShape] = Field(default_factory=list)


class OrchestrationFileResult(ContractModel):
    path: str
    source_sha256: Sha256
    byte_length: int = Field(ge=0)
    state: Literal["analyzed", "malformed", "unsupported", "failed"]
    reason: str
    # The inventory-only v1 contract cannot carry invented vulnerability records.
    findings: list[object] | None = Field(max_length=0)
    inventory: list[OrchestrationObservation]
    limitations_observed: list[OrchestrationObservation]


_HANDOFF = {"send", "forward", "handoff", "share"}
_ROUTE = {"route", "select", "dispatch", "choose"}
_STATE = {"update", "get", "persist", "store"}
_POLICY = {"update_routing_policy", "rewrite_handoff_rules", "tune_performance", "self_evaluate"}
_PERSIST = {"save_orchestrator", "persist_orchestrator", "write_orchestrator_config"}
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


def _memory_like(node: ast.AST) -> bool:
    if isinstance(node, (ast.Name, ast.Attribute)):
        name = node.id if isinstance(node, ast.Name) else node.attr
        words = set(re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).casefold().split("_"))
        return bool(words & {"memory", "context", "state", "history", "messages"}) or (
            isinstance(node, ast.Attribute) and _memory_like(node.value)
        )
    if isinstance(node, ast.Subscript):
        return _memory_like(node.value)
    if isinstance(node, (ast.List, ast.Tuple)):
        return any(_memory_like(item) for item in node.elts)
    if isinstance(node, ast.Dict):
        return any(_memory_like(item) for item in node.values)
    if isinstance(node, ast.JoinedStr):
        return any(
            isinstance(item, ast.FormattedValue) and _memory_like(item.value)
            for item in node.values
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _memory_like(node.left) or _memory_like(node.right)
    return False


def _receiver(node: ast.AST) -> bool:
    name = raw_name(node)
    return name is not None and name.split(".")[-1] == "orchestrator"


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
        self.inventory: list[OrchestrationObservation] = []
        self.issues: list[OrchestrationObservation] = []
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
        rule_id = f"ORG-{rule}" if rule else None
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
            OrchestrationObservation(
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
        self.visit(node.target)
        if node.value is not None:
            self.visit(node.value)

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
        state = (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr == "state"
            and _receiver(node.func.value.value)
        )
        rule: str | None = None
        kind = "call-naming"
        if leaf in _PERSIST:
            rule, kind = "010", "persistence-naming"
        elif state and leaf in _STATE:
            rule, kind = "003", "state-operation-naming"
        elif direct:
            if leaf in _HANDOFF:
                rule, kind = "001", "handoff-naming"
            elif leaf in _ROUTE:
                rule, kind = "002", "routing-naming"
            elif leaf in _POLICY:
                rule, kind = "005", "policy-update-naming"
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
            if rule != "010" and any(item.immediate_call for item in shapes):
                self.observe(
                    node,
                    "immediate-nested-call",
                    "Immediate argument expression only",
                    rule="011",
                    shapes=shapes,
                )
            if direct and leaf in _HANDOFF and not ambiguous:
                payloads = [
                    item.value
                    for item in node.keywords
                    if item.arg in {"data", "prompt", "context", "memory", "state"}
                ]
                if any(_memory_like(value) for value in payloads):
                    self.observe(
                        node,
                        "memory-like-payload",
                        "Direct name heuristic; no cross-agent confidentiality verdict",
                        rule="004",
                    )
                if node.args:
                    self.observe(
                        node,
                        "unresolved-payload-position",
                        "Unknown API positional parameters not interpreted as payload",
                        issue=True,
                    )
                if any(
                    isinstance(item, (ast.Call, ast.IfExp, ast.Starred))
                    or (isinstance(item, ast.Dict) and None in item.keys)
                    for value in payloads
                    for item in ast.walk(value)
                ):
                    self.observe(
                        node,
                        "unresolved-payload-flow",
                        "Opaque payload transformations or selectors not traced",
                        issue=True,
                    )
        elif direct or state or leaf in _HANDOFF | _ROUTE | _POLICY:
            self.observe(
                node,
                "unsupported-orchestration-candidate",
                "Method/receiver spelling outside supported inventory treatment",
                issue=True,
            )
        self.generic_visit(node)


def scan_source(data: bytes, *, path: str) -> OrchestrationFileResult:
    """Inspect explicit bytes; untrusted source must use the isolated worker."""
    canonical_artifact_path(path)
    digest = sha256_bytes(data)
    state: Literal["analyzed", "malformed", "unsupported", "failed"] = "analyzed"
    reason = "Bounded orchestration inventory only; no security detector is enabled"
    findings: list[object] | None = None
    inventory: list[OrchestrationObservation] = []
    issues: list[OrchestrationObservation] = []
    if PurePosixPath(path).suffix != ".py":
        state, reason = "unsupported", "Only Python source; no MCP or live state parsing"
    elif len(data) > MAX_INPUT_BYTES:
        state, reason = "failed", "Input exceeds 256 KiB"
    else:
        try:
            tree = ast.parse(
                data.decode("utf-8", errors="strict"), filename="<orchestration-input>"
            )
            if sum(1 for _ in ast.walk(tree)) > MAX_AST_NODES:
                raise ValueError("AST budget exceeded")
            analyzer = _Analyzer(path, digest)
            analyzer.visit(tree)
            findings = []

            def key(item: OrchestrationObservation) -> tuple[int, int, str, str]:
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
    return OrchestrationFileResult(
        path=path,
        source_sha256=digest,
        byte_length=len(data),
        state=state,
        reason=reason,
        findings=findings,
        inventory=inventory,
        limitations_observed=issues,
    )
