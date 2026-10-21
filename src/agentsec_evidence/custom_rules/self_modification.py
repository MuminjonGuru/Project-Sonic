"""Development-only self-modification syntax observations, not an agent behavior model."""

from __future__ import annotations

import ast
import re
from pathlib import PurePosixPath
from typing import Final, Literal

from pydantic import Field

from agentsec_evidence.agents.inputs import MAX_AST_NODES, MAX_INPUT_BYTES
from agentsec_evidence.agents.validation import canonical_artifact_path
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.custom_rules.python_static import (
    Bindings,
    Scope,
    SourceRange,
    arguments,
    location,
    raw_name,
)
from agentsec_evidence.custom_rules.self_modification_catalog import BY_ID
from agentsec_evidence.models.contracts import ContractModel, Sha256

VERSION: Final = "1.0.0"
MAX_RECORDS = 1000
LIMITATIONS = (
    "Development syntax observations, not verified vulnerabilities or agent self-modification.",
    "No target execution, model calls, filesystem writes, network or dynamic state inspection.",
    "Names do not prove receiver type, model output, attacker control, trust or reachability.",
    "No interprocedural/cross-file/assignment flow, sanitizer verification or object typing.",
    "Lambda/comprehension bodies, annotations, reflective and subscript writes not analyzed.",
    "No effective authorization, external review, recursion, termination or token-overflow proof.",
    "No guessed framework mutation APIs or MCP state/permission schema.",
    "Duplicate draft concepts remain non-emitting; cross-family overlap is not new coverage.",
    "No suppression handling, scores, snippets, identifiers or literal-value export.",
)


class SelfModificationObservation(ContractModel):
    kind: str
    location: SourceRange
    detail: str
    rule_id: str | None = None


class SelfModificationFinding(ContractModel):
    record_id: Sha256
    rule_id: str
    priority: Literal["low", "medium"]
    location: SourceRange
    callee: str
    evidence_kinds: list[str]
    verification: Literal["unreviewed-static-condition"] = "unreviewed-static-condition"


class SelfModificationFileResult(ContractModel):
    path: str
    source_sha256: Sha256
    byte_length: int = Field(ge=0)
    state: Literal["analyzed", "malformed", "unsupported", "failed"]
    reason: str
    findings: list[SelfModificationFinding] | None
    inventory: list[SelfModificationObservation]
    limitations_observed: list[SelfModificationObservation]


_PROMPT = {"prompt", "system_prompt"}
_MEMORY = {"memory", "memory_strategy", "memory_backend"}
_CONTEXT = {"max_tokens", "context_window", "max_history"}
_TOOLS = {"generate_tools", "update_tools", "update_tool_signature", "regenerate_tools"}
_PERSIST = {"save_self", "persist_self", "write_config", "save_state"}
_VALIDATE = {"validate_self", "verify_self", "pre_hook", "post_hook"}
_DRIFT = {"rollback_self", "revert_self", "snapshot_self", "diff_self", "commit_self"}
_MODIFY = _TOOLS | {"update_system_prompt", "update_memory", "rewrite", "regenerate", "update"}
_FRAMEWORKS = {
    "008": {"langchain", "langchain_core", "langchain_classic", "langchain_community", "langgraph"},
    "009": {"autogen", "autogen_core", "autogen_agentchat", "autogen_ext"},
}


def _words(name: str) -> set[str]:
    return set(re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).casefold().split("_"))


def _direct(node: ast.AST, kind: str) -> bool:
    """No flow through calls, conditionals or index selectors is inferred."""
    if isinstance(node, (ast.Name, ast.Attribute)):
        name = node.id if isinstance(node, ast.Name) else node.attr
        tokens = (
            {"response", "reply", "completion"}
            if kind == "response"
            else {
                "memory",
                "state",
                "history",
                "context",
                "messages",
            }
        )
        return bool(_words(name) & tokens) or (
            isinstance(node, ast.Attribute) and _direct(node.value, kind)
        )
    if isinstance(node, ast.Subscript):
        return _direct(node.value, kind)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _direct(node.left, kind) or _direct(node.right, kind)
    if isinstance(node, ast.JoinedStr):
        return any(
            isinstance(item, ast.FormattedValue) and _direct(item.value, kind)
            for item in node.values
        )
    return False


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


class _Analyzer(ast.NodeVisitor):
    def __init__(self, tree: ast.Module, path: str, digest: str) -> None:
        bindings = Bindings()
        bindings.visit(tree)
        self.scope = Scope(bindings, None, builtin_names=frozenset({"eval", "exec"}))
        self.path, self.digest = path, digest
        self.loop_depth = 0
        self.findings: dict[tuple[str, int, int], SelfModificationFinding] = {}
        self.inventory: list[SelfModificationObservation] = []
        self.issues: list[SelfModificationObservation] = []

    def _budget(self) -> None:
        if len(self.findings) + len(self.inventory) + len(self.issues) >= MAX_RECORDS:
            raise ValueError("Observation budget exceeded")

    def observe(
        self, node: ast.AST, kind: str, detail: str, *, rule: str | None = None, issue: bool = False
    ) -> None:
        self._budget()
        (self.issues if issue else self.inventory).append(
            SelfModificationObservation(
                kind=kind,
                location=location(node),
                detail=detail,
                rule_id=f"SELF-MOD-{rule}" if rule else None,
            )
        )

    def emit(self, suffix: str, node: ast.AST, callee: str, evidence: str) -> None:
        rule = BY_ID[f"SELF-MOD-{suffix}"]
        if rule.status != "active-condition" or rule.priority is None:
            raise ValueError("Nonactive ID cannot emit")
        span = location(node)
        key = (rule.rule_id, span.start_line, span.start_utf8_byte_column)
        if key in self.findings:
            return
        self._budget()
        self.findings[key] = SelfModificationFinding(
            record_id=sha256_bytes(
                f"{VERSION}:{self.path}:{self.digest}:{rule.rule_id}:{span.model_dump_json()}".encode()
            ),
            rule_id=rule.rule_id,
            priority=rule.priority,
            location=span,
            callee=callee,
            evidence_kinds=[evidence],
        )

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for value in [*node.decorator_list, *node.args.defaults, *node.args.kw_defaults]:
            if value is not None:
                self.visit(value)
        bindings = Bindings()
        for name in arguments(node.args):
            bindings.bind(name)
        for statement in node.body:
            bindings.visit(statement)
        parent, depth = self.scope, self.loop_depth
        outer: Scope | None = parent
        while outer is not None and outer.kind == "class":
            outer = outer.parent
        self.scope, self.loop_depth = Scope(bindings, outer, kind="function"), 0
        for statement in node.body:
            self.visit(statement)
        self.scope, self.loop_depth = parent, depth

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for value in [*node.decorator_list, *node.bases, *node.keywords]:
            self.visit(value)
        bindings = Bindings()
        for statement in node.body:
            bindings.visit(statement)
        parent, depth = self.scope, self.loop_depth
        self.scope, self.loop_depth = Scope(bindings, parent, kind="class"), 0
        for statement in node.body:
            self.visit(statement)
        self.scope, self.loop_depth = parent, depth

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

    def visit_TypeAlias(self, node: ast.TypeAlias) -> None:
        self.observe(node, "unsupported-scope", "Type alias expression not analyzed", issue=True)

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
            self.observe(node, "ambiguous-binding", "Wildcard import limits resolution", issue=True)

    def _target(self, node: ast.AST, target: ast.AST, value: ast.AST, *, add: bool = False) -> None:
        leaf = (raw_name(target) or "").split(".")[-1]
        if leaf in _MEMORY:
            self.observe(node, "memory-setting", "Name-based assignment only", rule="003")
        if leaf in _CONTEXT:
            self.observe(
                node, "context-setting", "Setting syntax, not token measurement", rule="004"
            )
        if leaf in {"version", "version_tag", "self_version"}:
            self.observe(node, "version-naming", "Version-named assignment", rule="013")
        if isinstance(target, ast.Attribute) and target.attr in _PROMPT:
            self.observe(node, "prompt-attribute", "Prompt-like attribute spelling only")
            if not _literal(value):
                self.emit(
                    "001",
                    node,
                    "attribute:prompt-like",
                    "nonliteral-additive-assignment" if add else "nonliteral-assignment",
                )
            self.observe(
                node,
                "unresolved-receiver",
                "Agent identity and descriptor behavior unknown",
                issue=True,
            )
        elif isinstance(target, ast.Name) and target.id in _PROMPT:
            self.observe(node, "prompt-variable", "Local naming is not an agent attribute")
        elif isinstance(target, (ast.Subscript, ast.Tuple, ast.List)):
            self.observe(
                node,
                "unsupported-write",
                "Subscript/destructuring write not classified",
                issue=True,
            )

    def visit_Assign(self, node: ast.Assign | ast.AnnAssign) -> None:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if node.value is not None:
            for target in targets:
                self._target(node, target, node.value)
            self.visit(node.value)
        for target in targets:
            self.visit(target)

    visit_AnnAssign = visit_Assign

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if isinstance(node.op, ast.Add):
            self._target(node, node.target, node.value, add=True)
        else:
            self.observe(
                node,
                "unsupported-write",
                "Non-additive augmented assignment not classified",
                issue=True,
            )
            leaf = (raw_name(node.target) or "").split(".")[-1]
            if leaf in _CONTEXT:
                self.observe(node, "context-setting", "Augmented setting syntax only", rule="004")
        self.visit(node.target)
        self.visit(node.value)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self._target(node, node.target, node.value)
        self.generic_visit(node)

    def visit_For(self, node: ast.For | ast.AsyncFor | ast.While) -> None:
        # The body is lexically in a loop; its execution and termination are not inferred.
        if isinstance(node, ast.While):
            self.visit(node.test)
        else:
            self.visit(node.iter)
            self.visit(node.target)
        self.loop_depth += 1
        for statement in node.body:
            self.visit(statement)
        self.loop_depth -= 1
        for statement in node.orelse:
            self.visit(statement)

    visit_AsyncFor = visit_For
    visit_While = visit_For

    def visit_Call(self, node: ast.Call) -> None:
        name = raw_name(node.func) or ""
        leaf = name.split(".")[-1]
        if leaf in _TOOLS:
            self.observe(node, "tool-update-naming", "Unverified tool API naming cue", rule="002")
        if leaf in _PERSIST:
            self.observe(
                node, "persistence-naming", "Unverified persistence naming cue", rule="006"
            )
        self_receiver = isinstance(node.func, ast.Attribute) and raw_name(node.func.value) == "self"
        self_argument = (
            bool(node.args) and isinstance(node.args[0], ast.Name) and node.args[0].id == "self"
        )
        if leaf in {"self_evaluate", "evaluate_self"} or (
            leaf == "evaluate" and (self_receiver or self_argument)
        ):
            self.observe(node, "evaluation-naming", "No claim about external review", rule="005")
        if leaf in _VALIDATE or (
            leaf in {"validate", "verify", "check"} and (self_receiver or self_argument)
        ):
            self.observe(node, "validation-naming", "Unverified control naming cue", rule="012")
        if leaf in _DRIFT or (
            leaf in {"diff", "rollback", "revert", "snapshot"} and (self_receiver or self_argument)
        ):
            self.observe(node, "drift-naming", "Unverified version/control naming cue", rule="013")
        if self.loop_depth and leaf in _MODIFY:
            self.observe(node, "loop-update-naming", "Lexical call in loop body only", rule="014")
        if any(item.arg in _CONTEXT for item in node.keywords):
            self.observe(node, "context-setting", "Keyword setting syntax only", rule="004")
        if leaf in _TOOLS | _PERSIST | _VALIDATE | _DRIFT | _MODIFY:
            self.observe(
                node, "unresolved-update-api", "No receiver type or framework contract", issue=True
            )
        if leaf in {
            "setattr",
            "__setattr__",
            "update_system_prompt",
            "suggest",
            "generate",
            "propose",
        }:
            self.observe(
                node,
                "unsupported-modification",
                "Reflective/method/model flow not traced",
                issue=True,
            )
        callee = self.scope.resolve(node.func)
        if callee in {"builtins.eval", "builtins.exec"}:
            keys = [item.arg for item in node.keywords]
            allowed = (
                {"globals", "locals", "closure"}
                if callee == "builtins.exec"
                else {"globals", "locals"}
            )
            valid = (
                1 <= len(node.args) <= 3
                and not any(isinstance(item, ast.Starred) for item in node.args)
                and len(keys) == len(set(keys))
                and set(keys) <= allowed
                and not set(keys) & set(("source", "globals", "locals")[: len(node.args)])
            )
            if not valid:
                self.observe(
                    node,
                    "unresolved-arguments",
                    "Unsupported Python 3.13 eval/exec call shape",
                    issue=True,
                )
            else:
                value = node.args[0]
                if any(
                    isinstance(item, (ast.Call, ast.IfExp, ast.Starred)) for item in ast.walk(value)
                ):
                    self.observe(
                        node,
                        "unresolved-value",
                        "Opaque value transformation not traced",
                        issue=True,
                    )
                if _direct(value, "response"):
                    self.emit("011", node, callee, "response-like-expression-to-code")
                if _direct(value, "memory"):
                    self.emit("101", node, callee, "memory-like-expression-to-code")
        elif leaf in {"eval", "exec"}:
            self.observe(
                node, "unresolved-callee", "Evaluation API shadowed or unestablished", issue=True
            )
        self.generic_visit(node)


def scan_source(data: bytes, *, path: str) -> SelfModificationFileResult:
    """Inspect explicit bytes; untrusted source must use the isolated worker."""
    canonical_artifact_path(path)
    digest = sha256_bytes(data)
    state: Literal["analyzed", "malformed", "unsupported", "failed"] = "analyzed"
    reason = "Bounded self-modification syntax inspection, not full security coverage"
    findings: list[SelfModificationFinding] | None = None
    inventory: list[SelfModificationObservation] = []
    issues: list[SelfModificationObservation] = []
    if PurePosixPath(path).suffix != ".py":
        state, reason = "unsupported", "Only Python source; no MCP or live state parsing"
    elif len(data) > MAX_INPUT_BYTES:
        state, reason = "failed", "Input exceeds 256 KiB"
    else:
        try:
            tree = ast.parse(
                data.decode("utf-8", errors="strict"), filename="<self-modification-input>"
            )
            if sum(1 for _ in ast.walk(tree)) > MAX_AST_NODES:
                raise ValueError("AST budget exceeded")
            analyzer = _Analyzer(tree, path, digest)
            analyzer.visit(tree)
            findings = sorted(
                analyzer.findings.values(),
                key=lambda item: (
                    item.location.start_line,
                    item.location.start_utf8_byte_column,
                    item.rule_id,
                ),
            )
            inventory, issues = analyzer.inventory, analyzer.issues
        except (SyntaxError, UnicodeError):
            state, reason = "malformed", "Invalid Python syntax or UTF-8"
        except (ValueError, RecursionError, MemoryError):
            state, reason = "failed", "Parser or observation resource guard reached"
    return SelfModificationFileResult(
        path=path,
        source_sha256=digest,
        byte_length=len(data),
        state=state,
        reason=reason,
        findings=findings,
        inventory=inventory,
        limitations_observed=issues,
    )
