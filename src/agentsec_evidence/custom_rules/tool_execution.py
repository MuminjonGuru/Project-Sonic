"""Five bounded AST checks repaired from the student's preserved tool-execution draft.

Parse untrusted source only in the restricted worker. No target imports, evaluation,
plugin loading, model calls, interprocedural analysis or exploitability verdicts.
"""

from __future__ import annotations

import ast
from pathlib import PurePosixPath
from typing import Final, Literal

from pydantic import Field

from agentsec_evidence.agents.inputs import MAX_AST_NODES, MAX_INPUT_BYTES
from agentsec_evidence.agents.validation import canonical_artifact_path
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.custom_rules.python_static import Bindings as _Bindings
from agentsec_evidence.custom_rules.python_static import Scope as _Scope
from agentsec_evidence.custom_rules.python_static import SourceRange as SourceRange
from agentsec_evidence.custom_rules.python_static import arguments as _arguments
from agentsec_evidence.custom_rules.python_static import location as _location
from agentsec_evidence.custom_rules.python_static import raw_name as _raw_name
from agentsec_evidence.models.contracts import ContractModel, Sha256

VERSION: Final = "1.0.0"
Severity = Literal["low", "medium", "high", "critical"]
SEVERITY_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
MAX_RECORDS = 1000
LIMITATIONS = (
    "Development-only static conditions, not confirmed vulnerabilities or runtime reachability.",
    "Only explicit builtins, supported standard-library imports and named LangChain decorators.",
    "No cross-file flow, assignment aliases, framework execution or sanitizer/control-flow proof.",
    "Import names are syntactic; module substitution and runtime monkey-patching are unverified.",
    "Literal arguments are inventory, not a safety verdict; dynamic shell flags are unknown.",
    "No MCP analysis, local rule loading, suppression policy, risk score or automatic grouping.",
)


class RuleSpec(ContractModel):
    rule_id: str
    title: str
    severity: Severity
    evidence_kind: str
    remediation: str


RULES = (
    RuleSpec(
        rule_id="TOOL-EXEC-001",
        title="Nonliteral code argument to eval or exec",
        severity="high",
        evidence_kind="call-and-argument-syntax",
        remediation="Prefer structured data and an operation allowlist over evaluating code.",
    ),
    RuleSpec(
        rule_id="TOOL-EXEC-002",
        title="Response-shaped expression passed to eval or exec",
        severity="high",
        evidence_kind="response-access-syntax-not-proven-llm-origin",
        remediation="Trace the response source; do not execute generated text as code.",
    ),
    RuleSpec(
        rule_id="TOOL-EXEC-003",
        title="Explicit shell invocation",
        severity="medium",
        evidence_kind="shell-declaration-not-proven-injection",
        remediation="Prefer argument vectors without a shell; also review command provenance.",
    ),
    RuleSpec(
        rule_id="TOOL-EXEC-004",
        title="Direct tool parameter reference passed to eval or exec",
        severity="high",
        evidence_kind="same-function-parameter-reference",
        remediation="Replace tool-argument evaluation with bounded, explicitly allowed operations.",
    ),
    RuleSpec(
        rule_id="TOOL-EXEC-005",
        title="Nonliteral module name passed to dynamic import",
        severity="medium",
        evidence_kind="import-argument-syntax-not-proven-execution-chain",
        remediation="Prefer fixed imports or a reviewed mapping to fixed module names.",
    ),
)
CATALOG_SHA256 = sha256_bytes(("\n".join(rule.model_dump_json() for rule in RULES) + "\n").encode())


class Observation(ContractModel):
    kind: str
    location: SourceRange
    detail: str


class ToolFinding(ContractModel):
    record_id: Sha256
    rule: RuleSpec
    location: SourceRange
    callee: str
    argument: str
    argument_truncated: bool
    tool_function: str | None
    parameter: str | None
    verification: Literal["unreviewed-static-condition"] = "unreviewed-static-condition"


class FileResult(ContractModel):
    path: str
    source_sha256: Sha256
    byte_length: int = Field(ge=0)
    state: Literal["analyzed", "malformed", "unsupported", "failed"]
    reason: str
    findings: list[ToolFinding] | None
    inventory: list[Observation]
    limitations_observed: list[Observation]


_DECORATORS = {"langchain_core.tools.tool", "langchain.tools.tool"}
_SUBPROCESS = {
    f"subprocess.{name}" for name in ("run", "Popen", "call", "check_call", "check_output")
}
_SHELL = {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"}
_CODE = {"builtins.eval", "builtins.exec"}
_IMPORT = {"builtins.__import__", "importlib.import_module"}
_TERMINALS = {name.rsplit(".", 1)[-1] for name in _SUBPROCESS | _SHELL | _CODE | _IMPORT}


class _Analyzer(ast.NodeVisitor):
    def __init__(self, source: str, path: str, digest: str, tree: ast.Module) -> None:
        bindings = _Bindings()
        bindings.visit(tree)
        self.scope = _Scope(bindings, None)
        self.source = source
        self.path = path
        self.digest = digest
        self.findings: list[ToolFinding] = []
        self.inventory: list[Observation] = []
        self.issues: list[Observation] = []

    def observe(self, node: ast.AST, kind: str, detail: str, *, issue: bool = False) -> None:
        self._budget()
        destination = self.issues if issue else self.inventory
        destination.append(Observation(kind=kind, location=_location(node), detail=detail))

    def _budget(self) -> None:
        if len(self.findings) + len(self.inventory) + len(self.issues) >= MAX_RECORDS:
            raise ValueError("Observation budget exceeded")

    def emit(self, rule_index: int, call: ast.Call, callee: str, argument: ast.AST) -> None:
        self._budget()
        location = _location(call)
        rule = RULES[rule_index]
        identity = (
            f"{VERSION}:{self.path}:{self.digest}:{rule.rule_id}:{location.model_dump_json()}"
        )
        snippet = ast.get_source_segment(self.source, argument) or "<source segment unavailable>"
        self.findings.append(
            ToolFinding(
                record_id=sha256_bytes(identity.encode()),
                rule=rule,
                location=location,
                callee=callee,
                argument=snippet[:512],
                argument_truncated=len(snippet) > 512,
                tool_function=self.scope.function if self.scope.tool else None,
                parameter=argument.id
                if rule_index == 3 and isinstance(argument, ast.Name)
                else None,
            )
        )

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        decorators = [
            self.scope.resolve(item.func if isinstance(item, ast.Call) else item)
            for item in node.decorator_list
        ]
        is_tool = any(name in _DECORATORS for name in decorators)
        if is_tool:
            self.observe(node, "tool-registration", f"Supported decorator on {node.name}")
        elif node.decorator_list:
            self.observe(
                node, "unresolved-decorator", "Not a supported tool registration", issue=True
            )
        for expression in [*node.decorator_list, *node.args.defaults, *node.args.kw_defaults]:
            if expression is not None:
                self.visit(expression)
        bindings = _Bindings()
        parameters = _arguments(node.args)
        for name in parameters:
            bindings.bind(name)
        for statement in node.body:
            bindings.visit(statement)
        parent = self.scope
        # A method does not close over the class namespace.
        lexical_parent = parent.parent if parent.kind == "class" else parent
        self.scope = _Scope(bindings, lexical_parent, node.name, is_tool, parameters, "function")
        for statement in node.body:
            self.visit(statement)
        self.scope = parent

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for expression in [*node.decorator_list, *node.bases, *node.keywords]:
            self.visit(expression)
        bindings = _Bindings()
        for statement in node.body:
            bindings.visit(statement)
        parent = self.scope
        self.scope = _Scope(bindings, parent, kind="class")
        for statement in node.body:
            self.visit(statement)
        self.scope = parent

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self.observe(node, "unsupported-scope", "Lambda body not analyzed", issue=True)
        for expression in [*node.args.defaults, *node.args.kw_defaults]:
            if expression is not None:
                self.visit(expression)

    def visit_ListComp(self, node: ast.AST) -> None:
        self.observe(node, "unsupported-scope", "Comprehension body not analyzed", issue=True)

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if any(alias.name == "*" for alias in node.names):
            self.observe(
                node, "ambiguous-bindings", "Wildcard import limits resolution", issue=True
            )

    def visit_Call(self, node: ast.Call) -> None:
        callee = self.scope.resolve(node.func)
        raw = _raw_name(node.func)
        if callee in _CODE | _SHELL | _SUBPROCESS | _IMPORT:
            self._supported_call(node, callee)
        elif raw and raw.rsplit(".", 1)[-1] in _TERMINALS:
            self.observe(
                node, "unresolved-callee", f"Cannot establish supported binding: {raw}", issue=True
            )
        self.generic_visit(node)

    def _supported_call(self, node: ast.Call, callee: str) -> None:
        if any(isinstance(arg, ast.Starred) for arg in node.args) or any(
            keyword.arg is None for keyword in node.keywords
        ):
            self.observe(
                node, "unresolved-arguments", "Expanded arguments not analyzed", issue=True
            )
            return
        argument = node.args[0] if node.args else None
        keyword_name = "name" if callee in _IMPORT else "args" if callee in _SUBPROCESS else None
        if keyword_name and argument is None:
            argument = next(
                (item.value for item in node.keywords if item.arg == keyword_name), None
            )
        if argument is None:
            self.observe(node, "unresolved-arguments", "No explicit supported argument", issue=True)
            return
        literal = isinstance(argument, ast.Constant)
        if callee in _CODE:
            if literal:
                self.observe(node, "literal-code-call", callee)
            else:
                self.emit(0, node, callee, argument)
                if _response_shape(argument):
                    self.emit(1, node, callee, argument)
                if (
                    self.scope.tool
                    and isinstance(argument, ast.Name)
                    and argument.id in self.scope.parameters
                    and len(self.scope.bindings.values[argument.id]) == 1
                ):
                    self.emit(3, node, callee, argument)
        elif callee in _SHELL:
            self.emit(2, node, callee, argument)
        elif callee in _SUBPROCESS:
            flags = [item.value for item in node.keywords if item.arg == "shell"]
            if not flags:
                self.observe(node, "subprocess-no-explicit-shell", callee)
            elif len(flags) != 1 or not isinstance(flags[0], ast.Constant):
                self.observe(
                    node, "unknown-shell-flag", "shell is not a single literal boolean", issue=True
                )
            elif flags[0].value is True:
                self.emit(2, node, callee, argument)
            elif flags[0].value is False:
                self.observe(node, "subprocess-shell-false", callee)
            else:
                self.observe(
                    node, "unknown-shell-flag", "Non-boolean shell value not modeled", issue=True
                )
        elif callee in _IMPORT:
            if literal:
                self.observe(node, "literal-module-import", callee)
            else:
                self.emit(4, node, callee, argument)


def _response_shape(node: ast.AST) -> bool:
    if _raw_name(node) in {"llm_result.output", "agent.response"}:
        return True
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "content"
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "message"
        and isinstance(node.value.value, ast.Subscript)
        and _raw_name(node.value.value.value) == "response.choices"
        and isinstance(node.value.value.slice, ast.Constant)
        and type(node.value.value.slice.value) is int
    )


def scan_source(data: bytes, *, path: str) -> FileResult:
    """Analyze supplied bytes, never a live import. Host use is for authored tests only."""
    canonical_artifact_path(path)
    digest = sha256_bytes(data)
    state: Literal["analyzed", "malformed", "unsupported", "failed"] = "analyzed"
    findings: list[ToolFinding] | None = None
    inventory: list[Observation] = []
    issues: list[Observation] = []
    reason = "Bounded checks completed; no claim of full Python or security coverage"
    if PurePosixPath(path).suffix != ".py":
        state, reason = "unsupported", "Only .py source is admitted by this detector"
    elif len(data) > MAX_INPUT_BYTES:
        state, reason = "failed", "Input exceeds 256 KiB"
    else:
        try:
            source = data.decode("utf-8", errors="strict")
            tree = ast.parse(source, filename="<tool-execution-input>")
            if sum(1 for _ in ast.walk(tree)) > MAX_AST_NODES:
                raise ValueError("AST node budget exceeded")
            analyzer = _Analyzer(source, path, digest, tree)
            analyzer.visit(tree)
            findings = sorted(
                analyzer.findings,
                key=lambda item: (
                    item.location.start_line,
                    item.location.start_utf8_byte_column,
                    item.rule.rule_id,
                ),
            )
            inventory, issues = analyzer.inventory, analyzer.issues
        except (SyntaxError, UnicodeError):
            state, reason = "malformed", "Invalid Python syntax or UTF-8 encoding"
        except (ValueError, RecursionError, MemoryError):
            state, reason = "failed", "Parser or observation resource guard reached"
    return FileResult(
        path=path,
        source_sha256=digest,
        byte_length=len(data),
        state=state,
        reason=reason,
        findings=findings,
        inventory=inventory,
        limitations_observed=issues,
    )
