"""Bounded memory/state syntax inspection; never execute code or inspect live memory."""

from __future__ import annotations

import ast
import re
from pathlib import PurePosixPath
from typing import Final, Literal

from pydantic import Field

from agentsec_evidence.agents.inputs import MAX_AST_NODES, MAX_INPUT_BYTES
from agentsec_evidence.agents.validation import canonical_artifact_path
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.custom_rules.memory_catalog import BY_ID
from agentsec_evidence.custom_rules.python_static import (
    Bindings,
    Scope,
    SourceRange,
    arguments,
    location,
    raw_name,
)
from agentsec_evidence.models.contracts import ContractModel, Sha256

VERSION: Final = "1.0.0"
MAX_RECORDS = 1000
LIMITATIONS = (
    "Development syntax observations, not verified vulnerabilities or live agent behavior.",
    "No target execution, model calls, memory-store reads, network requests or token counting.",
    "Memory and credential names are heuristics; source trust, value types and contents unknown.",
    "No cross-file/assignment flow, sanitizer validation, object typing or runtime import checks.",
    "Lambda/comprehension bodies and annotations are not analyzed.",
    "Unknown wrappers, transformations, assigned clients/loggers and dynamic APIs remain unknown.",
    "No effective storage, tenancy, authorization, cross-session isolation or poisoning checks.",
    "MCP uses the existing analyzer; no invented state-store/permission schema.",
    "No suppression policy, risk/confidence score, raw snippet, identifier or value export.",
)


class MemoryObservation(ContractModel):
    kind: str
    location: SourceRange
    detail: str
    rule_id: str | None = None


class MemoryFinding(ContractModel):
    record_id: Sha256
    rule_id: str
    priority: Literal["low", "medium"]
    location: SourceRange
    callee: str
    evidence_kinds: list[str]
    verification: Literal["unreviewed-static-condition"] = "unreviewed-static-condition"


class MemoryFileResult(ContractModel):
    path: str
    source_sha256: Sha256
    byte_length: int = Field(ge=0)
    state: Literal["analyzed", "malformed", "unsupported", "failed"]
    reason: str
    findings: list[MemoryFinding] | None
    inventory: list[MemoryObservation]
    limitations_observed: list[MemoryObservation]


_MEMORY_WORDS = {"memory", "state", "context", "history", "messages"}
_PERSIST = {
    "save_context",
    "save_chat_history",
    "write_memory",
    "store_memory",
    "persist_memory",
    "save_memory",
    "save_state",
    "load_state",
    "load_memory",
}
_SESSION = {"session_id", "user_id", "previous_sessions"}
_SERIALIZERS = {
    "json.dump",
    "json.dumps",
    "pickle.dump",
    "pickle.dumps",
    "yaml.dump",
    "yaml.safe_dump",
}
_LOG = {
    f"logging.{n}" for n in ("debug", "info", "warning", "error", "critical", "exception", "log")
}
_HTTP = {f"{m}.{n}" for m in ("requests", "httpx") for n in ("post", "put", "patch", "request")}
_SYSTEM = {
    "langchain_core.messages.SystemMessage",
    "langchain_core.messages.system.SystemMessage",
    "langchain.messages.SystemMessage",
}


def _words(name: str) -> set[str]:
    return set(re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).casefold().split("_"))


def _named(node: ast.AST, kind: str) -> bool:
    name = (
        node.id
        if isinstance(node, ast.Name)
        else node.attr
        if isinstance(node, ast.Attribute)
        else ""
    )
    words = _words(name)
    if kind == "memory":
        return bool(words & _MEMORY_WORDS) or name == "previous_turns"
    return bool(
        words & {"password", "passwd", "secret", "secrets", "token", "credential", "credentials"}
    ) or name.casefold() in {"api_key", "apikey"}


def _contains(node: ast.AST | None, kind: str) -> bool:
    """Follow explicit expression containers, not calls, selectors or implicit dataflow."""
    if node is None:
        return False
    if isinstance(node, (ast.Name, ast.Attribute)):
        return _named(node, kind) or (
            kind == "memory" and isinstance(node, ast.Attribute) and _contains(node.value, kind)
        )
    if isinstance(node, ast.Subscript):
        return _contains(node.value, kind)
    if isinstance(node, ast.Dict):
        return any(_contains(value, kind) for value in node.values)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_contains(value, kind) for value in node.elts)
    if isinstance(node, ast.JoinedStr):
        return any(
            isinstance(value, ast.FormattedValue) and _contains(value.value, kind)
            for value in node.values
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _contains(node.left, kind) or _contains(node.right, kind)
    return False


def _dynamic(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return False
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(item, ast.FormattedValue) for item in node.values)
    if isinstance(node, (ast.List, ast.Tuple)):
        return any(_dynamic(item) for item in node.elts)
    if isinstance(node, ast.Dict):
        return any(key is None or _dynamic(key) for key in node.keys) or any(
            _dynamic(value) for value in node.values
        )
    return True


def _expanded(node: ast.Call) -> bool:
    return any(isinstance(item, ast.Starred) for item in node.args) or any(
        item.arg is None for item in node.keywords
    )


def _argument(node: ast.Call, position: int | None, key: str) -> ast.expr | None:
    positional = node.args[position] if position is not None and len(node.args) > position else None
    named = [item.value for item in node.keywords if item.arg == key]
    if len(named) > 1 or (positional is not None and named):
        return None
    return positional if positional is not None else named[0] if named else None


def _shape(
    node: ast.Call,
    positional: tuple[str, ...],
    required: int,
    options: tuple[str, ...] = (),
) -> bool:
    keys = [item.arg for item in node.keywords]
    return (
        not _expanded(node)
        and len(node.args) <= len(positional)
        and len(keys) == len(set(keys))
        and set(keys) <= set(positional + options)
        and not set(keys) & set(positional[: len(node.args)])
        and all(name in keys for name in positional[len(node.args) : required])
    )


class _Analyzer(ast.NodeVisitor):
    def __init__(self, tree: ast.Module, path: str, digest: str) -> None:
        bindings = Bindings()
        bindings.visit(tree)
        self.scope = Scope(bindings, None, builtin_names=frozenset({"eval", "exec", "print"}))
        self.path, self.digest = path, digest
        self.findings: dict[tuple[str, int, int], MemoryFinding] = {}
        self.inventory: list[MemoryObservation] = []
        self.issues: list[MemoryObservation] = []

    def _budget(self) -> None:
        if len(self.findings) + len(self.inventory) + len(self.issues) >= MAX_RECORDS:
            raise ValueError("Observation budget exceeded")

    def observe(
        self, node: ast.AST, kind: str, detail: str, *, rule: str | None = None, issue: bool = False
    ) -> None:
        self._budget()
        (self.issues if issue else self.inventory).append(
            MemoryObservation(
                kind=kind,
                detail=detail,
                location=location(node),
                rule_id=f"MEM-SEC-{rule}" if rule else None,
            )
        )

    def emit(self, suffix: str, node: ast.AST, callee: str, evidence: str) -> None:
        rule_id = f"MEM-SEC-{suffix}"
        rule = BY_ID[rule_id]
        if rule.status != "active-condition" or rule.priority is None:
            raise ValueError("Nonactive ID cannot emit")
        span = location(node)
        key = (rule_id, span.start_line, span.start_utf8_byte_column)
        if key in self.findings:
            return
        self._budget()
        self.findings[key] = MemoryFinding(
            record_id=sha256_bytes(
                f"{VERSION}:{self.path}:{self.digest}:{rule_id}:{span.model_dump_json()}".encode()
            ),
            rule_id=rule_id,
            priority=rule.priority,
            location=span,
            callee=callee,
            evidence_kinds=[evidence],
        )

    def _value(self, node: ast.AST, value: ast.AST | None, kind: str) -> bool:
        if value is not None and any(
            isinstance(item, (ast.Call, ast.IfExp, ast.DictComp, ast.ListComp, ast.Starred))
            or (isinstance(item, ast.Dict) and None in item.keys)
            for item in ast.walk(value)
        ):
            self.observe(
                node, "unresolved-value", "Transformation or opaque flow not traced", issue=True
            )
        return _contains(value, kind)

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for value in [*node.decorator_list, *node.args.defaults, *node.args.kw_defaults]:
            if value is not None:
                self.visit(value)
        bindings = Bindings()
        for name in arguments(node.args):
            bindings.bind(name)
        for statement in node.body:
            bindings.visit(statement)
        parent = self.scope
        outer: Scope | None = parent
        while outer is not None and outer.kind == "class":
            outer = outer.parent
        self.scope = Scope(bindings, outer, kind="function")
        for statement in node.body:
            self.visit(statement)
        self.scope = parent

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for value in [*node.decorator_list, *node.bases, *node.keywords]:
            self.visit(value)
        bindings = Bindings()
        for statement in node.body:
            bindings.visit(statement)
        parent = self.scope
        self.scope = Scope(bindings, parent, kind="class")
        for statement in node.body:
            self.visit(statement)
        self.scope = parent

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
        for prefix, suffix in (("langchain", "005"), ("autogen", "006")):
            roots = (
                {
                    "langchain",
                    "langchain_core",
                    "langchain_community",
                    "langchain_classic",
                    "langgraph",
                }
                if prefix == "langchain"
                else {"autogen", "autogen_agentchat", "autogen_core", "autogen_ext"}
            )
            if any(module.split(".")[0] in roots for module in modules):
                self.observe(
                    node, "import-declaration", "Framework-family import spelling", rule=suffix
                )

    def visit_Import(self, node: ast.Import) -> None:
        self._import(node, [item.name for item in node.names])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if not node.level and node.module:
            self._import(node, [node.module])
        if any(item.name == "*" for item in node.names):
            self.observe(
                node, "ambiguous-binding", "Wildcard import limits API resolution", issue=True
            )

    def visit_Assign(self, node: ast.Assign | ast.AnnAssign) -> None:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if _contains(target, "memory") and _contains(node.value, "memory"):
                self.observe(
                    node, "memory-reference", "Name-based assignment reference", rule="009"
                )
            if isinstance(target, ast.Attribute) and _named(target, "memory"):
                self.observe(
                    node, "attribute-update", "Memory/state-like attribute assignment", rule="105"
                )
            name = raw_name(target) or ""
            if name.split(".")[-1] in _SESSION:
                self.observe(
                    node, "session-naming", "Session/user identifier assignment", rule="108"
                )
            if ({"memory", "state"} & _words(name.split(".")[-1])) and (
                _words(name.split(".")[-1]) & {"version", "snapshot"}
            ):
                self.observe(
                    node, "version-naming", "Memory version/snapshot naming cue", rule="106"
                )
            self.visit(target)
        if node.value is not None:
            self.visit(node.value)

    visit_AnnAssign = visit_Assign

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if isinstance(node.slice, ast.Slice) and _contains(node.value, "memory"):
            self.observe(
                node, "memory-slice", "Slice syntax; no token/overflow measurement", rule="101"
            )
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        # A duplicate/unpacked role or content can override earlier entries at runtime.
        pairs = [
            (key.value, value)
            for key, value in zip(node.keys, node.values, strict=True)
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        ]
        roles = [value for key, value in pairs if key == "role"]
        contents = [value for key, value in pairs if key == "content"]
        if roles or contents:
            if len(pairs) != len(node.keys) or len(roles) > 1 or len(contents) > 1:
                self.observe(
                    node, "ambiguous-message", "Role/content mapping may be overridden", issue=True
                )
            elif roles and contents and isinstance(roles[0], ast.Constant):
                if roles[0].value == "system":
                    self.observe(node, "system-message-shape", "Literal system-role mapping only")
                    if _dynamic(contents[0]):
                        self.emit(
                            "107", node, "dict:system-role", "nonliteral-system-content-shape"
                        )
            elif roles and contents:
                self.observe(
                    node, "unresolved-role", "Dynamic message role not resolved", issue=True
                )
        self.generic_visit(node)

    def _serialize(self, node: ast.Call, callee: str) -> None:
        module, method = callee.split(".")
        if module == "json":
            pos: tuple[str, ...] = ("obj", "fp") if method == "dump" else ("obj",)
            options = (
                "skipkeys",
                "ensure_ascii",
                "check_circular",
                "allow_nan",
                "cls",
                "indent",
                "separators",
                "default",
                "sort_keys",
            )
            valid = _shape(node, pos, len(pos), options)
            key = "obj"
        elif module == "pickle":
            pos = ("obj", "file", "protocol") if method == "dump" else ("obj", "protocol")
            valid = _shape(
                node, pos, 2 if method == "dump" else 1, ("fix_imports", "buffer_callback")
            )
            key = "obj"
        else:
            valid = _shape(
                node,
                ("data", "stream"),
                1,
                (
                    "Dumper",
                    "default_style",
                    "default_flow_style",
                    "canonical",
                    "indent",
                    "width",
                    "allow_unicode",
                    "line_break",
                    "encoding",
                    "explicit_start",
                    "explicit_end",
                    "version",
                    "tags",
                    "sort_keys",
                ),
            )
            if method == "safe_dump" and any(item.arg == "Dumper" for item in node.keywords):
                valid = False
            key = "data"
        if not valid:
            self.observe(
                node, "unresolved-arguments", "Unsupported serializer call shape", issue=True
            )
            return
        value = _argument(node, 0, key)
        if self._value(node, value, "secret"):
            self.emit("004", node, callee, "credential-like-identifier-in-serialization")
        if self._value(node, value, "memory"):
            self.observe(
                node, "serialization", "Memory-like value; no loader/storage verdict", rule="010"
            )
            stream = _argument(
                node, 1, "stream" if module == "yaml" else "fp" if module == "json" else "file"
            )
            if (module != "yaml" and method == "dump") or (
                module == "yaml"
                and stream is not None
                and not (isinstance(stream, ast.Constant) and stream.value is None)
            ):
                self.observe(
                    node, "stream-serialization", "Stream syntax; destination unknown", rule="008"
                )
        if any(
            item.arg in {"cls", "default", "Dumper", "buffer_callback"} for item in node.keywords
        ):
            self.observe(
                node,
                "unresolved-customization",
                "Custom serializer behavior not modeled",
                issue=True,
            )

    def visit_Call(self, node: ast.Call) -> None:
        callee = self.scope.resolve(node.func)
        name = raw_name(node.func) or ""
        leaf = name.split(".")[-1]
        memory_named = bool(_words(leaf) & _MEMORY_WORDS)
        memory_receiver = isinstance(node.func, ast.Attribute) and _contains(
            node.func.value, "memory"
        )
        if leaf in _PERSIST or (memory_receiver and leaf in {"save", "load", "persist", "store"}):
            self.observe(node, "persistence-naming", "Unverified memory API naming cue", rule="001")
            self.observe(
                node, "unresolved-memory-api", "Persistence semantics are unknown", issue=True
            )
        if memory_named and _words(leaf) & {"summarize", "compress", "reduce", "condense"}:
            self.observe(
                node, "compression-naming", "Summarization/compression API naming cue", rule="102"
            )
        if leaf in {"update_memory", "save_memory", "write_memory"}:
            self.observe(node, "update-naming", "Memory update API naming cue", rule="105")
        if memory_named and _words(leaf) & {"snapshot", "diff", "commit", "version"}:
            self.observe(
                node, "version-naming", "Memory snapshot/version API naming cue", rule="106"
            )
        if leaf == "load_session" or any(item.arg in _SESSION for item in node.keywords):
            self.observe(node, "session-naming", "Session/user identifier call syntax", rule="108")
        if (memory_named or any(_contains(value, "memory") for value in node.args)) and any(
            item.arg in {"max_tokens", "window", "limit"} for item in node.keywords
        ):
            self.observe(
                node, "context-bound-setting", "Setting present; no token measurement", rule="101"
            )

        known = callee in _SERIALIZERS | _LOG | _HTTP | _SYSTEM | {
            "builtins.eval",
            "builtins.exec",
            "builtins.print",
        }
        if known and _expanded(node):
            self.observe(node, "unresolved-arguments", "Expanded call arguments", issue=True)
        elif callee in _SERIALIZERS and callee is not None:
            self._serialize(node, callee)
        elif callee in {"builtins.eval", "builtins.exec"}:
            valid = bool(node.args) and not any(k.arg == "source" for k in node.keywords)
            valid = valid and _shape(
                node,
                ("source", "globals", "locals"),
                1,
                ("closure",) if callee == "builtins.exec" else (),
            )
            if not valid:
                self.observe(
                    node, "unresolved-arguments", "Unsupported evaluation shape", issue=True
                )
            elif self._value(node, node.args[0], "memory"):
                self.emit("103", node, callee, "memory-like-expression-to-code-evaluation")
        elif callee == "builtins.print" or callee in _LOG:
            keys = [item.arg for item in node.keywords]
            if callee == "builtins.print":
                valid = len(keys) == len(set(keys)) and set(keys) <= {"sep", "end", "file", "flush"}
                payload = list(node.args)
            else:
                msg_position = 1 if callee == "logging.log" else 0
                value = _argument(node, msg_position, "msg")
                valid = value is not None and len(keys) == len(set(keys))
                valid = valid and set(keys) <= {
                    "msg",
                    "level",
                    "exc_info",
                    "stack_info",
                    "stacklevel",
                    "extra",
                }
                if callee == "logging.log":
                    valid = valid and _argument(node, 0, "level") is not None
                elif "level" in keys:
                    valid = False
                payload = ([value] if value is not None else []) + node.args[msg_position + 1 :]
            if not valid:
                self.observe(
                    node, "unresolved-arguments", "Unsupported text-output call shape", issue=True
                )
            elif any(self._value(node, value, "memory") for value in payload):
                self.emit("104", node, callee, "memory-like-expression-to-text-output")
        elif callee in _HTTP and callee is not None:
            if not _shape(
                node,
                ("method", "url")
                if callee.endswith(".request")
                else ("url", "data", "json")
                if callee == "requests.post"
                else ("url", "data")
                if callee.startswith("requests.")
                else ("url",),
                2 if callee.endswith(".request") else 1,
                (
                    "data",
                    "json",
                    "params",
                    "headers",
                    "cookies",
                    "auth",
                    "timeout",
                    "allow_redirects",
                    "proxies",
                    "verify",
                    "cert",
                    "stream",
                    "hooks",
                    "files",
                )
                if callee.startswith("requests.")
                else (
                    "data",
                    "json",
                    "params",
                    "headers",
                    "cookies",
                    "auth",
                    "timeout",
                    "follow_redirects",
                    "proxy",
                    "verify",
                    "trust_env",
                    "content",
                    "files",
                ),
            ):
                self.observe(
                    node, "unresolved-arguments", "Unsupported HTTP call shape", issue=True
                )
            else:
                if any(item.arg in {"content", "files"} for item in node.keywords):
                    self.observe(
                        node,
                        "unsupported-body-field",
                        "Only data/json body expressions inspected",
                        issue=True,
                    )
                for key in ("data", "json"):
                    position = (
                        1
                        if key == "data"
                        and callee.startswith("requests.")
                        and not callee.endswith(".request")
                        else 2
                        if key == "json" and callee == "requests.post"
                        else None
                    )
                    if self._value(node, _argument(node, position, key), "memory"):
                        self.emit("104", node, callee, "memory-like-expression-in-http-body")
        elif callee in _SYSTEM and callee is not None:
            content = _argument(node, 0, "content")
            if (
                not _shape(
                    node, ("content",), 1, ("additional_kwargs", "response_metadata", "name", "id")
                )
                or content is None
            ):
                self.observe(
                    node, "unresolved-message", "Unsupported/ambiguous message content", issue=True
                )
            else:
                self.observe(node, "system-message-constructor", "Resolved constructor syntax only")
                if _dynamic(content):
                    self.emit("107", node, callee, "nonliteral-system-message-content")
        elif leaf in {
            "eval",
            "exec",
            "print",
            "send",
            "publish",
            "dump_memory",
            "SystemMessage",
            "info",
            "warning",
            "post",
            "put",
            "patch",
            "dump",
            "dumps",
        }:
            self.observe(
                node, "unresolved-callee", "Potential sink API is unestablished", issue=True
            )
        self.generic_visit(node)


def scan_source(data: bytes, *, path: str) -> MemoryFileResult:
    """Analyze explicit bytes; untrusted source must use the isolated worker."""
    canonical_artifact_path(path)
    digest = sha256_bytes(data)
    state: Literal["analyzed", "malformed", "unsupported", "failed"] = "analyzed"
    reason = "Bounded memory/state syntax inspection, not full security coverage"
    findings: list[MemoryFinding] | None = None
    inventory: list[MemoryObservation] = []
    issues: list[MemoryObservation] = []
    if PurePosixPath(path).suffix != ".py":
        state, reason = "unsupported", "Only Python source; no memory dump or MCP parsing"
    elif len(data) > MAX_INPUT_BYTES:
        state, reason = "failed", "Input exceeds 256 KiB"
    else:
        try:
            tree = ast.parse(data.decode("utf-8", errors="strict"), filename="<memory-input>")
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
    return MemoryFileResult(
        path=path,
        source_sha256=digest,
        byte_length=len(data),
        state=state,
        reason=reason,
        findings=findings,
        inventory=inventory,
        limitations_observed=issues,
    )
