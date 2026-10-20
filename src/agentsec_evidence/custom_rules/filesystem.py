"""Conservative filesystem syntax observations. Never access paths named in target code."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath
from typing import Final, Literal

from pydantic import Field

from agentsec_evidence.agents.inputs import MAX_AST_NODES, MAX_INPUT_BYTES
from agentsec_evidence.agents.validation import canonical_artifact_path
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.custom_rules.filesystem_catalog import BY_ID
from agentsec_evidence.custom_rules.python_static import (
    Bindings,
    Scope,
    SourceRange,
    arguments,
    location,
)
from agentsec_evidence.models.contracts import ContractModel, Sha256

VERSION: Final = "1.0.0"
MAX_RECORDS = 1000
LIMITATIONS = (
    "Development syntax conditions, not verified vulnerabilities or effective filesystem access.",
    "No target execution, content reads, path resolution, glob expansion or host ACL inspection.",
    "Imports are lexical; runtime types, local module substitution and monkey-patching unknown.",
    "No assignment aliases, cross-file flow, sanitization, symlink/race or containment checks.",
    "Path methods require an inline pathlib.Path receiver; assigned/opaque handles remain unknown.",
    "Lambda/comprehension bodies and annotations are not analyzed.",
    "POSIX/Windows lexical observations do not identify the target operating system.",
    "MCP stays with the existing analyzer; no fabricated permission schema or trust scores.",
    "No target suppressions, confidence/risk scores, raw snippets, target paths or secret values.",
)


class FilesystemObservation(ContractModel):
    kind: str
    location: SourceRange
    detail: str
    rule_id: str | None = None
    measurements: dict[str, int] = Field(default_factory=dict)


class FilesystemFinding(ContractModel):
    record_id: Sha256
    rule_id: str
    priority: Literal["low", "medium"]
    location: SourceRange
    callee: str
    evidence_kinds: list[str]
    verification: Literal["unreviewed-static-condition"] = "unreviewed-static-condition"


class FilesystemFileResult(ContractModel):
    path: str
    source_sha256: Sha256
    byte_length: int = Field(ge=0)
    state: Literal["analyzed", "malformed", "unsupported", "failed"]
    reason: str
    findings: list[FilesystemFinding] | None
    inventory: list[FilesystemObservation]
    limitations_observed: list[FilesystemObservation]


@dataclass(frozen=True)
class _PathSyntax:
    literal: str | None
    dynamic: bool
    interpolations: int
    valid: bool = True
    transformed: bool = False


_OPEN = {"builtins.open", "io.open"}
_COPY = {f"shutil.{name}" for name in ("copy", "copy2", "copyfile", "copytree", "move")}
_READ_METHODS = {"read_text", "read_bytes"}
_WRITE_METHODS = {"write_text", "write_bytes"}
_PATH_METHODS = _READ_METHODS | _WRITE_METHODS | {"open"}
_TRANSFORMS = {"resolve", "absolute", "expanduser", "joinpath"}
_CODE_SUFFIXES = {".py", ".js", ".ts", ".sh", ".rb", ".go"}
_CONFIG_SUFFIXES = {".json", ".yaml", ".yml", ".toml", ".xml"}
_STATE_NAMES = {"state", "memory", "session", "history", "context", "persist", "cache", "snapshot"}
_UNRESOLVED = _PATH_METHODS | {"write", "read", "save_state", "write_memory"}
_PATH_SIGNATURES = {
    "open": ("mode", "buffering", "encoding", "errors", "newline"),
    "read_text": ("encoding", "errors", "newline"),
    "read_bytes": (),
    "write_text": ("data", "encoding", "errors", "newline"),
    "write_bytes": ("data",),
}
_OPEN_SIGNATURE = (
    "file",
    "mode",
    "buffering",
    "encoding",
    "errors",
    "newline",
    "closefd",
    "opener",
)
_COPY_SIGNATURES = {
    "shutil.copy": ("src", "dst"),
    "shutil.copy2": ("src", "dst"),
    "shutil.copyfile": ("src", "dst"),
    "shutil.copytree": (
        "src",
        "dst",
        "symlinks",
        "ignore",
        "copy_function",
        "ignore_dangling_symlinks",
        "dirs_exist_ok",
    ),
    "shutil.move": ("src", "dst", "copy_function"),
}


def _valid_arguments(
    node: ast.Call,
    positional: tuple[str, ...],
    *,
    required: int = 0,
    keyword_only: tuple[str, ...] = (),
) -> bool:
    """Bound call-shape claims to the documented Python 3.13 signatures, not runtime types."""
    if _expanded(node) or len(node.args) > len(positional):
        return False
    keywords = [item.arg for item in node.keywords]
    return (
        len(keywords) == len(set(keywords))
        and set(keywords) <= set(positional + keyword_only)
        and not set(keywords) & set(positional[: len(node.args)])
        and all(name in keywords for name in positional[len(node.args) : required])
    )


def _string(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _expanded(node: ast.Call) -> bool:
    return any(isinstance(item, ast.Starred) for item in node.args) or any(
        item.arg is None for item in node.keywords
    )


def _argument(node: ast.Call, position: int | None, keyword: str) -> ast.expr | None:
    positional = node.args[position] if position is not None and len(node.args) > position else None
    named = [item.value for item in node.keywords if item.arg == keyword]
    if len(named) > 1 or (positional is not None and named):
        return None
    return positional if positional is not None else named[0] if named else None


def _secret_name(node: ast.AST) -> bool:
    if isinstance(node, (ast.Name, ast.Attribute)):
        value = node.id if isinstance(node, ast.Name) else node.attr
        name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value).casefold()
        return name in {"api_key", "apikey", "credential", "credentials"} or bool(
            set(name.split("_")) & {"password", "passwd", "secret", "token"}
        )
    if isinstance(node, ast.JoinedStr):
        return any(
            isinstance(value, ast.FormattedValue) and _secret_name(value.value)
            for value in node.values
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _secret_name(node.left) or _secret_name(node.right)
    return False


class _Analyzer(ast.NodeVisitor):
    def __init__(self, tree: ast.Module, path: str, digest: str) -> None:
        bindings = Bindings()
        bindings.visit(tree)
        self.scope = Scope(bindings, None, builtin_names=frozenset({"open", "eval", "exec"}))
        self.path, self.digest = path, digest
        self.findings: dict[tuple[str, int, int], FilesystemFinding] = {}
        self.inventory: list[FilesystemObservation] = []
        self.issues: list[FilesystemObservation] = []

    def _budget(self) -> None:
        if len(self.findings) + len(self.inventory) + len(self.issues) >= MAX_RECORDS:
            raise ValueError("Observation budget exceeded")

    def observe(
        self,
        node: ast.AST,
        kind: str,
        detail: str,
        *,
        rule: str | None = None,
        issue: bool = False,
        measurements: dict[str, int] | None = None,
    ) -> None:
        self._budget()
        (self.issues if issue else self.inventory).append(
            FilesystemObservation(
                kind=kind,
                location=location(node),
                detail=detail,
                rule_id=f"FS-ACCESS-{rule}" if rule else None,
                measurements=measurements or {},
            )
        )

    def emit(self, suffix: str, node: ast.Call, callee: str, evidence: str) -> None:
        rule_id = f"FS-ACCESS-{suffix}"
        rule = BY_ID[rule_id]
        if rule.status != "active-condition" or rule.priority is None:
            raise ValueError("Nonactive ID cannot emit")
        key = (rule_id, node.lineno, node.col_offset)
        if key in self.findings:
            self.findings[key].evidence_kinds = sorted(
                set(self.findings[key].evidence_kinds) | {evidence}
            )
            return
        self._budget()
        span = location(node)
        self.findings[key] = FilesystemFinding(
            record_id=sha256_bytes(
                f"{VERSION}:{self.path}:{self.digest}:{rule_id}:{span.model_dump_json()}".encode()
            ),
            rule_id=rule_id,
            priority=rule.priority,
            location=span,
            callee=callee,
            evidence_kinds=[evidence],
        )

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for item in [*node.decorator_list, *node.args.defaults, *node.args.kw_defaults]:
            if item is not None:
                self.visit(item)
        bindings = Bindings()
        for name in arguments(node.args):
            bindings.bind(name)
        for statement in node.body:
            bindings.visit(statement)
        parent = self.scope
        lexical_parent: Scope | None = parent
        while lexical_parent and lexical_parent.kind == "class":
            lexical_parent = lexical_parent.parent
        self.scope = Scope(bindings, lexical_parent, function=node.name, kind="function")
        for statement in node.body:
            self.visit(statement)
        self.scope = parent

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for item in [*node.decorator_list, *node.bases, *node.keywords]:
            self.visit(item)
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
        for item in [*node.args.defaults, *node.args.kw_defaults]:
            if item is not None:
                self.visit(item)

    def visit_ListComp(self, node: ast.AST) -> None:
        self.observe(node, "unsupported-scope", "Comprehension not analyzed", issue=True)

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if any(item.name == "*" for item in node.names):
            self.observe(node, "ambiguous-binding", "Wildcard import limits resolution", issue=True)

    def visit_Assign(self, node: ast.Assign | ast.AnnAssign) -> None:
        value = node.value
        if value is not None and (
            self._path_receiver(value)
            or (isinstance(value, ast.Call) and self.scope.resolve(value.func) in _OPEN)
        ):
            self.observe(
                node,
                "untracked-handle",
                "Assigned path/handle methods are not resolved",
                issue=True,
            )
        if isinstance(node, ast.AnnAssign):
            self.visit(node.target)
            if node.value is not None:
                self.visit(node.value)
        else:
            self.generic_visit(node)

    visit_AnnAssign = visit_Assign

    def _path_receiver(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            if self.scope.resolve(node.func) == "pathlib.Path":
                return True
            if isinstance(node.func, ast.Attribute) and node.func.attr in _TRANSFORMS:
                return self._path_receiver(node.func.value)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return self._path_receiver(node.left)
        return False

    def _path(self, node: ast.AST) -> _PathSyntax:
        if isinstance(node, ast.Constant):
            text = _string(node)
            return _PathSyntax(text, False, 0, valid=text is not None)
        if isinstance(node, ast.Call) and self.scope.resolve(node.func) == "pathlib.Path":
            if len(node.args) != 1 or node.keywords or _expanded(node):
                return _PathSyntax(None, False, 0, valid=False)
            return self._path(node.args[0])
        holes = sum(isinstance(item, ast.FormattedValue) for item in ast.walk(node))
        return _PathSyntax(None, True, holes, transformed=self._path_receiver(node))

    def _mode(self, node: ast.Call, position: int, *, default: str = "r") -> str | None:
        explicit = len(node.args) > position or any(item.arg == "mode" for item in node.keywords)
        argument = _argument(node, position, "mode")
        if not explicit:
            return default
        mode = _string(argument)
        if (
            mode is None
            or not mode
            or set(mode) - set("rwaxbt+")
            or sum(mode.count(c) for c in "rwax") != 1
            or any(mode.count(c) > 1 for c in "rwaxbt+")
            or ("b" in mode and "t" in mode)
        ):
            self.observe(
                node, "unresolved-mode", "Dynamic, invalid or ambiguous file mode", issue=True
            )
            return None
        return mode

    def _io(
        self,
        node: ast.Call,
        callee: str,
        path: ast.AST,
        *,
        writes: bool,
        reads: bool,
        role: str = "path",
    ) -> None:
        syntax = self._path(path)
        if not syntax.valid:
            self.observe(
                node,
                "unsupported-path",
                "Only supported string/path expressions are inspected",
                issue=True,
            )
            return
        self.observe(
            node, "filesystem-operation", f"{role}: read={reads}, write={writes}; syntax only"
        )
        if syntax.dynamic:
            self.emit("001", node, callee, f"nonliteral-{role}")
            if writes:
                self.emit("003", node, callee, f"nonliteral-write-{role}")
        if syntax.transformed:
            self.observe(
                node,
                "unresolved-transformation",
                "Path transformation does not establish containment",
                issue=True,
            )
        if syntax.interpolations:
            self.observe(
                node,
                "path-interpolation",
                "Formatted-expression count, not entropy",
                rule="008",
                measurements={"formatted_expressions": syntax.interpolations},
            )
        if syntax.literal is None:
            return
        # Pure lexical parsers never resolve or inspect the filesystem named by source code.
        posix, windows = PurePosixPath(syntax.literal), PureWindowsPath(syntax.literal)
        for flavor, value in (("posix", posix), ("windows", windows)):
            if ".." in value.parts:
                self.emit("005", node, callee, f"literal-parent-component-{flavor}")
        if reads:
            suffixes = {posix.suffix.lower(), windows.suffix.lower()}
            if suffixes & (_CODE_SUFFIXES | _CONFIG_SUFFIXES):
                self.observe(
                    node,
                    "filetype-declaration",
                    "Recognized code/config suffix; contents uninspected",
                    rule="004",
                )
        if syntax.literal in {"/tmp", "/run"} or syntax.literal.startswith(("/tmp/", "/run/")):
            self.observe(
                node,
                "temporary-path-prefix",
                "Literal POSIX-style prefix; no safety or anomaly verdict",
                rule="007",
            )
        if writes:
            self.observe(
                node,
                "write-path-structure",
                "Lexical component counts, not risk or actual depth",
                rule="009",
                measurements={
                    "posix_components": sum(part != posix.anchor for part in posix.parts),
                    "windows_components": sum(part != windows.anchor for part in windows.parts),
                },
            )
            stems = {posix.stem.lower(), windows.stem.lower()}
            components = {part.lower() for part in (*posix.parts, *windows.parts)}
            if components & _STATE_NAMES or any(
                stem.split("_")[0] in _STATE_NAMES for stem in stems
            ):
                self.observe(
                    node,
                    "state-like-destination",
                    "Filename/component heuristic; not confirmed agent state",
                    rule="012",
                )

    def _open_path(self, node: ast.Call) -> tuple[ast.AST, str | None] | None:
        if _expanded(node):
            return None
        if self.scope.resolve(node.func) in _OPEN:
            if not _valid_arguments(node, _OPEN_SIGNATURE, required=1):
                return None
            path = _argument(node, 0, "file")
            return (path, self._mode(node, 1)) if path is not None else None
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "open"
            and self._path_receiver(node.func.value)
        ):
            if not _valid_arguments(node, _PATH_SIGNATURES["open"]):
                return None
            return node.func.value, self._mode(node, 0)
        return None

    def _read_expression(self, node: ast.AST) -> bool:
        if (
            not isinstance(node, ast.Call)
            or _expanded(node)
            or not isinstance(node.func, ast.Attribute)
        ):
            return False
        if node.func.attr in _READ_METHODS and self._path_receiver(node.func.value):
            return self._path(node.func.value).valid and _valid_arguments(
                node, _PATH_SIGNATURES[node.func.attr]
            )
        if node.func.attr == "read" and isinstance(node.func.value, ast.Call):
            if len(node.args) > 1 or node.keywords:
                return False
            opened = self._open_path(node.func.value)
            return (
                opened is not None
                and opened[1] is not None
                and ("r" in opened[1] or "+" in opened[1])
            )
        return False

    def _write_value(self, node: ast.Call, callee: str, value: ast.AST | None) -> None:
        if value is None:
            self.observe(
                node, "unresolved-write-data", "Missing or ambiguous write data", issue=True
            )
        elif _secret_name(value):
            self.emit("006", node, callee, "credential-like-identifier-in-write")
        elif isinstance(value, ast.Call):
            self.observe(
                node,
                "unresolved-write-data",
                "Transformation not inspected for secret flow",
                issue=True,
            )

    def visit_Call(self, node: ast.Call) -> None:
        callee = self.scope.resolve(node.func)
        method = node.func.attr if isinstance(node.func, ast.Attribute) else None
        receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
        path_method = (
            method in _PATH_METHODS and receiver is not None and self._path_receiver(receiver)
        )
        inline_write = (
            method == "write"
            and isinstance(receiver, ast.Call)
            and (
                self.scope.resolve(receiver.func) in _OPEN
                or (
                    isinstance(receiver.func, ast.Attribute)
                    and receiver.func.attr == "open"
                    and self._path_receiver(receiver.func.value)
                )
            )
        )
        known = (
            callee in _OPEN | _COPY | {"builtins.exec", "builtins.eval"}
            or path_method
            or inline_write
        )
        if known and _expanded(node):
            self.observe(node, "unresolved-arguments", "Expanded call arguments", issue=True)
        elif callee in _COPY and not _valid_arguments(
            node,
            _COPY_SIGNATURES[callee],
            required=2,
            keyword_only=("follow_symlinks",)
            if callee in {"shutil.copy", "shutil.copy2", "shutil.copyfile"}
            else (),
        ):
            self.observe(node, "unresolved-arguments", "Unsupported copy call shape", issue=True)
        elif callee in {"builtins.exec", "builtins.eval"} and (
            not node.args
            or any(item.arg == "source" for item in node.keywords)
            or not _valid_arguments(
                node,
                ("source", "globals", "locals"),
                required=1,
                keyword_only=("closure",) if callee == "builtins.exec" else (),
            )
        ):
            self.observe(
                node, "unresolved-arguments", "Unsupported evaluation call shape", issue=True
            )
        elif callee in _OPEN or (path_method and method == "open"):
            opened = self._open_path(node)
            if opened is None:
                self.observe(
                    node, "unresolved-arguments", "Missing or ambiguous file argument", issue=True
                )
            elif isinstance(opened[0], ast.Constant) and type(opened[0].value) is int:
                self.observe(node, "file-descriptor", "Integer descriptor, not a path")
            else:
                path, mode = opened
                self._io(
                    node,
                    callee or "pathlib.Path().open",
                    path,
                    writes=mode is not None and bool(set(mode) & set("wax+")),
                    reads=mode is not None and ("r" in mode or "+" in mode),
                )
        elif path_method and receiver is not None and method is not None:
            if not _valid_arguments(
                node, _PATH_SIGNATURES[method], required=int(method in _WRITE_METHODS)
            ):
                self.observe(
                    node, "unresolved-arguments", "Unsupported path-method call shape", issue=True
                )
            else:
                self._io(
                    node,
                    f"pathlib.Path().{method}",
                    receiver,
                    writes=method in _WRITE_METHODS,
                    reads=method in _READ_METHODS,
                )
                if method in _WRITE_METHODS and self._path(receiver).valid:
                    self._write_value(node, f"pathlib.Path().{method}", _argument(node, 0, "data"))
        elif callee in _COPY and callee is not None:
            for position, name, writes in ((0, "src", False), (1, "dst", True)):
                value = _argument(node, position, name)
                if value is None:
                    self.observe(
                        node, "unresolved-arguments", "Missing or ambiguous copy path", issue=True
                    )
                else:
                    self._io(node, callee, value, writes=writes, reads=not writes, role=name)
        elif inline_write and isinstance(receiver, ast.Call):
            opened = self._open_path(receiver)
            if opened is None or opened[1] is None or not (set(opened[1]) & set("wax+")):
                self.observe(
                    node,
                    "unresolved-handle",
                    "Write-capable inline handle not established",
                    issue=True,
                )
            elif node.keywords:
                self.observe(
                    node, "unresolved-arguments", "Handle write data is positional-only", issue=True
                )
            else:
                self._write_value(
                    node, "open().write", node.args[0] if len(node.args) == 1 else None
                )
        elif callee in {"builtins.exec", "builtins.eval"} and node.args:
            if self._read_expression(node.args[0]):
                self.emit("011", node, callee, "direct-file-read-to-code-evaluation")
        elif method in _TRANSFORMS and receiver is not None and self._path_receiver(receiver):
            self.observe(node, "path-transformation", "Transformation syntax; no containment proof")
        elif method in _UNRESOLVED:
            self.observe(
                node,
                "unresolved-callee",
                "Path/handle-like method with unestablished receiver",
                issue=True,
            )
        elif isinstance(node.func, ast.Name) and node.func.id in {"open", "eval", "exec"}:
            self.observe(node, "unresolved-callee", "Builtin-like name is not resolved", issue=True)
        self.generic_visit(node)


def scan_source(data: bytes, *, path: str) -> FilesystemFileResult:
    """Analyze explicit bytes. Run untrusted source only through the restricted worker."""
    canonical_artifact_path(path)
    digest = sha256_bytes(data)
    state: Literal["analyzed", "malformed", "unsupported", "failed"] = "analyzed"
    reason = "Bounded filesystem syntax inspection, not full security coverage"
    findings: list[FilesystemFinding] | None = None
    inventory: list[FilesystemObservation] = []
    issues: list[FilesystemObservation] = []
    if PurePosixPath(path).suffix != ".py":
        state, reason = (
            "unsupported",
            "Only .py source is supported; MCP uses its existing analyzer",
        )
    elif len(data) > MAX_INPUT_BYTES:
        state, reason = "failed", "Input exceeds 256 KiB"
    else:
        try:
            tree = ast.parse(data.decode("utf-8", errors="strict"), filename="<filesystem-input>")
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
    return FilesystemFileResult(
        path=path,
        source_sha256=digest,
        byte_length=len(data),
        state=state,
        reason=reason,
        findings=findings,
        inventory=inventory,
        limitations_observed=issues,
    )
