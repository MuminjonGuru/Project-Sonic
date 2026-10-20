"""Bounded network/data-transfer syntax conditions; no network or target execution."""

from __future__ import annotations

import ast
import re
from pathlib import PurePosixPath
from typing import Final, Literal
from urllib.parse import parse_qsl, urlsplit

from pydantic import Field

from agentsec_evidence.agents.inputs import MAX_AST_NODES, MAX_INPUT_BYTES
from agentsec_evidence.agents.validation import canonical_artifact_path
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.custom_rules.network_catalog import BY_ID
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
    "Development-only static observations, not verified vulnerabilities, SSRF or exfiltration.",
    "Imports are lexical; runtime types, local module substitution and monkey-patching unknown.",
    "No assignment/instance aliases, cross-file flow, sanitization or effective-policy analysis.",
    "Lambda/comprehension bodies, annotations and opaque object methods are not analyzed.",
    "No MCP, target execution, network access, DNS queries, credentials lookup or model calls.",
    "Inventory-only and deferred IDs are not implemented vulnerability coverage.",
    "No trusted-host exceptions, target-local suppressions, risk score or automatic grouping.",
    "Evidence omits expression text, URL values, query values, secret names and credential values.",
)


class NetworkObservation(ContractModel):
    kind: str
    location: SourceRange
    detail: str
    rule_id: str | None = None


class NetworkFinding(ContractModel):
    record_id: Sha256
    rule_id: str
    priority: Literal["low", "medium"]
    location: SourceRange
    callee: str
    evidence_kinds: list[str]
    verification: Literal["unreviewed-static-condition"] = "unreviewed-static-condition"


class NetworkFileResult(ContractModel):
    path: str
    source_sha256: Sha256
    byte_length: int = Field(ge=0)
    state: Literal["analyzed", "malformed", "unsupported", "failed"]
    reason: str
    findings: list[NetworkFinding] | None
    inventory: list[NetworkObservation]
    limitations_observed: list[NetworkObservation]


_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
_HTTP: dict[str, tuple[int | None, str]] = {
    f"{prefix}.{method}": (0, "url")
    for prefix in (
        "requests",
        "httpx",
        "requests.Session()",
        "httpx.Client()",
        "httpx.AsyncClient()",
        "aiohttp.ClientSession()",
    )
    for method in _METHODS
}
_HTTP.update(
    {
        f"{prefix}.request": (1, "url")
        for prefix in (
            "requests",
            "httpx",
            "requests.Session()",
            "httpx.Client()",
            "httpx.AsyncClient()",
            "aiohttp.ClientSession()",
        )
    }
)
_HTTP.update(
    {
        "urllib.request.urlopen": (0, "url"),
        "httpx.Client": (None, "base_url"),
        "httpx.AsyncClient": (None, "base_url"),
        "aiohttp.ClientSession": (0, "base_url"),
        "httpx.stream": (1, "url"),
    }
)
_WS = {
    "websockets.connect",
    "websockets.asyncio.client.connect",
    "websockets.sync.client.connect",
    "websocket.create_connection",
}
_GRPC = {
    f"{prefix}.{kind}_channel" for prefix in ("grpc", "grpc.aio") for kind in ("secure", "insecure")
}
_DNS = {
    "socket.getaddrinfo": (0, "host"),
    "socket.gethostbyname": (0, "hostname"),
    "dns.resolver.resolve": (0, "qname"),
}
_LOG = {
    "builtins.print",
    *(
        f"logging.{name}"
        for name in ("debug", "info", "warning", "error", "critical", "exception", "log")
    ),
}
_FACTORIES = {"requests.Session", "httpx.Client", "httpx.AsyncClient", "aiohttp.ClientSession"}
_S3 = {"boto3.client(s3).get_object", "boto3.client(s3).put_object"}
_SENSITIVE = {
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "client_secret",
    "aws_secret_access_key",
}
_UNRESOLVED_TERMINALS = {
    "request",
    "urlopen",
    "connect",
    "insecure_channel",
    "secure_channel",
    "get_object",
    "put_object",
    "ProxyHandler",
}


def _string(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _sensitive_name(name: str) -> bool:
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).casefold().replace("-", "_")
    return normalized in _SENSITIVE or bool(
        set(normalized.split("_")) & {"password", "passwd", "secret", "token"}
    )


def _direct_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        return [node.attr]
    if isinstance(node, ast.JoinedStr):
        return [
            name
            for item in node.values
            if isinstance(item, ast.FormattedValue)
            for name in _direct_names(item.value)
        ]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _direct_names(node.left) + _direct_names(node.right)
    return []


def _pieces(node: ast.AST) -> list[str | None]:
    text = _string(node)
    if text is not None:
        return [text]
    if isinstance(node, ast.JoinedStr):
        return [
            item.value if isinstance(item, ast.Constant) and isinstance(item.value, str) else None
            for item in node.values
        ]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _pieces(node.left) + _pieces(node.right)
    return [None]


def _interpolated_authority(node: ast.AST) -> bool:
    pieces = _pieces(node)
    if None not in pieces:
        return False
    prefix = "".join(item for item in pieces[: pieces.index(None)] if item is not None)
    if "://" not in prefix:
        return False
    scheme, authority = prefix.split("://", 1)
    return scheme.casefold() in {"http", "https", "ws", "wss"} and not any(
        delimiter in authority for delimiter in "/?#"
    )


def _literal_container(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple)):
        return all(_literal_container(item) for item in node.elts)
    if isinstance(node, ast.Dict):
        return all(key is not None and _literal_container(key) for key in node.keys) and all(
            _literal_container(value) for value in node.values
        )
    return False


class _Analyzer(ast.NodeVisitor):
    def __init__(self, source: str, path: str, digest: str, tree: ast.Module) -> None:
        bindings = Bindings()
        bindings.visit(tree)
        self.scope = Scope(bindings, None, builtin_names=frozenset({"print"}))
        self.path, self.digest = path, digest
        self.findings: dict[tuple[str, int, int], NetworkFinding] = {}
        self.inventory: list[NetworkObservation] = []
        self.issues: list[NetworkObservation] = []

    def _budget(self) -> None:
        if len(self.findings) + len(self.inventory) + len(self.issues) >= MAX_RECORDS:
            raise ValueError("Observation budget exceeded")

    def observe(
        self, node: ast.AST, kind: str, detail: str, *, rule: str | None = None, issue: bool = False
    ) -> None:
        self._budget()
        target = self.issues if issue else self.inventory
        target.append(
            NetworkObservation(
                kind=kind,
                location=location(node),
                detail=detail,
                rule_id=f"NET-DATA-{rule}" if rule else None,
            )
        )

    def emit(self, suffix: str, node: ast.Call, callee: str, evidence: str) -> None:
        rule_id = f"NET-DATA-{suffix}"
        rule = BY_ID[rule_id]
        if rule.status != "active-condition" or rule.priority is None:
            raise ValueError("Nonactive rule cannot emit a finding")
        key = (rule_id, node.lineno, node.col_offset)
        if key in self.findings:
            self.findings[key].evidence_kinds = sorted(
                set(self.findings[key].evidence_kinds) | {evidence}
            )
            return
        self._budget()
        span = location(node)
        identity = f"{VERSION}:{self.path}:{self.digest}:{rule_id}:{span.model_dump_json()}"
        self.findings[key] = NetworkFinding(
            record_id=sha256_bytes(identity.encode()),
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
        for expression in [*node.decorator_list, *node.bases, *node.keywords]:
            self.visit(expression)
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

    def visit_Assign(self, node: ast.Assign | ast.AnnAssign) -> None:
        if isinstance(node.value, ast.Call):
            factory = self.scope.resolve(node.value.func)
            if factory in _FACTORIES | {"boto3.client", "logging.getLogger"}:
                self.observe(
                    node,
                    "untracked-instance",
                    "Assigned client/logger methods are not resolved by this version",
                    issue=True,
                )
        self.generic_visit(node)

    visit_AnnAssign = visit_Assign

    def visit_ListComp(self, node: ast.AST) -> None:
        self.observe(node, "unsupported-scope", "Comprehension not analyzed", issue=True)

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if any(alias.name == "*" for alias in node.names):
            self.observe(
                node, "ambiguous-bindings", "Wildcard import limits resolution", issue=True
            )

    def _callee(self, node: ast.AST) -> str | None:
        direct = self.scope.resolve(node)
        if direct:
            return direct
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Call):
            factory = self.scope.resolve(node.value.func)
            if factory in _FACTORIES:
                return f"{factory}().{node.attr}"
            if factory == "boto3.client" and not self._expanded(node.value):
                service = self._argument(node.value, 0, "service_name")
                if _string(service) == "s3":
                    return f"boto3.client(s3).{node.attr}"
        return None

    @staticmethod
    def _expanded(node: ast.Call) -> bool:
        return any(isinstance(item, ast.Starred) for item in node.args) or any(
            item.arg is None for item in node.keywords
        )

    @staticmethod
    def _argument(node: ast.Call, position: int | None, keyword: str) -> ast.expr | None:
        positional = (
            node.args[position] if position is not None and len(node.args) > position else None
        )
        named = [item.value for item in node.keywords if item.arg == keyword]
        if len(named) > 1 or (positional is not None and named):
            return None
        return positional if positional is not None else named[0] if named else None

    def _environment_key(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Subscript) and self.scope.resolve(node.value) == "os.environ":
            return _string(node.slice)
        if isinstance(node, ast.Call) and not self._expanded(node):
            name = self.scope.resolve(node.func)
            if name in {"os.getenv", "os.environ.get"}:
                return _string(self._argument(node, 0, "key"))
        return None

    def _environment_in(self, node: ast.AST) -> bool:
        return any(
            (key := self._environment_key(item)) is not None and _sensitive_name(key)
            for item in ast.walk(node)
        )

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if self._environment_key(node) == "SPIFFE_ID":
            self.observe(node, "identity-input", "SPIFFE_ID environment read", rule="108")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        callee = self._callee(node.func)
        if self._environment_key(node) == "SPIFFE_ID":
            self.observe(node, "identity-input", "SPIFFE_ID environment read", rule="108")
        supported = callee in set(_HTTP) | _WS | _GRPC | set(_DNS) | _LOG | _S3 | {
            "urllib.request.ProxyHandler",
        }
        if supported and self._expanded(node):
            self.observe(node, "unresolved-arguments", "Expanded call arguments", issue=True)
        elif supported and callee is not None:
            self._check_call(node, callee)
        elif callee in _FACTORIES | {"boto3.client", "logging.getLogger"}:
            self.observe(
                node,
                "client-constructor",
                "Assigned client/logger instances are not tracked; inline support is bounded",
            )
        elif isinstance(node.func, ast.Attribute) and node.func.attr in _UNRESOLVED_TERMINALS:
            self.observe(
                node,
                "unresolved-callee",
                "Call name resembles a supported API but its binding is unestablished",
                issue=True,
            )
        self.generic_visit(node)

    def _check_call(self, node: ast.Call, callee: str) -> None:
        if callee in _HTTP:
            position, keyword = _HTTP[callee]
            argument = self._argument(node, position, keyword)
            if argument is not None:
                self._url(node, callee, argument, "001")
            elif callee not in _FACTORIES:
                self.observe(
                    node, "unresolved-arguments", "Missing or ambiguous destination", issue=True
                )
            self._http_options(node, callee)
        elif callee in _WS:
            argument = self._argument(node, 0, "url" if callee.startswith("websocket.") else "uri")
            if argument is None:
                self.observe(
                    node, "unresolved-arguments", "Missing or ambiguous WebSocket URI", issue=True
                )
            else:
                self._url(node, callee, argument, "101")
        elif callee in _GRPC:
            argument = self._argument(node, 0, "target")
            self._nonliteral(node, callee, argument, "102", "channel-target")
            self.observe(
                node,
                "channel-constructor",
                "Explicit insecure channel"
                if "insecure_channel" in callee
                else "Secure-channel API declaration; credentials not verified",
            )
        elif callee in _S3:
            for key in ("Bucket", "Key"):
                argument = self._argument(node, None, key)
                self._nonliteral(node, callee, argument, "103", f"storage-{key.casefold()}")
        elif callee in _DNS:
            position, keyword = _DNS[callee]
            argument = self._argument(node, position, keyword)
            if argument is None:
                self.observe(
                    node, "unresolved-arguments", "Missing or ambiguous DNS name", issue=True
                )
            elif (
                isinstance(argument, ast.JoinedStr)
                or (isinstance(argument, ast.BinOp) and isinstance(argument.op, ast.Add))
            ) and None in _pieces(argument):
                self.emit("107", node, callee, "interpolated-dns-name")
            else:
                self.observe(
                    node, "dns-name", "No supported interpolation condition; source unknown"
                )
        elif callee == "urllib.request.ProxyHandler":
            argument = self._argument(node, 0, "proxies")
            if argument is not None and not _literal_container(argument):
                self.emit("109", node, callee, "nonliteral-proxy-configuration")
            else:
                self.observe(node, "proxy-configuration", "Literal or default proxy configuration")
        elif callee in _LOG:
            values = list(node.args[1:] if callee == "logging.log" else node.args)
            if callee != "builtins.print":
                message = self._argument(node, 1 if callee == "logging.log" else 0, "msg")
                if message is None:
                    self.observe(
                        node, "unresolved-arguments", "Missing or ambiguous log message", issue=True
                    )
                    return
                if any(item.arg == "msg" for item in node.keywords):
                    values.append(message)
            if any(_sensitive_name(name) for value in values for name in _direct_names(value)):
                self.emit("005", node, callee, "credential-like-identifier")
            elif any(isinstance(value, ast.Call) for value in values):
                self.observe(
                    node,
                    "unresolved-logging-value",
                    "Called transformations are not inspected for secret flow",
                    issue=True,
                )

    def _nonliteral(
        self, node: ast.Call, callee: str, argument: ast.AST | None, rule: str, detail: str
    ) -> None:
        if argument is None:
            self.observe(
                node, "unresolved-arguments", "Missing or ambiguous protocol argument", issue=True
            )
        elif isinstance(argument, ast.Constant):
            self.observe(node, "protocol-argument", "Literal argument, not a safety verdict")
        else:
            self.emit(rule, node, callee, detail)

    def _url(self, node: ast.Call, callee: str, argument: ast.AST, rule: str) -> None:
        text = _string(argument)
        if isinstance(argument, ast.Constant) and text is None:
            self.observe(
                node, "unsupported-url-value", "Non-string literal destination", issue=True
            )
            return
        if text is None:
            self.emit(rule, node, callee, "nonliteral-destination-expression")
            if _interpolated_authority(argument):
                self.emit("003", node, callee, "url-authority-interpolation")
            if any(_sensitive_name(name) for name in _direct_names(argument)):
                self.emit("002", node, callee, "credential-like-identifier-in-url")
        else:
            self.observe(
                node, "literal-url", "Literal destination; value omitted; trust unverified"
            )
            try:
                parts = urlsplit(text)
                if parts.username or parts.password:
                    self.emit("002", node, callee, "literal-url-userinfo")
                if any(
                    _sensitive_name(key)
                    for key, _ in parse_qsl(parts.query, keep_blank_values=True, max_num_fields=128)
                ):
                    self.emit("002", node, callee, "credential-shaped-query-key")
            except ValueError:
                self.observe(
                    node,
                    "unsupported-url-shape",
                    "URL parsing failed or query-field budget exceeded",
                    issue=True,
                )
        if self._environment_in(argument):
            self.emit("110", node, callee, "credential-like-environment-read-in-url")

    def _http_options(self, node: ast.Call, callee: str) -> None:
        options = {item.arg: item.value for item in node.keywords if item.arg}
        duplicate = len(options) != len(node.keywords)
        if duplicate:
            self.observe(
                node, "unresolved-options", "Duplicate option names are not evaluated", issue=True
            )
            return
        # Option names belong to API signatures, not all calls that happen to use HTTP.
        if callee.startswith("requests."):
            allowed = {"params", "headers", "verify", "stream", "proxies"}
        elif callee.startswith("httpx."):
            allowed = {"params", "headers"}
            if "()" not in callee:
                allowed |= {"verify", "proxy"}
        elif callee == "aiohttp.ClientSession":
            allowed = {"headers"}
        elif callee.startswith("aiohttp."):
            allowed = {"params", "headers", "proxy"}
        else:
            allowed = set()
        relevant = {"params", "headers", "verify", "stream", "proxy", "proxies"}
        if set(options) & relevant - allowed:
            self.observe(
                node,
                "unsupported-api-option",
                "Option outside the supported API signature; no condition inferred from it",
                issue=True,
            )
        options = {key: value for key, value in options.items() if key in allowed}
        # A query is an exposure surface; a normal Authorization header is not itself a leak.
        params = options.get("params")
        if isinstance(params, ast.Dict):
            if any(key is None or _string(key) is None for key in params.keys):
                self.observe(
                    node,
                    "unresolved-query",
                    "Unpacked or nonliteral query keys cannot be enumerated",
                    issue=True,
                )
            if any(
                (name := _string(key)) is not None and _sensitive_name(name) for key in params.keys
            ):
                self.emit("002", node, callee, "credential-shaped-query-key")
            if self._environment_in(params):
                self.emit("110", node, callee, "credential-like-environment-read-in-query")
        elif params is not None and not (isinstance(params, ast.Constant) and params.value is None):
            self.observe(
                node, "unresolved-query", "Only an inline query dictionary is inspected", issue=True
            )
        if "headers" in options:
            self.observe(
                node,
                "headers-declaration",
                "Header expression present; authorization and data classification unverified",
            )
        if "verify" in options:
            flag = options["verify"]
            label = (
                "true"
                if isinstance(flag, ast.Constant) and flag.value is True
                else (
                    "false"
                    if isinstance(flag, ast.Constant) and flag.value is False
                    else "other/unknown"
                )
            )
            self.observe(node, "tls-setting", f"Explicit verify={label}", rule="105")
        stream = options.get("stream")
        if callee == "httpx.stream" or (isinstance(stream, ast.Constant) and stream.value is True):
            self.observe(node, "response-streaming", "Explicit streaming declaration", rule="004")
        proxy_key = "proxies" if callee.startswith("requests.") else "proxy"
        proxy = options.get(proxy_key)
        if proxy is not None:
            if not _literal_container(proxy):
                self.emit("109", node, callee, "nonliteral-proxy-configuration")
            else:
                self.observe(node, "proxy-configuration", "Literal explicit proxy configuration")


def scan_source(data: bytes, *, path: str) -> NetworkFileResult:
    """Analyze explicit source bytes. Untrusted inputs require the restricted worker."""
    canonical_artifact_path(path)
    digest = sha256_bytes(data)
    state: Literal["analyzed", "malformed", "unsupported", "failed"] = "analyzed"
    reason = "Bounded network syntax checks completed, not full security coverage"
    findings: list[NetworkFinding] | None = None
    inventory: list[NetworkObservation] = []
    issues: list[NetworkObservation] = []
    if PurePosixPath(path).suffix != ".py":
        state, reason = "unsupported", "Only .py source is supported"
    elif len(data) > MAX_INPUT_BYTES:
        state, reason = "failed", "Input exceeds 256 KiB"
    else:
        try:
            source = data.decode("utf-8", errors="strict")
            tree = ast.parse(source, filename="<network-data-input>")
            if sum(1 for _ in ast.walk(tree)) > MAX_AST_NODES:
                raise ValueError("AST node budget exceeded")
            analyzer = _Analyzer(source, path, digest, tree)
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
            state, reason = "malformed", "Invalid Python syntax or UTF-8 encoding"
        except (ValueError, RecursionError, MemoryError):
            state, reason = "failed", "Parser or observation resource guard reached"
    return NetworkFileResult(
        path=path,
        source_sha256=digest,
        byte_length=len(data),
        state=state,
        reason=reason,
        findings=findings,
        inventory=inventory,
        limitations_observed=issues,
    )
