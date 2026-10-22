"""Annotation-aware 1.1.0 treatment; the original 1.0.0 evidence stays replayable."""

from __future__ import annotations

import ast
from pathlib import PurePosixPath

from agentsec_evidence.agents.inputs import MAX_AST_NODES, MAX_INPUT_BYTES
from agentsec_evidence.agents.validation import canonical_artifact_path
from agentsec_evidence.core.identity import sha256_bytes
from agentsec_evidence.custom_rules import tool_execution as original

VERSION = "1.1.0"
LIMITATIONS = (
    *original.LIMITATIONS,
    "Annotation evaluation follows Python 3.13 syntax, not a detected target runtime.",
    "Postponed and function-local variable annotations are not ordinary call evidence; "
    "later annotation introspection is not modeled.",
    "Function-signature annotations and type-alias scopes remain outside this treatment.",
)


class AnnotationAnalyzer(original._Analyzer):
    def __init__(self, source: str, path: str, digest: str, tree: ast.Module) -> None:
        super().__init__(source, path, digest, tree)
        self.postponed = any(
            isinstance(node, ast.ImportFrom)
            and node.module == "__future__"
            and node.level == 0
            and any(alias.name == "annotations" for alias in node.names)
            for node in tree.body
        )

    def emit(self, rule_index: int, call: ast.Call, callee: str, argument: ast.AST) -> None:
        super().emit(rule_index, call, callee, argument)
        finding = self.findings[-1]
        identity = (
            f"{VERSION}:{self.path}:{self.digest}:{finding.rule.rule_id}:"
            f"{finding.location.model_dump_json()}"
        )
        self.findings[-1] = finding.model_copy(
            update={"record_id": sha256_bytes(identity.encode())}
        )

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        # Assignment values and target expressions still execute when annotations do not.
        if node.value is not None:
            self.visit(node.value)
        self.visit(node.target)
        if self.postponed or self.scope.kind == "function":
            self.observe(
                node.annotation,
                "annotation-not-ordinary-execution",
                "Postponed annotation" if self.postponed else "Function-local annotation",
                issue=True,
            )
        else:
            self.visit(node.annotation)

    def visit_TypeAlias(self, node: ast.TypeAlias) -> None:
        self.observe(node, "unsupported-scope", "Lazy type-alias scope not analyzed", issue=True)


def scan_source(data: bytes, *, path: str) -> original.FileResult:
    """Parse only authored tests on the host; foreign inputs belong in the isolated worker."""
    canonical_artifact_path(path)
    base = dict(path=path, source_sha256=sha256_bytes(data), byte_length=len(data))
    if PurePosixPath(path).suffix != ".py":
        state, reason = "unsupported", "Only .py source is admitted by this detector"
    elif len(data) > MAX_INPUT_BYTES:
        state, reason = "failed", "Input exceeds 256 KiB"
    else:
        try:
            source = data.decode("utf-8", errors="strict")
            tree = ast.parse(source, filename="<tool-execution-v2-input>")
            if sum(1 for _ in ast.walk(tree)) > MAX_AST_NODES:
                raise ValueError("AST node budget exceeded")
            analyzer = AnnotationAnalyzer(source, path, str(base["source_sha256"]), tree)
            analyzer.visit(tree)
            return original.FileResult.model_validate(
                {
                    **base,
                    "state": "analyzed",
                    "reason": (
                        "Bounded checks completed; no claim of full Python or security coverage"
                    ),
                    "findings": sorted(
                        analyzer.findings,
                        key=lambda f: (
                            f.location.start_line,
                            f.location.start_utf8_byte_column,
                            f.rule.rule_id,
                        ),
                    ),
                    "inventory": analyzer.inventory,
                    "limitations_observed": analyzer.issues,
                }
            )
        except (SyntaxError, UnicodeError):
            state, reason = "malformed", "Invalid Python syntax or UTF-8 encoding"
        except (ValueError, RecursionError, MemoryError):
            state, reason = "failed", "Parser or observation resource guard reached"
    return original.FileResult.model_validate(
        {
            **base,
            "state": state,
            "reason": reason,
            "findings": None,
            "inventory": [],
            "limitations_observed": [],
        }
    )
