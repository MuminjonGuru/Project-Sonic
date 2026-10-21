"""Shared conservative Python syntax helpers; never import or execute target code."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from pydantic import Field

from agentsec_evidence.models.contracts import ContractModel


class SourceRange(ContractModel):
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    start_utf8_byte_column: int = Field(ge=0)
    end_utf8_byte_column: int = Field(ge=0)


def location(node: ast.AST) -> SourceRange:
    if not isinstance(node, (ast.stmt, ast.expr)):
        raise ValueError("Observation lacks a source range")
    return SourceRange(
        start_line=node.lineno,
        end_line=node.end_lineno or node.lineno,
        start_utf8_byte_column=node.col_offset,
        end_utf8_byte_column=node.end_col_offset or 0,
    )


def raw_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = raw_name(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


@dataclass
class Bindings(ast.NodeVisitor):
    """Collect lexical rebinding conservatively, without following nested bodies."""

    values: dict[str, list[str | None]] = field(default_factory=dict)
    wildcard: bool = False
    conditional: int = 0

    def bind(self, name: str, value: str | None = None) -> None:
        self.values.setdefault(name, []).append(value)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.bind(node.id)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[0]
            value = alias.name if alias.asname else alias.name.split(".")[0]
            self.bind(name, value if not self.conditional else None)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name == "*":
                self.wildcard = True
                continue
            value = f"{node.module}.{alias.name}"
            self.bind(
                alias.asname or alias.name,
                value if not self.conditional and not node.level else None,
            )

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.bind(node.name)
        for expression in [*node.decorator_list, *node.args.defaults, *node.args.kw_defaults]:
            if expression is not None:
                self.visit(expression)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.bind(node.name)
        for expression in [*node.decorator_list, *node.bases, *node.keywords]:
            self.visit(expression)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for expression in [*node.args.defaults, *node.args.kw_defaults]:
            if expression is not None:
                self.visit(expression)

    def visit_Global(self, node: ast.Global | ast.Nonlocal) -> None:
        for name in node.names:
            self.bind(name)

    visit_Nonlocal = visit_Global

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.bind(node.name)
        self.generic_visit(node)

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        if node.name:
            self.bind(node.name)
        self.generic_visit(node)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:
        if node.name:
            self.bind(node.name)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        if node.rest:
            self.bind(node.rest)
        self.generic_visit(node)

    def generic_visit(self, node: ast.AST) -> None:
        # Conditional imports do not prove a binding exists at the later call site.
        guarded = isinstance(
            node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.TryStar, ast.Match)
        )
        self.conditional += int(guarded)
        super().generic_visit(node)
        self.conditional -= int(guarded)


@dataclass
class Scope:
    bindings: Bindings
    parent: Scope | None
    function: str | None = None
    tool: bool = False
    parameters: frozenset[str] = frozenset()
    kind: str = "module"
    builtin_names: frozenset[str] = frozenset({"eval", "exec", "__import__"})

    def resolve(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Attribute):
            parent = self.resolve(node.value)
            return f"{parent}.{node.attr}" if parent else None
        if not isinstance(node, ast.Name):
            return None
        if self.bindings.wildcard:
            return None
        if node.id in self.bindings.values:
            values = self.bindings.values[node.id]
            return values[0] if len(values) == 1 else None
        if self.parent:
            return self.parent.resolve(node)
        return f"builtins.{node.id}" if node.id in self.builtin_names else None


def arguments(args: ast.arguments) -> frozenset[str]:
    return frozenset(
        argument.arg
        for argument in [
            *args.posonlyargs,
            *args.args,
            *args.kwonlyargs,
            *([args.vararg] if args.vararg else []),
            *([args.kwarg] if args.kwarg else []),
        ]
    )
