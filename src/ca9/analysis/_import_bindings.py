"""Resolve name reads to statically bound imports in their Python scope."""

from __future__ import annotations

import ast
import builtins
from collections import defaultdict
from dataclasses import dataclass

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


@dataclass(frozen=True)
class ImportedName:
    qualified: str
    from_import: bool


@dataclass(frozen=True)
class _Binding:
    value: ImportedName | None
    # Direct statements in this scope execute in order. Conditional bindings
    # remain possible, including writes on another iteration of a loop.
    position: tuple[int, int] | None


class ImportBindings:
    def __init__(self, tree: ast.Module, parents: dict[int, ast.AST]) -> None:
        self.parents = parents
        self.scopes: dict[ast.AST, ast.AST] = {tree: tree}
        self.names: dict[ast.AST, dict[str, list[_Binding]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self.redirects: dict[tuple[ast.AST, str], ast.AST] = {}
        declarations: list[ast.Global | ast.Nonlocal] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.Global, ast.Nonlocal)):
                declarations.append(node)
            else:
                self._record(node)
        for declaration in declarations:
            scope = self._scope(declaration)
            for name in declaration.names:
                target: ast.AST = tree
                if isinstance(declaration, ast.Nonlocal):
                    target = self._scope(scope)
                    while not isinstance(target, ast.Module):
                        if isinstance(target, _FUNCTIONS) and name in self.names.get(target, {}):
                            break
                        target = self._scope(target)
                self.redirects[scope, name] = target
                if name in self.names.get(scope, {}):
                    # Another function can rebind this name between two reads.
                    self.names[target][name].append(_Binding(None, None))

    def _scope(self, node: ast.AST) -> ast.AST:
        path = []
        while node not in self.scopes:
            path.append(node)
            parent = self.parents[id(node)]
            if isinstance(
                parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ) and isinstance(node, ast.stmt):
                scope = parent
                break
            if isinstance(parent, ast.Lambda) and parent.body is node:
                scope = parent
                break
            if isinstance(parent, _COMPREHENSIONS):
                scope = parent
                break
            if isinstance(parent, ast.comprehension) and parent.iter is node:
                comp = self.parents[id(parent)]
                # Only the outermost iterable is evaluated in the enclosing scope.
                if comp.generators[0] is parent:
                    node = comp
                    continue
            node = parent
        else:
            scope = self.scopes[node]
        for item in path:
            self.scopes[item] = scope
        return scope

    def _record(self, node: ast.AST) -> None:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            is_from = isinstance(node, ast.ImportFrom)
            for alias in node.names:
                if is_from:
                    name = alias.asname or alias.name
                    qualified = f"{node.module}.{alias.name}" if not node.level else None
                else:
                    name = alias.asname or alias.name.split(".")[0]
                    qualified = alias.name if alias.asname else name
                value = ImportedName(qualified, is_from) if qualified and name != "*" else None
                self._bind(self._scope(node), name, value, node)
        elif isinstance(node, (*_FUNCTIONS, ast.ClassDef)):
            if not isinstance(node, ast.Lambda):
                self._bind(self._scope(node), node.name, None, node)
            if isinstance(node, _FUNCTIONS):
                for arg in ast.iter_child_nodes(node.args):
                    if isinstance(arg, ast.arg):
                        self.names[node][arg.arg].append(_Binding(None, (0, 0)))
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            scope = self._scope(node)
            owner = self.parents[id(node)]
            while isinstance(owner, (ast.List, ast.Tuple, ast.Starred)):
                owner = self.parents[id(owner)]
            if isinstance(owner, ast.NamedExpr):
                while isinstance(scope, _COMPREHENSIONS):
                    scope = self._scope(scope)
            self._bind(scope, node.id, None, owner)
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            self._bind(self._scope(node), node.name, None, node)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            self._bind(self._scope(node), node.rest, None, node)

    def _bind(self, scope: ast.AST, name: str, value: ImportedName | None, owner: ast.AST) -> None:
        position = None
        if (
            isinstance(
                owner,
                (
                    ast.Import,
                    ast.ImportFrom,
                    ast.Assign,
                    ast.AnnAssign,
                    ast.AugAssign,
                    ast.Delete,
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.ClassDef,
                ),
            )
            and self.parents.get(id(owner)) is scope
        ):
            position = (owner.end_lineno or owner.lineno, owner.end_col_offset or 0)
        self.names[scope][name].append(_Binding(value, position))

    def resolve(self, node: ast.Name) -> ImportedName | None:
        local = scope = self._scope(node)
        while True:
            scope = self.redirects.get((scope, node.id), scope)
            names = self.names.get(scope, {})
            bindings = names.get(node.id, [])
            wildcard = names.get("*", [])
            if bindings or wildcard:
                candidates = [*bindings, *wildcard]
                if scope is local:
                    position = (node.lineno, node.col_offset)
                    ordered = [b for b in candidates if b.position and b.position <= position]
                    last = max(ordered, key=lambda b: b.position) if ordered else None
                    values = {b.value for b in candidates if b.position is None}
                    if last:
                        values.add(last.value)
                    elif isinstance(scope, ast.ClassDef) or (
                        isinstance(scope, ast.Module) and node.id in vars(builtins)
                    ):
                        # An unbound class name falls back to globals and an
                        # unbound module name can fall back to a builtin.
                        values.add(None)
                else:
                    # A function or closure can run after later assignments.
                    values = {b.value for b in candidates}
                    if (
                        isinstance(scope, ast.Module)
                        and node.id in vars(builtins)
                        and not any(b.position for b in candidates)
                    ):
                        values.add(None)
                return values.pop() if len(values) == 1 else None
            if isinstance(scope, ast.Module):
                return None
            scope = self._scope(scope)
            # Class namespaces aren't lexical enclosing scopes for methods,
            # comprehensions, or nested classes.
            while isinstance(scope, ast.ClassDef):
                scope = self._scope(scope)
