from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from ca9.analysis.api_usage import FileSymbolIndex, _resolve_call_fqname, build_file_index

_EXCLUDED_DIRS = {
    ".venv",
    "venv",
    ".env",
    "env",
    "node_modules",
    ".git",
    "__pycache__",
    ".tox",
    ".nox",
    ".eggs",
    ".mypy_cache",
    "site-packages",
    "dist-packages",
}

_NON_RUNTIME_DIRS = {
    "tests",
    "test",
    "testing",
    "docs",
    "doc",
    "demo",
    "demos",
    "examples",
    "example",
    "benchmarks",
    "benchmark",
    "fixtures",
    "htmlcov",
}


def _is_runtime_python_file(py_file: Path, repo_path: Path) -> bool:
    rel_parts = py_file.relative_to(repo_path).parts
    parent_names = set(rel_parts[:-1])

    if _EXCLUDED_DIRS & parent_names:
        return False

    if _NON_RUNTIME_DIRS & parent_names:
        return False

    filename = py_file.name
    if filename == "conftest.py":
        return False

    return not (
        len(rel_parts) == 1 and (filename.startswith("test_") or filename.endswith("_test.py"))
    )


@dataclass(frozen=True)
class CallGraphNode:
    file_path: str
    function_name: str
    line_start: int
    line_end: int
    is_entry_point: bool = False


@dataclass
class CallGraph:
    nodes: dict[str, CallGraphNode] = field(default_factory=dict)
    edges: dict[str, set[str]] = field(default_factory=dict)
    entry_points: list[str] = field(default_factory=list)

    def add_node(self, qualified_name: str, node: CallGraphNode) -> None:
        self.nodes[qualified_name] = node
        if qualified_name not in self.edges:
            self.edges[qualified_name] = set()
        if node.is_entry_point and qualified_name not in self.entry_points:
            self.entry_points.append(qualified_name)

    def add_edge(self, caller: str, callee: str) -> None:
        self.edges.setdefault(caller, set()).add(callee)


def _module_name_from_path(file_path: Path, repo_path: Path) -> str:
    rel = file_path.relative_to(repo_path)
    parts = list(rel.parts)
    if parts[-1] == "__init__.py":
        parts = parts[:-1]
    else:
        parts[-1] = parts[-1].removesuffix(".py")
    return ".".join(parts)


def _qualified_function_name(module: str, class_name: str | None, func_name: str) -> str:
    if class_name:
        return f"{module}.{class_name}.{func_name}"
    return f"{module}.{func_name}"


def _extract_functions(
    tree: ast.Module,
    module_name: str,
    file_path: str,
) -> list[tuple[str, CallGraphNode]]:
    results: list[tuple[str, CallGraphNode]] = []

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qname = _qualified_function_name(module_name, None, node.name)
            results.append(
                (
                    qname,
                    CallGraphNode(
                        file_path=file_path,
                        function_name=node.name,
                        line_start=node.lineno,
                        line_end=node.end_lineno or node.lineno,
                    ),
                )
            )

        elif isinstance(node, ast.ClassDef):
            for item in ast.iter_child_nodes(node):
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    qname = _qualified_function_name(module_name, node.name, item.name)
                    results.append(
                        (
                            qname,
                            CallGraphNode(
                                file_path=file_path,
                                function_name=item.name,
                                line_start=item.lineno,
                                line_end=item.end_lineno or item.lineno,
                            ),
                        )
                    )

    return results


def _is_main_block(node: ast.AST) -> bool:
    if not isinstance(node, ast.If):
        return False

    test = node.test
    return (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and test.left.id == "__name__"
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.Eq)
        and len(test.comparators) == 1
        and isinstance(test.comparators[0], ast.Constant)
        and test.comparators[0].value == "__main__"
    )


def _extract_main_blocks(
    tree: ast.Module,
    module_name: str,
    file_path: str,
) -> list[tuple[str, CallGraphNode]]:
    results: list[tuple[str, CallGraphNode]] = []

    for node in ast.iter_child_nodes(tree):
        if not _is_main_block(node):
            continue
        results.append(
            (
                f"{module_name}.__main__",
                CallGraphNode(
                    file_path=file_path,
                    function_name="__main__",
                    line_start=node.lineno,
                    line_end=node.end_lineno or node.lineno,
                ),
            )
        )

    return results


def _extract_calls_in_function(
    func_node: ast.AST,
    index: FileSymbolIndex,
) -> list[str]:
    calls: list[str] = []
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call):
            resolved = _resolve_call_fqname(node.func, index)
            if resolved:
                calls.append(resolved)
            elif isinstance(node.func, ast.Name):
                calls.append(node.func.id)
    return calls


def _resolve_callee(
    raw_callee: str,
    index: FileSymbolIndex,
    module_name: str,
    all_qualified_names: set[str],
) -> str | None:
    if raw_callee in all_qualified_names:
        return raw_callee

    local_candidate = f"{module_name}.{raw_callee}"
    if local_candidate in all_qualified_names:
        return local_candidate

    if raw_callee in index.symbol_aliases:
        resolved = index.symbol_aliases[raw_callee]
        if resolved in all_qualified_names:
            return resolved

    suffix = raw_callee.rsplit(".", 1)[-1]
    for qname in all_qualified_names:
        if qname.endswith(f".{suffix}"):
            parts = raw_callee.split(".")
            qparts = qname.split(".")
            if len(parts) >= 2 and len(qparts) >= 2:
                if parts[0] == qparts[0] or parts[0] in index.module_aliases:
                    return qname
            elif len(parts) == 1:
                if qname.startswith(module_name + "."):
                    return qname

    return None


def build_call_graph(
    repo_path: Path,
    entry_point_names: set[str] | None = None,
) -> CallGraph:
    graph = CallGraph()

    file_data: list[tuple[str, str, str, ast.Module, FileSymbolIndex]] = []

    for py_file in repo_path.rglob("*.py"):
        if not _is_runtime_python_file(py_file, repo_path):
            continue

        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        try:
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            continue

        module_name = _module_name_from_path(py_file, repo_path)
        index = build_file_index(str(py_file), source)
        file_data.append((str(py_file), module_name, source, tree, index))

        funcs = _extract_functions(tree, module_name, str(py_file))
        funcs.extend(_extract_main_blocks(tree, module_name, str(py_file)))
        for qname, node in funcs:
            is_ep = entry_point_names is not None and qname in entry_point_names
            if is_ep:
                node = CallGraphNode(
                    file_path=node.file_path,
                    function_name=node.function_name,
                    line_start=node.line_start,
                    line_end=node.line_end,
                    is_entry_point=True,
                )
            graph.add_node(qname, node)

    all_qnames = set(graph.nodes.keys())

    for _file_path, module_name, _source, tree, index in file_data:
        for node in ast.iter_child_nodes(tree):
            func_nodes: list[tuple[str, ast.AST]] = []

            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qname = _qualified_function_name(module_name, None, node.name)
                func_nodes.append((qname, node))
            elif isinstance(node, ast.ClassDef):
                for item in ast.iter_child_nodes(node):
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        qname = _qualified_function_name(module_name, node.name, item.name)
                        func_nodes.append((qname, item))
            elif _is_main_block(node):
                func_nodes.append((f"{module_name}.__main__", node))

            for qname, func_node in func_nodes:
                raw_calls = _extract_calls_in_function(func_node, index)
                for raw in raw_calls:
                    resolved = _resolve_callee(raw, index, module_name, all_qnames)
                    if resolved and resolved != qname:
                        graph.add_edge(qname, resolved)

    return graph
