from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from ca9.analysis._import_bindings import ImportBindings
from ca9.analysis.ast_scanner import iter_runtime_python_files, read_python_source
from ca9.models import ApiTarget, ApiUsageHit


@dataclass
class FileSymbolIndex:
    file_path: str
    module_aliases: dict[str, str] = field(default_factory=dict)
    symbol_aliases: dict[str, str] = field(default_factory=dict)
    parse_error: str | None = None


def build_file_index(file_path: str, source: str) -> FileSymbolIndex:
    index = FileSymbolIndex(file_path=file_path)

    try:
        tree = ast.parse(source, filename=file_path)
    except (SyntaxError, ValueError, RecursionError) as e:
        index.parse_error = str(e)
        return index

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    name = alias.asname
                else:
                    name = alias.name
                index.module_aliases[name] = alias.name

        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                if alias.asname:
                    local_name = alias.asname
                else:
                    local_name = alias.name
                fqname = f"{node.module}.{alias.name}"
                index.symbol_aliases[local_name] = fqname

    return index


def _resolve_call_fqname(
    node: ast.expr,
    index: FileSymbolIndex,
) -> str | None:
    if isinstance(node, ast.Name):
        name = node.id
        if name in index.symbol_aliases:
            return index.symbol_aliases[name]
        if name in index.module_aliases:
            return index.module_aliases[name]
        return None

    if isinstance(node, ast.Attribute):
        base = _resolve_attr_chain(node.value, index)
        if base is not None:
            return f"{base}.{node.attr}"
        return None

    return None


def _resolve_attr_chain(
    node: ast.expr,
    index: FileSymbolIndex,
) -> str | None:
    if isinstance(node, ast.Name):
        name = node.id
        if name in index.module_aliases:
            return index.module_aliases[name]
        if name in index.symbol_aliases:
            return index.symbol_aliases[name]
        return None

    if isinstance(node, ast.Attribute):
        base = _resolve_attr_chain(node.value, index)
        if base is not None:
            return f"{base}.{node.attr}"
        return None

    return None


def _classify_match(fqname: str, target: ApiTarget) -> str:
    if target.kind == "class":
        return "class_instantiation"
    if "." in fqname:
        parts = fqname.rsplit(".", 1)
        if parts[0] in ("", None):
            return "direct_call"
        return "attribute_call"
    return "imported_symbol_call"


def _get_source_line(source_lines: list[str], lineno: int) -> str | None:
    if 0 < lineno <= len(source_lines):
        return source_lines[lineno - 1].strip()[:120]
    return None


_MATCH_TYPE_CONFIDENCE: dict[str, int] = {
    "direct_call": 90,
    "class_instantiation": 85,
    "attribute_call": 80,
    "imported_symbol_call": 75,
    "symbol_reference": 50,
}


def _build_parent_map(tree: ast.Module) -> dict[int, ast.AST]:
    parent_map: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent_map[id(child)] = node
    return parent_map


def scan_file_for_api_usage(
    file_path: str,
    source: str,
    targets: list[ApiTarget],
) -> list[ApiUsageHit]:
    # Match exact owners or a re-export explicitly named by the rule.
    # Different classes in a package can implement unrelated methods of the same name.
    targets_by_name = {alias: target for target in targets for alias in target.aliases}
    targets_by_name.update((target.fqname, target) for target in targets)

    try:
        tree = ast.parse(source, filename=file_path)
    except (SyntaxError, ValueError, RecursionError):
        return []

    parent_map = _build_parent_map(tree)
    bindings = ImportBindings(tree, parent_map)
    source_lines = source.splitlines()
    hits: list[ApiUsageHit] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            base = node.func
            attributes: list[str] = []
            while isinstance(base, ast.Attribute):
                attributes.append(base.attr)
                base = base.value
            binding = bindings.resolve(base) if isinstance(base, ast.Name) else None
            resolved = ".".join((binding.qualified, *reversed(attributes))) if binding else None
            if resolved is None:
                continue

            target = targets_by_name.get(resolved)
            if target is None:
                continue

            match_type = _classify_match(resolved, target)
            hits.append(
                ApiUsageHit(
                    file_path=file_path,
                    line=node.lineno,
                    col=node.col_offset,
                    match_type=match_type,
                    matched_target=target.fqname,
                    code_snippet=_get_source_line(source_lines, node.lineno),
                    confidence=_MATCH_TYPE_CONFIDENCE.get(match_type, 80),
                )
            )

        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if _is_call_func(node, parent_map):
                continue
            binding = bindings.resolve(node)
            if binding and binding.from_import:
                target = targets_by_name.get(binding.qualified)
                if target:
                    hits.append(
                        ApiUsageHit(
                            file_path=file_path,
                            line=node.lineno,
                            col=node.col_offset,
                            match_type="symbol_reference",
                            matched_target=target.fqname,
                            code_snippet=_get_source_line(source_lines, node.lineno),
                            confidence=_MATCH_TYPE_CONFIDENCE["symbol_reference"],
                        )
                    )

    by_location: dict[tuple[int, str], ApiUsageHit] = {}
    for hit in hits:
        key = (hit.line, hit.matched_target)
        previous = by_location.get(key)
        if previous is None or previous.match_type == "symbol_reference":
            by_location[key] = hit

    return list(by_location.values())


def _is_call_func(node: ast.Name, parent_map: dict[int, ast.AST]) -> bool:
    parent = parent_map.get(id(node))
    return isinstance(parent, ast.Call) and parent.func is node


def find_api_usage(
    repo_root: Path,
    targets: list[ApiTarget],
) -> list[ApiUsageHit]:
    if not targets:
        return []

    all_hits: list[ApiUsageHit] = []

    for py_file in iter_runtime_python_files(repo_root):
        try:
            source = read_python_source(py_file)
        except (OSError, SyntaxError, UnicodeError):
            continue

        hits = scan_file_for_api_usage(str(py_file), source, targets)
        all_hits.extend(hits)

    return all_hits
