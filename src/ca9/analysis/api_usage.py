from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

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
    except SyntaxError as e:
        index.parse_error = str(e)
        return index

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname if alias.asname else alias.name
                index.module_aliases[name] = alias.name

        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                local_name = alias.asname if alias.asname else alias.name
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


def scan_file_for_api_usage(
    file_path: str,
    source: str,
    targets: list[ApiTarget],
) -> list[ApiUsageHit]:
    index = build_file_index(file_path, source)
    if index.parse_error:
        return []

    fqname_set: set[str] = set()
    fqname_to_target: dict[str, ApiTarget] = {}
    for t in targets:
        fqname_set.add(t.fqname)
        fqname_to_target[t.fqname] = t
        for alias in t.aliases:
            fqname_set.add(alias)
            fqname_to_target[alias] = t

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return []

    source_lines = source.splitlines()
    hits: list[ApiUsageHit] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            resolved = _resolve_call_fqname(node.func, index)
            if resolved is None:
                continue

            matched_target = _match_fqname(resolved, fqname_set)
            if matched_target is None:
                continue

            target = fqname_to_target.get(matched_target)
            if target is None:
                continue

            hits.append(
                ApiUsageHit(
                    file_path=file_path,
                    line=node.lineno,
                    col=node.col_offset,
                    match_type=_classify_match(resolved, target),
                    matched_target=matched_target,
                    code_snippet=_get_source_line(source_lines, node.lineno),
                    confidence=80,
                )
            )

        elif isinstance(node, ast.Name):
            if node.id in index.symbol_aliases:
                resolved = index.symbol_aliases[node.id]
                matched = _match_fqname(resolved, fqname_set)
                if matched and not _is_call_child(node, tree):
                    hits.append(
                        ApiUsageHit(
                            file_path=file_path,
                            line=node.lineno,
                            col=node.col_offset,
                            match_type="symbol_reference",
                            matched_target=matched,
                            code_snippet=_get_source_line(source_lines, node.lineno),
                            confidence=60,
                        )
                    )

    seen: set[tuple[int, str]] = set()
    deduped: list[ApiUsageHit] = []
    for hit in hits:
        key = (hit.line, hit.matched_target)
        if key not in seen:
            seen.add(key)
            deduped.append(hit)

    return deduped


def _match_fqname(resolved: str, fqname_set: set[str]) -> str | None:
    if resolved in fqname_set:
        return resolved

    for fq in fqname_set:
        if resolved.endswith(f".{fq.rsplit('.', 1)[-1]}") and resolved.startswith(fq.rsplit(".", 1)[0]):
            return fq

    return None


def _is_call_child(node: ast.Name, tree: ast.Module) -> bool:
    for parent in ast.walk(tree):
        if isinstance(parent, ast.Call) and parent.func is node:
            return True
    return False


def find_api_usage(
    repo_root: Path,
    targets: list[ApiTarget],
) -> list[ApiUsageHit]:
    if not targets:
        return []

    all_hits: list[ApiUsageHit] = []

    for py_file in repo_root.rglob("*.py"):
        rel = str(py_file.relative_to(repo_root))
        if rel.startswith("."):
            continue

        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        hits = scan_file_for_api_usage(str(py_file), source, targets)
        all_hits.extend(hits)

    return all_hits
