from __future__ import annotations

import ast
import sys
from dataclasses import dataclass, field
from pathlib import Path

_MAX_MODULES = 5000


def locate_package(import_name: str, search_path: list[str] | None = None) -> Path | None:
    """Find an installed package directory or module file without importing it."""
    parts = import_name.split(".")
    for entry in sys.path if search_path is None else search_path:
        if not entry:
            continue
        base = Path(entry).joinpath(*parts)
        try:
            if (base / "__init__.py").is_file():
                return base
            module_file = base.with_name(parts[-1] + ".py")
            if module_file.is_file():
                return module_file
        except OSError:
            continue
    return None


@dataclass
class PackageImportGraph:
    """Static import closure over one installed package's own modules."""

    import_name: str
    root: Path
    _files: dict[str, Path | None] = field(default_factory=dict)
    _edges: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def module_file(self, module: str) -> Path | None:
        if module in self._files:
            return self._files[module]
        found: Path | None = None
        if module == self.import_name:
            found = self.root / "__init__.py" if self.root.is_dir() else self.root
        elif module.startswith(self.import_name + ".") and self.root.is_dir():
            rel = module[len(self.import_name) + 1 :].split(".")
            base = self.root.joinpath(*rel)
            if (base / "__init__.py").is_file():
                found = base / "__init__.py"
            elif base.with_name(rel[-1] + ".py").is_file():
                found = base.with_name(rel[-1] + ".py")
        self._files[module] = found
        return found

    def _in_package(self, module: str) -> bool:
        return module == self.import_name or module.startswith(self.import_name + ".")

    def _existing_chain(self, dotted: str) -> list[str]:
        # Importing a.b.c executes a, a.b and a.b.c; "from a.b import Name"
        # stops at the deepest prefix that is a module.
        modules: list[str] = []
        base_depth = self.import_name.count(".") + 1
        parts = dotted.split(".")
        for i in range(base_depth, len(parts) + 1):
            module = ".".join(parts[:i])
            if self.module_file(module) is None:
                break
            modules.append(module)
        return modules

    def _imports_of(self, module: str) -> tuple[str, ...]:
        if module in self._edges:
            return self._edges[module]
        path = self.module_file(module)
        found: list[str] = []
        if path is not None:
            try:
                tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
            except (OSError, SyntaxError, ValueError):
                tree = None
            if tree is not None:
                is_package = path.name == "__init__.py"
                for node in ast.walk(tree):
                    found.extend(_imported_names(node, module, is_package))
        edges = tuple(name for name in found if self._in_package(name))
        self._edges[module] = edges
        return edges

    def defines_module_getattr(self, module: str) -> bool:
        # PEP 562 lazy loaders import submodules on attribute access, which
        # static import edges do not show.
        path = self.module_file(module)
        if path is None:
            return False
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, SyntaxError, ValueError):
            return True
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name == "__getattr__":
                return True
            if isinstance(node, ast.Assign | ast.AnnAssign):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    for name in ast.walk(target):
                        if isinstance(name, ast.Name) and name.id == "__getattr__":
                            return True
        return False

    def closure(self, imported: set[str]) -> set[str]:
        queue: list[str] = []
        for name in imported:
            if self._in_package(name):
                queue.extend(self._existing_chain(name))
        seen: set[str] = set()
        while queue and len(seen) < _MAX_MODULES:
            module = queue.pop()
            if module in seen:
                continue
            seen.add(module)
            for target in self._imports_of(module):
                queue.extend(m for m in self._existing_chain(target) if m not in seen)
        return seen


def _imported_names(node: ast.AST, module: str, is_package: bool) -> list[str]:
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    if isinstance(node, ast.ImportFrom):
        if node.level:
            package = module if is_package else module.rpartition(".")[0]
            parts = package.split(".") if package else []
            if node.level > 1:
                parts = parts[: len(parts) - (node.level - 1)]
            base = ".".join(parts)
            target = f"{base}.{node.module}" if node.module else base
        else:
            target = node.module or ""
        if not target:
            return []
        names = [target]
        names.extend(f"{target}.{alias.name}" for alias in node.names if alias.name != "*")
        return names
    if isinstance(node, ast.Call):
        from ca9.analysis.ast_scanner import _extract_dynamic_import_name

        dynamic = _extract_dynamic_import_name(node)
        if dynamic and not dynamic.startswith("."):
            return [dynamic]
    return []


def submodules_loaded_by_package(
    import_name: str,
    imported: set[str],
    targets: tuple[str, ...],
    search_path: list[str] | None = None,
) -> tuple[bool | None, str]:
    """Whether the package's own imports, starting from what the app imports, load a target.

    Returns (True, how) when a target is loaded, (False, how) when the installed
    source shows none is, and (None, why) when the source cannot settle it.
    """
    root = locate_package(import_name, search_path)
    if root is None:
        return None, f"installed source for '{import_name}' was not found"

    graph = PackageImportGraph(import_name, root)
    missing = [t for t in targets if graph.module_file(t) is None]
    if missing:
        return None, (
            f"affected module {', '.join(missing)} was not found in the installed "
            f"'{import_name}' source"
        )

    seeds = {name for name in imported if graph._in_package(name)}
    loaded = graph.closure(seeds)
    if len(loaded) >= _MAX_MODULES:
        return None, f"import graph for '{import_name}' is too large to analyze"
    for target in targets:
        for module in sorted(loaded):
            if module == target or module.startswith(target + "."):
                return True, f"loaded by '{import_name}' internal imports ({module})"
    for target in targets:
        parts = target.split(".")
        for depth in range(import_name.count(".") + 1, len(parts)):
            parent = ".".join(parts[:depth])
            if parent in loaded and graph.defines_module_getattr(parent):
                return None, (
                    f"'{parent}' defines a module __getattr__ that can lazily import {target}"
                )
    return False, (
        f"installed '{import_name}' source shows the modules the project imports "
        f"({len(loaded)} analyzed) do not import it"
    )
