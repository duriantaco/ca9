from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from ca9.analysis.api_usage import FileSymbolIndex, build_file_index
from ca9.analysis.call_graph import _module_name_from_path

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
class EntryPoint:
    qualified_name: str
    file_path: str
    line: int
    kind: str
    route: str = ""


def _detect_framework_apps(tree: ast.Module) -> dict[str, str]:
    apps: dict[str, str] = {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not node.targets or not isinstance(node.targets[0], ast.Name):
            continue

        var_name = node.targets[0].id
        call = node.value

        if isinstance(call, ast.Call):
            func = call.func
            func_name = ""
            if isinstance(func, ast.Name):
                func_name = func.id
            elif isinstance(func, ast.Attribute):
                func_name = func.attr

            if func_name in ("Flask", "Blueprint"):
                apps[var_name] = "flask"
            elif func_name in ("FastAPI", "APIRouter"):
                apps[var_name] = "fastapi"
            elif func_name == "Celery":
                apps[var_name] = "celery"
            elif func_name == "Typer":
                apps[var_name] = "typer"
            elif func_name in ("Group", "group"):
                apps[var_name] = "click"

    return apps


def _extract_route_path(decorator: ast.expr) -> str:
    if isinstance(decorator, ast.Call) and decorator.args:
        arg = decorator.args[0]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
    return ""


def _detect_flask_routes(
    tree: ast.Module, apps: dict[str, str], module_name: str, file_path: str
) -> list[EntryPoint]:
    entries: list[EntryPoint] = []
    flask_vars = {k for k, v in apps.items() if v == "flask"}

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call):
                continue
            func = dec.func
            if not isinstance(func, ast.Attribute):
                continue
            if func.attr != "route":
                continue
            if isinstance(func.value, ast.Name) and func.value.id in flask_vars:
                qname = f"{module_name}.{node.name}"
                entries.append(
                    EntryPoint(
                        qualified_name=qname,
                        file_path=file_path,
                        line=node.lineno,
                        kind="flask_route",
                        route=_extract_route_path(dec),
                    )
                )

    return entries


_FASTAPI_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}


def _detect_fastapi_routes(
    tree: ast.Module, apps: dict[str, str], module_name: str, file_path: str
) -> list[EntryPoint]:
    entries: list[EntryPoint] = []
    fastapi_vars = {k for k, v in apps.items() if v == "fastapi"}

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call):
                continue
            func = dec.func
            if not isinstance(func, ast.Attribute):
                continue
            if func.attr not in _FASTAPI_METHODS:
                continue
            if isinstance(func.value, ast.Name) and func.value.id in fastapi_vars:
                qname = f"{module_name}.{node.name}"
                entries.append(
                    EntryPoint(
                        qualified_name=qname,
                        file_path=file_path,
                        line=node.lineno,
                        kind="fastapi_route",
                        route=_extract_route_path(dec),
                    )
                )

    return entries


def _detect_django_views(
    tree: ast.Module,
    index: FileSymbolIndex,
    module_name: str,
    file_path: str,
) -> list[EntryPoint]:
    entries: list[EntryPoint] = []

    if not file_path.endswith("urls.py"):
        return entries

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            func_name = ""
            if isinstance(func, ast.Name):
                func_name = func.id
            elif isinstance(func, ast.Attribute):
                func_name = func.attr

            if func_name == "path" and len(node.args) >= 2:
                route_arg = node.args[0]
                view_arg = node.args[1]

                route = ""
                if isinstance(route_arg, ast.Constant) and isinstance(route_arg.value, str):
                    route = route_arg.value

                view_name = _resolve_entry_reference(view_arg, index, module_name)

                if view_name:
                    entries.append(
                        EntryPoint(
                            qualified_name=view_name,
                            file_path=file_path,
                            line=node.lineno,
                            kind="django_view",
                            route=route,
                        )
                    )

    return entries


def _detect_click_commands(
    tree: ast.Module, apps: dict[str, str], module_name: str, file_path: str
) -> list[EntryPoint]:
    entries: list[EntryPoint] = []

    click_decorators = {"command", "group"}
    click_vars = {k for k, v in apps.items() if v == "click"}

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        for dec in node.decorator_list:
            dec_name = ""
            if isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Attribute):
                    dec_name = dec.func.attr
                    if isinstance(dec.func.value, ast.Name):
                        if dec.func.value.id in click_vars:
                            dec_name = dec.func.attr
                elif isinstance(dec.func, ast.Name):
                    dec_name = dec.func.id
            elif isinstance(dec, ast.Attribute):
                dec_name = dec.attr
                if isinstance(dec.value, ast.Attribute):
                    if dec.value.attr in ("click",):
                        dec_name = dec.attr

            if dec_name in click_decorators:
                qname = f"{module_name}.{node.name}"
                entries.append(
                    EntryPoint(
                        qualified_name=qname,
                        file_path=file_path,
                        line=node.lineno,
                        kind="click_command",
                    )
                )

    return entries


def _detect_typer_commands(
    tree: ast.Module, apps: dict[str, str], module_name: str, file_path: str
) -> list[EntryPoint]:
    entries: list[EntryPoint] = []
    typer_vars = {k for k, v in apps.items() if v == "typer"}

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        for dec in node.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            if not isinstance(target, ast.Attribute):
                continue
            if target.attr not in ("command", "callback"):
                continue
            if isinstance(target.value, ast.Name) and target.value.id in typer_vars:
                qname = f"{module_name}.{node.name}"
                entries.append(
                    EntryPoint(
                        qualified_name=qname,
                        file_path=file_path,
                        line=node.lineno,
                        kind="typer_command",
                    )
                )

    return entries


def _detect_celery_tasks(
    tree: ast.Module, apps: dict[str, str], module_name: str, file_path: str
) -> list[EntryPoint]:
    entries: list[EntryPoint] = []
    celery_vars = {k for k, v in apps.items() if v == "celery"}

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        for dec in node.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec

            is_task = False
            if isinstance(target, ast.Name) and target.id == "shared_task":
                is_task = True
            elif isinstance(target, ast.Attribute) and target.attr == "task":
                if isinstance(target.value, ast.Name) and target.value.id in celery_vars:
                    is_task = True

            if is_task:
                qname = f"{module_name}.{node.name}"
                entries.append(
                    EntryPoint(
                        qualified_name=qname,
                        file_path=file_path,
                        line=node.lineno,
                        kind="celery_task",
                    )
                )

    return entries


def _detect_main_blocks(tree: ast.Module, module_name: str, file_path: str) -> list[EntryPoint]:
    entries: list[EntryPoint] = []

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.If):
            test = node.test
            if isinstance(test, ast.Compare):
                if (
                    isinstance(test.left, ast.Name)
                    and test.left.id == "__name__"
                    and len(test.ops) == 1
                    and isinstance(test.ops[0], ast.Eq)
                    and len(test.comparators) == 1
                    and isinstance(test.comparators[0], ast.Constant)
                    and test.comparators[0].value == "__main__"
                ):
                    entries.append(
                        EntryPoint(
                            qualified_name=f"{module_name}.__main__",
                            file_path=file_path,
                            line=node.lineno,
                            kind="main_block",
                        )
                    )

    return entries


def detect_entry_points(repo_path: Path) -> list[EntryPoint]:
    entries: list[EntryPoint] = []

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
        file_str = str(py_file)
        index = build_file_index(file_str, source)

        apps = _detect_framework_apps(tree)

        entries.extend(_detect_flask_routes(tree, apps, module_name, file_str))
        entries.extend(_detect_fastapi_routes(tree, apps, module_name, file_str))
        entries.extend(_detect_django_views(tree, index, module_name, file_str))
        entries.extend(_detect_click_commands(tree, apps, module_name, file_str))
        entries.extend(_detect_typer_commands(tree, apps, module_name, file_str))
        entries.extend(_detect_celery_tasks(tree, apps, module_name, file_str))
        entries.extend(_detect_main_blocks(tree, module_name, file_str))

    return entries


def _resolve_entry_reference(
    node: ast.expr,
    index: FileSymbolIndex,
    module_name: str,
) -> str:
    if isinstance(node, ast.Name):
        if node.id in index.symbol_aliases:
            return index.symbol_aliases[node.id]
        if node.id in index.module_aliases:
            return index.module_aliases[node.id]
        return f"{module_name}.{node.id}"

    if isinstance(node, ast.Attribute):
        base = _resolve_entry_reference(node.value, index, module_name)
        return f"{base}.{node.attr}" if base else ""

    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        base = _resolve_entry_reference(node.func.value, index, module_name)
        return f"{base}.{node.func.attr}" if base else ""

    return ""
