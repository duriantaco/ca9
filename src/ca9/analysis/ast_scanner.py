from __future__ import annotations

import ast
import importlib.metadata
import re
from pathlib import Path

PYPI_TO_IMPORT: dict[str, str] = {
    "beautifulsoup4": "bs4",
    "dateutil": "dateutil",
    "django-rest-framework": "rest_framework",
    "djangorestframework": "rest_framework",
    "elasticsearch-dsl": "elasticsearch_dsl",
    "google-api-python-client": "googleapiclient",
    "google-auth": "google.auth",
    "google-cloud-storage": "google.cloud.storage",
    "jinja2": "jinja2",
    "msgpack-python": "msgpack",
    "opencv-python": "cv2",
    "opencv-python-headless": "cv2",
    "pillow": "PIL",
    "protobuf": "google.protobuf",
    "pyasn1": "pyasn1",
    "pycryptodome": "crypto",
    "pyjwt": "jwt",
    "pymongo": "pymongo",
    "pyopenssl": "openssl",
    "python-dateutil": "dateutil",
    "python-dotenv": "dotenv",
    "python-jose": "jose",
    "python-multipart": "multipart",
    "pyyaml": "yaml",
    "scikit-learn": "sklearn",
    "sentry-sdk": "sentry_sdk",
    "setuptools": "setuptools",
    "typing-extensions": "typing_extensions",
    "websocket-client": "websocket",
}


def pypi_to_import_name(package_name: str) -> str:
    lower = package_name.lower()
    if lower in PYPI_TO_IMPORT:
        return PYPI_TO_IMPORT[lower]
    return lower.replace("-", "_")


def collect_imports_from_source(source: str) -> set[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()

    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
            for alias in node.names:
                if alias.name != "*":
                    imports.add(f"{node.module}.{alias.name}")
    return imports


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


def collect_imports_from_repo(repo_path: Path) -> set[str]:
    all_imports: set[str] = set()
    for py_file in repo_path.rglob("*.py"):
        if _EXCLUDED_DIRS & {p.name for p in py_file.relative_to(repo_path).parents}:
            continue
        try:
            source = py_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        all_imports.update(collect_imports_from_source(source))
    return all_imports


def is_package_imported(package_name: str, repo_imports: set[str]) -> bool:
    import_name = pypi_to_import_name(package_name)
    target = import_name.lower()

    for imp in repo_imports:
        imp_lower = imp.lower()
        if imp_lower == target:
            return True
        if imp_lower.startswith(target + ".") or target.startswith(imp_lower + "."):
            return True

    return False


def is_submodule_imported(
    submodule_paths: tuple[str, ...],
    repo_imports: set[str],
) -> tuple[bool, str | None]:
    for submod in submodule_paths:
        target = submod.lower()
        for imp in repo_imports:
            imp_lower = imp.lower()
            if imp_lower == target:
                return True, imp
            if imp_lower.startswith(target + "."):
                return True, imp
            if "." in imp_lower and target.startswith(imp_lower + "."):
                return True, imp
    return False, None


_REQ_NAME_RE = re.compile(r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)")


def _parse_requirement_name(req_str: str) -> str | None:
    m = _REQ_NAME_RE.match(req_str.strip())
    if m:
        return m.group(1)
    return None


def _get_direct_deps(package_name: str) -> list[str]:
    try:
        reqs = importlib.metadata.requires(package_name)
    except importlib.metadata.PackageNotFoundError:
        return []
    if reqs is None:
        return []
    deps = []
    for req_str in reqs:
        if "extra ==" in req_str or "extra==" in req_str:
            continue
        name = _parse_requirement_name(req_str)
        if name:
            deps.append(name)
    return deps


def resolve_transitive_deps(repo_imports: set[str]) -> dict[str, str]:
    directly_imported: set[str] = set()
    try:
        for dist in importlib.metadata.distributions():
            name = dist.metadata["Name"]
            if name and is_package_imported(name, repo_imports):
                directly_imported.add(name)
    except Exception:
        return {}

    direct_lower = {n.lower() for n in directly_imported}

    transitive: dict[str, str] = {}
    visited: set[str] = set()

    def _walk(pkg_name: str, root: str) -> None:
        key = pkg_name.lower()
        if key in visited:
            return
        visited.add(key)
        for dep in _get_direct_deps(pkg_name):
            dep_lower = dep.lower()
            if dep_lower not in direct_lower and dep_lower not in transitive:
                transitive[dep_lower] = root
            _walk(dep, root)

    for pkg in directly_imported:
        _walk(pkg, pkg)

    return transitive
