from __future__ import annotations

import ast
import importlib.metadata
import json
import re
import sys
from pathlib import Path

from packaging.markers import InvalidMarker, Marker, default_environment
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

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
        elif isinstance(node, ast.Call):
            dynamic_import = _extract_dynamic_import_name(node)
            if dynamic_import:
                imports.add(dynamic_import)
    return imports


def _extract_static_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _extract_dynamic_import_name(node: ast.Call) -> str | None:
    if not node.args:
        return None

    func = node.func
    is_dynamic_import = False

    if isinstance(func, ast.Name) and func.id in ("__import__", "import_module"):
        is_dynamic_import = True
    elif isinstance(func, ast.Attribute) and func.attr == "import_module":
        if isinstance(func.value, ast.Name) and func.value.id == "importlib":
            is_dynamic_import = True

    if not is_dynamic_import:
        return None

    module_name = _extract_static_string(node.args[0])
    if not module_name:
        return None

    return module_name


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


def collect_imports_from_repo(repo_path: Path) -> set[str]:
    all_imports: set[str] = set()
    for py_file in repo_path.rglob("*.py"):
        if not _is_runtime_python_file(py_file, repo_path):
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
        if imp_lower.startswith(target + "."):
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


def _extract_exact_version(specifiers) -> str | None:
    exact_versions = [
        spec.version
        for spec in specifiers
        if spec.operator in ("==", "===") and "*" not in spec.version
    ]
    if len(exact_versions) == 1:
        return exact_versions[0]
    return None


def _load_toml(path: Path) -> dict:
    try:
        import tomllib
    except ModuleNotFoundError:
        try:
            import tomli as tomllib
        except ModuleNotFoundError:
            return {}

    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except OSError:
        return {}


def _extract_req_name_from_line(line: str) -> str | None:
    req = line.strip()
    if not req or req.startswith("#"):
        return None

    if " #" in req:
        req = req.split(" #", 1)[0].strip()

    if req.startswith(("-c ", "--constraint ")):
        return None

    if req.startswith(("-r ", "--requirement ")):
        return None

    if req.startswith("-e "):
        editable = req[3:].strip()
        if "#egg=" in editable:
            return editable.split("#egg=", 1)[1].strip() or None
        return None

    if " @ " in req:
        req = req.split(" @ ", 1)[0].strip()

    return _parse_requirement_name(req)


def _extract_req_exact_version_from_line(line: str) -> str | None:
    req = line.strip()
    if not req or req.startswith("#"):
        return None

    if " #" in req:
        req = req.split(" #", 1)[0].strip()

    if req.startswith(("-c ", "--constraint ", "-r ", "--requirement ", "-e ")):
        return None

    if " @ " in req:
        return None

    try:
        parsed = Requirement(req)
    except InvalidRequirement:
        return None

    return _extract_exact_version(parsed.specifier)


def _merge_declared_dependency(
    declared: dict[str, tuple[str, str | None]],
    name: str,
    version: str | None,
) -> None:
    key = canonicalize_name(name)
    existing = declared.get(key)
    if existing is None or (existing[1] is None and version is not None):
        declared[key] = (name, version)


def _iter_requirement_inventory(
    path: Path,
    seen: set[Path],
) -> dict[str, tuple[str, str | None]]:
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path

    if resolved in seen or not path.is_file():
        return {}
    seen.add(resolved)

    declared: dict[str, tuple[str, str | None]] = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return declared

    constraints: dict[str, tuple[str, str | None]] = {}

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        include_target: Path | None = None
        constraint_target: Path | None = None
        if line.startswith("-r "):
            include_target = path.parent / line[3:].strip()
        elif line.startswith("--requirement "):
            include_target = path.parent / line[len("--requirement ") :].strip()
        elif line.startswith("-c "):
            constraint_target = path.parent / line[3:].strip()
        elif line.startswith("--constraint "):
            constraint_target = path.parent / line[len("--constraint ") :].strip()

        if include_target is not None:
            nested = _iter_requirement_inventory(include_target, seen)
            for nested_name, nested_data in nested.items():
                declared[nested_name] = nested_data
            continue

        if constraint_target is not None:
            constraints.update(_iter_constraint_inventory(constraint_target, seen))
            continue

        name = _extract_req_name_from_line(line)
        if name:
            version = _extract_req_exact_version_from_line(line)
            _merge_declared_dependency(declared, name, version)

    _apply_constraint_versions(declared, constraints)
    return declared


def _iter_constraint_inventory(
    path: Path,
    seen: set[Path],
) -> dict[str, tuple[str, str | None]]:
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path

    if resolved in seen or not path.is_file():
        return {}
    seen.add(resolved)

    constraints: dict[str, tuple[str, str | None]] = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return constraints

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("-c "):
            constraints.update(_iter_constraint_inventory(path.parent / line[3:].strip(), seen))
            continue
        if line.startswith("--constraint "):
            constraints.update(
                _iter_constraint_inventory(path.parent / line[len("--constraint ") :].strip(), seen)
            )
            continue

        name = _extract_req_name_from_line(line)
        if not name:
            continue
        version = _extract_req_exact_version_from_line(line)
        if version:
            _merge_declared_dependency(constraints, name, version)

    return constraints


def _apply_constraint_versions(
    declared: dict[str, tuple[str, str | None]],
    constraints: dict[str, tuple[str, str | None]],
) -> None:
    for key, (_constraint_name, version) in constraints.items():
        if version is None or key not in declared:
            continue
        name, existing_version = declared[key]
        if existing_version is None:
            declared[key] = (name, version)


def _parse_dependency_requirement(req: str) -> tuple[str | None, str | None]:
    try:
        parsed = Requirement(req)
    except InvalidRequirement:
        name = _parse_requirement_name(req)
        return name, None

    return parsed.name, _extract_exact_version(parsed.specifier)


def _extract_poetry_exact_version(value: object) -> str | None:
    if isinstance(value, dict):
        value = value.get("version")

    if not isinstance(value, str):
        return None

    spec = value.strip()
    if not spec or spec == "*":
        return None

    if spec.startswith("==="):
        exact = spec[3:].strip()
        return exact or None

    if spec.startswith("=="):
        exact = spec[2:].strip()
        return exact or None

    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.!+_-]*", spec):
        return spec

    return None


def _extract_pipfile_exact_version(value: object) -> str | None:
    if isinstance(value, dict):
        value = value.get("version")

    if not isinstance(value, str):
        return None

    spec = value.strip()
    if not spec or spec == "*":
        return None

    try:
        parsed = Requirement(f"placeholder{spec}")
    except InvalidRequirement:
        if spec.startswith("==") and len(spec) > 2:
            return spec[2:].strip()
        return None

    return _extract_exact_version(parsed.specifier)


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _discover_project_name(pyproject_data: dict) -> str | None:
    project = pyproject_data.get("project", {})
    if isinstance(project, dict):
        name = project.get("name")
        if isinstance(name, str) and name.strip():
            return name

    tool = pyproject_data.get("tool", {})
    if isinstance(tool, dict):
        poetry = tool.get("poetry", {})
        if isinstance(poetry, dict):
            name = poetry.get("name")
            if isinstance(name, str) and name.strip():
                return name

    return None


def _lock_packages_by_name(lock_data: dict) -> dict[str, list[tuple[str, str, dict]]]:
    packages = lock_data.get("package", [])
    if isinstance(packages, dict):
        packages = [packages]
    if not isinstance(packages, list):
        return {}

    by_name: dict[str, list[tuple[str, str, dict]]] = {}
    for entry in packages:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        version = entry.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        by_name.setdefault(canonicalize_name(name), []).append((name, version, entry))
    return by_name


def _marker_matches_current_env(marker_str: str) -> bool:
    try:
        marker = Marker(marker_str)
    except InvalidMarker:
        return False

    env = default_environment()
    env["python_full_version"] = sys.version.split(" ", 1)[0]
    return marker.evaluate(env)


def _resolve_unique_locked_version(
    packages_by_name: dict[str, list[tuple[str, str, dict]]],
    dep_key: str,
) -> str | None:
    candidates = {version for _name, version, _entry in packages_by_name.get(dep_key, [])}
    if len(candidates) == 1:
        return next(iter(candidates))
    return None


def _resolve_uv_locked_versions(
    lock_data: dict,
    declared: dict[str, tuple[str, str | None]],
    project_name: str | None,
) -> dict[str, str]:
    packages_by_name = _lock_packages_by_name(lock_data)
    resolved: dict[str, str] = {}

    root_entry: dict | None = None
    if project_name:
        root_key = canonicalize_name(project_name)
        for _name, _version, entry in packages_by_name.get(root_key, []):
            source = entry.get("source", {})
            if isinstance(source, dict) and source.get("editable") == ".":
                root_entry = entry
                break
            if isinstance(source, dict) and source.get("virtual") == ".":
                root_entry = entry
                break

    if root_entry is not None:
        dependencies = root_entry.get("dependencies", [])
        if isinstance(dependencies, list):
            for dep in dependencies:
                if not isinstance(dep, dict):
                    continue
                dep_name = dep.get("name")
                if not isinstance(dep_name, str):
                    continue
                dep_key = canonicalize_name(dep_name)
                if dep_key not in declared:
                    continue

                marker = dep.get("marker")
                if isinstance(marker, str) and marker and not _marker_matches_current_env(marker):
                    continue

                version = dep.get("version")
                if isinstance(version, str) and version:
                    resolved[dep_key] = version
                    continue

                unique_version = _resolve_unique_locked_version(packages_by_name, dep_key)
                if unique_version:
                    resolved[dep_key] = unique_version

    for dep_key in declared:
        if dep_key in resolved:
            continue
        unique_version = _resolve_unique_locked_version(packages_by_name, dep_key)
        if unique_version:
            resolved[dep_key] = unique_version

    return resolved


def _resolve_poetry_locked_versions(
    lock_data: dict,
    declared: dict[str, tuple[str, str | None]],
) -> dict[str, str]:
    packages_by_name = _lock_packages_by_name(lock_data)
    resolved: dict[str, str] = {}

    for dep_key in declared:
        unique_version = _resolve_unique_locked_version(packages_by_name, dep_key)
        if unique_version:
            resolved[dep_key] = unique_version

    return resolved


def _merge_lockfile_versions(
    repo_path: Path,
    declared: dict[str, tuple[str, str | None]],
    pyproject_data: dict,
) -> None:
    project_name = _discover_project_name(pyproject_data)

    uv_lock_path = repo_path / "uv.lock"
    if uv_lock_path.is_file():
        uv_data = _load_toml(uv_lock_path)
        resolved = _resolve_uv_locked_versions(uv_data, declared, project_name)
        for dep_key, version in resolved.items():
            name, existing_version = declared[dep_key]
            if existing_version is None:
                declared[dep_key] = (name, version)

    poetry_lock_path = repo_path / "poetry.lock"
    if poetry_lock_path.is_file():
        poetry_data = _load_toml(poetry_lock_path)
        resolved = _resolve_poetry_locked_versions(poetry_data, declared)
        for dep_key, version in resolved.items():
            name, existing_version = declared[dep_key]
            if existing_version is None:
                declared[dep_key] = (name, version)


def _merge_pipfile_inventory(
    repo_path: Path,
    declared: dict[str, tuple[str, str | None]],
) -> None:
    pipfile_path = repo_path / "Pipfile"
    if pipfile_path.is_file():
        pipfile_data = _load_toml(pipfile_path)
        packages = pipfile_data.get("packages", {})
        if isinstance(packages, dict):
            for name, spec in packages.items():
                _merge_declared_dependency(declared, name, _extract_pipfile_exact_version(spec))

    lock_path = repo_path / "Pipfile.lock"
    if not lock_path.is_file():
        return

    lock_data = _load_json(lock_path)
    default = lock_data.get("default", {})
    if not isinstance(default, dict):
        return

    for name, entry in default.items():
        version: str | None = None
        if isinstance(entry, dict):
            version = _extract_pipfile_exact_version(entry.get("version"))
        elif isinstance(entry, str):
            version = _extract_pipfile_exact_version(entry)
        _merge_declared_dependency(declared, name, version)


def discover_declared_dependency_inventory(repo_path: Path) -> dict[str, tuple[str, str | None]]:
    declared: dict[str, tuple[str, str | None]] = {}
    pyproject_data: dict = {}

    pyproject_path = repo_path / "pyproject.toml"
    if pyproject_path.is_file():
        pyproject_data = _load_toml(pyproject_path)
        project = pyproject_data.get("project", {})
        if isinstance(project, dict):
            for req in project.get("dependencies", []):
                if isinstance(req, str):
                    name, version = _parse_dependency_requirement(req)
                    if name:
                        _merge_declared_dependency(declared, name, version)
            optional_deps = project.get("optional-dependencies", {})
            if isinstance(optional_deps, dict):
                for reqs in optional_deps.values():
                    if not isinstance(reqs, list):
                        continue
                    for req in reqs:
                        if isinstance(req, str):
                            name, version = _parse_dependency_requirement(req)
                            if name:
                                _merge_declared_dependency(declared, name, version)

        tool = pyproject_data.get("tool", {})
        if isinstance(tool, dict):
            poetry = tool.get("poetry", {})
            if isinstance(poetry, dict):
                poetry_deps = poetry.get("dependencies", {})
                if isinstance(poetry_deps, dict):
                    for name, spec in poetry_deps.items():
                        if name.lower() != "python":
                            _merge_declared_dependency(
                                declared,
                                name,
                                _extract_poetry_exact_version(spec),
                            )

    seen_requirement_files: set[Path] = set()
    for req_file in sorted(repo_path.glob("requirements*.txt")):
        inventory = _iter_requirement_inventory(req_file, seen_requirement_files)
        for name, data in inventory.items():
            declared[name] = data

    _merge_pipfile_inventory(repo_path, declared)
    _merge_lockfile_versions(repo_path, declared, pyproject_data)

    return declared


def _iter_requirement_names(path: Path, seen: set[Path]) -> set[str]:
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path

    if resolved in seen or not path.is_file():
        return set()
    seen.add(resolved)

    names: set[str] = set()
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return names

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        include_target: Path | None = None
        if line.startswith("-r "):
            include_target = path.parent / line[3:].strip()
        elif line.startswith("--requirement "):
            include_target = path.parent / line[len("--requirement ") :].strip()

        if include_target is not None:
            names.update(_iter_requirement_names(include_target, seen))
            continue

        name = _extract_req_name_from_line(line)
        if name:
            names.add(canonicalize_name(name))

    return names


def discover_declared_dependencies(repo_path: Path) -> set[str]:
    return set(discover_declared_dependency_inventory(repo_path))


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


def resolve_transitive_deps(repo_imports: set[str]) -> tuple[dict[str, str], bool]:
    directly_imported: set[str] = set()
    try:
        for dist in importlib.metadata.distributions():
            name = dist.metadata["Name"]
            if name and is_package_imported(name, repo_imports):
                directly_imported.add(name)
    except Exception:
        return {}, False

    direct_lower = {canonicalize_name(n) for n in directly_imported}
    if not direct_lower:
        return {}, False

    transitive: dict[str, str] = {}
    visited: set[str] = set()

    def _walk(pkg_name: str, root: str) -> None:
        key = canonicalize_name(pkg_name)
        if key in visited:
            return
        visited.add(key)
        for dep in _get_direct_deps(pkg_name):
            dep_lower = canonicalize_name(dep)
            if dep_lower not in direct_lower and dep_lower not in transitive:
                transitive[dep_lower] = root
            _walk(dep, root)

    for pkg in directly_imported:
        _walk(pkg, pkg)

    return transitive, True
