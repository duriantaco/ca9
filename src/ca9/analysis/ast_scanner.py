from __future__ import annotations

import ast
import importlib.metadata
import json
import os
import re
import sys
from pathlib import Path

from packaging.markers import InvalidMarker, Marker, default_environment
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from ca9.analysis.import_names import (
    CURATED_RENAMES,
    environment_index,
    resolve_import_names,
)
from ca9.readers.requirements import (
    looks_like_source_reference,
    parse_requirement_reference,
    requirement_option,
)

# Primary import names for distributions whose module name differs from the
# distribution name. Kept for compatibility; see ca9.analysis.import_names.
PYPI_TO_IMPORT: dict[str, str] = {
    name: import_names[0] for name, import_names in CURATED_RENAMES.items()
}


def pypi_to_import_name(package_name: str) -> str:
    return resolve_import_names(package_name).primary


def pypi_to_import_names(package_name: str) -> tuple[str, ...]:
    return resolve_import_names(package_name).names


def collect_imports_from_source(source: str) -> set[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()

    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _add_with_parents(imports, alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            # Relative imports name project modules, not installed packages.
            if node.level:
                continue
            _add_with_parents(imports, node.module)
            for alias in node.names:
                if alias.name != "*":
                    imports.add(f"{node.module}.{alias.name}")
        elif isinstance(node, ast.Call):
            dynamic_import = _extract_dynamic_import_name(node)
            if dynamic_import:
                _add_with_parents(imports, dynamic_import)
    return imports


def _add_with_parents(imports: set[str], module: str) -> None:
    # Importing a.b.c executes a and a.b first, so record every parent package.
    parts = module.split(".")
    for i in range(1, len(parts) + 1):
        imports.add(".".join(parts[:i]))


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


def iter_runtime_python_files(repo_path: Path):
    for dirpath, dirnames, filenames in os.walk(repo_path):
        # Prune vendored environments instead of walking and discarding them.
        dirnames[:] = sorted(d for d in dirnames if d not in _EXCLUDED_DIRS)
        for filename in sorted(filenames):
            if not filename.endswith(".py"):
                continue
            py_file = Path(dirpath) / filename
            if _is_runtime_python_file(py_file, repo_path):
                yield py_file


def collect_imports_from_repo(repo_path: Path) -> set[str]:
    all_imports: set[str] = set()
    for py_file in iter_runtime_python_files(repo_path):
        try:
            source = py_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        all_imports.update(collect_imports_from_source(source))
    return all_imports


def is_package_imported(package_name: str, repo_imports: set[str]) -> bool:
    return imports_any_module(pypi_to_import_names(package_name), repo_imports)


def imports_any_module(import_names: tuple[str, ...], repo_imports: set[str]) -> bool:
    targets = [name.lower() for name in import_names]
    for imp in repo_imports:
        imp_lower = imp.lower()
        for target in targets:
            if imp_lower == target or imp_lower.startswith(target + "."):
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


# pip treats "#" at line start or after whitespace as a comment.
_REQ_COMMENT_RE = re.compile(r"(^|\s+)#.*$")


def requirement_file_lines(text: str) -> list[str]:
    """Return logical requirement-file lines the way pip reads them.

    Backslash continuations are joined first, except that a comment line never
    continues; comments are stripped after joining.
    """
    logical: list[str] = []
    pending: list[str] = []
    for line in text.splitlines():
        if not line.endswith("\\") or _REQ_COMMENT_RE.match(line):
            if _REQ_COMMENT_RE.match(line):
                # Keep a leading space so a comment that ends a continuation
                # is still removed below.
                line = " " + line
            pending.append(line)
            logical.append("".join(pending))
            pending = []
        else:
            pending.append(line.strip("\\"))
    if pending:
        logical.append("".join(pending))
    return [stripped for line in logical if (stripped := _REQ_COMMENT_RE.sub("", line).strip())]


def split_requirement_options(line: str) -> tuple[str, tuple[str, ...]]:
    """Split a requirement line into the requirement and its --hash values.

    Like pip, the requirement ends at the first token starting with "-"; the
    remaining per-requirement options are dropped after collecting hashes.
    """
    tokens = line.split()
    index = 0
    while index < len(tokens) and not tokens[index].startswith("-"):
        index += 1
    requirement = " ".join(tokens[:index])
    options = tokens[index:]
    hashes: list[str] = []
    position = 0
    while position < len(options):
        token = options[position]
        position += 1
        if token.startswith("--hash="):
            value = token[len("--hash=") :]
        elif token == "--hash" and position < len(options):
            value = options[position]
            position += 1
        else:
            continue
        if value:
            hashes.append(value)
    return requirement, tuple(dict.fromkeys(hashes))


def _extract_req_name_from_line(line: str) -> str | None:
    req = line.strip()
    if not req or req.startswith("#"):
        return None

    if " #" in req:
        req = req.split(" #", 1)[0].strip()

    option = requirement_option(req)
    if option is not None:
        option_name, value = option
        if option_name == "--editable" and value:
            return _editable_requirement_name(value)
        return None

    req, _hashes = split_requirement_options(req)

    if looks_like_source_reference(req):
        reference = parse_requirement_reference(req)
        if reference is None:
            return None
        return reference.name

    if " @ " in req:
        req = req.split(" @ ", 1)[0].strip()

    return _parse_requirement_name(req)


def _editable_requirement_name(value: str) -> str | None:
    """Name of an editable install: #egg=, PEP 508 name, or the VCS/path name."""
    reference = parse_requirement_reference(value)
    if reference is not None:
        return reference.name
    if "#egg=" in value:
        return _parse_requirement_name(value.split("#egg=", 1)[1])
    return None


def _extract_req_exact_version_from_line(line: str) -> str | None:
    req = line.strip()
    if not req or req.startswith("#"):
        return None

    if " #" in req:
        req = req.split(" #", 1)[0].strip()

    if requirement_option(req) is not None:
        return None

    req, _hashes = split_requirement_options(req)

    if " @ " in req or looks_like_source_reference(req):
        reference = parse_requirement_reference(req)
        if reference is None:
            return None
        return reference.version

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
    hashes: dict[str, tuple[str, ...]] | None = None,
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
        lines = requirement_file_lines(path.read_text(encoding="utf-8", errors="ignore"))
    except OSError:
        return declared

    constraints: dict[str, tuple[str, str | None]] = {}

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        include_target: Path | None = None
        constraint_target: Path | None = None
        option = requirement_option(line)
        if option is not None and option[1]:
            if option[0] == "--requirement":
                include_target = path.parent / option[1]
            elif option[0] == "--constraint":
                constraint_target = path.parent / option[1]

        if include_target is not None:
            nested = _iter_requirement_inventory(include_target, seen, hashes)
            for nested_name, nested_data in nested.items():
                declared[nested_name] = nested_data
            continue

        if constraint_target is not None:
            constraints.update(_iter_constraint_inventory(constraint_target, seen, hashes))
            continue

        name = _extract_req_name_from_line(line)
        if name:
            version = _extract_req_exact_version_from_line(line)
            _merge_declared_dependency(declared, name, version)
            _record_requirement_hashes(hashes, name, line)

    _apply_constraint_versions(declared, constraints)
    return declared


def _iter_constraint_inventory(
    path: Path,
    seen: set[Path],
    hashes: dict[str, tuple[str, ...]] | None = None,
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
        lines = requirement_file_lines(path.read_text(encoding="utf-8", errors="ignore"))
    except OSError:
        return constraints

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        option = requirement_option(line)
        if option is not None and option[0] == "--constraint" and option[1]:
            constraints.update(_iter_constraint_inventory(path.parent / option[1], seen, hashes))
            continue

        name = _extract_req_name_from_line(line)
        if not name:
            continue
        version = _extract_req_exact_version_from_line(line)
        if version:
            _merge_declared_dependency(constraints, name, version)
        _record_requirement_hashes(hashes, name, line)

    return constraints


def _record_requirement_hashes(
    hashes: dict[str, tuple[str, ...]] | None,
    name: str,
    line: str,
) -> None:
    if hashes is None or line.startswith("-"):
        return
    _requirement, line_hashes = split_requirement_options(line)
    if line_hashes:
        key = canonicalize_name(name)
        hashes[key] = tuple(dict.fromkeys([*hashes.get(key, ()), *line_hashes]))


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


def discover_requirement_hashes(repo_path: Path) -> dict[str, tuple[str, ...]]:
    """Map canonical names to the --hash pins in requirements*.txt files."""
    hashes: dict[str, tuple[str, ...]] = {}
    seen: set[Path] = set()
    for req_file in sorted(repo_path.glob("requirements*.txt")):
        _iter_requirement_inventory(req_file, seen, hashes)
    return hashes


def _parse_dependency_requirement(req: str) -> tuple[str | None, str | None]:
    req, _hashes = split_requirement_options(req.strip())
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
        lines = requirement_file_lines(path.read_text(encoding="utf-8", errors="ignore"))
    except OSError:
        return names

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        option = requirement_option(line)
        if option is not None and option[0] == "--requirement" and option[1]:
            names.update(_iter_requirement_names(path.parent / option[1], seen))
            continue

        name = _extract_req_name_from_line(line)
        if name:
            names.add(canonicalize_name(name))

    return names


def discover_declared_dependencies(repo_path: Path) -> set[str]:
    return set(discover_declared_dependency_inventory(repo_path))


def _get_direct_deps(package_name: str) -> list[str]:
    reqs = environment_index().requirements(package_name)
    if not reqs:
        try:
            reqs = importlib.metadata.requires(package_name) or []
        except importlib.metadata.PackageNotFoundError:
            return []
    deps = []
    for req_str in reqs:
        if "extra ==" in req_str or "extra==" in req_str:
            continue
        name = _parse_requirement_name(req_str)
        if name:
            deps.append(name)
    return deps


def _directly_imported_distributions(repo_imports: set[str]) -> set[str] | None:
    index = environment_index()
    if not index.available:
        return None
    return {
        key
        for key in index.distributions
        if imports_any_module(index.resolve(key).names, repo_imports)
    }


def resolve_transitive_deps(repo_imports: set[str]) -> tuple[dict[str, str], bool]:
    directly_imported = _directly_imported_distributions(repo_imports)
    if not directly_imported:
        return {}, False

    direct_lower = set(directly_imported)
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

    for pkg in sorted(directly_imported):
        _walk(pkg, pkg)

    return transitive, True


def resolve_optional_dependents(repo_imports: set[str]) -> dict[str, str]:
    """Map packages named only in extras of imported distributions to that distribution.

    Libraries often import optional dependencies lazily (pandas -> openpyxl), so
    such a package can run without the project importing it.
    """
    directly_imported = _directly_imported_distributions(repo_imports) or set()
    index = environment_index()
    optional: dict[str, str] = {}
    for key in sorted(directly_imported):
        for req_str in index.requirements(key):
            if "extra ==" not in req_str and "extra==" not in req_str:
                continue
            name = _parse_requirement_name(req_str)
            if name:
                optional.setdefault(canonicalize_name(name), key)
    return optional


def _local_module_names(repo_path: Path) -> set[str]:
    names: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in _EXCLUDED_DIRS]
        py_files = [f for f in filenames if f.endswith(".py")]
        if not py_files:
            continue
        rel_parts = Path(dirpath).relative_to(repo_path).parts
        names.update(part.lower() for part in rel_parts)
        names.update(f[:-3].lower() for f in py_files)
    return names


def find_unresolved_imports(repo_path: Path, repo_imports: set[str]) -> tuple[str, ...]:
    """Top-level modules the project imports that no installed distribution provides.

    The environment dependency graph only covers installed distributions, so an
    imported package missing from the environment hides its dependencies.
    """
    index = environment_index()
    if not index.available:
        return ()

    provided: set[str] = set()
    provided_parents: set[str] = set()
    for key in index.distributions:
        for name in index.resolve(key).names:
            lowered = name.lower()
            provided.add(lowered)
            parts = lowered.split(".")
            for i in range(1, len(parts)):
                provided_parents.add(".".join(parts[:i]))

    ignored = set(getattr(sys, "stdlib_module_names", ())) | set(sys.builtin_module_names)
    ignored |= {"__future__", "__main__"}
    ignored = {name.lower() for name in ignored} | _local_module_names(repo_path)

    unresolved: set[str] = set()
    for imp in repo_imports:
        lowered = imp.lower()
        parts = lowered.split(".")
        if parts[0] in ignored:
            continue
        if lowered in provided_parents:
            continue
        if any(".".join(parts[:i]) in provided for i in range(1, len(parts) + 1)):
            continue
        unresolved.add(imp.split(".", 1)[0])
    if not unresolved:
        return ()

    # An import of a module missing here that sits under "except ImportError"
    # (as the attempt or the fallback) either never runs or fails in this
    # environment, so it loads nothing; only unguarded imports count.
    unguarded: set[str] = set()
    for py_file in iter_runtime_python_files(repo_path):
        try:
            source = py_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if any(name in source for name in unresolved - unguarded):
            unguarded |= _unguarded_import_roots(source) & unresolved
        if unguarded == unresolved:
            break
    return tuple(sorted(unguarded))


_IMPORT_ERROR_NAMES = frozenset(
    {"ImportError", "ModuleNotFoundError", "Exception", "BaseException"}
)


def _catches_import_error(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        return True
    types = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    return any(isinstance(t, ast.Name) and t.id in _IMPORT_ERROR_NAMES for t in types)


def _unguarded_import_roots(source: str) -> set[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()

    try_types = tuple(t for t in (ast.Try, getattr(ast, "TryStar", None)) if t is not None)
    guarded: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, try_types) and any(_catches_import_error(h) for h in node.handlers):
            for stmt in [*node.body, *node.handlers]:
                guarded.update(id(child) for child in ast.walk(stmt))

    roots: set[str] = set()
    for node in ast.walk(tree):
        if id(node) in guarded:
            continue
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            roots.add(node.module.split(".", 1)[0])
        elif isinstance(node, ast.Call):
            dynamic = _extract_dynamic_import_name(node)
            if dynamic:
                roots.add(dynamic.split(".", 1)[0])
    return roots
