from __future__ import annotations

import ast
import configparser
import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from packaging.utils import canonicalize_name

from ca9.analysis.import_names import INDIRECT_USE_PACKAGES, EnvironmentIndex

_MAX_FILE_BYTES = 1_000_000

_TOKEN_SPLIT_RE = re.compile(r"[\s,;'\"()\[\]{}=<>|&`]+")
_TOKEN_RE = re.compile(r"[a-z_][a-z0-9_-]*(?:\.[a-z_][a-z0-9_-]*)*")
_DOTTED_MODULE_RE = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+")

# Keyword arguments that declare dependencies rather than use them (setup.py).
_DEPENDENCY_KWARGS = frozenset(
    {"install_requires", "extras_require", "setup_requires", "tests_require", "python_requires"}
)
# Config keys that declare dependencies (setup.cfg, tox.ini).
_DEPENDENCY_CONFIG_KEYS = frozenset(
    {"install_requires", "setup_requires", "tests_require", "extras_require", "deps", "requires"}
)

_TEXT_CONFIG_PATTERNS = (
    "Procfile",
    "Procfile.*",
    "Dockerfile",
    "Dockerfile.*",
    "*.dockerfile",
    "Containerfile",
    "docker-compose*.yml",
    "docker-compose*.yaml",
    "compose*.yml",
    "compose*.yaml",
    "app.yaml",
    "Makefile",
    "*.sh",
    "*.conf",
)
_PARSED_CONFIG_PATTERNS = ("*.ini", "*.cfg")
_WORKFLOW_PATTERNS = ("*.yml", "*.yaml")
# Entry-point groups that only install commands; other groups are plugin hooks
# that a host framework can load without the project naming the package.
_SCRIPT_ENTRY_POINT_GROUPS = frozenset({"console_scripts", "gui_scripts"})
_TOML_PATTERN = "*.toml"
_SKIPPED_TOML = frozenset({"poetry.lock", "uv.lock", "pdm.lock", "pipfile", "pylock.toml"})


@dataclass
class RepoReferences:
    """Names the project mentions outside import statements."""

    # Lowercased token (and each dotted parent) -> first file mentioning it.
    tokens: dict[str, str] = field(default_factory=dict)
    # Dotted module paths named by string literals in runtime Python code.
    dotted_strings: dict[str, str] = field(default_factory=dict)

    def find(self, names: tuple[str, ...] | list[str]) -> list[str]:
        hits: list[str] = []
        for name in names:
            location = self.tokens.get(name.lower())
            if location is not None:
                hits.append(f"'{name}' is named in {location}")
        return hits


def _add_tokens(refs: RepoReferences, text: str, location: str) -> None:
    for raw in _TOKEN_SPLIT_RE.split(text):
        if not raw:
            continue
        if "://" in raw:
            # Connection URLs select drivers: postgresql+psycopg2://, redis://
            parts = raw.split("://", 1)[0].split("+")
        else:
            # Path segments (/usr/bin/gunicorn) and "module:attr" app specs.
            parts = [segment.split(":", 1)[0] for segment in re.split(r"[/\\]+", raw)]
        for part in parts:
            token = part.strip("-./\\").lower()
            if not token or not _TOKEN_RE.fullmatch(token):
                continue
            pieces = token.split(".")
            for i in range(1, len(pieces) + 1):
                refs.tokens.setdefault(".".join(pieces[:i]), location)


def _docstring_ids(tree: ast.AST) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                ids.add(id(body[0].value))
    return ids


def _dependency_declaration_ids(tree: ast.AST) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg in _DEPENDENCY_KWARGS:
                    ids.update(id(child) for child in ast.walk(keyword.value))
    return ids


def _scan_python(refs: RepoReferences, source: str, location: str) -> None:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return
    skipped = _docstring_ids(tree) | _dependency_declaration_ids(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if id(node) in skipped:
            continue
        value = node.value
        _add_tokens(refs, value, location)
        candidate = value.strip().split(":", 1)[0]
        if _DOTTED_MODULE_RE.fullmatch(candidate):
            refs.dotted_strings.setdefault(candidate, location)


def _iter_toml_strings(value: object, skip: bool = False):
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = str(key).lower()
            child_skip = skip or "dependencies" in lowered or "requires" in lowered
            child_skip = child_skip or lowered == "dependency-groups"
            yield from _iter_toml_strings(child, child_skip)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_toml_strings(child, skip)
    elif isinstance(value, str) and not skip:
        yield value


def _scan_toml(refs: RepoReferences, path: Path, text: str, location: str) -> None:
    from ca9.analysis.ast_scanner import _load_toml

    data = _load_toml(path)
    if not data:
        # Unparseable config still counts: scan the raw text conservatively.
        _add_tokens(refs, text, location)
        return
    for value in _iter_toml_strings(data):
        _add_tokens(refs, value, location)


def _scan_ini(refs: RepoReferences, text: str, location: str) -> None:
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(text)
    except configparser.Error:
        _add_tokens(refs, text, location)
        return
    for section in parser.sections():
        _add_tokens(refs, section, location)
        if section.lower().startswith("options.extras_require"):
            continue
        for key, value in parser.items(section, raw=True):
            if key.lower() in _DEPENDENCY_CONFIG_KEYS:
                continue
            _add_tokens(refs, value or "", location)


def _matches(name: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in patterns)


def _is_scanned_config(name: str) -> bool:
    lowered = name.lower()
    # Dependency declarations and lockfiles list packages without using them.
    if lowered in _SKIPPED_TOML or lowered.startswith(("requirements", "constraints")):
        return False
    return (
        _matches(name, _TEXT_CONFIG_PATTERNS)
        or _matches(name, _PARSED_CONFIG_PATTERNS)
        or fnmatch.fnmatch(name, _TOML_PATTERN)
    )


def _iter_repo_files(repo_path: Path):
    from ca9.analysis.ast_scanner import _EXCLUDED_DIRS, _NON_RUNTIME_DIRS

    skipped_dirs = _EXCLUDED_DIRS | _NON_RUNTIME_DIRS
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = sorted(d for d in dirnames if d not in skipped_dirs)
        for filename in sorted(filenames):
            yield Path(dirpath) / filename


def scan_repo_references(repo_path: Path) -> RepoReferences:
    from ca9.analysis.ast_scanner import _is_runtime_python_file

    refs = RepoReferences()
    for path in _iter_repo_files(repo_path):
        if not path.is_file():
            continue
        try:
            rel = path.relative_to(repo_path)
        except ValueError:
            continue
        name = path.name
        is_python = name.endswith(".py")
        is_workflow = rel.parts[:2] == (".github", "workflows") and _matches(
            name, _WORKFLOW_PATTERNS
        )
        if is_python:
            if not _is_runtime_python_file(path, repo_path):
                continue
        elif not is_workflow and not _is_scanned_config(name):
            continue

        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        location = rel.as_posix()
        if is_python:
            _scan_python(refs, text, location)
        elif fnmatch.fnmatch(name, _TOML_PATTERN):
            _scan_toml(refs, path, text, location)
        elif _matches(name, _PARSED_CONFIG_PATTERNS):
            _scan_ini(refs, text, location)
        else:
            _add_tokens(refs, text, location)
    return refs


def collect_indirect_use_signals(
    package_name: str,
    import_names: tuple[str, ...],
    references: RepoReferences | None,
    index: EnvironmentIndex | None,
    optional_dependents: dict[str, str] | None = None,
) -> tuple[str, ...]:
    """Reasons a package may run although no import statement names it."""
    key = canonicalize_name(package_name)
    signals: list[str] = []

    curated_reason = INDIRECT_USE_PACKAGES.get(key)
    if curated_reason:
        signals.append(f"'{package_name}' {curated_reason}")

    if index is not None:
        groups = index.entry_points(package_name)
        plugin_groups = {
            group: names
            for group, names in groups.items()
            if group not in _SCRIPT_ENTRY_POINT_GROUPS
        }
        if plugin_groups:
            rendered = "; ".join(
                f"{group}: {', '.join(names[:3])}"
                for group, names in list(plugin_groups.items())[:3]
            )
            signals.append(f"'{package_name}' declares entry points ({rendered})")
        scripts = sorted(
            {name for group in _SCRIPT_ENTRY_POINT_GROUPS for name in groups.get(group, ())}
        )
        if scripts:
            if references is None:
                signals.append(
                    f"'{package_name}' installs commands ({', '.join(scripts[:3])}) "
                    "and the repository was not searched for them"
                )
            else:
                signals.extend(
                    f"'{package_name}' installs a command: {hit}"
                    for hit in references.find(scripts)
                )

    dependent = (optional_dependents or {}).get(key)
    if dependent:
        signals.append(f"'{package_name}' is an optional dependency of imported '{dependent}'")

    if references is not None:
        names = list(import_names)
        for alias in (key, key.replace("-", "_")):
            if alias not in (n.lower() for n in names):
                names.append(alias)
        signals.extend(references.find(names))

    return tuple(signals)
