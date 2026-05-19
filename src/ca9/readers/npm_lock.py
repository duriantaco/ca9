from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ca9.core.models import (
    Artifact,
    DependencyEdge,
    Inventory,
    Package,
    SourceEvidence,
    SourceInput,
    package_key,
)

READER_NAME = "npm lockfile"
NPM_REGISTRY = "https://registry.npmjs.org"


def read_npm_lock(repo_path: Path) -> Inventory:
    for filename in ("package-lock.json", "npm-shrinkwrap.json"):
        lock_path = repo_path / filename
        if lock_path.is_file():
            return load_npm_lock(lock_path, repo_path=repo_path)
    return Inventory(
        repo_path=str(repo_path),
        warnings=(f"no package-lock.json or npm-shrinkwrap.json found at {repo_path}",),
        metadata={"reader": READER_NAME},
    )


def load_npm_lock(lock_path: Path, repo_path: Path | None = None) -> Inventory:
    repo = repo_path or lock_path.parent
    data, warnings = _load_json(lock_path)
    if data is None:
        return Inventory(
            repo_path=str(repo), warnings=tuple(warnings), metadata={"reader": READER_NAME}
        )

    evidence = SourceEvidence(source=lock_path.name, path=str(lock_path), reader=READER_NAME)
    source_input = SourceInput(
        kind="lockfile",
        path=str(lock_path),
        source=lock_path.name,
        metadata=_lock_metadata(data),
    )

    entries = _lock_entries(data)
    if not entries:
        return Inventory(
            repo_path=str(repo),
            source_inputs=(source_input,),
            warnings=tuple([*warnings, "npm lockfile did not contain package entries"]),
            metadata={"reader": READER_NAME},
        )

    package_index = _index_entries(entries)
    root_key = _entry_key(entries.get(""))
    direct_child_keys = _direct_child_keys(entries, root_key, package_index)

    packages = tuple(
        sorted(
            (
                _package_from_entry(path, entry, evidence, root_key, direct_child_keys)
                for path, entry in entries.items()
            ),
            key=lambda package: package.key,
        )
    )
    edges = tuple(
        sorted(
            _dependency_edges(entries, package_index, root_key, evidence),
            key=lambda edge: (
                edge.parent_key or "",
                edge.child_key,
                ",".join(edge.groups),
            ),
        )
    )

    return Inventory(
        repo_path=str(repo),
        source_inputs=(source_input,),
        packages=packages,
        dependency_edges=edges,
        warnings=tuple(warnings),
        metadata={"reader": READER_NAME},
    )


def _load_json(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        data = json.loads(path.read_text())
    except OSError as exc:
        return None, [f"cannot read npm lockfile: {exc}"]
    except json.JSONDecodeError as exc:
        return None, [f"cannot parse npm lockfile: {exc}"]

    if not isinstance(data, dict):
        return None, ["npm lockfile did not parse to an object"]
    return data, []


def _lock_metadata(data: dict[str, Any]) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    for key in ("name", "version", "lockfileVersion"):
        if key in data:
            metadata[key] = data[key]
    return metadata


def _lock_entries(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    packages = data.get("packages")
    if isinstance(packages, dict):
        entries: dict[str, dict[str, Any]] = {}
        for path, raw in packages.items():
            if not isinstance(raw, dict):
                continue
            lock_path = str(path)
            if lock_path:
                entry = _entry_with_name(lock_path, raw)
            else:
                entry = dict(raw)
                entry.setdefault("name", _string_or_none(data.get("name")) or "root")
                version = _string_or_none(entry.get("version")) or _string_or_none(
                    data.get("version")
                )
                if version:
                    entry["version"] = version
            if _entry_name(lock_path, entry):
                entries[lock_path] = entry
        return entries

    dependencies = data.get("dependencies")
    if not isinstance(dependencies, dict):
        return {}

    required_names = _v1_required_names(dependencies)
    root_dependency_names = [
        name
        for name, raw in dependencies.items()
        if isinstance(name, str)
        and isinstance(raw, dict)
        and _normalize_npm_name(name) not in required_names
    ]
    entries: dict[str, dict[str, Any]] = {
        "": {
            "name": _string_or_none(data.get("name")) or "root",
            "version": _string_or_none(data.get("version")),
            "dependencies": {name: "*" for name in root_dependency_names},
        }
    }
    for name, raw in dependencies.items():
        if isinstance(raw, dict):
            _collect_v1_dependency(entries, f"node_modules/{name}", name, raw)
    return entries


def _v1_required_names(dependencies: dict[str, Any]) -> set[str]:
    required: set[str] = set()
    for raw in dependencies.values():
        if not isinstance(raw, dict):
            continue
        for name in _v1_requires(raw):
            required.add(_normalize_npm_name(name))
        nested = raw.get("dependencies")
        if isinstance(nested, dict):
            required.update(_v1_required_names(nested))
    return required


def _collect_v1_dependency(
    entries: dict[str, dict[str, Any]],
    path: str,
    name: str,
    raw: dict[str, Any],
) -> None:
    entry = dict(raw)
    entry["name"] = name
    entries[path] = entry

    child_dependencies = raw.get("dependencies")
    if not isinstance(child_dependencies, dict):
        return
    for child_name, child_raw in child_dependencies.items():
        if isinstance(child_raw, dict):
            child_path = f"{path}/node_modules/{child_name}"
            _collect_v1_dependency(entries, child_path, child_name, child_raw)


def _entry_with_name(path: str, raw: dict[str, Any]) -> dict[str, Any]:
    entry = dict(raw)
    entry.setdefault("name", _entry_name(path, raw))
    return entry


def _entry_name(path: str, raw: dict[str, Any]) -> str | None:
    name = _string_or_none(raw.get("name"))
    if name:
        return name
    if not path:
        return None

    parts = path.split("/")
    if "node_modules" not in parts:
        return None
    index = len(parts) - 1 - parts[::-1].index("node_modules")
    if index + 1 >= len(parts):
        return None
    first = parts[index + 1]
    if first.startswith("@") and index + 2 < len(parts):
        return f"{first}/{parts[index + 2]}"
    return first


def _entry_key(entry: dict[str, Any] | None) -> str | None:
    if not entry:
        return None
    name = _string_or_none(entry.get("name"))
    version = _string_or_none(entry.get("version"))
    if not name:
        return None
    return package_key("npm", name, version)


def _index_entries(
    entries: dict[str, dict[str, Any]],
) -> dict[str, list[tuple[str, str | None, str, str]]]:
    index: dict[str, list[tuple[str, str | None, str, str]]] = {}
    for path, entry in entries.items():
        name = _string_or_none(entry.get("name"))
        if not name:
            continue
        version = _string_or_none(entry.get("version"))
        key = package_key("npm", name, version)
        index.setdefault(_normalize_npm_name(name), []).append((path, version, name, key))
    return index


def _direct_child_keys(
    entries: dict[str, dict[str, Any]],
    root_key: str | None,
    package_index: dict[str, list[tuple[str, str | None, str, str]]],
) -> set[str]:
    if not root_key:
        return set()

    root = entries.get("", {})
    direct: set[str] = set()
    for dep_name in _iter_dependency_names(root):
        resolved = _resolve_dependency("", dep_name, package_index)
        direct.add(resolved["key"])
    return direct


def _package_from_entry(
    path: str,
    entry: dict[str, Any],
    evidence: SourceEvidence,
    root_key: str | None,
    direct_child_keys: set[str],
) -> Package:
    name = _string_or_none(entry.get("name")) or _entry_name(path, entry) or ""
    version = _string_or_none(entry.get("version"))
    key = package_key("npm", name, version)

    if path == "":
        dependency_kind = "project"
    elif root_key and key in direct_child_keys:
        dependency_kind = "direct"
    elif root_key:
        dependency_kind = "transitive"
    else:
        dependency_kind = "unknown"

    resolved = _string_or_none(entry.get("resolved"))
    source_registry = _registry_from_resolved(resolved)
    source_kind = _source_kind(entry, resolved)
    metadata: dict[str, Any] = {
        "lockfile_path": path,
        "dependency_count": len(_iter_dependency_names(entry)),
    }
    if source_kind:
        metadata["source_kind"] = source_kind
    if bool(entry.get("dev")):
        metadata["dev"] = True
    if bool(entry.get("optional")):
        metadata["optional"] = True

    return Package(
        name=name,
        version=version,
        ecosystem="npm",
        dependency_kind=dependency_kind,
        source_registry=source_registry,
        artifacts=_artifacts_from_entry(entry, source_registry, evidence),
        evidence=(evidence,),
        metadata=metadata,
    )


def _artifacts_from_entry(
    entry: dict[str, Any],
    source_registry: str | None,
    evidence: SourceEvidence,
) -> tuple[Artifact, ...]:
    resolved = _string_or_none(entry.get("resolved"))
    if not resolved or not resolved.startswith(("http://", "https://", "file:")):
        return ()
    return (
        Artifact(
            kind="npm-tarball",
            url=resolved,
            hash=_string_or_none(entry.get("integrity")),
            source=source_registry,
            evidence=(evidence,),
        ),
    )


def _dependency_edges(
    entries: dict[str, dict[str, Any]],
    package_index: dict[str, list[tuple[str, str | None, str, str]]],
    root_key: str | None,
    evidence: SourceEvidence,
) -> list[DependencyEdge]:
    edges: list[DependencyEdge] = []
    for parent_path, entry in entries.items():
        parent_key = _entry_key(entry)
        if not parent_key:
            continue
        parent_name = _string_or_none(entry.get("name"))
        parent_version = _string_or_none(entry.get("version"))

        for dep_name, groups in _iter_dependencies(entry):
            resolved = _resolve_dependency(parent_path, dep_name, package_index)
            edges.append(
                DependencyEdge(
                    parent_key=parent_key,
                    child_key=resolved["key"],
                    parent_name=parent_name,
                    parent_version=parent_version,
                    child_name=resolved["name"],
                    child_version=resolved["version"],
                    dependency_kind="direct" if parent_key == root_key else "transitive",
                    groups=groups,
                    evidence=(evidence,),
                )
            )
    return edges


def _iter_dependency_names(entry: dict[str, Any]) -> list[str]:
    return [name for name, _groups in _iter_dependencies(entry)]


def _iter_dependencies(entry: dict[str, Any]) -> list[tuple[str, tuple[str, ...]]]:
    dependencies: list[tuple[str, tuple[str, ...]]] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for key, group in (
        ("dependencies", ()),
        ("requires", ()),
        ("devDependencies", ("dev",)),
        ("optionalDependencies", ("optional",)),
        ("peerDependencies", ("peer",)),
    ):
        value = entry.get(key)
        if not isinstance(value, dict):
            continue
        for name in value:
            if isinstance(name, str) and name.strip():
                item = (name.strip(), group)
                if item not in seen:
                    dependencies.append(item)
                    seen.add(item)
    return dependencies


def _v1_requires(entry: dict[str, Any]) -> list[str]:
    value = entry.get("requires")
    if not isinstance(value, dict):
        return []
    return [name.strip() for name in value if isinstance(name, str) and name.strip()]


def _resolve_dependency(
    parent_path: str,
    dep_name: str,
    package_index: dict[str, list[tuple[str, str | None, str, str]]],
) -> dict[str, str | None]:
    candidates = package_index.get(_normalize_npm_name(dep_name), [])
    candidate_paths = _candidate_dependency_paths(parent_path, dep_name)
    for candidate_path in candidate_paths:
        for path, version, name, key in candidates:
            if path == candidate_path:
                return {"name": name, "version": version, "key": key}

    if len(candidates) == 1:
        _path, version, name, key = candidates[0]
        return {"name": name, "version": version, "key": key}

    return {"name": dep_name, "version": None, "key": package_key("npm", dep_name)}


def _candidate_dependency_paths(parent_path: str, dep_name: str) -> list[str]:
    candidates: list[str] = []
    current = parent_path
    while True:
        prefix = f"{current}/" if current else ""
        candidates.append(f"{prefix}node_modules/{dep_name}")
        if not current:
            break
        parts = current.split("/")
        if "node_modules" not in parts:
            current = ""
            continue
        index = len(parts) - 1 - parts[::-1].index("node_modules")
        current = "/".join(parts[:index])
    return candidates


def _registry_from_resolved(resolved: str | None) -> str | None:
    if not resolved or not resolved.startswith(("http://", "https://")):
        return None
    parsed = urlparse(resolved)
    if not parsed.scheme or not parsed.netloc:
        return None
    if parsed.netloc == "registry.npmjs.org":
        return NPM_REGISTRY
    return f"{parsed.scheme}://{parsed.netloc}"


def _source_kind(entry: dict[str, Any], resolved: str | None) -> str | None:
    version = _string_or_none(entry.get("version")) or ""
    if (resolved and resolved.startswith(("git+", "git://", "github:"))) or version.startswith(
        ("git+", "git://", "github:")
    ):
        return "git"
    if resolved and resolved.startswith("file:"):
        return "path"
    if resolved and resolved.startswith(("http://", "https://")):
        return "registry" if _registry_from_resolved(resolved) == NPM_REGISTRY else "url"
    return None


def _normalize_npm_name(name: str) -> str:
    return name.strip().lower()


def _string_or_none(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value
    if value is not None and not isinstance(value, (dict, list, tuple)):
        return str(value)
    return None
