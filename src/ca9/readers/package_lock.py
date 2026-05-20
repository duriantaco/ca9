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

READER_NAME = "package-lock.json"


def read_package_lock(repo_path: Path) -> Inventory:
    lock_path = repo_path / "package-lock.json"
    if not lock_path.is_file():
        return Inventory(
            repo_path=str(repo_path),
            warnings=(f"no package-lock.json found at {lock_path}",),
            metadata={"reader": READER_NAME},
        )
    return load_package_lock(lock_path, repo_path=repo_path)


def load_package_lock(lock_path: Path, repo_path: Path | None = None) -> Inventory:
    repo = repo_path or lock_path.parent
    data, warnings = _load_json(lock_path)
    if data is None:
        return Inventory(
            repo_path=str(repo),
            warnings=tuple(warnings),
            metadata={"reader": READER_NAME},
        )

    raw_packages = data.get("packages", {})
    if not isinstance(raw_packages, dict):
        raw_packages = {}
        warnings.append("package-lock.json packages table is not an object")
    if not raw_packages and data.get("lockfileVersion") == 1:
        warnings.append("package-lock.json lockfileVersion 1 is not supported yet")

    evidence = SourceEvidence(source=READER_NAME, path=str(lock_path), reader=READER_NAME)
    source_input = SourceInput(
        kind="lockfile",
        path=str(lock_path),
        source=READER_NAME,
        metadata=_lock_metadata(data),
    )

    package_paths = {path for path in raw_packages if path}
    root = raw_packages.get("", {})
    root_dependencies = _root_dependency_paths(root, package_paths)
    packages = tuple(
        sorted(
            _packages_from_lock(raw_packages, evidence, root_dependencies),
            key=lambda package: package.key,
        )
    )
    edges = tuple(
        sorted(
            _dependency_edges(raw_packages, package_paths, evidence),
            key=lambda edge: (
                edge.parent_key or "",
                edge.child_key,
                ",".join(edge.groups),
                edge.marker or "",
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
        with path.open() as f:
            data = json.load(f)
    except OSError as exc:
        return None, [f"cannot read package-lock.json: {exc}"]
    except json.JSONDecodeError as exc:
        return None, [f"cannot parse package-lock.json: {exc}"]

    if not isinstance(data, dict):
        return None, ["package-lock.json did not parse to an object"]
    return data, []


def _lock_metadata(data: dict[str, Any]) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    for key in ("name", "version", "lockfileVersion", "requires"):
        value = data.get(key)
        if value is not None:
            metadata[key] = value
    return metadata


def _packages_from_lock(
    raw_packages: dict[str, Any],
    evidence: SourceEvidence,
    root_dependencies: set[str],
) -> list[Package]:
    packages: list[Package] = []
    root = raw_packages.get("", {})
    if isinstance(root, dict):
        root_package = _root_package(root, evidence)
        if root_package is not None:
            packages.append(root_package)

    for path, entry in raw_packages.items():
        if not path or not isinstance(entry, dict):
            continue
        package = _package_from_entry(path, entry, evidence, root_dependencies)
        if package is not None:
            packages.append(package)
    return packages


def _root_package(root: dict[str, Any], evidence: SourceEvidence) -> Package | None:
    name = _string_or_none(root.get("name"))
    version = _string_or_none(root.get("version"))
    if not name or not version:
        return None
    return Package(
        name=name,
        version=version,
        ecosystem="npm",
        dependency_kind="project",
        evidence=(evidence,),
        metadata=_entry_metadata(root, "", set()),
    )


def _package_from_entry(
    path: str,
    entry: dict[str, Any],
    evidence: SourceEvidence,
    root_dependencies: set[str],
) -> Package | None:
    name = _entry_name(path, entry)
    version = _string_or_none(entry.get("version"))
    if not name or not version:
        return None

    dependency_kind = "direct" if path in root_dependencies else "transitive"
    resolved = _string_or_none(entry.get("resolved"))
    integrity = _string_or_none(entry.get("integrity"))
    source_registry = _registry_from_resolved(resolved)
    return Package(
        name=name,
        version=version,
        ecosystem="npm",
        dependency_kind=dependency_kind,
        source_registry=source_registry,
        artifacts=_artifacts_from_entry(resolved, integrity, source_registry, evidence),
        evidence=(evidence,),
        metadata=_entry_metadata(entry, path, root_dependencies),
    )


def _entry_metadata(entry: dict[str, Any], path: str, root_dependencies: set[str]) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    dependency_items = _entry_dependency_items(entry)
    if dependency_items:
        metadata["dependencies"] = dependency_items
        metadata["dependency_count"] = len(dependency_items)
    if path and path in root_dependencies:
        metadata["root_dependency"] = True

    for key in ("dev", "optional", "devOptional", "inBundle", "hasInstallScript", "license"):
        value = entry.get(key)
        if value is not None:
            metadata[_snake_case(key)] = value

    resolved = _string_or_none(entry.get("resolved"))
    source_kind = _source_kind(resolved)
    if source_kind:
        metadata["source_kind"] = source_kind
    return metadata


def _entry_dependency_items(entry: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for group, field in (
        ("runtime", "dependencies"),
        ("dev", "devDependencies"),
        ("optional", "optionalDependencies"),
        ("peer", "peerDependencies"),
    ):
        dependencies = entry.get(field, {})
        if not isinstance(dependencies, dict):
            continue
        for name, spec in sorted(dependencies.items()):
            if not isinstance(name, str):
                continue
            item: dict[str, Any] = {"name": name, "group": group}
            if isinstance(spec, str):
                item["specifier"] = spec
            items.append(item)
    return items


def _dependency_edges(
    raw_packages: dict[str, Any],
    package_paths: set[str],
    evidence: SourceEvidence,
) -> list[DependencyEdge]:
    edges: list[DependencyEdge] = []
    for parent_path, entry in raw_packages.items():
        if not isinstance(entry, dict):
            continue
        parent_name = _entry_name(parent_path, entry)
        parent_version = _string_or_none(entry.get("version"))
        parent_key = (
            package_key("npm", parent_name, parent_version)
            if parent_name and parent_version
            else None
        )
        parent_is_root = parent_path == ""

        for dependency in _iter_dependencies(entry):
            child_path = _resolve_child_path(parent_path, dependency.name, package_paths)
            child_entry = raw_packages.get(child_path, {}) if child_path else {}
            child_version = (
                _string_or_none(child_entry.get("version"))
                if isinstance(child_entry, dict)
                else None
            )
            child_key = package_key("npm", dependency.name, child_version)
            edges.append(
                DependencyEdge(
                    parent_key=parent_key,
                    child_key=child_key,
                    parent_name=parent_name,
                    parent_version=parent_version,
                    child_name=dependency.name,
                    child_version=child_version,
                    dependency_kind="direct" if parent_is_root else "transitive",
                    groups=(dependency.group,) if dependency.group != "runtime" else (),
                    evidence=(evidence,),
                )
            )
    return edges


def _root_dependency_paths(root: object, package_paths: set[str]) -> set[str]:
    if not isinstance(root, dict):
        return set()
    paths: set[str] = set()
    for dependency in _iter_dependencies(root):
        child_path = _resolve_child_path("", dependency.name, package_paths)
        if child_path:
            paths.add(child_path)
    return paths


def _iter_dependencies(entry: dict[str, Any]) -> list[_Dependency]:
    dependencies: list[_Dependency] = []
    for group, field in (
        ("runtime", "dependencies"),
        ("dev", "devDependencies"),
        ("optional", "optionalDependencies"),
        ("peer", "peerDependencies"),
    ):
        raw = entry.get(field, {})
        if not isinstance(raw, dict):
            continue
        for name in sorted(raw):
            if isinstance(name, str) and name.strip():
                dependencies.append(_Dependency(name=name.strip(), group=group))
    return dependencies


class _Dependency:
    def __init__(self, *, name: str, group: str) -> None:
        self.name = name
        self.group = group


def _resolve_child_path(parent_path: str, name: str, package_paths: set[str]) -> str | None:
    candidates = _node_modules_candidates(parent_path, name)
    for candidate in candidates:
        if candidate in package_paths:
            return candidate
    return None


def _node_modules_candidates(parent_path: str, name: str) -> list[str]:
    if not parent_path:
        return [f"node_modules/{name}"]

    candidates = [f"{parent_path}/node_modules/{name}"]
    current = parent_path
    while "/node_modules/" in current:
        current = current.rsplit("/node_modules/", 1)[0]
        candidates.append(f"{current}/node_modules/{name}")
    candidates.append(f"node_modules/{name}")
    return candidates


def _entry_name(path: str, entry: dict[str, Any]) -> str | None:
    name = _string_or_none(entry.get("name"))
    if name:
        return name
    if not path:
        return None
    segment = path.rsplit("node_modules/", 1)[-1]
    if not segment:
        return None
    parts = segment.split("/")
    if parts[0].startswith("@") and len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0]


def _artifacts_from_entry(
    resolved: str | None,
    integrity: str | None,
    source_registry: str | None,
    evidence: SourceEvidence,
) -> tuple[Artifact, ...]:
    if not resolved:
        return ()
    return (
        Artifact(
            kind="npm-tarball",
            url=resolved,
            hash=integrity,
            source=source_registry,
            evidence=(evidence,),
        ),
    )


def _registry_from_resolved(resolved: str | None) -> str | None:
    if not resolved:
        return None
    parsed = urlparse(resolved)
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _source_kind(resolved: str | None) -> str | None:
    if not resolved:
        return None
    if resolved.startswith(("git+", "github:")):
        return "git"
    parsed = urlparse(resolved)
    if parsed.scheme in {"http", "https"}:
        return "registry"
    if parsed.scheme:
        return parsed.scheme
    return None


def _string_or_none(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _snake_case(value: str) -> str:
    result = []
    for char in value:
        if char.isupper():
            result.extend(["_", char.lower()])
        else:
            result.append(char)
    return "".join(result).lstrip("_")
