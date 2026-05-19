from __future__ import annotations

from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from ca9.core.models import (
    Artifact,
    DependencyEdge,
    Inventory,
    Package,
    SourceEvidence,
    SourceInput,
    package_key,
)

READER_NAME = "fyn.lock"


def read_fyn_lock(repo_path: Path) -> Inventory:
    lock_path = repo_path / "fyn.lock"
    if not lock_path.is_file():
        return Inventory(
            repo_path=str(repo_path),
            warnings=(f"no fyn.lock found at {lock_path}",),
            metadata={"reader": READER_NAME},
        )
    return load_fyn_lock(lock_path, repo_path=repo_path)


def load_fyn_lock(lock_path: Path, repo_path: Path | None = None) -> Inventory:
    repo = repo_path or lock_path.parent
    data, warnings = _load_toml(lock_path)
    if data is None:
        return Inventory(
            repo_path=str(repo), warnings=tuple(warnings), metadata={"reader": READER_NAME}
        )

    raw_packages = data.get("package", [])
    if isinstance(raw_packages, dict):
        raw_packages = [raw_packages]
    if not isinstance(raw_packages, list):
        raw_packages = []
        warnings.append("fyn.lock package table is not a list")

    entries = [entry for entry in raw_packages if isinstance(entry, dict)]
    evidence = SourceEvidence(source="fyn.lock", path=str(lock_path), reader=READER_NAME)
    source_input = SourceInput(
        kind="lockfile",
        path=str(lock_path),
        source="fyn.lock",
        metadata=_lock_metadata(data),
    )

    package_index = _index_packages(entries)
    root_keys = _root_package_keys(entries)
    direct_child_keys = _direct_child_keys(entries, package_index, root_keys)

    packages = tuple(
        sorted(
            (
                _package_from_entry(entry, evidence, package_index, root_keys, direct_child_keys)
                for entry in entries
            ),
            key=lambda package: package.key,
        )
    )
    edges = tuple(
        sorted(
            _dependency_edges(entries, package_index, root_keys, evidence),
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


def _load_toml(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        import tomllib
    except ModuleNotFoundError:
        try:
            import tomli as tomllib
        except ModuleNotFoundError:
            return None, [
                "cannot parse fyn.lock because no TOML parser is available; "
                "install tomli on Python 3.10"
            ]

    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except OSError as exc:
        return None, [f"cannot read fyn.lock: {exc}"]
    except Exception as exc:
        return None, [f"cannot parse fyn.lock: {exc}"]

    if not isinstance(data, dict):
        return None, ["fyn.lock did not parse to a TOML table"]
    return data, []


def _lock_metadata(data: dict[str, Any]) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    for key in ("version", "revision", "requires-python", "resolution-markers"):
        value = data.get(key)
        if value is not None:
            metadata[key.replace("-", "_")] = value
    return metadata


def _index_packages(entries: list[dict[str, Any]]) -> dict[str, list[tuple[str, str, str]]]:
    index: dict[str, list[tuple[str, str, str]]] = {}
    for entry in entries:
        name = entry.get("name")
        version = entry.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        key = package_key("pypi", name, version)
        index.setdefault(str(canonicalize_name(name)), []).append((name, version, key))
    return index


def _entry_key(entry: dict[str, Any]) -> str | None:
    name = entry.get("name")
    version = entry.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        return None
    return package_key("pypi", name, version)


def _is_root_entry(entry: dict[str, Any]) -> bool:
    source = entry.get("source")
    if not isinstance(source, dict):
        return False
    return (
        source.get("editable") == "." or source.get("virtual") == "." or source.get("path") == "."
    )


def _root_package_keys(entries: list[dict[str, Any]]) -> set[str]:
    roots: set[str] = set()
    for entry in entries:
        if not _is_root_entry(entry):
            continue
        key = _entry_key(entry)
        if key:
            roots.add(key)
    return roots


def _direct_child_keys(
    entries: list[dict[str, Any]],
    package_index: dict[str, list[tuple[str, str, str]]],
    root_keys: set[str],
) -> set[str]:
    direct: set[str] = set()
    for entry in entries:
        parent_key = _entry_key(entry)
        if parent_key not in root_keys:
            continue
        for dependency, _groups in _iter_entry_dependencies(entry):
            dep_name = _dependency_name(dependency)
            if not dep_name:
                continue
            resolved = _resolve_dependency(dep_name, dependency, package_index)
            direct.add(resolved["key"])
    return direct


def _package_from_entry(
    entry: dict[str, Any],
    evidence: SourceEvidence,
    package_index: dict[str, list[tuple[str, str, str]]],
    root_keys: set[str],
    direct_child_keys: set[str],
) -> Package:
    name = _string_or_empty(entry.get("name"))
    version = _string_or_none(entry.get("version"))
    source = entry.get("source")
    source_registry = source.get("registry") if isinstance(source, dict) else None
    key = package_key("pypi", name, version)

    if key in root_keys:
        dependency_kind = "project"
    elif root_keys and key in direct_child_keys:
        dependency_kind = "direct"
    elif root_keys:
        dependency_kind = "transitive"
    else:
        dependency_kind = "unknown"

    metadata = {"dependency_count": len(_iter_entry_dependencies(entry))}
    source_kind = _source_kind(source)
    if source_kind:
        metadata["source_kind"] = source_kind

    return Package(
        name=name,
        version=version,
        ecosystem="pypi",
        dependency_kind=dependency_kind,
        source_registry=source_registry if isinstance(source_registry, str) else None,
        artifacts=_artifacts_from_entry(entry, source_registry, evidence),
        evidence=(evidence,),
        metadata=metadata | _dependency_metadata(entry, package_index),
    )


def _source_kind(source: object) -> str | None:
    if not isinstance(source, dict):
        return None
    for key in ("editable", "virtual", "path", "registry", "git", "url"):
        if key in source:
            return key
    return None


def _dependency_metadata(
    entry: dict[str, Any],
    package_index: dict[str, list[tuple[str, str, str]]],
) -> dict[str, Any]:
    dependency_names: list[dict[str, Any]] = []
    for dependency, groups in _iter_entry_dependencies(entry):
        dep_name = _dependency_name(dependency)
        if not dep_name:
            continue
        resolved = _resolve_dependency(dep_name, dependency, package_index)
        item: dict[str, Any] = {"name": dep_name}
        if resolved["version"]:
            item["version"] = resolved["version"]
        marker = _dependency_marker(dependency)
        if marker:
            item["marker"] = marker
        if groups:
            item["groups"] = list(groups)
        dependency_names.append(item)
    if not dependency_names:
        return {}
    return {"dependencies": dependency_names}


def _artifacts_from_entry(
    entry: dict[str, Any],
    source_registry: object,
    evidence: SourceEvidence,
) -> tuple[Artifact, ...]:
    artifacts: list[Artifact] = []
    source = source_registry if isinstance(source_registry, str) else None
    sdist = entry.get("sdist")
    if isinstance(sdist, dict):
        artifacts.append(_artifact_from_mapping("sdist", sdist, source, evidence))

    wheels = entry.get("wheels", [])
    if isinstance(wheels, dict):
        wheels = [wheels]
    if isinstance(wheels, list):
        for wheel in wheels:
            if isinstance(wheel, dict):
                artifacts.append(_artifact_from_mapping("wheel", wheel, source, evidence))

    return tuple(artifacts)


def _artifact_from_mapping(
    kind: str,
    raw: dict[str, Any],
    source: str | None,
    evidence: SourceEvidence,
) -> Artifact:
    size = raw.get("size")
    if not isinstance(size, int):
        size = None
    return Artifact(
        kind=kind,
        url=_string_or_none(raw.get("url")),
        hash=_string_or_none(raw.get("hash")),
        size=size,
        upload_time=_string_or_none(raw.get("upload-time")),
        source=source,
        evidence=(evidence,),
    )


def _dependency_edges(
    entries: list[dict[str, Any]],
    package_index: dict[str, list[tuple[str, str, str]]],
    root_keys: set[str],
    evidence: SourceEvidence,
) -> list[DependencyEdge]:
    edges: list[DependencyEdge] = []
    for entry in entries:
        parent_key = _entry_key(entry)
        if not parent_key:
            continue
        parent_name = _string_or_none(entry.get("name"))
        parent_version = _string_or_none(entry.get("version"))

        for dependency, groups in _iter_entry_dependencies(entry):
            dep_name = _dependency_name(dependency)
            if not dep_name:
                continue
            resolved = _resolve_dependency(dep_name, dependency, package_index)
            edges.append(
                DependencyEdge(
                    parent_key=parent_key,
                    child_key=resolved["key"],
                    parent_name=parent_name,
                    parent_version=parent_version,
                    child_name=resolved["name"],
                    child_version=resolved["version"],
                    dependency_kind="direct" if parent_key in root_keys else "transitive",
                    groups=groups,
                    extras=_dependency_extras(dependency),
                    marker=_dependency_marker(dependency),
                    evidence=(evidence,),
                )
            )
    return edges


def _iter_entry_dependencies(entry: dict[str, Any]) -> list[tuple[object, tuple[str, ...]]]:
    dependencies: list[tuple[object, tuple[str, ...]]] = []

    runtime_dependencies = entry.get("dependencies", [])
    if isinstance(runtime_dependencies, list):
        dependencies.extend((dependency, ()) for dependency in runtime_dependencies)

    dev_dependencies = entry.get("dev-dependencies", {})
    if isinstance(dev_dependencies, dict):
        for group, group_deps in dev_dependencies.items():
            if not isinstance(group, str) or not isinstance(group_deps, list):
                continue
            dependencies.extend((dependency, (group,)) for dependency in group_deps)

    optional_dependencies = entry.get("optional-dependencies", {})
    if isinstance(optional_dependencies, dict):
        for group, group_deps in optional_dependencies.items():
            if not isinstance(group, str) or not isinstance(group_deps, list):
                continue
            dependencies.extend((dependency, (group,)) for dependency in group_deps)

    return dependencies


def _resolve_dependency(
    dep_name: str,
    dependency: object,
    package_index: dict[str, list[tuple[str, str, str]]],
) -> dict[str, str | None]:
    dep_version = _dependency_version(dependency)
    dep_key = str(canonicalize_name(dep_name))
    candidates = package_index.get(dep_key, [])

    if dep_version:
        for name, version, key in candidates:
            if version == dep_version:
                return {"name": name, "version": version, "key": key}
        return {
            "name": dep_name,
            "version": dep_version,
            "key": package_key("pypi", dep_name, dep_version),
        }

    if len(candidates) == 1:
        name, version, key = candidates[0]
        return {"name": name, "version": version, "key": key}

    return {"name": dep_name, "version": None, "key": package_key("pypi", dep_name)}


def _dependency_name(dependency: object) -> str | None:
    if isinstance(dependency, dict):
        name = dependency.get("name")
        if isinstance(name, str) and name.strip():
            return name.strip()
        requirement = dependency.get("requirement")
        if isinstance(requirement, str):
            return _requirement_name(requirement)
        return None
    if isinstance(dependency, str):
        return _requirement_name(dependency)
    return None


def _dependency_version(dependency: object) -> str | None:
    if isinstance(dependency, dict):
        version = dependency.get("version")
        if isinstance(version, str) and version.strip():
            return version.strip()
    if isinstance(dependency, str):
        try:
            parsed = Requirement(dependency)
        except InvalidRequirement:
            return None
        exact_versions = [
            spec.version
            for spec in parsed.specifier
            if spec.operator in ("==", "===") and "*" not in spec.version
        ]
        if len(exact_versions) == 1:
            return exact_versions[0]
    return None


def _dependency_marker(dependency: object) -> str | None:
    if isinstance(dependency, dict):
        marker = dependency.get("marker")
        if isinstance(marker, str) and marker.strip():
            return marker.strip()
    if isinstance(dependency, str):
        try:
            parsed = Requirement(dependency)
        except InvalidRequirement:
            return None
        if parsed.marker is not None:
            return str(parsed.marker)
    return None


def _dependency_extras(dependency: object) -> tuple[str, ...]:
    extras: set[str] = set()
    if isinstance(dependency, dict):
        extra = dependency.get("extra")
        if isinstance(extra, str) and extra.strip():
            extras.add(extra.strip())
        elif isinstance(extra, list):
            extras.update(item.strip() for item in extra if isinstance(item, str) and item.strip())
        extras_value = dependency.get("extras")
        if isinstance(extras_value, list):
            extras.update(
                item.strip() for item in extras_value if isinstance(item, str) and item.strip()
            )
    elif isinstance(dependency, str):
        try:
            parsed = Requirement(dependency)
        except InvalidRequirement:
            return ()
        extras.update(parsed.extras)
    return tuple(sorted(extras))


def _requirement_name(value: str) -> str | None:
    try:
        parsed = Requirement(value)
    except InvalidRequirement:
        name = value.split(";", 1)[0].split("[", 1)[0].split(" ", 1)[0].strip()
        return name or None
    return parsed.name


def _string_or_none(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value
    if value is not None and not isinstance(value, (dict, list, tuple)):
        return str(value)
    return None


def _string_or_empty(value: object) -> str:
    result = _string_or_none(value)
    return result or ""
