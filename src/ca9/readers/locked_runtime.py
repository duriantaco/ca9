"""Select the local root's runtime dependency closure from v1 fyn and uv locks."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

from packaging.markers import (
    InvalidMarker,
    Marker,
    UndefinedComparison,
    UndefinedEnvironmentName,
    default_environment,
)
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from ca9.readers.fyn_lock import (
    _dependency_extras,
    _dependency_marker,
    _dependency_name,
    _dependency_version,
    _is_root_entry,
    _load_toml,
)


@dataclass
class LockedRuntime:
    packages: dict[str, tuple[str, str]] = field(default_factory=dict)
    direct: set[str] = field(default_factory=set)
    local: set[str] = field(default_factory=set)
    unresolved: set[str] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)


def _local(entry: dict) -> bool:
    source = entry.get("source")
    if not isinstance(source, dict) or len(source) != 1:
        return False
    kind, location = next(iter(source.items()))
    return (
        kind in {"editable", "virtual", "directory", "path"}
        and isinstance(location, str)
        and bool(location)
    )


def _valid_release(entry: dict) -> bool:
    version = entry.get("version")
    if not isinstance(version, str):
        return False
    try:
        Version(version)
        return True
    except InvalidVersion:
        return False


def _public_release(entry: dict) -> bool:
    source = entry.get("source")
    registry = (
        source.get("registry") if isinstance(source, dict) and set(source) == {"registry"} else None
    )
    return isinstance(registry, str) and registry.rstrip("/") == "https://pypi.org/simple"


def _active(marker: str | None, extra: str) -> bool:
    return not marker or Marker(marker).evaluate({"extra": extra})


def _same_version(left: str, right: object) -> bool:
    try:
        return isinstance(right, str) and Version(left) == Version(right)
    except InvalidVersion:
        return False


def _project_requirements(project: dict) -> dict[str, list[Requirement]]:
    requirements: dict[str, list[Requirement]] = defaultdict(list)
    for item in project.get("dependencies", []):
        if not isinstance(item, str):
            continue
        try:
            req = Requirement(item)
        except InvalidRequirement:
            continue
        try:
            if req.marker and not req.marker.evaluate({"extra": ""}):
                continue
        except (UndefinedComparison, UndefinedEnvironmentName):
            pass
        requirements[canonicalize_name(req.name)].append(req)
    return requirements


def _matches_edge(entry: dict, edge: object, extra: str, requirement: Requirement | None) -> bool:
    if (
        requirement
        and requirement.specifier
        and (
            not _valid_release(entry)
            or not requirement.specifier.contains(entry["version"], prereleases=True)
        )
    ):
        return False
    version = _dependency_version(edge)
    if version and not _same_version(version, entry.get("version")):
        return False
    if isinstance(edge, dict) and "source" in edge and edge["source"] != entry.get("source"):
        return False
    forks = entry.get("resolution-markers", [])
    if not isinstance(forks, list) or not all(isinstance(m, str) for m in forks):
        raise ValueError("invalid resolution markers")
    return not forks or any(_active(marker, extra) for marker in forks)


def _members(data: dict) -> set[str]:
    manifest = data.get("manifest")
    names = manifest.get("members") if isinstance(manifest, dict) else None
    if isinstance(names, list):
        return {canonicalize_name(name) for name in names if isinstance(name, str)}
    return set()


def select_locked_runtime(repo: Path, declared: dict[str, tuple[str, str | None]]) -> LockedRuntime:
    result = LockedRuntime()
    paths = [path for name in ("fyn.lock", "uv.lock") if (path := repo / name).is_file()]
    if not paths:
        return result
    if len(paths) > 1:
        result.warnings.append(
            "cannot choose a runtime dependency graph between fyn.lock and uv.lock"
        )
        return result

    path = paths[0]
    data, errors = _load_toml(path)
    if data is None:
        result.warnings.extend(errors)
        return result
    entries = data.get("package")
    if data.get("version") != 1 or not isinstance(entries, list):
        result.warnings.append(
            f"{path.name}: unsupported lock format for runtime dependency selection"
        )
        return result
    try:
        requires_python = SpecifierSet(data.get("requires-python", ""))
        python_version = default_environment()["python_full_version"]
        if not requires_python.contains(python_version, prereleases=True):
            result.warnings.append(
                f"{path.name}: Python {python_version} is outside {requires_python}"
            )
            return result
    except (InvalidSpecifier, TypeError):
        result.warnings.append(f"{path.name}: invalid requires-python constraint")
        return result

    members = _members(data)
    by_name: dict[str, list[int]] = defaultdict(list)
    roots = set()
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            continue
        name = canonicalize_name(entry["name"])
        by_name[name].append(i)
        if (_is_root_entry(entry) or name in members) and _local(entry):
            roots.add(i)
            result.local.add(name)

    if not roots:
        result.warnings.append(
            f"{path.name}: no local project root for runtime dependency selection"
        )
        return result
    requirements: dict[str, list[Requirement]] = {}
    configured_sources: dict = {}
    manifest_path = repo / "pyproject.toml"
    if manifest_path.is_file():
        manifest, _errors = _load_toml(manifest_path)
        project = manifest.get("project") if manifest else None
        project_name = project.get("name") if isinstance(project, dict) else None
        if isinstance(project_name, str) and canonicalize_name(project_name) not in result.local:
            result.warnings.append(f"{path.name}: local lock roots do not match {project_name}")
            return result
        if isinstance(project, dict):
            requirements = _project_requirements(project)
        tool = manifest.get("tool") if manifest else None
        uv = tool.get("uv") if isinstance(tool, dict) else None
        sources = uv.get("sources") if isinstance(uv, dict) else None
        if isinstance(sources, dict):
            configured_sources = {canonicalize_name(k): v for k, v in sources.items()}
    result.unresolved.update(members - result.local)

    queue = deque((i, "") for i in sorted(roots))
    seen: set[tuple[int, str]] = set()
    invalid_edges: set[str] = set()
    while queue:
        i, extra = queue.popleft()
        if (i, extra) in seen:
            continue
        seen.add((i, extra))
        parent = entries[i]
        if extra:
            groups = parent.get("optional-dependencies", {})
            edges = groups.get(extra, []) if isinstance(groups, dict) else None
        else:
            edges = parent.get("dependencies", [])
        if not isinstance(edges, list):
            invalid_edges.add(parent["name"])
            continue
        for edge in edges:
            name = _dependency_name(edge)
            if not name:
                invalid_edges.add(parent["name"])
                continue
            key = canonicalize_name(name)
            try:
                if (
                    isinstance(edge, dict)
                    and "marker" in edge
                    and not isinstance(edge["marker"], str)
                ):
                    raise ValueError("invalid marker")
                raw = edge.get("requirement") if isinstance(edge, dict) else edge
                requirement = Requirement(raw) if isinstance(raw, str) else None
                if requirement and (requirement.url or canonicalize_name(requirement.name) != key):
                    result.unresolved.add(key)
                    continue
                if not _active(_dependency_marker(edge), extra) or (
                    requirement
                    and requirement.marker
                    and not requirement.marker.evaluate({"extra": extra})
                ):
                    continue
                candidates = [
                    j
                    for j in by_name.get(key, ())
                    if _matches_edge(entries[j], edge, extra, requirement)
                ]
            except (ValueError, InvalidMarker, UndefinedComparison, UndefinedEnvironmentName):
                result.unresolved.add(key)
                continue
            if i in roots:
                result.direct.add(key)
            if len(candidates) != 1:
                result.unresolved.add(key)
                continue
            child_index = candidates[0]
            child = entries[child_index]
            version = child.get("version")
            if child_index not in roots:
                # Old lock entries sometimes omit the source for explicitly
                # declared direct packages. Preserve that existing scan input.
                declared_direct = (
                    i in roots
                    and key in declared
                    and "source" not in child
                    and key not in configured_sources
                )
                if not _valid_release(child) or not (_public_release(child) or declared_direct):
                    # We still know its outgoing lock edges, even when this
                    # package's own identity cannot be matched against PyPI.
                    result.unresolved.add(key)
                else:
                    pinned = declared.get(key, ("", None))[1]
                    existing = result.packages.get(key)
                    incompatible_manifest = any(
                        req.url or not req.specifier.contains(version, prereleases=True)
                        for req in requirements.get(key, ())
                    )
                    override = configured_sources.get(key)
                    local_override = isinstance(override, dict) and bool(
                        {"path", "git", "url", "workspace"} & override.keys()
                    )
                    if (
                        (pinned and not _same_version(pinned, version))
                        or (existing and not _same_version(existing[1], version))
                        or incompatible_manifest
                        or local_override
                    ):
                        result.unresolved.add(key)
                        continue
                    result.packages[key] = (child["name"], version)
            queue.append((child_index, ""))
            extras = set(_dependency_extras(edge))
            if requirement:
                extras.update(requirement.extras)
            queue.extend((child_index, requested) for requested in sorted(extras))

    # Existing scans include declared optional dependencies. Keep their locked
    # pins without adding transitives from inactive optional groups.
    if path.name == "uv.lock":
        for key, (_, pin) in declared.items():
            candidates = by_name.get(key, [])
            if pin or key in result.packages or key in result.unresolved or len(candidates) != 1:
                continue
            entry = entries[candidates[0]]
            if (
                _public_release(entry)
                and _valid_release(entry)
                and key not in configured_sources
                and all(
                    not req.url and req.specifier.contains(entry["version"], prereleases=True)
                    for req in requirements.get(key, ())
                )
            ):
                result.packages[key] = (entry["name"], entry["version"])

    if invalid_edges:
        names = ", ".join(sorted(invalid_edges)[:5])
        result.warnings.append(f"{path.name}: invalid dependency entries for {names}")
    if result.unresolved:
        names = ", ".join(sorted(result.unresolved)[:5])
        result.warnings.append(f"{path.name}: unresolved runtime dependency evidence for {names}")
    return result
