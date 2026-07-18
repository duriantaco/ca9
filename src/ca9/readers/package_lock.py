from __future__ import annotations

import json
import posixpath
import re
from fnmatch import fnmatchcase
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

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

    package_paths = {path for path in raw_packages if isinstance(path, str) and path}
    root = raw_packages.get("", {})
    package_identities = _package_identities(raw_packages)
    workspace_paths = _workspace_paths(root, package_paths)
    requested_specifiers = _requested_specifiers_by_path(raw_packages, package_paths)
    root_dependencies = _root_dependency_paths(root, raw_packages, package_paths)
    packages = tuple(
        sorted(
            _packages_from_lock(
                raw_packages,
                evidence,
                root_dependencies,
                package_identities,
                workspace_paths,
                requested_specifiers,
                lock_path.parent,
            ),
            key=lambda package: package.key,
        )
    )
    edges = tuple(
        sorted(
            _dependency_edges(raw_packages, package_paths, package_identities, evidence),
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
    package_identities: dict[str, tuple[str, ...]],
    workspace_paths: set[str],
    requested_specifiers: dict[str, tuple[str, ...]],
    lock_directory: Path,
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
        package = _package_from_entry(
            path,
            entry,
            evidence,
            root_dependencies,
            package_identities,
            workspace_paths,
            requested_specifiers,
            lock_directory,
        )
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
    package_identities: dict[str, tuple[str, ...]],
    workspace_paths: set[str],
    requested_specifiers: dict[str, tuple[str, ...]],
    lock_directory: Path,
) -> Package | None:
    name = _entry_name(path, entry, package_identities)
    version = _string_or_none(entry.get("version"))
    if not name or (
        not version and (entry.get("link") is True or entry.get("hasInstallScript") is not True)
    ):
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
        artifacts=_artifacts_from_entry(
            resolved,
            integrity,
            source_registry,
            evidence,
            lock_directory,
        ),
        evidence=(evidence,),
        metadata=_entry_metadata(
            entry,
            path,
            root_dependencies,
            package_identities,
            workspace_paths,
            requested_specifiers,
        ),
    )


def _entry_metadata(
    entry: dict[str, Any],
    path: str,
    root_dependencies: set[str],
    package_identities: dict[str, tuple[str, ...]] | None = None,
    workspace_paths: set[str] | None = None,
    requested_specifiers: dict[str, tuple[str, ...]] | None = None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    if path:
        # Preserve the lockfile installation location. Consumers that need to
        # inspect an installed package must not assume every dependency is
        # hoisted to the repository's top-level node_modules directory.
        metadata["lock_path"] = path
        metadata["lock_occurrence_id"] = f"{READER_NAME}:{path}"
        if workspace_paths and path in workspace_paths:
            metadata["local_workspace"] = True
        installed_names = (package_identities or {}).get(path, ())
        if installed_names:
            metadata["installed_names"] = list(installed_names)
        if len(installed_names) > 1:
            metadata["identity_ambiguous"] = True
        if _has_node_modules_segment(path) and not installed_names:
            metadata["identity_unverified"] = True
        declared_name = _string_or_none(entry.get("name"))
        if (
            declared_name
            and installed_names
            and any(
                declared_name.lower() != installed_name.lower()
                for installed_name in installed_names
            )
        ):
            metadata["self_name"] = declared_name
    dependency_items = _entry_dependency_items(entry)
    if dependency_items:
        metadata["dependencies"] = dependency_items
        metadata["dependency_count"] = len(dependency_items)
    if path and path in root_dependencies:
        metadata["root_dependency"] = True

    for key in (
        "dev",
        "optional",
        "devOptional",
        "inBundle",
        "hasInstallScript",
        "license",
        "link",
    ):
        value = entry.get(key)
        if value is not None:
            metadata[_snake_case(key)] = value

    if path:
        specifiers = (requested_specifiers or {}).get(path, ())
        metadata["requested_specifiers"] = list(specifiers)
        requested_source_kind = (
            "workspace"
            if workspace_paths and path in workspace_paths
            else _requested_source_kind(specifiers)
        )
        metadata["requested_source_kind"] = requested_source_kind
        # Consumers making lifecycle-script decisions need the requested source,
        # not merely the final tarball URL. A direct HTTPS tarball and a normal
        # registry package can have indistinguishable `resolved` fields.
        metadata["source_kind"] = requested_source_kind
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
    package_identities: dict[str, tuple[str, ...]],
    evidence: SourceEvidence,
) -> list[DependencyEdge]:
    edges: list[DependencyEdge] = []
    for parent_path, entry in raw_packages.items():
        if not isinstance(entry, dict):
            continue
        parent_name = _entry_name(parent_path, entry, package_identities)
        parent_version = _string_or_none(entry.get("version"))
        parent_key = (
            package_key("npm", parent_name, parent_version)
            if parent_name and parent_version
            else None
        )
        parent_is_root = parent_path == ""

        for dependency in _iter_dependencies(entry):
            child_path = _resolve_child_path(parent_path, dependency.name, package_paths)
            resolved_child_path = _follow_link_target(child_path, raw_packages)
            child_entry = raw_packages.get(resolved_child_path, {}) if resolved_child_path else {}
            child_version = (
                _string_or_none(child_entry.get("version"))
                if isinstance(child_entry, dict)
                else None
            )
            child_name = (
                _entry_name(
                    resolved_child_path or child_path or "",
                    child_entry,
                    package_identities,
                )
                if isinstance(child_entry, dict)
                else None
            ) or dependency.name
            child_key = package_key("npm", child_name, child_version)
            edges.append(
                DependencyEdge(
                    parent_key=parent_key,
                    child_key=child_key,
                    parent_name=parent_name,
                    parent_version=parent_version,
                    child_name=child_name,
                    child_version=child_version,
                    dependency_kind="direct" if parent_is_root else "transitive",
                    groups=(dependency.group,) if dependency.group != "runtime" else (),
                    evidence=(evidence,),
                )
            )
    return edges


def _root_dependency_paths(
    root: object,
    raw_packages: dict[str, Any],
    package_paths: set[str],
) -> set[str]:
    if not isinstance(root, dict):
        return set()
    paths: set[str] = set()
    for dependency in _iter_dependencies(root):
        child_path = _resolve_child_path("", dependency.name, package_paths)
        if child_path:
            paths.add(child_path)
            resolved_path = _follow_link_target(child_path, raw_packages)
            if resolved_path:
                paths.add(resolved_path)
    return paths


def _requested_specifiers_by_path(
    raw_packages: dict[str, Any], package_paths: set[str]
) -> dict[str, tuple[str, ...]]:
    requested: dict[str, list[str]] = {}
    for parent_path, entry in raw_packages.items():
        if not isinstance(parent_path, str) or not isinstance(entry, dict):
            continue
        for dependency in _iter_dependencies(entry):
            if dependency.specifier is None:
                continue
            child_path = _resolve_child_path(parent_path, dependency.name, package_paths)
            if not child_path:
                continue
            _append_unique(requested, child_path, dependency.specifier)
            resolved_path = _follow_link_target(child_path, raw_packages)
            if resolved_path and resolved_path != child_path:
                _append_unique(requested, resolved_path, dependency.specifier)
    return {path: tuple(values) for path, values in requested.items()}


def _append_unique(values: dict[str, list[str]], path: str, value: str) -> None:
    existing = values.setdefault(path, [])
    if value not in existing:
        existing.append(value)


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
        for name, specifier in sorted(raw.items(), key=lambda item: str(item[0])):
            if isinstance(name, str) and name.strip():
                dependencies.append(
                    _Dependency(
                        name=name.strip(),
                        group=group,
                        specifier=_string_or_none(specifier),
                    )
                )
    return dependencies


class _Dependency:
    def __init__(self, *, name: str, group: str, specifier: str | None) -> None:
        self.name = name
        self.group = group
        self.specifier = specifier


def _resolve_child_path(parent_path: str, name: str, package_paths: set[str]) -> str | None:
    candidates = _node_modules_candidates(parent_path, name)
    for candidate in candidates:
        if candidate in package_paths:
            return candidate
    return None


def _follow_link_target(path: str | None, raw_packages: dict[str, Any]) -> str | None:
    current = path
    seen: set[str] = set()
    while current and current not in seen:
        seen.add(current)
        entry = raw_packages.get(current)
        if not isinstance(entry, dict) or entry.get("link") is not True:
            return current
        target = _normalized_lock_target(_string_or_none(entry.get("resolved")))
        if not target or target not in raw_packages:
            return current
        current = target
    return current


def _normalized_lock_target(resolved: str | None) -> str | None:
    if not resolved or "\\" in resolved or "\x00" in resolved:
        return None
    parsed = urlparse(resolved)
    if parsed.scheme == "file":
        if parsed.netloc not in {"", "localhost"}:
            return None
        value = unquote(parsed.path)
    elif parsed.scheme:
        return None
    else:
        value = unquote(resolved)
    normalized = posixpath.normpath(value)
    if normalized in {"", "."} or normalized.startswith("/"):
        return None
    return normalized


def _package_identities(raw_packages: dict[str, Any]) -> dict[str, tuple[str, ...]]:
    identities: dict[str, set[str]] = {}
    for path in raw_packages:
        if not isinstance(path, str):
            continue
        installed_name = _installed_name_from_path(path)
        if installed_name:
            identities.setdefault(path, set()).add(installed_name)

    for path, entry in raw_packages.items():
        if (
            not isinstance(path, str)
            or not isinstance(entry, dict)
            or entry.get("link") is not True
        ):
            continue
        installed_name = _installed_name_from_path(path)
        target = _normalized_lock_target(_string_or_none(entry.get("resolved")))
        if installed_name and target and target in raw_packages:
            identities.setdefault(target, set()).add(installed_name)
    return {path: tuple(sorted(names)) for path, names in identities.items()}


def _workspace_paths(root: object, package_paths: set[str]) -> set[str]:
    if not isinstance(root, dict):
        return set()
    positive, negative = _workspace_patterns(root.get("workspaces"))
    if not positive:
        return set()
    paths: set[str] = set()
    for path in package_paths:
        if not _safe_workspace_candidate(path) or _has_node_modules_segment(path):
            continue
        if any(_workspace_pattern_matches(path, pattern) for pattern in positive) and not any(
            _workspace_pattern_matches(path, pattern) for pattern in negative
        ):
            paths.add(path)
    return paths


def _safe_workspace_candidate(path: str) -> bool:
    if not path or "\\" in path or path.startswith("/"):
        return False
    return all(part not in {"", ".", ".."} for part in path.split("/"))


def _workspace_patterns(value: object) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if isinstance(value, dict):
        value = value.get("packages")
    if not isinstance(value, list):
        return (), ()
    positive: list[str] = []
    negative: list[str] = []
    for item in value:
        if not isinstance(item, str):
            continue
        raw = item.strip().replace("\\", "/").rstrip("/")
        is_negative = raw.startswith("!")
        if is_negative:
            raw = raw[1:]
        while raw.startswith("./"):
            raw = raw[2:]
        if not raw or raw.startswith("/") or ".." in raw.split("/"):
            continue
        (negative if is_negative else positive).append(raw)
    return tuple(positive), tuple(negative)


def _workspace_pattern_matches(path: str, pattern: str) -> bool:
    path_parts = tuple(part for part in path.split("/") if part)
    pattern_parts = tuple(part for part in pattern.split("/") if part)
    return _match_path_parts(path_parts, pattern_parts)


@lru_cache(maxsize=4096)
def _match_path_parts(path: tuple[str, ...], pattern: tuple[str, ...]) -> bool:
    if not pattern:
        return not path
    head, *tail = pattern
    remaining = tuple(tail)
    if head == "**":
        return _match_path_parts(path, remaining) or (
            bool(path) and _match_path_parts(path[1:], pattern)
        )
    return bool(path) and fnmatchcase(path[0], head) and _match_path_parts(path[1:], remaining)


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


def _entry_name(
    path: str,
    entry: dict[str, Any],
    package_identities: dict[str, tuple[str, ...]] | None = None,
) -> str | None:
    # Package.name is the package's declared/advisory identity. The installed
    # dependency identity used by npm allowScripts is carried separately in
    # metadata.installed_names; changing Package.name for aliases would break
    # inventory, SBOM, and advisory matching semantics.
    name = _string_or_none(entry.get("name"))
    if name:
        return name
    installed_name = _installed_name_from_path(path)
    if installed_name:
        return installed_name
    identities = (package_identities or {}).get(path, ())
    if len(identities) == 1:
        return identities[0]
    return identities[0] if identities else None


def _installed_name_from_path(path: str) -> str | None:
    path_parts = path.split("/")
    indices = [index for index, part in enumerate(path_parts) if part == "node_modules"]
    if not indices:
        return None
    parts = path_parts[indices[-1] + 1 :]
    if not parts or not parts[0]:
        return None
    if parts[0].startswith("@") and len(parts) == 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0] if len(parts) == 1 else None


def _has_node_modules_segment(path: str) -> bool:
    return "node_modules" in path.split("/")


def _artifacts_from_entry(
    resolved: str | None,
    integrity: str | None,
    source_registry: str | None,
    evidence: SourceEvidence,
    lock_directory: Path,
) -> tuple[Artifact, ...]:
    if not resolved:
        return ()
    artifact_url = _resolved_artifact_url(resolved, lock_directory)
    if artifact_url is None:
        return ()
    return (
        Artifact(
            kind="npm-tarball",
            url=artifact_url,
            hash=integrity,
            source=source_registry,
            evidence=(evidence,),
        ),
    )


def _registry_from_resolved(resolved: str | None) -> str | None:
    if not resolved:
        return None
    parsed = urlparse(resolved)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return None
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _requested_source_kind(specifiers: tuple[str, ...]) -> str:
    if not specifiers:
        return "unknown"
    kinds = {_specifier_source_kind(specifier) for specifier in specifiers}
    if len(kinds) == 1:
        return kinds.pop()
    return "mixed"


def _specifier_source_kind(specifier: str) -> str:
    normalized = specifier.strip().lower()
    if not normalized:
        return "unknown"
    if normalized.startswith("workspace:"):
        return "workspace"
    if (
        normalized.startswith("file:")
        or normalized.startswith(("./", "../", "/", "~/", "\\\\"))
        or re.match(r"^[a-z]:[\\/]", normalized)
        or ("://" not in normalized and normalized.endswith((".tgz", ".tar.gz", ".tar")))
    ):
        return "file"
    if normalized.startswith(
        (
            "git+",
            "git://",
            "git@",
            "git:",
            "ssh:",
            "github:",
            "gitlab:",
            "bitbucket:",
        )
    ):
        return "git"
    if normalized.startswith(("http://", "https://")):
        return "remote"
    if normalized.startswith("npm:"):
        return "registry"
    if (
        normalized in {".", ".."}
        or normalized.count("/") > 1
        or (normalized.startswith("@") and normalized.count("/") == 1)
    ):
        return "file"
    # npm-package-arg treats the common owner/repository shorthand as GitHub.
    if normalized.count("/") == 1 and not normalized.startswith("@"):
        return "git"
    return "registry"


def _resolved_artifact_url(resolved: str, lock_directory: Path) -> str | None:
    if "\\" in resolved or "\x00" in resolved or resolved.startswith("//"):
        return None
    parsed = urlparse(resolved)
    if parsed.scheme and parsed.scheme != "file":
        return resolved
    if parsed.netloc not in {"", "localhost"} or parsed.query or parsed.fragment:
        return None
    value = unquote(parsed.path)
    if not value or "\\" in value or "\x00" in value:
        return None
    path = Path(value)
    if not parsed.scheme and not (
        path.is_absolute()
        or value.startswith(("./", "../", "~/"))
        or value.lower().endswith((".tgz", ".tar.gz", ".tar.bz2", ".tar.xz"))
    ):
        return resolved
    if not path.is_absolute():
        path = lock_directory / path
    try:
        return path.resolve(strict=False).as_uri()
    except (OSError, ValueError):
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
