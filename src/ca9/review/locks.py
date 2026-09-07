"""Occurrence-preserving inputs for dependency update review.

The inventory reader supplies npm's identity and resolution rules. This layer
adds strict input validation and keeps records the inventory reader cannot
inspect, so malformed metadata cannot masquerade as a removed dependency.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from ca9.core.models import Package, SourceEvidence
from ca9.readers.package_lock import (
    _installed_name_from_path,
    _normalized_lock_target,
    _package_from_entry,
    _package_identities,
    _requested_specifiers_by_path,
    _resolve_child_path,
    _root_dependency_paths,
    _workspace_paths,
)

MAX_LOCK_BYTES = 32 * 1024 * 1024
MAX_CHAINS_PER_OCCURRENCE = 32
MAX_CHAIN_DEPTH = 64
MAX_CHAIN_STEPS = 100_000
_DEPENDENCY_FIELDS = (
    ("runtime", "dependencies"),
    ("dev", "devDependencies"),
    ("optional", "optionalDependencies"),
    ("peer", "peerDependencies"),
)
_ALIAS = re.compile(r"^npm:(@[^/@\s]+/[^/@\s]+|[^/@\s]+)(?:@.+)?$")


@dataclass(frozen=True)
class LockOccurrence:
    path: str
    package: Package
    chains: tuple[tuple[str, ...], ...]
    metadata: dict[str, object]


@dataclass(frozen=True)
class LockState:
    label: str
    occurrences: dict[str, LockOccurrence]
    issues: tuple[str, ...]


@dataclass(frozen=True)
class LockChange:
    path: str
    status: str
    base: LockOccurrence | None
    head: LockOccurrence | None


def load_lock(path: Path, label: str | None = None) -> LockState:
    """Load an npm lockfile without accessing artifacts or installed packages."""
    path = Path(path)
    data = _read_lock(path)
    raw_packages = data["packages"]
    assert isinstance(raw_packages, dict)
    root = raw_packages[""]
    assert isinstance(root, dict)
    issues: list[str] = []
    _validate_entry("", root, issues)
    # Helpers accept only validated table shapes. Preserve the original records
    # below, including malformed records, for comparison and coverage accounting.
    entries = {
        name: _helper_entry(entry) for name, entry in raw_packages.items() if _valid_path(name)
    }
    paths = set(entries) - {""}
    identities = _package_identities(entries)
    workspace_paths = _workspace_paths(root, paths)
    requested = _requested_specifiers_by_path(entries, paths)
    direct_paths = _root_dependency_paths(root, entries, paths)
    evidence = SourceEvidence(source="package-lock.json", path=str(path), reader=__name__)
    occurrences: dict[str, LockOccurrence] = {}
    for lock_path, raw_entry in sorted(raw_packages.items()):
        if not lock_path:
            continue
        entry = raw_entry if isinstance(raw_entry, dict) else {}
        entry_issues: list[str] = []
        _validate_entry(lock_path, raw_entry, entry_issues)
        validation_issues = list(entry_issues)
        package = None
        if _valid_path(lock_path):
            try:
                package = _package_from_entry(
                    lock_path,
                    entry,
                    evidence,
                    direct_paths,
                    identities,
                    workspace_paths,
                    requested,
                    path.parent,
                )
            except ValueError:
                issue = f"{lock_path}: invalid package source metadata"
                entry_issues.append(issue)
                validation_issues.append(issue)
        if package is None:
            package = Package(
                name=_installed_name_from_path(lock_path) or lock_path,
                version=_string(entry.get("version")),
                ecosystem="npm",
                dependency_kind="direct" if lock_path in direct_paths else "transitive",
                evidence=(evidence,),
                metadata={"lock_path": lock_path},
            )
        aliases = {
            match.group(1)
            for specifier in requested.get(lock_path, ())
            if (match := _ALIAS.fullmatch(specifier))
        }
        if len(aliases) > 1:
            issue = f"{lock_path}: conflicting npm alias identities"
            entry_issues.append(issue)
            validation_issues.append(issue)
        elif aliases:
            alias_name = next(iter(aliases))
            if not _string(entry.get("name")):
                package = replace(package, name=alias_name)
            elif package.name != alias_name:
                issue = f"{lock_path}: declared identity disagrees with npm alias"
                entry_issues.append(issue)
                validation_issues.append(issue)
        source_kind = str(package.metadata.get("source_kind", "unknown"))
        if entry.get("link") is True or lock_path in workspace_paths:
            source_kind = "workspace" if lock_path in workspace_paths else "link"
            entry_issues.append(
                f"{lock_path}: workspace or linked package has no registry artifact"
            )
        elif entry.get("inBundle") is True:
            entry_issues.append(f"{lock_path}: bundled package cannot be inspected independently")
        elif source_kind not in {"registry", "unknown"}:
            entry_issues.append(
                f"{lock_path}: {source_kind} package is outside registry artifact scope"
            )
        if not _installed_name_from_path(lock_path) and lock_path not in workspace_paths:
            issue = f"{lock_path}: no npm installation identity"
            entry_issues.append(issue)
            validation_issues.append(issue)
        resolved = _string(entry.get("resolved"))
        if not resolved:
            entry_issues.append(f"{lock_path}: missing resolved artifact URL")
        elif not _https_source(resolved):
            entry_issues.append(
                f"{lock_path}: artifact source is not an HTTPS URL without credentials"
            )
        if not _string(entry.get("integrity")):
            entry_issues.append(f"{lock_path}: missing artifact integrity")
        if not package.version:
            entry_issues.append(f"{lock_path}: missing package version")
        metadata = _metadata(lock_path, package, entry, source_kind, requested.get(lock_path, ()))
        # Invalid records cannot be compared through their normalized defaults:
        # distinct malformed inputs may otherwise collapse to one empty package.
        if validation_issues:
            metadata["identity"] = _digest(
                {"normalized_identity": metadata["identity"], "invalid_record": raw_entry}
            )
        metadata["validation_issues"] = list(dict.fromkeys(validation_issues))
        metadata["inspection_supported"] = not entry_issues
        metadata["issues"] = list(dict.fromkeys(entry_issues))
        occurrences[lock_path] = LockOccurrence(lock_path, package, (), metadata)
        issues.extend(entry_issues)
    chains, chain_issues, cycle_references = _dependency_chains(entries, paths)
    issues.extend(chain_issues)
    for lock_path, occurrence in occurrences.items():
        occurrences[lock_path] = replace(
            occurrence,
            chains=chains.get(lock_path, ()),
            metadata={
                **occurrence.metadata,
                "chain_semantics": "simple root-to-occurrence paths",
                "cycle_references": sorted(cycle_references.get(lock_path, ())),
            },
        )
    return LockState(
        label if label is not None else str(path), occurrences, tuple(dict.fromkeys(issues))
    )


def compare_locks(base: LockState, head: LockState) -> tuple[LockChange, ...]:
    """Match installation locations, including repeated copies and npm aliases."""
    changes: list[LockChange] = []
    for path in sorted(base.occurrences.keys() | head.occurrences.keys()):
        before = base.occurrences.get(path)
        after = head.occurrences.get(path)
        if before is None:
            status = "added"
        elif after is None:
            status = "removed"
        elif before.metadata.get("identity") == after.metadata.get("identity"):
            status = "unchanged"
        else:
            status = "changed"
        changes.append(LockChange(path, status, before, after))
    return tuple(changes)


def _read_lock(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as stream:
            contents = stream.read(MAX_LOCK_BYTES + 1)
        if len(contents) > MAX_LOCK_BYTES:
            raise ValueError(f"lockfile exceeds {MAX_LOCK_BYTES} bytes")
        data = json.loads(contents, object_pairs_hook=_unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        # JSON parser errors include no source contents, which may contain URLs
        # carrying credentials. Never interpolate a raw invalid record here.
        raise ValueError(f"cannot read npm lockfile: {type(exc).__name__}") from exc
    if not isinstance(data, dict):
        raise ValueError("npm lockfile must be a JSON object")
    version = data.get("lockfileVersion")
    if type(version) is not int or version not in {2, 3}:
        raise ValueError("dependency review supports npm lockfileVersion 2 and 3")
    packages = data.get("packages")
    if not isinstance(packages, dict) or not isinstance(packages.get(""), dict):
        raise ValueError("npm lockfile must contain a packages object with a root entry")
    return data


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("npm lockfile contains duplicate JSON keys")
        result[name] = value
    return result


def _helper_entry(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    entry = dict(value)
    resolved = _string(entry.get("resolved"))
    if resolved:
        try:
            urlsplit(resolved)
        except ValueError:
            entry.pop("resolved", None)
    return entry


def _valid_path(path: str) -> bool:
    return not path or (
        not any(ord(char) < 32 or ord(char) == 127 for char in path)
        and "\\" not in path
        and ":" not in path
        and not path.startswith("/")
        and all(part not in {"", ".", ".."} for part in path.split("/"))
    )


def _validate_entry(path: str, entry: object, issues: list[str]) -> None:
    location = path or "root"
    if not _valid_path(path):
        issues.append(f"{location}: invalid installation path")
    if not isinstance(entry, dict):
        issues.append(f"{location}: package entry is not an object")
        return
    for key in ("name", "version", "resolved", "integrity"):
        if key in entry and not _string(entry[key]):
            issues.append(f"{location}: {key} must be a nonempty string")
    if (
        "name" in entry
        and isinstance(entry["name"], str)
        and not _valid_dependency_name(entry["name"])
    ):
        issues.append(f"{location}: invalid declared package name")
    for key in ("dev", "optional", "devOptional", "inBundle", "link", "hasInstallScript"):
        if key in entry and type(entry[key]) is not bool:
            issues.append(f"{location}: {key} must be a boolean")
    for _, field in _DEPENDENCY_FIELDS:
        if field not in entry:
            continue
        dependencies = entry[field]
        if not isinstance(dependencies, dict):
            issues.append(f"{location}: {field} must be an object")
            continue
        if any(
            not _valid_dependency_name(name) or not _string(spec)
            for name, spec in dependencies.items()
        ):
            issues.append(f"{location}: {field} contains invalid dependency names or specifiers")
    for field in ("os", "cpu", "libc"):
        if field in entry and (
            not isinstance(entry[field], list) or any(not _string(value) for value in entry[field])
        ):
            issues.append(f"{location}: {field} must be an array of nonempty strings")
    if "peerDependenciesMeta" in entry:
        raw = entry["peerDependenciesMeta"]
        if not isinstance(raw, dict):
            issues.append(f"{location}: peerDependenciesMeta must be an object")
        elif any(
            not _valid_dependency_name(name)
            or not isinstance(value, dict)
            or any(key != "optional" for key in value)
            or ("optional" in value and type(value["optional"]) is not bool)
            for name, value in raw.items()
        ):
            issues.append(
                f"{location}: peerDependenciesMeta contains invalid or unsupported metadata"
            )


def _valid_dependency_name(name: str) -> bool:
    parts = name.split("/")
    valid_parts = len(parts) == 1 or (len(parts) == 2 and parts[0].startswith("@"))
    return (
        valid_parts
        and all(part not in {"", ".", "..", "@"} for part in parts)
        and not any(char.isspace() or ord(char) < 32 for char in name)
        and "\\" not in name
        and ":" not in name
    )


def _metadata(
    path: str,
    package: Package,
    entry: dict[str, object],
    source_kind: str,
    requested: tuple[str, ...],
) -> dict[str, object]:
    dependencies: list[dict[str, str]] = []
    raw_dependencies: list[dict[str, str]] = []
    for group, field in _DEPENDENCY_FIELDS:
        raw = entry.get(field)
        if isinstance(raw, dict):
            for name, specifier in sorted(raw.items()):
                if _valid_dependency_name(name) and (value := _string(specifier)):
                    raw_dependencies.append({"group": group, "name": name, "specifier": value})
                    dependencies.append(
                        {"group": group, "name": name, "specifier": _display_source(value)}
                    )
    resolved = _string(entry.get("resolved"))
    registry_identity = package.source_registry
    if resolved and registry_identity is not None:
        parts = urlsplit(resolved)
        credentials, separator, host = parts.netloc.rpartition("@")
        # Normalize host spelling without lowercasing case-sensitive credentials.
        registry_identity = (
            f"{parts.scheme.lower()}://" + (credentials + "@" if separator else "") + host.lower()
        )
    metadata: dict[str, object] = {
        "installed_name": _installed_name_from_path(path),
        "package_name": package.name,
        "version": package.version,
        "dependency_kind": package.dependency_kind,
        "source_kind": source_kind,
        "source": _display_source(resolved) if resolved else None,
        "source_registry": _display_source(package.source_registry)
        if package.source_registry
        else None,
        "integrity": _integrity(entry.get("integrity")),
        "dependencies": dependencies,
        "peer_metadata": _peer_metadata(entry),
        "platforms": {
            key: sorted(set(value))
            if isinstance(value, list) and all(isinstance(item, str) for item in value)
            else None
            for key in ("os", "cpu", "libc")
            for value in (entry.get(key, []),)
        },
        "requested_specifiers": sorted(_display_source(spec) for spec in requested),
        "has_install_script": entry.get("hasInstallScript", False),
        "dev": entry.get("dev", False),
        "optional": entry.get("optional", False),
        "dev_optional": entry.get("devOptional", False),
        "in_bundle": entry.get("inBundle", False),
        "link": entry.get("link", False),
    }
    # URLs and specifiers can contain credentials. Compare their exact identity
    # using digests, while exposing only redacted display metadata.
    metadata["comparison_identities"] = {
        key: _digest(value)
        for key, value in {
            "source": resolved,
            "source_registry": registry_identity,
            "dependencies": raw_dependencies,
            "requested_specifiers": sorted(requested),
        }.items()
    }
    # Per-declaration digests distinguish removals from changes hidden by display
    # redaction without keeping another copy of credential-bearing specifiers.
    metadata["dependency_comparison_identities"] = [
        {**item, "specifier": _digest(item["specifier"])} for item in raw_dependencies
    ]
    metadata["artifact_identity"] = _digest(
        {"resolved": resolved, "integrity": _integrity(entry.get("integrity"))}
    )
    metadata["identity"] = _digest(
        {
            "facts": dict(metadata),
            "resolved": resolved,
            "dependencies": {field: entry.get(field, {}) for _, field in _DEPENDENCY_FIELDS},
            "peer_metadata": entry.get("peerDependenciesMeta", {}),
            "platforms": metadata["platforms"],
            "requested": sorted(requested),
        }
    )
    return metadata


def _peer_metadata(entry: dict[str, object]) -> dict[str, object]:
    raw = entry.get("peerDependenciesMeta", {})
    if not isinstance(raw, dict):
        return {}
    return {
        name: {"optional": value["optional"]} if type(value.get("optional")) is bool else {}
        for name, value in sorted(raw.items())
        if _valid_dependency_name(name) and isinstance(value, dict)
    }


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _string(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _integrity(value: object) -> str | None:
    raw = _string(value)
    return " ".join(sorted(set(raw.split()))) if raw else None


def _https_source(value: str) -> bool:
    try:
        parts = urlsplit(value)
        return bool(
            parts.scheme == "https" and parts.hostname and not parts.username and not parts.password
        )
    except ValueError:
        return False


def _display_source(value: str) -> str:
    if "://" not in value:
        return value
    try:
        parts = urlsplit(value)
        hostname = parts.hostname
        if not hostname:
            return "[invalid source URL]"
        host = f"[{hostname}]" if ":" in hostname else hostname
        if parts.port:
            host = f"{host}:{parts.port}"
        return urlunsplit((parts.scheme, host, parts.path, "[redacted]" if parts.query else "", ""))
    except ValueError:
        return "[invalid source URL]"


def _dependency_chains(
    entries: dict[str, dict[str, object]], paths: set[str]
) -> tuple[dict[str, tuple[tuple[str, ...], ...]], list[str], dict[str, set[str]]]:
    """Enumerate simple root paths; keep cycle edges as references.

    Repeating a node cannot add a new simple path, so a cycle is not missing
    scope. Resource limits that omit otherwise distinct paths are explicit
    issues instead.
    """
    edges: dict[str, set[str]] = {}
    issues: list[str] = []
    for parent, entry in entries.items():
        children = edges.setdefault(parent, set())
        if entry.get("link") is True:
            target = _normalized_lock_target(_string(entry.get("resolved")))
            if target in paths:
                children.add(target)
            else:
                issues.append(f"{parent}: unresolved local link target")
        optional = entry.get("optionalDependencies", {})
        peer_meta = entry.get("peerDependenciesMeta", {})
        for group, field in _DEPENDENCY_FIELDS:
            # Published packages' development dependencies are not installed.
            if group == "dev" and parent and "node_modules" in parent.split("/"):
                continue
            raw = entry.get(field, {})
            if not isinstance(raw, dict):
                continue
            for name in sorted(raw):
                if not _valid_dependency_name(name):
                    continue
                child = _resolve_child_path(parent, name, paths)
                if child:
                    children.add(child)
                    continue
                peer = peer_meta.get(name, {}) if isinstance(peer_meta, dict) else {}
                optional_peer = isinstance(peer, dict) and peer.get("optional") is True
                if group == "optional" or (isinstance(optional, dict) and name in optional):
                    continue
                if group == "peer" and optional_peer:
                    continue
                issues.append(f"{parent or 'root'}: unresolved {group} dependency {name}")
    collected: dict[str, list[tuple[str, ...]]] = {}
    cycle_references: dict[str, set[str]] = {}
    queue = deque([("", ("",))])
    steps = 0
    while queue:
        parent, chain = queue.popleft()
        for child in sorted(edges.get(parent, ())):
            steps += 1
            if steps > MAX_CHAIN_STEPS:
                issues.append("dependency chain enumeration reached its step limit")
                return (
                    {path: tuple(value) for path, value in collected.items()},
                    issues,
                    cycle_references,
                )
            if child in chain:
                cycle_references.setdefault(parent, set()).add(child)
                continue
            if len(chain) >= MAX_CHAIN_DEPTH:
                issues.append(f"{child}: dependency chain depth limit reached")
                continue
            child_chains = collected.setdefault(child, [])
            if len(child_chains) >= MAX_CHAINS_PER_OCCURRENCE:
                issues.append(f"{child}: dependency chain count limit reached")
                continue
            child_chain = (*chain, child)
            child_chains.append(child_chain)
            queue.append((child, child_chain))
    return (
        {path: tuple(value) for path, value in collected.items()},
        list(dict.fromkeys(issues)),
        cycle_references,
    )
