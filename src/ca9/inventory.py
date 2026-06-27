from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from ca9.analysis.ast_scanner import discover_declared_dependency_inventory
from ca9.config import _load_toml
from ca9.core.models import (
    Artifact,
    DependencyEdge,
    Inventory,
    Package,
    SourceEvidence,
    SourceInput,
)
from ca9.readers.fyn_lock import read_fyn_lock
from ca9.readers.package_lock import read_package_lock


@dataclass(frozen=True)
class _DeclaredSource:
    source_kind: str
    url: str | None
    source_registry: str | None
    evidence: SourceEvidence


def build_inventory(repo_path: Path) -> Inventory:
    inventories: list[Inventory] = []
    fyn_lock_path = repo_path / "fyn.lock"
    if fyn_lock_path.is_file():
        inventories.append(read_fyn_lock(repo_path))
    package_lock_path = repo_path / "package-lock.json"
    if package_lock_path.is_file():
        inventories.append(read_package_lock(repo_path))
    declared = _declared_dependency_inventory(repo_path)
    if declared.packages:
        inventories.append(declared)
    if not inventories:
        return declared
    if len(inventories) == 1:
        return inventories[0]
    return _merge_inventories(repo_path, inventories)


def inventory_to_json(inventory: Inventory) -> str:
    return json.dumps(inventory.to_dict(), indent=2)


def inventory_to_table(inventory: Inventory) -> str:
    summary = inventory.summary()
    dependency_kinds = summary["dependency_kinds"]
    lines = [
        f"ca9 package inventory for {inventory.repo_path}",
        f"Packages: {summary['packages']}",
        f"Dependency edges: {summary['dependency_edges']}",
    ]

    if dependency_kinds:
        kind_text = " | ".join(f"{kind}: {count}" for kind, count in dependency_kinds.items())
        lines.append(f"Dependency kinds: {kind_text}")

    if inventory.source_inputs:
        sources = ", ".join(source_input.source for source_input in inventory.source_inputs)
        lines.append(f"Sources: {sources}")

    if inventory.warnings:
        lines.append("")
        lines.append("Warnings:")
        lines.extend(f"  - {warning}" for warning in inventory.warnings)

    if inventory.packages:
        lines.append("")
        lines.append("Packages:")
        for package in inventory.packages:
            version = package.version or "unknown"
            lines.append(f"  - {package.name} {version} ({package.dependency_kind})")

    return "\n".join(lines)


def _merge_inventories(repo_path: Path, inventories: list[Inventory]) -> Inventory:
    package_by_key: dict[str, Package] = {}
    source_inputs: list[SourceInput] = []
    warnings: list[str] = []
    edges: list[DependencyEdge] = []
    edge_keys: set[tuple[object, ...]] = set()

    for inventory in inventories:
        source_inputs.extend(inventory.source_inputs)
        warnings.extend(inventory.warnings)
        for package in inventory.packages:
            package_by_key.setdefault(package.key, package)
        for edge in inventory.dependency_edges:
            edge_key = (
                edge.parent_key,
                edge.child_key,
                edge.dependency_kind,
                edge.groups,
                edge.extras,
                edge.marker,
            )
            if edge_key in edge_keys:
                continue
            edge_keys.add(edge_key)
            edges.append(edge)

    return Inventory(
        repo_path=str(repo_path),
        source_inputs=tuple(_dedupe_source_inputs(source_inputs)),
        packages=tuple(sorted(package_by_key.values(), key=lambda package: package.key)),
        dependency_edges=tuple(edges),
        warnings=tuple(dict.fromkeys(warnings)),
        metadata={
            "reader": "merged inventory",
            "sources": [source_input.source for source_input in source_inputs],
        },
    )


def _dedupe_source_inputs(source_inputs: list[SourceInput]) -> list[SourceInput]:
    deduped: dict[tuple[str, str, str], SourceInput] = {}
    for source_input in source_inputs:
        deduped.setdefault(
            (source_input.kind, source_input.path, source_input.source),
            source_input,
        )
    return list(deduped.values())


def _declared_dependency_inventory(repo_path: Path) -> Inventory:
    declared = discover_declared_dependency_inventory(repo_path)
    declared_sources = _declared_direct_sources(repo_path)
    source_input = SourceInput(
        kind="manifest",
        path=str(repo_path),
        source="ca9 native manifest readers",
        metadata={"reader": "declared dependency inventory"},
    )
    evidence = SourceEvidence(
        source="declared dependency inventory",
        path=str(repo_path),
        reader="ca9 native manifest readers",
    )
    packages = tuple(
        _declared_package(name, version, declared_sources.get(_key), evidence)
        for _key, (name, version) in sorted(declared.items())
    )

    warnings: tuple[str, ...] = ()
    if not packages:
        warnings = ("no fyn.lock, package-lock.json, or declared Python dependencies found",)

    return Inventory(
        repo_path=str(repo_path),
        source_inputs=(source_input,),
        packages=packages,
        warnings=warnings,
        metadata={"reader": "declared dependency inventory"},
    )


def _declared_package(
    name: str,
    version: str | None,
    declared_source: _DeclaredSource | None,
    fallback_evidence: SourceEvidence,
) -> Package:
    metadata = {}
    artifacts: tuple[Artifact, ...] = ()
    evidence = fallback_evidence
    source_registry = None
    if declared_source is not None:
        evidence = declared_source.evidence
        source_registry = declared_source.source_registry
        metadata["source_kind"] = declared_source.source_kind
        if declared_source.url:
            metadata["source_url"] = declared_source.url
            artifacts = (
                Artifact(
                    kind="direct-url" if declared_source.source_kind != "git" else "git-source",
                    url=declared_source.url,
                    source=_url_origin(declared_source.url),
                    evidence=(declared_source.evidence,),
                ),
            )
    return Package(
        name=name,
        version=version,
        dependency_kind="direct",
        source_registry=source_registry,
        artifacts=artifacts,
        evidence=(evidence,),
        metadata=metadata,
    )


def _declared_direct_sources(repo_path: Path) -> dict[str, _DeclaredSource]:
    sources: dict[str, _DeclaredSource] = {}
    pyproject_path = repo_path / "pyproject.toml"
    if pyproject_path.is_file():
        _merge_pyproject_direct_sources(sources, pyproject_path)

    seen: set[Path] = set()
    for req_file in sorted(repo_path.glob("requirements*.txt")):
        _merge_requirements_direct_sources(sources, req_file, seen)

    pipfile_path = repo_path / "Pipfile"
    if pipfile_path.is_file():
        _merge_pipfile_direct_sources(sources, pipfile_path)

    return sources


def _merge_pyproject_direct_sources(
    sources: dict[str, _DeclaredSource],
    pyproject_path: Path,
) -> None:
    data = _load_toml(pyproject_path)
    evidence = SourceEvidence(
        source="pyproject.toml",
        path=str(pyproject_path),
        reader="ca9 native manifest readers",
    )
    project = data.get("project", {})
    if isinstance(project, dict):
        for req in project.get("dependencies", []):
            if isinstance(req, str):
                _record_requirement_source(sources, req, evidence)
        optional_deps = project.get("optional-dependencies", {})
        if isinstance(optional_deps, dict):
            for reqs in optional_deps.values():
                if isinstance(reqs, list):
                    for req in reqs:
                        if isinstance(req, str):
                            _record_requirement_source(sources, req, evidence)

    tool = data.get("tool", {})
    if not isinstance(tool, dict):
        return
    poetry = tool.get("poetry", {})
    if not isinstance(poetry, dict):
        return
    poetry_deps = poetry.get("dependencies", {})
    if isinstance(poetry_deps, dict):
        for name, spec in poetry_deps.items():
            if isinstance(name, str) and name.lower() != "python":
                _record_mapping_source(sources, name, spec, evidence)


def _merge_requirements_direct_sources(
    sources: dict[str, _DeclaredSource],
    path: Path,
    seen: set[Path],
) -> None:
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    if resolved in seen or not path.is_file():
        return
    seen.add(resolved)

    evidence = SourceEvidence(
        source="requirements.txt",
        path=str(path),
        reader="ca9 native manifest readers",
    )
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return

    for raw_line in lines:
        line = _strip_requirement_comment(raw_line)
        if not line:
            continue
        index_url = _requirement_index_url(line)
        if index_url:
            _record_requirement_file_registry(sources, path, index_url, evidence)
            continue
        include_target = _requirement_include_target(path, line)
        if include_target is not None:
            _merge_requirements_direct_sources(sources, include_target, seen)
            continue
        if line.startswith(("-c ", "--constraint ")):
            continue
        if line.startswith("-e "):
            _record_editable_source(sources, line[3:].strip(), evidence)
        else:
            _record_requirement_source(sources, line, evidence)


def _merge_pipfile_direct_sources(
    sources: dict[str, _DeclaredSource],
    pipfile_path: Path,
) -> None:
    data = _load_toml(pipfile_path)
    evidence = SourceEvidence(
        source="Pipfile",
        path=str(pipfile_path),
        reader="ca9 native manifest readers",
    )
    source_indexes = _pipfile_source_indexes(data)
    for section_name in ("packages", "dev-packages"):
        section = data.get(section_name, {})
        if not isinstance(section, dict):
            continue
        for name, spec in section.items():
            if isinstance(name, str):
                _record_mapping_source(sources, name, spec, evidence)
                registry = _pipfile_registry_for_spec(spec, source_indexes)
                if registry:
                    _record_registry_source(sources, name, registry, evidence)


def _record_requirement_source(
    sources: dict[str, _DeclaredSource],
    requirement: str,
    evidence: SourceEvidence,
) -> None:
    try:
        parsed = Requirement(requirement)
    except InvalidRequirement:
        _record_editable_source(sources, requirement, evidence)
        return
    if not parsed.url:
        return
    _record_source(sources, parsed.name, parsed.url, evidence)


def _record_mapping_source(
    sources: dict[str, _DeclaredSource],
    name: str,
    spec: object,
    evidence: SourceEvidence,
) -> None:
    if not isinstance(spec, dict):
        return
    for key in ("git", "url", "path"):
        value = spec.get(key)
        if isinstance(value, str) and value.strip():
            _record_source(sources, name, value.strip(), evidence, source_kind=key)
            return


def _record_editable_source(
    sources: dict[str, _DeclaredSource],
    value: str,
    evidence: SourceEvidence,
) -> None:
    name = _egg_name(value)
    if name:
        _record_source(sources, name, value, evidence)


def _record_source(
    sources: dict[str, _DeclaredSource],
    name: str,
    url: str,
    evidence: SourceEvidence,
    source_kind: str | None = None,
) -> None:
    key = canonicalize_name(name)
    sources[key] = _DeclaredSource(
        source_kind=source_kind or _source_kind_from_url(url),
        url=url,
        source_registry=None,
        evidence=evidence,
    )


def _record_registry_source(
    sources: dict[str, _DeclaredSource],
    name: str,
    registry: str,
    evidence: SourceEvidence,
) -> None:
    key = canonicalize_name(name)
    existing = sources.get(key)
    if existing and existing.url:
        sources[key] = _DeclaredSource(
            source_kind=existing.source_kind,
            url=existing.url,
            source_registry=registry,
            evidence=existing.evidence,
        )
        return
    sources[key] = _DeclaredSource(
        source_kind="registry",
        url=None,
        source_registry=registry,
        evidence=evidence,
    )


def _strip_requirement_comment(line: str) -> str:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return ""
    if " #" in stripped:
        stripped = stripped.split(" #", 1)[0].strip()
    return stripped


def _requirement_include_target(path: Path, line: str) -> Path | None:
    if line.startswith("-r "):
        return path.parent / line[3:].strip()
    if line.startswith("--requirement "):
        return path.parent / line[len("--requirement ") :].strip()
    return None


def _requirement_index_url(line: str) -> str | None:
    prefixes = (
        "--index-url=",
        "--extra-index-url=",
        "--find-links=",
        "-i=",
        "-f=",
    )
    for prefix in prefixes:
        if line.startswith(prefix):
            return line[len(prefix) :].strip() or None
    option_prefixes = (
        "--index-url ",
        "--extra-index-url ",
        "--find-links ",
        "-i ",
        "-f ",
    )
    for prefix in option_prefixes:
        if line.startswith(prefix):
            return line[len(prefix) :].strip() or None
    return None


def _record_requirement_file_registry(
    sources: dict[str, _DeclaredSource],
    path: Path,
    registry: str,
    evidence: SourceEvidence,
) -> None:
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return
    for raw_line in lines:
        line = _strip_requirement_comment(raw_line)
        if not line or _requirement_index_url(line):
            continue
        if line.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
            continue
        if line.startswith("-e "):
            name = _egg_name(line[3:].strip())
        else:
            try:
                parsed = Requirement(line)
            except InvalidRequirement:
                name = None
            else:
                name = parsed.name
        if name:
            _record_registry_source(sources, name, registry, evidence)


def _egg_name(value: str) -> str | None:
    if "#egg=" not in value:
        return None
    fragment = value.split("#", 1)[1]
    parsed = parse_qs(fragment)
    egg_values = parsed.get("egg")
    if egg_values and egg_values[0].strip():
        return egg_values[0].strip()
    return value.split("#egg=", 1)[1].split("&", 1)[0].strip() or None


def _pipfile_source_indexes(data: dict) -> dict[str, str]:
    sources = data.get("source", [])
    if isinstance(sources, dict):
        sources = [sources]
    if not isinstance(sources, list):
        return {}
    indexes: dict[str, str] = {}
    default_url: str | None = None
    for item in sources:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        url = item.get("url")
        if isinstance(url, str) and url.strip():
            if default_url is None:
                default_url = url.strip()
            if isinstance(name, str) and name.strip():
                indexes[name.strip()] = url.strip()
    if default_url:
        indexes.setdefault("", default_url)
    return indexes


def _pipfile_registry_for_spec(spec: object, source_indexes: dict[str, str]) -> str | None:
    if isinstance(spec, dict):
        index = spec.get("index")
        if isinstance(index, str) and index in source_indexes:
            return source_indexes[index]
        for key in ("git", "url", "path"):
            if key in spec:
                return None
    return source_indexes.get("")


def _source_kind_from_url(url: str) -> str:
    value = url.strip().lower()
    parsed = urlparse(value)
    if value.startswith(("git+", "github:")) or parsed.scheme in {"git", "git+https", "git+ssh"}:
        return "git"
    if parsed.scheme in {"http", "https"}:
        return "direct_url"
    if parsed.scheme == "file":
        return "path"
    return "url"


def _url_origin(url: str) -> str | None:
    parsed = urlparse(url.strip())
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
    return None
