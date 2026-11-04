from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import parse_qs, urlparse, urlsplit

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from ca9.analysis.ast_scanner import (
    discover_declared_dependency_inventory,
    discover_requirement_hashes,
    requirement_file_lines,
    split_requirement_options,
)
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
from ca9.readers.requirements import (
    RequirementReference,
    is_local_location,
    parse_requirement_reference,
    requirement_option,
    valid_hash_pins,
    vcs_reference,
)

PYPI_SIMPLE_INDEX = "https://pypi.org/simple"
_COMMIT_RE = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})")


@dataclass(frozen=True)
class _DeclaredSource:
    source_kind: str
    url: str | None
    source_registry: str | None
    evidence: SourceEvidence
    reference: RequirementReference | None = None
    registry_mode: str | None = None
    candidate_registries: tuple[str, ...] = ()


@dataclass(frozen=True)
class _IndexExposure:
    """Which indexes may serve a package: none declared, local only, one, or several."""

    mode: str | None
    candidates: tuple[str, ...] = ()
    implicit: bool = False


@dataclass(frozen=True)
class _RequirementIndexes:
    """Index options pip applies to one install, gathered from a file and its includes."""

    index_urls: tuple[str, ...] = ()
    extra_index_urls: tuple[str, ...] = ()
    find_links: tuple[str, ...] = ()
    no_index: bool = False

    @property
    def declared(self) -> bool:
        return bool(self.index_urls or self.extra_index_urls or self.find_links or self.no_index)

    def merged_with(self, other: _RequirementIndexes) -> _RequirementIndexes:
        return _RequirementIndexes(
            index_urls=(*self.index_urls, *other.index_urls),
            extra_index_urls=(*self.extra_index_urls, *other.extra_index_urls),
            find_links=(*self.find_links, *other.find_links),
            no_index=self.no_index or other.no_index,
        )

    def exposure(self) -> _IndexExposure:
        """Remote indexes pip may pick a release from.

        Every --index-url seen counts, since the last one processed wins. Local
        --find-links directories and file:// locations are not remote indexes.
        """
        if not self.declared:
            return _IndexExposure(None, (PYPI_SIMPLE_INDEX,), implicit=True)
        remote: list[str] = []
        if not self.no_index:
            if self.index_urls:
                remote.extend(self.index_urls)
            else:
                remote.append(PYPI_SIMPLE_INDEX)
            remote.extend(self.extra_index_urls)
        remote.extend(self.find_links)
        candidates = _unique_indexes(item for item in remote if not is_local_location(item))
        if not candidates:
            return _IndexExposure("local")
        if not self.index_urls and _only_default_index(candidates):
            return _IndexExposure(None, candidates, implicit=True)
        if len(candidates) == 1:
            return _IndexExposure("exclusive", candidates)
        return _IndexExposure("merged", candidates)


@dataclass(frozen=True)
class _RequirementFile:
    path: Path
    evidence: SourceEvidence
    indexes: _RequirementIndexes
    includes: tuple[Path, ...]
    registry_names: tuple[str, ...]
    references: tuple[RequirementReference, ...]


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
    declared_hashes = discover_requirement_hashes(repo_path)
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
        _declared_package(
            name,
            version,
            declared_sources.get(_key),
            evidence,
            declared_hashes.get(_key, ()),
        )
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
    hashes: tuple[str, ...] = (),
) -> Package:
    metadata = {}
    artifacts: tuple[Artifact, ...] = ()
    reference = None
    if declared_source is not None:
        reference = declared_source.reference
    if reference is not None:
        hashes = valid_hash_pins((*hashes, *reference.fragment_hashes))
    else:
        hashes = valid_hash_pins(hashes)
    if hashes:
        # pip --hash pins identify the allowed distribution files.
        metadata["hashes"] = list(hashes)
    evidence = fallback_evidence
    source_registry = None
    if declared_source is not None:
        evidence = declared_source.evidence
        source_registry = declared_source.source_registry
        metadata["source_kind"] = declared_source.source_kind
        if declared_source.registry_mode:
            metadata["registry_mode"] = declared_source.registry_mode
            metadata["candidate_registries"] = list(declared_source.candidate_registries)
        if reference is not None:
            metadata.update(_reference_metadata(reference, hashes, version))
        if declared_source.url:
            metadata["source_url"] = declared_source.url
            artifacts = (_declared_artifact(declared_source, reference, hashes),)
    return Package(
        name=name,
        version=version,
        dependency_kind="direct",
        source_registry=source_registry,
        artifacts=artifacts,
        evidence=(evidence,),
        metadata=metadata,
    )


def _reference_metadata(
    reference: RequirementReference,
    hashes: tuple[str, ...],
    version: str | None,
) -> dict[str, object]:
    metadata: dict[str, object] = {}
    if reference.source_kind in {"git", "vcs"}:
        metadata["vcs_ref"] = reference.vcs_ref
        metadata["pinned_commit"] = reference.pinned_commit
    else:
        metadata["has_hash"] = bool(hashes)
    if reference.name_inferred:
        metadata["name_inferred"] = True
    if reference.version and reference.version == version:
        metadata["version_source"] = "filename"
    return metadata


def _declared_artifact(
    declared_source: _DeclaredSource,
    reference: RequirementReference | None,
    hashes: tuple[str, ...],
) -> Artifact:
    url = declared_source.url or ""
    kind = "direct-url"
    if declared_source.source_kind in {"git", "vcs"}:
        kind = "git-source"
    if (
        reference is not None
        and reference.source_kind == "path"
        and reference.local_path is not None
        and reference.artifact_kind in {"wheel", "sdist"}
    ):
        return Artifact(
            kind=reference.artifact_kind,
            url=reference.local_path.as_uri(),
            hash=" ".join(hashes) or None,
            evidence=(declared_source.evidence,),
        )
    return Artifact(
        kind=kind,
        url=url,
        hash=" ".join(hashes) or None,
        source=_url_origin(url),
        evidence=(declared_source.evidence,),
    )


def _declared_direct_sources(repo_path: Path) -> dict[str, _DeclaredSource]:
    sources: dict[str, _DeclaredSource] = {}
    pyproject_path = repo_path / "pyproject.toml"
    if pyproject_path.is_file():
        _merge_pyproject_direct_sources(sources, pyproject_path)

    _merge_requirements_direct_sources(sources, sorted(repo_path.glob("requirements*.txt")))

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
    base_dir = pyproject_path.parent
    project = data.get("project", {})
    if isinstance(project, dict):
        for req in project.get("dependencies", []):
            if isinstance(req, str):
                _record_requirement_source(sources, req, evidence, base_dir)
        optional_deps = project.get("optional-dependencies", {})
        if isinstance(optional_deps, dict):
            for reqs in optional_deps.values():
                if isinstance(reqs, list):
                    for req in reqs:
                        if isinstance(req, str):
                            _record_requirement_source(sources, req, evidence, base_dir)

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
                _record_mapping_source(sources, name, spec, evidence, base_dir)


def _merge_requirements_direct_sources(
    sources: dict[str, _DeclaredSource],
    roots: list[Path],
) -> None:
    """Record requirement-file sources and the index exposure of each package.

    pip applies index options from every -r/-c file of one install to the whole
    install, so each top-level file is read with its include closure. A package
    listed by several top-level files takes the widest exposure: merged beats
    exclusive, and a file without index options adds the default PyPI index.
    """
    files: dict[Path, _RequirementFile] = {}
    root_keys: list[Path] = []
    for root in roots:
        key = _load_requirement_file(root, files)
        if key is not None:
            root_keys.append(key)

    for parsed in files.values():
        for reference in parsed.references:
            _record_reference(sources, reference, parsed.evidence)

    exposures: dict[str, list[tuple[str, SourceEvidence, _IndexExposure]]] = {}
    for root_key in root_keys:
        closure = _requirement_closure(root_key, files)
        indexes = _RequirementIndexes()
        for member in closure:
            indexes = indexes.merged_with(files[member].indexes)
        exposure = indexes.exposure()
        for member in closure:
            parsed = files[member]
            for name in parsed.registry_names:
                exposures.setdefault(canonicalize_name(name), []).append(
                    (name, parsed.evidence, exposure)
                )

    for entries in exposures.values():
        combined = _combine_exposures([entry[2] for entry in entries])
        if combined.mode is None:
            continue
        _record_index_source(sources, entries[0][0], combined, entries[0][1])


def _load_requirement_file(path: Path, files: dict[Path, _RequirementFile]) -> Path | None:
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    if resolved in files:
        return resolved
    if not path.is_file():
        return None
    lines = _requirement_lines(path)
    if lines is None:
        return None
    evidence = SourceEvidence(
        source="requirements.txt",
        path=str(path),
        reader="ca9 native manifest readers",
    )
    index_urls: list[str] = []
    extra: list[str] = []
    find_links: list[str] = []
    no_index = False
    include_paths: list[Path] = []
    registry_names: list[str] = []
    references: list[RequirementReference] = []
    for line in lines:
        option = requirement_option(line)
        if option is not None:
            option_name, value = option
            if value and option_name in {"--index-url", "--extra-index-url", "--find-links"}:
                value = _without_credentials(value)
            if option_name in {"--requirement", "--constraint"} and value:
                include_paths.append(path.parent / value)
            elif option_name == "--editable" and value:
                reference = _editable_reference(value, path.parent)
                if reference is not None:
                    references.append(reference)
            elif option_name == "--index-url" and value:
                index_urls.append(value)
            elif option_name == "--extra-index-url" and value:
                extra.append(value)
            elif option_name == "--find-links" and value:
                find_links.append(value)
            elif option_name == "--no-index":
                no_index = True
            continue
        requirement = split_requirement_options(line)[0]
        reference = parse_requirement_reference(requirement, base_dir=path.parent)
        if reference is not None:
            references.append(reference)
            continue
        try:
            parsed = Requirement(requirement)
        except InvalidRequirement:
            continue
        registry_names.append(parsed.name)
    files[resolved] = _RequirementFile(
        path=path,
        evidence=evidence,
        indexes=_RequirementIndexes(
            index_urls=tuple(index_urls),
            extra_index_urls=tuple(extra),
            find_links=tuple(find_links),
            no_index=no_index,
        ),
        includes=(),
        registry_names=tuple(registry_names),
        references=tuple(references),
    )
    includes: list[Path] = []
    for include in include_paths:
        key = _load_requirement_file(include, files)
        if key is not None:
            includes.append(key)
    files[resolved] = replace(files[resolved], includes=tuple(includes))
    return resolved


def _requirement_closure(root: Path, files: dict[Path, _RequirementFile]) -> list[Path]:
    closure: list[Path] = []
    pending = [root]
    seen: set[Path] = set()
    while pending:
        current = pending.pop()
        if current in seen or current not in files:
            continue
        seen.add(current)
        closure.append(current)
        pending.extend(files[current].includes)
    return closure


def _combine_exposures(exposures: list[_IndexExposure]) -> _IndexExposure:
    if all(exposure.mode is None for exposure in exposures):
        return _IndexExposure(None)
    candidates = _unique_indexes(
        candidate for exposure in exposures for candidate in exposure.candidates
    )
    implicit = all(exposure.implicit or exposure.mode == "local" for exposure in exposures)
    if not candidates:
        return _IndexExposure("local")
    if implicit and _only_default_index(candidates):
        return _IndexExposure(None)
    if len(candidates) == 1:
        return _IndexExposure("exclusive", candidates)
    return _IndexExposure("merged", candidates)


def _unique_indexes(values: Iterable[str]) -> tuple[str, ...]:
    unique: dict[str, str] = {}
    for value in values:
        unique.setdefault(_normalized_index(value), value)
    return tuple(unique.values())


def _only_default_index(candidates: tuple[str, ...]) -> bool:
    return len(candidates) == 1 and _normalized_index(candidates[0]) == PYPI_SIMPLE_INDEX


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
                _record_mapping_source(sources, name, spec, evidence, pipfile_path.parent)
                registry = _pipfile_registry_for_spec(spec, source_indexes)
                if registry:
                    _record_registry_source(sources, name, registry, evidence)


def _record_requirement_source(
    sources: dict[str, _DeclaredSource],
    requirement: str,
    evidence: SourceEvidence,
    base_dir: Path | None = None,
) -> None:
    reference = parse_requirement_reference(requirement, base_dir=base_dir)
    if reference is not None:
        _record_reference(sources, reference, evidence)


def _record_mapping_source(
    sources: dict[str, _DeclaredSource],
    name: str,
    spec: object,
    evidence: SourceEvidence,
    base_dir: Path | None = None,
) -> None:
    if not isinstance(spec, dict):
        return
    for key in ("git", "url", "path"):
        value = spec.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        location = value.strip()
        if key == "git":
            reference = _mapping_git_reference(name, location, spec)
        elif key == "path":
            reference = parse_requirement_reference(f"{name} @ {location}", base_dir=base_dir)
            if reference is None or reference.source_kind != "path":
                reference = _mapping_path_reference(name, location, base_dir)
        else:
            reference = parse_requirement_reference(f"{name} @ {location}", base_dir=base_dir)
        if reference is None:
            _record_source(sources, name, location, evidence, source_kind=key)
        else:
            _record_reference(sources, reference, evidence)
        return


def _mapping_git_reference(name: str, location: str, spec: dict) -> RequirementReference:
    """Git sources in poetry/Pipfile tables name the revision in rev/ref/tag/branch."""
    revision = None
    pinned = False
    for field_name in ("rev", "ref", "tag", "branch"):
        value = spec.get(field_name)
        if isinstance(value, str) and value.strip():
            revision = value.strip()
            pinned = field_name in {"rev", "ref"} and bool(_COMMIT_RE.fullmatch(revision))
            break
    if revision is None:
        vcs_url = location
        if "+" not in location.split(":", 1)[0]:
            vcs_url = f"git+{location}"
        revision = vcs_reference(vcs_url)
        pinned = bool(revision and _COMMIT_RE.fullmatch(revision))
    return RequirementReference(
        name=name,
        source_kind="git",
        url=location,
        vcs_ref=revision,
        pinned_commit=pinned,
    )


def _mapping_path_reference(
    name: str,
    location: str,
    base_dir: Path | None,
) -> RequirementReference | None:
    path_value = location
    if not location.startswith(("./", "../", "/", "~/")):
        path_value = f"./{location}"
    parsed = parse_requirement_reference(path_value, base_dir=base_dir)
    if parsed is None:
        return None
    return RequirementReference(
        name=name,
        source_kind="path",
        url=location,
        version=parsed.version,
        local_path=parsed.local_path,
        artifact_kind=parsed.artifact_kind,
    )


def _editable_reference(value: str, base_dir: Path | None) -> RequirementReference | None:
    """An editable install: a VCS URL, a local directory, or PEP 508 ``name @ url``."""
    reference = parse_requirement_reference(value, base_dir=base_dir)
    if reference is not None:
        return reference
    name = _egg_name(value)
    if name:
        return RequirementReference(name=name, source_kind=_source_kind_from_url(value), url=value)
    return None


def _record_reference(
    sources: dict[str, _DeclaredSource],
    reference: RequirementReference,
    evidence: SourceEvidence,
) -> None:
    key = canonicalize_name(reference.name)
    sources[key] = _DeclaredSource(
        source_kind=reference.source_kind,
        url=reference.url,
        source_registry=None,
        evidence=evidence,
        reference=reference,
    )


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
        return
    sources[key] = _DeclaredSource(
        source_kind="registry",
        url=None,
        source_registry=registry,
        evidence=evidence,
        registry_mode="exclusive",
        candidate_registries=(registry,),
    )


def _record_index_source(
    sources: dict[str, _DeclaredSource],
    name: str,
    exposure: _IndexExposure,
    evidence: SourceEvidence,
) -> None:
    key = canonicalize_name(name)
    existing = sources.get(key)
    if existing and existing.url:
        return
    registry = None
    if exposure.mode == "exclusive":
        registry = exposure.candidates[0]
    sources[key] = _DeclaredSource(
        source_kind="registry",
        url=None,
        source_registry=registry,
        evidence=evidence,
        registry_mode=exposure.mode,
        candidate_registries=exposure.candidates,
    )


def _requirement_lines(path: Path) -> list[str] | None:
    try:
        return requirement_file_lines(path.read_text(encoding="utf-8", errors="ignore"))
    except OSError:
        return None


def _without_credentials(value: str) -> str:
    """Drop user:token from an index URL so it is neither reported nor compared."""
    try:
        split = urlsplit(value)
        if not split.netloc or "@" not in split.netloc:
            return value
        host = split.netloc.rsplit("@", 1)[1]
    except ValueError:
        return value
    return split._replace(netloc=host).geturl()


def _normalized_index(value: str) -> str:
    split = urlsplit(value.strip())
    if split.scheme and split.netloc:
        return f"{split.scheme.lower()}://{split.netloc.lower()}{split.path.rstrip('/')}"
    return value.strip().rstrip("/")


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
