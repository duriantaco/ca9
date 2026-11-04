from __future__ import annotations

import json
import re
from dataclasses import dataclass
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
    parse_requirement_reference,
    valid_hash_pins,
    vcs_reference,
)

PYPI_SIMPLE_INDEX = "https://pypi.org/simple"
_COMMIT_RE = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})")
_REQUIREMENT_LONG_OPTIONS = (
    "--index-url",
    "--extra-index-url",
    "--no-index",
    "--find-links",
    "--constraint",
    "--requirement",
    "--editable",
    "--trusted-host",
    "--pre",
    "--prefer-binary",
    "--require-hashes",
    "--only-binary",
    "--no-binary",
    "--use-feature",
    "--global-option",
    "--config-settings",
    "--hash",
)
_REQUIREMENT_SHORT_OPTIONS = {
    "-i": "--index-url",
    "-f": "--find-links",
    "-c": "--constraint",
    "-r": "--requirement",
    "-e": "--editable",
}
_VALUE_OPTIONS = frozenset(
    {
        "--index-url",
        "--extra-index-url",
        "--find-links",
        "--constraint",
        "--requirement",
        "--editable",
        "--trusted-host",
        "--only-binary",
        "--no-binary",
        "--use-feature",
        "--global-option",
        "--config-settings",
        "--hash",
    }
)


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
class _RequirementIndexes:
    """The package indexes one requirements file tells pip to search."""

    index_url: str | None = None
    extra_index_urls: tuple[str, ...] = ()
    find_links: tuple[str, ...] = ()
    no_index: bool = False

    @property
    def declared(self) -> bool:
        return bool(self.index_url or self.extra_index_urls or self.find_links or self.no_index)

    @property
    def candidates(self) -> tuple[str, ...]:
        indexes: list[str] = []
        if not self.no_index:
            indexes.append(self.index_url or PYPI_SIMPLE_INDEX)
            indexes.extend(self.extra_index_urls)
        indexes.extend(self.find_links)
        unique: dict[str, str] = {}
        for index in indexes:
            unique.setdefault(_normalized_index(index), index)
        return tuple(unique.values())

    @property
    def mode(self) -> str | None:
        """exclusive: one index serves every package; merged: pip picks the best match."""
        if not self.declared:
            return None
        candidates = self.candidates
        if not candidates:
            return None
        if len(candidates) == 1:
            return "exclusive"
        return "merged"


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
    lines = _requirement_lines(path)
    if lines is None:
        return

    indexes = _requirement_file_indexes(lines)
    for line in lines:
        option = _requirement_option(line)
        if option is not None:
            option_name, value = option
            if option_name == "--requirement" and value:
                _merge_requirements_direct_sources(sources, path.parent / value, seen)
            elif option_name == "--editable" and value:
                _record_editable_source(sources, value, evidence, path.parent)
            continue
        requirement = split_requirement_options(line)[0]
        reference = parse_requirement_reference(requirement, base_dir=path.parent)
        if reference is not None:
            _record_reference(sources, reference, evidence)
            continue
        if indexes.mode is None:
            continue
        try:
            parsed = Requirement(requirement)
        except InvalidRequirement:
            continue
        _record_index_source(sources, parsed.name, indexes, evidence)


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


def _record_editable_source(
    sources: dict[str, _DeclaredSource],
    value: str,
    evidence: SourceEvidence,
    base_dir: Path | None = None,
) -> None:
    name = _egg_name(value)
    if not name:
        return
    reference = parse_requirement_reference(value, base_dir=base_dir)
    if reference is not None and canonicalize_name(reference.name) == canonicalize_name(name):
        _record_reference(sources, reference, evidence)
        return
    _record_source(sources, name, value, evidence)


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
    indexes: _RequirementIndexes,
    evidence: SourceEvidence,
) -> None:
    key = canonicalize_name(name)
    existing = sources.get(key)
    if existing and existing.url:
        return
    candidates = indexes.candidates
    registry = None
    if indexes.mode == "exclusive":
        registry = candidates[0]
    sources[key] = _DeclaredSource(
        source_kind="registry",
        url=None,
        source_registry=registry,
        evidence=evidence,
        registry_mode=indexes.mode,
        candidate_registries=candidates,
    )


def _requirement_lines(path: Path) -> list[str] | None:
    try:
        return requirement_file_lines(path.read_text(encoding="utf-8", errors="ignore"))
    except OSError:
        return None


def _requirement_option(line: str) -> tuple[str, str | None] | None:
    """Return (canonical option, value) for a pip requirements-file option line.

    Long options may be abbreviated to any unique prefix, as optparse allows, and
    take their value after "=" or whitespace.
    """
    if not line.startswith("-"):
        return None
    if line.startswith("--"):
        token = re.match(r"--[A-Za-z0-9-]*", line).group(0)
        rest = line[len(token) :]
        if token in _REQUIREMENT_LONG_OPTIONS:
            option = token
        else:
            matches = [name for name in _REQUIREMENT_LONG_OPTIONS if name.startswith(token)]
            if len(matches) != 1:
                return (token, None)
            option = matches[0]
    else:
        option = _REQUIREMENT_SHORT_OPTIONS.get(line[:2])
        if option is None:
            return (line[:2], None)
        rest = line[2:]
    if option not in _VALUE_OPTIONS:
        return (option, None)
    if rest.startswith("="):
        rest = rest[1:]
    value = rest.strip()
    if option != "--editable":
        parts = value.split()
        if parts:
            value = parts[0]
        else:
            value = ""
    return (option, value or None)


def _requirement_file_indexes(lines: list[str]) -> _RequirementIndexes:
    index_url: str | None = None
    extra: list[str] = []
    find_links: list[str] = []
    no_index = False
    for line in lines:
        option = _requirement_option(line)
        if option is None:
            continue
        option_name, value = option
        if value:
            value = _without_credentials(value)
        if option_name == "--index-url" and value:
            index_url = value
        elif option_name == "--extra-index-url" and value:
            extra.append(value)
        elif option_name == "--find-links" and value:
            find_links.append(value)
        elif option_name == "--no-index":
            no_index = True
    return _RequirementIndexes(
        index_url=index_url,
        extra_index_urls=tuple(extra),
        find_links=tuple(find_links),
        no_index=no_index,
    )


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
