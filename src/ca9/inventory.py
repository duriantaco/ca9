from __future__ import annotations

import json
from pathlib import Path

from ca9.analysis.ast_scanner import discover_declared_dependency_inventory
from ca9.core.models import DependencyEdge, Inventory, Package, SourceEvidence, SourceInput
from ca9.readers.fyn_lock import read_fyn_lock
from ca9.readers.npm_lock import read_npm_lock


def build_inventory(repo_path: Path) -> Inventory:
    inventories: list[Inventory] = []

    fyn_lock_path = repo_path / "fyn.lock"
    if fyn_lock_path.is_file():
        inventories.append(read_fyn_lock(repo_path))

    npm_lock_path = repo_path / "package-lock.json"
    npm_shrinkwrap_path = repo_path / "npm-shrinkwrap.json"
    if npm_lock_path.is_file() or npm_shrinkwrap_path.is_file():
        inventories.append(read_npm_lock(repo_path))

    if not fyn_lock_path.is_file():
        declared = _declared_dependency_inventory(repo_path)
        if declared.packages or not inventories:
            inventories.append(declared)

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


def _declared_dependency_inventory(repo_path: Path) -> Inventory:
    declared = discover_declared_dependency_inventory(repo_path)
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
        Package(name=name, version=version, dependency_kind="direct", evidence=(evidence,))
        for _key, (name, version) in sorted(declared.items())
    )

    warnings: tuple[str, ...] = ()
    if not packages:
        warnings = ("no fyn.lock, npm lockfile, or declared Python dependencies found",)

    return Inventory(
        repo_path=str(repo_path),
        source_inputs=(source_input,),
        packages=packages,
        warnings=warnings,
        metadata={"reader": "declared dependency inventory"},
    )


def _merge_inventories(repo_path: Path, inventories: list[Inventory]) -> Inventory:
    if not inventories:
        return _declared_dependency_inventory(repo_path)
    if len(inventories) == 1:
        return inventories[0]

    packages: dict[str, Package] = {}
    edges: dict[
        tuple[str | None, str, tuple[str, ...], tuple[str, ...], str | None],
        DependencyEdge,
    ] = {}
    source_inputs: list[SourceInput] = []
    warnings: list[str] = []
    readers: list[str] = []

    for inventory in inventories:
        reader = inventory.metadata.get("reader")
        if isinstance(reader, str):
            readers.append(reader)
        for source_input in inventory.source_inputs:
            source_inputs.append(source_input)
        warnings.extend(inventory.warnings)
        for package in inventory.packages:
            packages.setdefault(package.key, package)
        for edge in inventory.dependency_edges:
            edge_key = (
                edge.parent_key,
                edge.child_key,
                edge.groups,
                edge.extras,
                edge.marker,
            )
            edges.setdefault(edge_key, edge)

    return Inventory(
        repo_path=str(repo_path),
        source_inputs=tuple(source_inputs),
        packages=tuple(sorted(packages.values(), key=lambda package: package.key)),
        dependency_edges=tuple(
            sorted(
                edges.values(),
                key=lambda edge: (
                    edge.parent_key or "",
                    edge.child_key,
                    ",".join(edge.groups),
                    ",".join(edge.extras),
                    edge.marker or "",
                ),
            )
        ),
        warnings=tuple(warnings),
        metadata={"reader": "merged inventory", "readers": sorted(set(readers))},
    )
