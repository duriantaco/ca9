from __future__ import annotations

import json
from pathlib import Path

from ca9.analysis.ast_scanner import discover_declared_dependency_inventory
from ca9.core.models import Inventory, Package, SourceEvidence, SourceInput
from ca9.readers.fyn_lock import read_fyn_lock


def build_inventory(repo_path: Path) -> Inventory:
    fyn_lock_path = repo_path / "fyn.lock"
    if fyn_lock_path.is_file():
        return read_fyn_lock(repo_path)
    return _declared_dependency_inventory(repo_path)


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
        warnings = ("no fyn.lock or declared Python dependencies found",)

    return Inventory(
        repo_path=str(repo_path),
        source_inputs=(source_input,),
        packages=packages,
        warnings=warnings,
        metadata={"reader": "declared dependency inventory"},
    )
