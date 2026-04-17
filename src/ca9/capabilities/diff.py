from __future__ import annotations

import json
from typing import Any

from ca9.capabilities.models import AssetChange, Capability, CapabilityChange, CapabilityDiff
from ca9.capabilities.normalize import is_scope_wider
from ca9.capabilities.risk import assess_risk


def compute_diff(base_bom: dict[str, Any], head_bom: dict[str, Any]) -> CapabilityDiff:
    base_hash = _extract_bom_hash(base_bom)
    head_hash = _extract_bom_hash(head_bom)

    base_components = {c["bom-ref"]: c for c in base_bom.get("components", [])}
    head_components = {c["bom-ref"]: c for c in head_bom.get("components", [])}

    assets_added: list[AssetChange] = []
    assets_removed: list[AssetChange] = []
    assets_changed: list[AssetChange] = []

    for bom_ref, component in head_components.items():
        if bom_ref not in base_components:
            kind = _get_component_kind(component)
            if kind and kind != "repo":
                assets_added.append(AssetChange(id=bom_ref, kind=kind))

    for bom_ref, component in base_components.items():
        if bom_ref not in head_components:
            kind = _get_component_kind(component)
            if kind and kind != "repo":
                assets_removed.append(AssetChange(id=bom_ref, kind=kind))

    for bom_ref in base_components:
        if bom_ref in head_components:
            base_comp = base_components[bom_ref]
            head_comp = head_components[bom_ref]
            kind = _get_component_kind(head_comp)
            base_hash_prop = _get_property(base_comp, "ca9.hash.content")
            head_hash_prop = _get_property(head_comp, "ca9.hash.content")
            if base_hash_prop and head_hash_prop and base_hash_prop != head_hash_prop:
                if kind and kind != "repo":
                    assets_changed.append(AssetChange(id=bom_ref, kind=kind, change="content_hash"))

    base_caps = _extract_capabilities(base_bom)
    head_caps = _extract_capabilities(head_bom)

    capabilities_added: list[CapabilityChange] = []
    capabilities_removed: list[CapabilityChange] = []
    capabilities_widened: list[CapabilityChange] = []

    for cap in head_caps:
        if not _find_capability(base_caps, cap):
            capabilities_added.append(
                CapabilityChange(
                    capability=cap.name, scope=cap.scope, asset=cap.asset, evidence=cap.evidence
                )
            )

    for cap in base_caps:
        if not _find_capability(head_caps, cap):
            capabilities_removed.append(
                CapabilityChange(
                    capability=cap.name, scope=cap.scope, asset=cap.asset, evidence=cap.evidence
                )
            )

    for head_cap in head_caps:
        for base_cap in base_caps:
            if (
                head_cap.name == base_cap.name
                and head_cap.asset == base_cap.asset
                and head_cap.scope != base_cap.scope
                and is_scope_wider(base_cap.scope, head_cap.scope)
            ):
                capabilities_widened.append(
                    CapabilityChange(
                        capability=head_cap.name,
                        asset=head_cap.asset,
                        from_scope=base_cap.scope,
                        to_scope=head_cap.scope,
                        scope=head_cap.scope,
                        evidence=head_cap.evidence,
                    )
                )

    risk = assess_risk(assets_added, assets_changed, capabilities_added, capabilities_widened)

    return CapabilityDiff(
        base_ref="base",
        base_bom_hash=base_hash,
        head_ref="head",
        head_bom_hash=head_hash,
        assets_added=assets_added,
        assets_removed=assets_removed,
        assets_changed=assets_changed,
        capabilities_added=capabilities_added,
        capabilities_removed=capabilities_removed,
        capabilities_widened=capabilities_widened,
        risk=risk,
    )


def _extract_bom_hash(bom: dict[str, Any]) -> str:
    for prop in bom.get("metadata", {}).get("properties", []):
        if prop.get("name") == "ca9.bom.hash":
            return prop.get("value", "unknown")
    return "unknown"


def _get_component_kind(component: dict[str, Any]) -> str:
    for prop in component.get("properties", []):
        if prop.get("name") == "ca9.ai.asset.kind":
            return prop.get("value", "unknown")
    return "unknown"


def _get_property(component: dict[str, Any], prop_name: str) -> str:
    for prop in component.get("properties", []):
        if prop.get("name") == prop_name:
            return prop.get("value", "")
    return ""


def _extract_capabilities(bom: dict[str, Any]) -> list[Capability]:
    capabilities: list[Capability] = []
    for service in bom.get("services", []):
        if service.get("name") == "ca9.ai.capabilities":
            for prop in service.get("properties", []):
                if prop.get("name") == "ca9.capability.record":
                    cap = _parse_capability_record(prop.get("value", ""))
                    if cap:
                        capabilities.append(cap)
    return capabilities


def _parse_capability_record(record: str) -> Capability | None:
    try:
        data = json.loads(record)
        if "cap" in data and "scope" in data and "asset" in data:
            return Capability(
                name=data["cap"],
                scope=data["scope"],
                asset=data["asset"],
                evidence=data.get("evidence", []),
            )
    except (json.JSONDecodeError, KeyError):
        pass
    return None


def _find_capability(capabilities: list[Capability], target: Capability) -> bool:
    return any(
        c.name == target.name and c.scope == target.scope and c.asset == target.asset
        for c in capabilities
    )
