from __future__ import annotations

import sys
from pathlib import Path

from ca9.capabilities.detectors.agent_frameworks import detect_agent_frameworks
from ca9.capabilities.detectors.agent_tools import detect_agent_tools
from ca9.capabilities.detectors.cloud_storage import detect_cloud_storage
from ca9.capabilities.detectors.egress import detect_egress
from ca9.capabilities.detectors.mcp import detect_mcp
from ca9.capabilities.detectors.prompts import detect_prompts
from ca9.capabilities.detectors.providers import detect_providers
from ca9.capabilities.models import (
    AIBom,
    Capability,
    CapabilityHit,
    Component,
    Property,
    Service,
    create_aibom,
)
from ca9.capabilities.normalize import deduplicate_capabilities, normalize_scope


def scan_repository(repo_path: str | Path, quiet: bool = False) -> AIBom:
    repo_path_obj = Path(repo_path).resolve()

    def _log(msg: str) -> None:
        if not quiet:
            print(msg, file=sys.stderr)

    _log(f"ca9: Scanning capabilities in {repo_path_obj}")

    aibom = create_aibom(repo_root=str(repo_path_obj))
    all_components: list[Component] = []
    all_capabilities: list[Capability] = []

    detectors = [
        ("MCP servers", detect_mcp),
        ("prompts", detect_prompts),
        ("LLM providers", detect_providers),
        ("network egress", detect_egress),
        ("agent frameworks", detect_agent_frameworks),
        ("cloud storage", detect_cloud_storage),
        ("agent tools", detect_agent_tools),
    ]

    for label, detector_fn in detectors:
        _log(f"  Detecting {label}...")
        components, capabilities = detector_fn(repo_path_obj)
        all_components.extend(components)
        all_capabilities.extend(capabilities)
        _log(f"    Found {len(components)} {label}")

    aibom.components.extend(all_components)

    for cap in all_capabilities:
        cap.scope = normalize_scope(cap.scope)

    deduplicated = deduplicate_capabilities(all_capabilities)
    _log(f"  Total capabilities: {len(deduplicated)}")

    if deduplicated:
        capability_properties = [
            Property(name="ca9.capability.record", value=cap.to_record_string())
            for cap in deduplicated
        ]
        aibom.services.append(Service(name="ca9.ai.capabilities", properties=capability_properties))

    return aibom


def scan_capabilities(repo_path: Path) -> list[CapabilityHit]:
    aibom = scan_repository(repo_path, quiet=True)

    hits: list[CapabilityHit] = []

    capability_records: list[Capability] = []
    for service in aibom.services:
        if service.name == "ca9.ai.capabilities":
            import json

            for prop in service.properties:
                if prop.name == "ca9.capability.record":
                    try:
                        data = json.loads(prop.value)
                        capability_records.append(
                            Capability(
                                name=data["cap"],
                                scope=data["scope"],
                                asset=data["asset"],
                                evidence=data.get("evidence", []),
                            )
                        )
                    except (json.JSONDecodeError, KeyError):
                        pass

    component_files: dict[str, str] = {}
    for comp in aibom.components:
        file_prop = comp.get_property("ca9.location.file")
        if file_prop:
            component_files[comp.bom_ref] = file_prop

    for cap in capability_records:
        source_file = component_files.get(cap.asset, "")
        if not source_file and cap.evidence:
            source_file = (
                cap.evidence[0].split(":")[0] if ":" in cap.evidence[0] else cap.evidence[0]
            )

        hits.append(
            CapabilityHit(
                name=cap.name,
                scope=cap.scope,
                source_file=source_file,
                asset_ref=cap.asset,
            )
        )

    return hits
