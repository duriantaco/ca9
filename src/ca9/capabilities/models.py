from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Property:
    name: str
    value: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "value": self.value}


def sort_properties_key(prop_dict: dict[str, str]) -> tuple:
    return (prop_dict["name"], prop_dict["value"])


def sort_component_key(component: Component) -> tuple:
    return (component.bom_ref, component.name)


def sort_service_key(service: Service) -> str:
    return service.name


@dataclass
class Component:
    type: str  # application, service, library, data
    name: str
    version: str
    bom_ref: str
    properties: list[Property] = field(default_factory=list)

    def to_dict(self) -> dict:
        result: dict = {
            "type": self.type,
            "name": self.name,
            "version": self.version,
            "bom-ref": self.bom_ref,
        }
        if self.properties:
            result["properties"] = sorted(
                [p.to_dict() for p in self.properties], key=sort_properties_key
            )
        return result

    def get_property(self, name: str) -> str | None:
        for prop in self.properties:
            if prop.name == name:
                return prop.value
        return None

    def get_kind(self) -> str | None:
        return self.get_property("ca9.ai.asset.kind")


@dataclass
class Service:
    name: str
    properties: list[Property] = field(default_factory=list)

    def to_dict(self) -> dict:
        result: dict = {"name": self.name}
        if self.properties:
            result["properties"] = sorted(
                [p.to_dict() for p in self.properties], key=sort_properties_key
            )
        return result


@dataclass
class Tool:
    vendor: str
    name: str
    version: str

    def to_dict(self) -> dict[str, str]:
        return {"vendor": self.vendor, "name": self.name, "version": self.version}


@dataclass
class Metadata:
    timestamp: str
    tools: list[Tool]
    properties: list[Property] = field(default_factory=list)

    def to_dict(self) -> dict:
        result: dict = {
            "timestamp": self.timestamp,
            "tools": [t.to_dict() for t in self.tools],
        }
        if self.properties:
            result["properties"] = sorted(
                [p.to_dict() for p in self.properties], key=sort_properties_key
            )
        return result


@dataclass
class AIBom:
    metadata: Metadata
    components: list[Component] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    bom_format: str = "CycloneDX"
    spec_version: str = "1.5"
    version: int = 1
    schema: str = "https://cyclonedx.org/schema/bom-1.5.schema.json"

    def to_dict(self) -> dict:
        result: dict = {
            "$schema": self.schema,
            "bomFormat": self.bom_format,
            "specVersion": self.spec_version,
            "version": self.version,
            "metadata": self.metadata.to_dict(),
        }
        if self.components:
            result["components"] = [
                c.to_dict() for c in sorted(self.components, key=sort_component_key)
            ]
        if self.services:
            result["services"] = [s.to_dict() for s in sorted(self.services, key=sort_service_key)]
        return result

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def to_canonical_dict(self) -> dict:
        result: dict = {
            "bomFormat": self.bom_format,
            "specVersion": self.spec_version,
            "version": self.version,
        }
        canonical_metadata: dict = {"tools": [t.to_dict() for t in self.metadata.tools]}
        if self.metadata.properties:
            canonical_props = [
                p.to_dict()
                for p in self.metadata.properties
                if p.name not in ("ca9.bom.hash", "ca9.repo.root")
            ]
            if canonical_props:
                canonical_metadata["properties"] = sorted(canonical_props, key=sort_properties_key)
        result["metadata"] = canonical_metadata
        if self.components:
            result["components"] = [
                c.to_dict() for c in sorted(self.components, key=sort_component_key)
            ]
        if self.services:
            result["services"] = [s.to_dict() for s in sorted(self.services, key=sort_service_key)]
        return result

    def calculate_hash(self) -> str:
        canonical = self.to_canonical_dict()
        content = json.dumps(canonical, separators=(",", ":"), sort_keys=True)
        return f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"


@dataclass
class Capability:
    name: str  # filesystem.read, filesystem.write, exec.shell, network.egress, etc.
    scope: str
    asset: str
    evidence: list[str] = field(default_factory=list)

    def to_record_string(self) -> str:
        return json.dumps(
            {
                "cap": self.name,
                "scope": self.scope,
                "asset": self.asset,
                "evidence": self.evidence[:5],
            },
            separators=(",", ":"),
            sort_keys=True,
        )

    def __hash__(self):
        return hash((self.name, self.scope, self.asset))

    def __eq__(self, other):
        if not isinstance(other, Capability):
            return False
        return self.name == other.name and self.scope == other.scope and self.asset == other.asset


@dataclass
class AssetChange:
    id: str
    kind: str
    change: str | None = None


@dataclass
class CapabilityChange:
    capability: str
    scope: str
    asset: str
    evidence: list[str] = field(default_factory=list)
    from_scope: str | None = None
    to_scope: str | None = None


@dataclass
class Risk:
    level: str  # low, medium, high, critical
    reasons: list[str] = field(default_factory=list)


def create_default_risk() -> Risk:
    return Risk(level="low")


@dataclass
class CapabilityDiff:
    base_ref: str
    base_bom_hash: str
    head_ref: str
    head_bom_hash: str
    assets_added: list[AssetChange] = field(default_factory=list)
    assets_removed: list[AssetChange] = field(default_factory=list)
    assets_changed: list[AssetChange] = field(default_factory=list)
    capabilities_added: list[CapabilityChange] = field(default_factory=list)
    capabilities_removed: list[CapabilityChange] = field(default_factory=list)
    capabilities_widened: list[CapabilityChange] = field(default_factory=list)
    risk: Risk = field(default_factory=create_default_risk)

    def to_dict(self) -> dict:
        return {
            "base": {"ref": self.base_ref, "bom_hash": self.base_bom_hash},
            "head": {"ref": self.head_ref, "bom_hash": self.head_bom_hash},
            "assets": {
                "added": [{"id": a.id, "kind": a.kind} for a in self.assets_added],
                "removed": [{"id": a.id, "kind": a.kind} for a in self.assets_removed],
                "changed": [
                    {"id": a.id, "kind": a.kind, "change": a.change} for a in self.assets_changed
                ],
            },
            "capabilities": {
                "added": [
                    {
                        "capability": c.capability,
                        "scope": c.scope,
                        "asset": c.asset,
                        "evidence": c.evidence,
                    }
                    for c in self.capabilities_added
                ],
                "removed": [
                    {
                        "capability": c.capability,
                        "scope": c.scope,
                        "asset": c.asset,
                        "evidence": c.evidence,
                    }
                    for c in self.capabilities_removed
                ],
                "widened": [
                    {
                        "capability": c.capability,
                        "asset": c.asset,
                        "from": c.from_scope,
                        "to": c.to_scope,
                        "evidence": c.evidence,
                    }
                    for c in self.capabilities_widened
                ],
            },
            "risk": {"level": self.risk.level, "reasons": self.risk.reasons},
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


@dataclass(frozen=True)
class BlastRadius:
    capabilities: tuple[str, ...] = ()  # capability names found (deduplicated)
    details: tuple[CapabilityHit, ...] = ()  # full hit details
    risk_level: str = "low"
    risk_reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "risk_level": self.risk_level,
            "risk_reasons": list(self.risk_reasons),
            "capabilities": list(self.capabilities),
            "details": [h.to_dict() for h in self.details],
        }


@dataclass(frozen=True)
class CapabilityHit:
    name: str  # exec.shell, filesystem.write, network.egress, etc.
    scope: str  # path, domain, or "*"
    source_file: str  # relative path where capability was detected
    asset_ref: str  # bom-ref style identifier

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "scope": self.scope,
            "file": self.source_file,
            "asset": self.asset_ref,
        }


def generate_bom_ref(kind: str, *parts: str) -> str:
    return f"{kind}:{':'.join(parts)}"


def hash_content(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


def hash_content_short(content: str, length: int = 12) -> str:
    return hash_content(content)[:length]


def create_aibom(repo_root: str = ".") -> AIBom:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    metadata = Metadata(
        timestamp=timestamp,
        tools=[Tool(vendor="ca9", name="ca9", version="0.2.0")],
        properties=[
            Property(name="ca9.repo.root", value=repo_root),
            Property(name="ca9.scan.deterministic", value="true"),
        ],
    )
    components = [
        Component(
            type="application",
            name="repo",
            version="0.0.0",
            bom_ref="repo:root",
            properties=[Property(name="ca9.ai.asset.kind", value="repo")],
        )
    ]
    return AIBom(metadata=metadata, components=components)
