from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from packaging.utils import canonicalize_name


def _drop_none(data: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if value is not None}


def normalized_package_name(name: str, ecosystem: str = "pypi") -> str:
    if ecosystem.lower() == "npm":
        return name.strip().lower()
    return str(canonicalize_name(name))


def package_key(ecosystem: str, name: str, version: str | None = None) -> str:
    base = f"{ecosystem.lower()}:{normalized_package_name(name, ecosystem)}"
    if version:
        return f"{base}@{version}"
    return base


def purl_for_package(ecosystem: str, name: str, version: str | None = None) -> str:
    purl_type = ecosystem.lower()
    normalized = normalized_package_name(name, ecosystem)
    if version:
        return f"pkg:{purl_type}/{quote(normalized)}@{quote(version)}"
    return f"pkg:{purl_type}/{quote(normalized)}"


@dataclass(frozen=True)
class SourceEvidence:
    source: str
    path: str | None = None
    reader: str | None = None
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return _drop_none(
            {
                "source": self.source,
                "path": self.path,
                "reader": self.reader,
                "detail": self.detail,
            }
        )


@dataclass(frozen=True)
class SourceInput:
    kind: str
    path: str
    source: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "source": self.source,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class Artifact:
    kind: str
    url: str | None = None
    hash: str | None = None
    size: int | None = None
    upload_time: str | None = None
    source: str | None = None
    evidence: tuple[SourceEvidence, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data = _drop_none(
            {
                "kind": self.kind,
                "url": self.url,
                "hash": self.hash,
                "size": self.size,
                "upload_time": self.upload_time,
                "source": self.source,
            }
        )
        if self.evidence:
            data["evidence"] = [item.to_dict() for item in self.evidence]
        return data


@dataclass(frozen=True)
class Package:
    name: str
    version: str | None = None
    ecosystem: str = "pypi"
    dependency_kind: str = "unknown"
    source_registry: str | None = None
    artifacts: tuple[Artifact, ...] = ()
    evidence: tuple[SourceEvidence, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def normalized_name(self) -> str:
        return normalized_package_name(self.name, self.ecosystem)

    @property
    def key(self) -> str:
        return package_key(self.ecosystem, self.name, self.version)

    @property
    def purl(self) -> str:
        return purl_for_package(self.ecosystem, self.name, self.version)

    def to_dict(self) -> dict[str, Any]:
        return _drop_none(
            {
                "key": self.key,
                "ecosystem": self.ecosystem,
                "name": self.name,
                "normalized_name": self.normalized_name,
                "version": self.version,
                "purl": self.purl,
                "dependency_kind": self.dependency_kind,
                "source_registry": self.source_registry,
                "artifacts": [artifact.to_dict() for artifact in self.artifacts],
                "evidence": [item.to_dict() for item in self.evidence],
                "metadata": dict(self.metadata),
            }
        )


@dataclass(frozen=True)
class DependencyEdge:
    parent_key: str | None
    child_key: str
    parent_name: str | None = None
    parent_version: str | None = None
    child_name: str = ""
    child_version: str | None = None
    dependency_kind: str = "unknown"
    groups: tuple[str, ...] = ()
    extras: tuple[str, ...] = ()
    marker: str | None = None
    evidence: tuple[SourceEvidence, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return _drop_none(
            {
                "parent_key": self.parent_key,
                "child_key": self.child_key,
                "parent_name": self.parent_name,
                "parent_version": self.parent_version,
                "child_name": self.child_name,
                "child_version": self.child_version,
                "dependency_kind": self.dependency_kind,
                "groups": list(self.groups),
                "extras": list(self.extras),
                "marker": self.marker,
                "evidence": [item.to_dict() for item in self.evidence],
            }
        )


@dataclass(frozen=True)
class Advisory:
    id: str
    package_name: str
    ecosystem: str = "pypi"
    source: str = ""
    aliases: tuple[str, ...] = ()
    severity: str = "unknown"
    summary: str = ""
    references: tuple[str, ...] = ()
    evidence: tuple[SourceEvidence, ...] = ()

    @property
    def key(self) -> str:
        return f"{self.source or 'advisory'}:{self.id}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "id": self.id,
            "package_name": self.package_name,
            "ecosystem": self.ecosystem,
            "source": self.source,
            "aliases": list(self.aliases),
            "severity": self.severity,
            "summary": self.summary,
            "references": list(self.references),
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(frozen=True)
class Evidence:
    kind: str
    description: str
    source: SourceEvidence
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "description": self.description,
            "source": self.source.to_dict(),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class RiskSignal:
    signal_type: str
    package_key: str
    severity: str = "unknown"
    confidence: str = "medium"
    advisory_key: str | None = None
    evidence: tuple[Evidence, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        raw = {
            "signal_type": self.signal_type,
            "package_key": self.package_key,
            "advisory_key": self.advisory_key,
            "metadata": self.metadata,
        }
        payload = json.dumps(raw, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return _drop_none(
            {
                "key": self.key,
                "signal_type": self.signal_type,
                "package_key": self.package_key,
                "severity": self.severity,
                "confidence": self.confidence,
                "advisory_key": self.advisory_key,
                "evidence": [item.to_dict() for item in self.evidence],
                "metadata": dict(self.metadata),
            }
        )


@dataclass(frozen=True)
class Finding:
    title: str
    signal_type: str
    package_key: str
    severity: str = "unknown"
    signals: tuple[RiskSignal, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        raw = {
            "title": self.title,
            "signal_type": self.signal_type,
            "package_key": self.package_key,
            "severity": self.severity,
            "signal_keys": [signal.key for signal in self.signals],
        }
        payload = json.dumps(raw, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "title": self.title,
            "signal_type": self.signal_type,
            "package_key": self.package_key,
            "severity": self.severity,
            "signals": [signal.to_dict() for signal in self.signals],
            "evidence": [item.to_dict() for item in self.evidence],
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class Decision:
    action: str
    finding_fingerprint: str
    reason: str = ""
    policy_id: str | None = None
    evidence: tuple[Evidence, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return _drop_none(
            {
                "action": self.action,
                "finding_fingerprint": self.finding_fingerprint,
                "reason": self.reason,
                "policy_id": self.policy_id,
                "evidence": [item.to_dict() for item in self.evidence],
            }
        )


@dataclass(frozen=True)
class Inventory:
    repo_path: str
    source_inputs: tuple[SourceInput, ...] = ()
    packages: tuple[Package, ...] = ()
    dependency_edges: tuple[DependencyEdge, ...] = ()
    warnings: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        by_kind: dict[str, int] = {}
        for package in self.packages:
            by_kind[package.dependency_kind] = by_kind.get(package.dependency_kind, 0) + 1
        return {
            "packages": len(self.packages),
            "dependency_edges": len(self.dependency_edges),
            "dependency_kinds": dict(sorted(by_kind.items())),
            "source_inputs": len(self.source_inputs),
            "warnings": len(self.warnings),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "ca9.inventory.v1",
            "repo_path": self.repo_path,
            "summary": self.summary(),
            "source_inputs": [source_input.to_dict() for source_input in self.source_inputs],
            "packages": [package.to_dict() for package in self.packages],
            "dependency_edges": [edge.to_dict() for edge in self.dependency_edges],
            "warnings": list(self.warnings),
            "metadata": dict(self.metadata),
        }
