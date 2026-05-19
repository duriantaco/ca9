from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from urllib.parse import urlparse

from ca9.core.models import (
    Decision,
    Evidence,
    Finding,
    Inventory,
    Package,
    RiskSignal,
    SourceEvidence,
)
from ca9.core.models import (
    package_key as normalized_package_key,
)
from ca9.models import Vulnerability

DEFAULT_TRUSTED_INDEXES = ("https://pypi.org/simple",)
BLOCKING_SIGNALS = {"malware", "untrusted_registry"}


@dataclass(frozen=True)
class SupplyChainPolicy:
    trusted_indexes: tuple[str, ...] = DEFAULT_TRUSTED_INDEXES
    private_indexes: tuple[str, ...] = ()
    internal_package_patterns: tuple[str, ...] = ()
    block_untrusted_direct: bool = True
    warn_on_missing_artifact_hash: bool = True
    warn_on_missing_artifact_metadata: bool = True
    warn_on_sdist_only: bool = True
    warn_on_mutable_source: bool = True


def analyze_supply_chain(
    inventory: Inventory,
    policy: SupplyChainPolicy | None = None,
) -> list[Finding]:
    active_policy = policy or SupplyChainPolicy()
    findings: list[Finding] = []

    for package in inventory.packages:
        findings.extend(_artifact_source_findings(package, active_policy))
        findings.extend(_dependency_confusion_findings(package, active_policy))
        findings.extend(_install_risk_findings(package, active_policy))

    return _sort_findings(findings)


def findings_from_malware_advisories(vulnerabilities: list[Vulnerability]) -> list[Finding]:
    findings: list[Finding] = []
    for vuln in vulnerabilities:
        advisory_ids = {vuln.id, *vuln.aliases}
        if not any(_is_malware_advisory_id(advisory_id) for advisory_id in advisory_ids):
            continue

        source = SourceEvidence(
            source=vuln.advisory_source or "osv.dev",
            path=vuln.advisory_url or None,
            reader="osv malware advisory",
        )
        evidence = Evidence(
            kind="malware_advisory",
            description=f"{vuln.id} identifies {vuln.package_name} as malicious",
            source=source,
            metadata={
                "advisory_id": vuln.id,
                "aliases": list(vuln.aliases),
                "references": list(vuln.references),
                "published_at": vuln.published_at,
                "modified_at": vuln.modified_at,
                "cache_stale": vuln.cache_stale,
            },
        )
        package_key = normalized_package_key(
            vuln.ecosystem, vuln.package_name, vuln.package_version
        )
        signal = RiskSignal(
            signal_type="malware",
            package_key=package_key,
            severity="critical",
            confidence="high",
            advisory_key=vuln.id,
            evidence=(evidence,),
            metadata={"package": vuln.package_name, "version": vuln.package_version},
        )
        findings.append(
            Finding(
                title=f"Malicious package advisory for {vuln.package_name}",
                signal_type="malware",
                package_key=package_key,
                severity="critical",
                signals=(signal,),
                evidence=(evidence,),
                metadata={
                    "action": "block",
                    "package": vuln.package_name,
                    "version": vuln.package_version,
                    "advisory_id": vuln.id,
                },
            )
        )

    return _sort_findings(findings)


def evaluate_supply_chain_findings(findings: list[Finding]) -> list[Decision]:
    decisions: list[Decision] = []
    for finding in findings:
        action = str(finding.metadata.get("action") or "")
        if action not in {"block", "warn", "pass", "investigate"}:
            action = "block" if finding.signal_type in BLOCKING_SIGNALS else "warn"
        decisions.append(
            Decision(
                action=action,
                finding_fingerprint=finding.fingerprint,
                reason=str(finding.metadata.get("reason") or _default_reason(finding)),
                policy_id=str(finding.metadata.get("policy_id") or f"ca9.{finding.signal_type}"),
            )
        )
    return decisions


def _artifact_source_findings(package: Package, policy: SupplyChainPolicy) -> list[Finding]:
    findings: list[Finding] = []
    source = _package_evidence(package, "package inventory")

    if package.source_registry and not _is_trusted_index(package.source_registry, policy):
        direct = package.dependency_kind in {"direct", "project"}
        severity = "high" if direct else "medium"
        action = "block" if direct and policy.block_untrusted_direct else "warn"
        evidence = Evidence(
            kind="artifact_source",
            description=f"{package.name} resolves from untrusted registry {package.source_registry}",
            source=source,
            metadata={
                "registry": package.source_registry,
                "trusted_indexes": list(policy.trusted_indexes),
                "dependency_kind": package.dependency_kind,
            },
        )
        findings.append(
            _finding(
                package,
                title=f"Untrusted package registry for {package.name}",
                signal_type="untrusted_registry",
                severity=severity,
                action=action,
                evidence=evidence,
                reason="direct dependency from an untrusted index"
                if direct
                else "transitive dependency from an untrusted index",
            )
        )

    if (
        policy.warn_on_missing_artifact_metadata
        and package.source_registry
        and not package.artifacts
    ):
        evidence = Evidence(
            kind="artifact_integrity",
            description=f"{package.name} has registry metadata but no artifact records",
            source=source,
            metadata={"registry": package.source_registry},
        )
        findings.append(
            _finding(
                package,
                title=f"Missing artifact metadata for {package.name}",
                signal_type="missing_artifact_metadata",
                severity="low",
                action="warn",
                evidence=evidence,
                reason="registry package has no wheel or sdist metadata in inventory",
            )
        )

    if policy.warn_on_missing_artifact_hash:
        for artifact in package.artifacts:
            if not artifact.url or artifact.hash:
                continue
            evidence = Evidence(
                kind="artifact_integrity",
                description=f"{package.name} artifact has no hash",
                source=artifact.evidence[0] if artifact.evidence else source,
                metadata={"artifact_kind": artifact.kind, "url": artifact.url},
            )
            findings.append(
                _finding(
                    package,
                    title=f"Missing artifact hash for {package.name}",
                    signal_type="missing_artifact_hash",
                    severity=_kind_weighted_severity(package, direct="medium", transitive="low"),
                    action="warn",
                    evidence=evidence,
                    reason="artifact URL is present without an integrity hash",
                )
            )

    return findings


def _install_risk_findings(package: Package, policy: SupplyChainPolicy) -> list[Finding]:
    findings: list[Finding] = []
    artifact_kinds = {artifact.kind for artifact in package.artifacts}
    source = _package_evidence(package, "package inventory")

    if policy.warn_on_sdist_only and "sdist" in artifact_kinds and "wheel" not in artifact_kinds:
        evidence = Evidence(
            kind="install_risk",
            description=f"{package.name} only has an sdist artifact in inventory",
            source=source,
            metadata={"artifact_kinds": sorted(artifact_kinds)},
        )
        findings.append(
            _finding(
                package,
                title=f"Source distribution install risk for {package.name}",
                signal_type="sdist_only",
                severity=_kind_weighted_severity(package, direct="medium", transitive="low"),
                action="warn",
                evidence=evidence,
                reason="install may execute build backend or setup code because no wheel was recorded",
            )
        )

    source_kind = str(package.metadata.get("source_kind") or "")
    if policy.warn_on_mutable_source and source_kind in {"git", "url", "path"}:
        evidence = Evidence(
            kind="artifact_source",
            description=f"{package.name} resolves from mutable source kind {source_kind}",
            source=source,
            metadata={"source_kind": source_kind, "dependency_kind": package.dependency_kind},
        )
        findings.append(
            _finding(
                package,
                title=f"Mutable package source for {package.name}",
                signal_type="mutable_source",
                severity=_kind_weighted_severity(package, direct="medium", transitive="low"),
                action="warn",
                evidence=evidence,
                reason="package source is not a registry-pinned immutable artifact",
            )
        )

    return findings


def _dependency_confusion_findings(
    package: Package,
    policy: SupplyChainPolicy,
) -> list[Finding]:
    if not policy.internal_package_patterns:
        return []

    matched_pattern = _matched_internal_pattern(package.name, policy.internal_package_patterns)
    if matched_pattern is None:
        return []

    source = _package_evidence(package, "package inventory")
    registry = package.source_registry or ""
    if registry and _is_private_index(registry, policy):
        return []

    direct = package.dependency_kind in {"direct", "project"}
    action = "block" if direct else "investigate"
    severity = "critical" if direct else "high"
    reason = (
        f"internal package pattern {matched_pattern!r} resolved from "
        f"{registry or 'an unknown index'} instead of a configured private index"
    )
    evidence = Evidence(
        kind="dependency_confusion",
        description=reason,
        source=source,
        metadata={
            "internal_pattern": matched_pattern,
            "actual_registry": registry or None,
            "private_indexes": list(policy.private_indexes),
            "trusted_indexes": list(policy.trusted_indexes),
            "dependency_kind": package.dependency_kind,
        },
    )
    return [
        _finding(
            package,
            title=f"Possible dependency confusion for {package.name}",
            signal_type="dependency_confusion",
            severity=severity,
            action=action,
            evidence=evidence,
            reason=reason,
        )
    ]


def _finding(
    package: Package,
    *,
    title: str,
    signal_type: str,
    severity: str,
    action: str,
    evidence: Evidence,
    reason: str,
) -> Finding:
    signal = RiskSignal(
        signal_type=signal_type,
        package_key=package.key,
        severity=severity,
        confidence="medium",
        evidence=(evidence,),
        metadata={
            "package": package.name,
            "version": package.version,
            "dependency_kind": package.dependency_kind,
        },
    )
    return Finding(
        title=title,
        signal_type=signal_type,
        package_key=package.key,
        severity=severity,
        signals=(signal,),
        evidence=(evidence,),
        metadata={
            "action": action,
            "reason": reason,
            "package": package.name,
            "version": package.version,
            "dependency_kind": package.dependency_kind,
            "policy_id": f"ca9.{signal_type}",
        },
    )


def _package_evidence(package: Package, default_source: str) -> SourceEvidence:
    if package.evidence:
        return package.evidence[0]
    return SourceEvidence(source=default_source, reader="ca9 supply-chain analyzer")


def _is_trusted_index(registry: str, policy: SupplyChainPolicy) -> bool:
    normalized_registry = _normalize_index_url(registry)
    trusted = {_normalize_index_url(item) for item in policy.trusted_indexes}
    return normalized_registry in trusted


def _is_private_index(registry: str, policy: SupplyChainPolicy) -> bool:
    normalized_registry = _normalize_index_url(registry)
    private_indexes = {_normalize_index_url(item) for item in policy.private_indexes}
    return normalized_registry in private_indexes


def _matched_internal_pattern(name: str, patterns: tuple[str, ...]) -> str | None:
    normalized_name = _normalize_package_glob_target(name)
    for pattern in patterns:
        normalized_pattern = _normalize_package_glob_target(pattern)
        if fnmatch(normalized_name, normalized_pattern):
            return pattern
    return None


def _normalize_package_glob_target(value: str) -> str:
    return value.strip().lower().replace("_", "-").replace(".", "-")


def _normalize_index_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if not parsed.scheme or not parsed.netloc:
        return value.strip().rstrip("/").lower()
    path = parsed.path.rstrip("/")
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}"


def _kind_weighted_severity(package: Package, *, direct: str, transitive: str) -> str:
    if package.dependency_kind in {"direct", "project"}:
        return direct
    return transitive


def _is_malware_advisory_id(value: str) -> bool:
    upper = value.upper()
    return upper.startswith("MAL-") or upper.startswith("PYSEC-MAL-")


def _default_reason(finding: Finding) -> str:
    if finding.signal_type == "malware":
        return "known malicious package advisory matched this package"
    if finding.signal_type == "untrusted_registry":
        return "package resolves from an untrusted registry"
    return "supply-chain risk signal matched this package"


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    return sorted(
        findings,
        key=lambda finding: (
            severity_order.get(finding.severity, 5),
            finding.signal_type,
            finding.package_key,
            finding.title,
        ),
    )
