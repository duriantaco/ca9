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
from ca9.package_policy import PolicyException, action_for_mode, find_policy_exception
from ca9.readers.requirements import vcs_reference

_COMMIT_REF_LENGTHS = (40, 64)
_NON_INDEX_SOURCE_KINDS = frozenset(
    {"git", "vcs", "url", "direct_url", "path", "file", "remote", "workspace"}
)
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")

DEFAULT_TRUSTED_INDEXES = ("https://pypi.org/simple", "https://registry.npmjs.org")
BLOCKING_SIGNALS = {"malware", "untrusted_registry"}


@dataclass(frozen=True)
class SupplyChainPolicy:
    trusted_indexes: tuple[str, ...] = DEFAULT_TRUSTED_INDEXES
    denied_indexes: tuple[str, ...] = ()
    private_indexes: tuple[str, ...] = ()
    internal_package_patterns: tuple[str, ...] = ()
    mode: str = "block"
    block_untrusted_direct: bool = True
    warn_on_missing_artifact_hash: bool = True
    warn_on_missing_artifact_metadata: bool = True
    warn_on_sdist_only: bool = True
    warn_on_mutable_source: bool = True
    exceptions: tuple[PolicyException, ...] = ()


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
        if not _is_malware_advisory(vuln):
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
                "malicious": vuln.malicious,
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
                    "malicious": vuln.malicious,
                },
            )
        )

    return _sort_findings(findings)


def evaluate_supply_chain_findings(
    findings: list[Finding],
    policy: SupplyChainPolicy | None = None,
) -> list[Decision]:
    active_policy = policy or SupplyChainPolicy()
    decisions: list[Decision] = []
    for finding in findings:
        action = str(finding.metadata.get("action") or "")
        if action not in {"block", "warn", "pass", "investigate"}:
            action = "block" if finding.signal_type in BLOCKING_SIGNALS else "warn"
        if not finding.metadata.get("mode_applied"):
            action = action_for_mode(action, active_policy.mode)
        policy_id = str(finding.metadata.get("policy_id") or f"ca9.{finding.signal_type}")
        reason = str(finding.metadata.get("reason") or _default_reason(finding))
        exception = find_policy_exception(
            active_policy.exceptions,
            policy_id=policy_id,
            ecosystem=_finding_ecosystem(finding),
            package=_optional_metadata_string(finding, "package"),
            version=_optional_metadata_string(finding, "version"),
        )
        decision_evidence: tuple[Evidence, ...] = ()
        if exception is not None and action != "pass":
            original_action = action
            action = exception.action
            decision_evidence = (_policy_exception_evidence(exception, original_action),)
            reason = (
                f"{reason}; exception owned by {exception.owner} applies until "
                f"{exception.expires}: {exception.reason}"
            )
        decisions.append(
            Decision(
                action=action,
                finding_fingerprint=finding.fingerprint,
                reason=reason,
                policy_id=policy_id,
                evidence=decision_evidence,
            )
        )
    return decisions


def _finding_ecosystem(finding: Finding) -> str | None:
    if ":" not in finding.package_key:
        return None
    return finding.package_key.split(":", 1)[0].lower()


def _optional_metadata_string(finding: Finding, key: str) -> str | None:
    value = finding.metadata.get(key)
    return str(value) if value is not None else None


def _policy_exception_evidence(
    exception: PolicyException,
    original_action: str,
) -> Evidence:
    return Evidence(
        kind="policy_exception",
        description=(
            f"{exception.owner} accepted this {exception.policy_id} decision until "
            f"{exception.expires}"
        ),
        source=SourceEvidence(
            source="ca9 package policy",
            path=exception.source,
            reader="ca9 policy exception matcher",
        ),
        metadata={
            **exception.to_dict(),
            "original_action": original_action,
        },
    )


def package_registries(package: Package) -> tuple[str, ...]:
    """Every index the package may be installed from.

    A merged setup (pip --extra-index-url, --find-links) lets the installer take
    the best match from any of its indexes, so each one is a possible source.
    """
    candidates = package.metadata.get("candidate_registries")
    if package.metadata.get("registry_mode") == "merged" and isinstance(candidates, list):
        registries = tuple(item for item in candidates if isinstance(item, str) and item)
        if registries:
            return registries
    if package.source_registry:
        return (package.source_registry,)
    return ()


def _artifact_source_findings(package: Package, policy: SupplyChainPolicy) -> list[Finding]:
    findings: list[Finding] = []
    source = _package_evidence(package, "package inventory")
    registries = package_registries(package)
    merged = package.metadata.get("registry_mode") == "merged"

    denied = [registry for registry in registries if _is_denied_index(registry, policy)]
    if denied:
        direct = package.dependency_kind in {"direct", "project"}
        metadata = {
            "registry": denied[0],
            "denied_indexes": list(policy.denied_indexes),
            "dependency_kind": package.dependency_kind,
        }
        if merged:
            metadata["registry_mode"] = "merged"
            metadata["candidate_registries"] = list(registries)
        evidence = Evidence(
            kind="artifact_source",
            description=f"{package.name} resolves from denied registry {denied[0]}",
            source=source,
            metadata=metadata,
        )
        findings.append(
            _finding(
                package,
                title=f"Denied package registry for {package.name}",
                signal_type="denied_registry",
                severity="high" if direct else "medium",
                action="block",
                evidence=evidence,
                reason="package resolves from a denied registry",
            )
        )
        return findings

    untrusted = [registry for registry in registries if not _is_trusted_index(registry, policy)]
    if untrusted:
        direct = package.dependency_kind in {"direct", "project"}
        severity = "high" if direct else "medium"
        action = "block" if direct and policy.block_untrusted_direct else "warn"
        metadata = {
            "registry": untrusted[0],
            "trusted_indexes": list(policy.trusted_indexes),
            "dependency_kind": package.dependency_kind,
        }
        if merged:
            metadata["registry_mode"] = "merged"
            metadata["candidate_registries"] = list(registries)
            metadata["untrusted_registries"] = untrusted
        evidence = Evidence(
            kind="artifact_source",
            description=f"{package.name} resolves from untrusted registry {untrusted[0]}",
            source=source,
            metadata=metadata,
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
            if artifact.kind == "git-source" and git_source_evidence(package)["pinned_commit"]:
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

    for artifact in package.artifacts:
        if not artifact.url or not artifact.url.lower().startswith("http://"):
            continue
        evidence = Evidence(
            kind="artifact_transport",
            description=f"{package.name} artifact uses insecure HTTP URL {artifact.url}",
            source=artifact.evidence[0] if artifact.evidence else source,
            metadata={
                "artifact_kind": artifact.kind,
                "url": artifact.url,
                "dependency_kind": package.dependency_kind,
            },
        )
        findings.append(
            _finding(
                package,
                title=f"Insecure artifact URL for {package.name}",
                signal_type="http_artifact_url",
                severity=_kind_weighted_severity(package, direct="high", transitive="medium"),
                action="block" if package.dependency_kind in {"direct", "project"} else "warn",
                evidence=evidence,
                reason="package artifact is fetched over unauthenticated HTTP",
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
    source_url = str(package.metadata.get("source_url") or "")
    if source_kind in {"git", "vcs"}:
        git_evidence = git_source_evidence(package)
        evidence = Evidence(
            kind="artifact_source",
            description=f"{package.name} resolves from a Git dependency",
            source=source,
            metadata={
                "source_kind": source_kind,
                "source_url": source_url or git_evidence["source_url"],
                "dependency_kind": package.dependency_kind,
                **git_evidence,
            },
        )
        if git_evidence["pinned_commit"]:
            severity = "low"
            reason = (
                "Git dependency pinned to a full commit; it still bypasses registry "
                "release and artifact controls"
            )
        else:
            severity = _kind_weighted_severity(package, direct="medium", transitive="low")
            reason = (
                "Git dependency on a mutable ref; whoever controls the branch or tag "
                "changes the installed code"
            )
        findings.append(
            _finding(
                package,
                title=f"Git dependency for {package.name}",
                signal_type="git_dependency",
                severity=severity,
                action="warn",
                evidence=evidence,
                reason=reason,
            )
        )
    elif source_kind in {"url", "direct_url"}:
        has_hash = url_source_has_hash(package)
        evidence = Evidence(
            kind="artifact_source",
            description=f"{package.name} resolves from a direct URL dependency",
            source=source,
            metadata={
                "source_kind": source_kind,
                "source_url": source_url or None,
                "dependency_kind": package.dependency_kind,
                "has_hash": has_hash,
                "mutable": not has_hash,
            },
        )
        if has_hash:
            severity = "low"
            reason = (
                "direct URL dependency pinned by hash; it still bypasses registry release "
                "and provenance controls"
            )
        else:
            severity = _kind_weighted_severity(package, direct="medium", transitive="low")
            reason = (
                "direct URL dependency without a hash; the server can change the installed "
                "file at any time"
            )
        findings.append(
            _finding(
                package,
                title=f"Direct URL dependency for {package.name}",
                signal_type="direct_url_dependency",
                severity=severity,
                action="warn",
                evidence=evidence,
                reason=reason,
            )
        )

    if policy.warn_on_mutable_source and source_kind in {"path"}:
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
    registries = package_registries(package)
    source_kind = str(package.metadata.get("source_kind") or "")
    if not registries and source_kind in _NON_INDEX_SOURCE_KINDS:
        return []
    if not registries and package.metadata.get("registry_mode") == "local":
        return []

    source = _package_evidence(package, "package inventory")
    public = [registry for registry in registries if not _is_private_index(registry, policy)]
    if registries and not public:
        return []

    merged = package.metadata.get("registry_mode") == "merged"
    registry = ""
    if not merged:
        registry = package.source_registry or ""
    direct = package.dependency_kind in {"direct", "project"}
    action = "block" if direct else "investigate"
    severity = "critical" if direct else "high"
    if merged:
        reason = (
            f"internal package pattern {matched_pattern!r} installs from merged indexes "
            f"({', '.join(registries)}); the installer takes the best version from any of "
            f"them, so a public upload to {public[0]} wins over the private index"
        )
    else:
        reason = (
            f"internal package pattern {matched_pattern!r} resolved from "
            f"{registry or 'an unknown index'} instead of a configured private index"
        )
    metadata = {
        "internal_pattern": matched_pattern,
        "actual_registry": registry or None,
        "private_indexes": list(policy.private_indexes),
        "trusted_indexes": list(policy.trusted_indexes),
        "dependency_kind": package.dependency_kind,
    }
    if merged:
        metadata["registry_mode"] = "merged"
        metadata["candidate_registries"] = list(registries)
        metadata["public_registries"] = public
    evidence = Evidence(
        kind="dependency_confusion",
        description=reason,
        source=source,
        metadata=metadata,
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


def git_source_evidence(package: Package) -> dict[str, object]:
    """Describe whether a Git dependency is pinned to a full commit.

    A full 40 (or 64) hex digit commit id is immutable; a branch, tag, short id or
    missing ref lets whoever controls the repository change the installed code.
    """
    source_url = package.metadata.get("source_url")
    url = None
    if isinstance(source_url, str) and source_url:
        url = source_url
    if url is None:
        for artifact in package.artifacts:
            if artifact.url:
                url = artifact.url
                break
    ref = package.metadata.get("vcs_ref")
    if (not isinstance(ref, str) or not ref) and url:
        ref = vcs_reference(url)
    pinned = _is_full_commit(ref)
    if "pinned_commit" in package.metadata and package.metadata.get("pinned_commit") is not True:
        pinned = False
    return {
        "source_url": url,
        "ref": ref,
        "pinned_commit": pinned,
        "mutable": not pinned,
    }


def url_source_has_hash(package: Package) -> bool:
    """True when a URL dependency carries a hash that pins its file."""
    recorded = package.metadata.get("has_hash")
    if isinstance(recorded, bool):
        return recorded
    return any(artifact.url and artifact.hash for artifact in package.artifacts)


def _is_full_commit(ref: object) -> bool:
    if not isinstance(ref, str):
        return False
    return len(ref) in _COMMIT_REF_LENGTHS and all(char in _HEX_DIGITS for char in ref)


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
    # A configured private index is an explicit trust decision for the
    # internal packages it serves.
    return _registry_matches(registry, policy.trusted_indexes) or _registry_matches(
        registry, policy.private_indexes
    )


def _is_denied_index(registry: str, policy: SupplyChainPolicy) -> bool:
    return _registry_matches(registry, policy.denied_indexes)


def _is_private_index(registry: str, policy: SupplyChainPolicy) -> bool:
    return _registry_matches(registry, policy.private_indexes)


def internal_pattern_for(name: str, patterns: tuple[str, ...]) -> str | None:
    """The internal package pattern a name matches, ignoring case, '_' and '.'."""
    return _matched_internal_pattern(name, patterns)


def registry_matches(registry: str, candidates: tuple[str, ...]) -> bool:
    """True when the registry is one of the candidates or beneath one of them."""
    return _registry_matches(registry, candidates)


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


def _registry_matches(registry: str, candidates: tuple[str, ...]) -> bool:
    normalized_registry = _normalize_index_url(registry)
    registry_host = _index_host(registry)
    for candidate in candidates:
        normalized_candidate = _normalize_index_url(candidate)
        if normalized_registry == normalized_candidate:
            return True
        # A configured index with a path covers registries beneath it, matched
        # on whole path segments so ".../npm-internal" never covers
        # ".../npm-internal-evil".
        if "://" in normalized_candidate and normalized_registry.startswith(
            normalized_candidate + "/"
        ):
            return True
        candidate_host = _index_host(candidate)
        parsed_candidate = urlparse(candidate.strip())
        candidate_path = parsed_candidate.path.rstrip("/") if parsed_candidate.netloc else ""
        if (
            candidate_host
            and registry_host
            and candidate_host == registry_host
            and not candidate_path
        ):
            return True
    return False


def _index_host(value: str) -> str:
    raw = value.strip()
    parsed = urlparse(raw)
    if parsed.netloc:
        return parsed.netloc.lower()
    return raw.split("/", 1)[0].lower()


def _kind_weighted_severity(package: Package, *, direct: str, transitive: str) -> str:
    if package.dependency_kind in {"direct", "project"}:
        return direct
    return transitive


def _is_malware_advisory_id(value: str) -> bool:
    upper = value.upper()
    return upper.startswith("MAL-") or upper.startswith("PYSEC-MAL-")


def _is_malware_advisory(vuln: Vulnerability) -> bool:
    # Structured evidence only (an explicit flag or a MAL- id/alias): advisory text
    # such as "malicious URL" or "exfiltrate" also describes ordinary CVEs.
    if vuln.malicious:
        return True

    advisory_ids = {vuln.id, *vuln.aliases}
    return any(_is_malware_advisory_id(advisory_id) for advisory_id in advisory_ids)


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
