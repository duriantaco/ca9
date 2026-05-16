from __future__ import annotations

from dataclasses import dataclass
from email.parser import Parser

from ca9.artifacts.model import ArtifactFile, ArtifactSnapshot
from ca9.core.models import Evidence, Finding, RiskSignal, SourceEvidence

MAX_METADATA_BYTES = 1024 * 1024
METADATA_SUFFIXES = (".dist-info/METADATA", "/PKG-INFO")


@dataclass(frozen=True)
class LicensePolicy:
    denied_licenses: tuple[str, ...] = ()
    require_known_license: bool = False

    @property
    def enabled(self) -> bool:
        return bool(self.denied_licenses or self.require_known_license)


@dataclass(frozen=True)
class LicenseMetadata:
    file_path: str
    license_expression: str | None = None
    license_field: str | None = None
    classifiers: tuple[str, ...] = ()

    @property
    def raw_values(self) -> tuple[str, ...]:
        values: list[str] = []
        if self.license_expression:
            values.append(self.license_expression)
        if self.license_field:
            values.append(self.license_field)
        values.extend(self.classifiers)
        return tuple(values)


def analyze_license_policy(
    snapshots: tuple[ArtifactSnapshot, ...],
    policy: LicensePolicy,
) -> list[Finding]:
    if not policy.enabled:
        return []

    findings: list[Finding] = []
    denied = tuple(_normalize_license(value) for value in policy.denied_licenses if value.strip())

    for snapshot in snapshots:
        metadata_files = _metadata_files(snapshot)
        if not metadata_files and policy.require_known_license:
            findings.append(
                _unknown_license_finding(snapshot, None, "no package metadata file found")
            )
            continue

        found_known_license = False
        for file in metadata_files:
            metadata = _read_license_metadata(file)
            if metadata is None:
                continue
            normalized_values = tuple(
                _normalize_license(value) for value in metadata.raw_values if value.strip()
            )
            known_values = tuple(value for value in normalized_values if value)
            if known_values:
                found_known_license = True

            for raw, normalized in zip(metadata.raw_values, normalized_values, strict=False):
                matched = _matched_denied_license(normalized, denied)
                if matched:
                    findings.append(
                        _denied_license_finding(snapshot, metadata, raw, normalized, matched)
                    )

        if policy.require_known_license and not found_known_license:
            first_metadata = metadata_files[0] if metadata_files else None
            findings.append(
                _unknown_license_finding(
                    snapshot,
                    first_metadata,
                    "no known license metadata was found",
                )
            )

    return _dedupe_findings(findings)


def _metadata_files(snapshot: ArtifactSnapshot) -> list[ArtifactFile]:
    return [
        file
        for file in snapshot.files
        if file.relative_path.endswith(METADATA_SUFFIXES)
        or file.relative_path.rsplit("/", 1)[-1] == "PKG-INFO"
    ]


def _read_license_metadata(file: ArtifactFile) -> LicenseMetadata | None:
    if file.size > MAX_METADATA_BYTES:
        return None
    try:
        text = file.path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    message = Parser().parsestr(text)
    classifiers = tuple(
        value for value in message.get_all("Classifier", []) if value.startswith("License ::")
    )
    return LicenseMetadata(
        file_path=file.relative_path,
        license_expression=_clean_license_value(message.get("License-Expression")),
        license_field=_clean_license_value(message.get("License")),
        classifiers=classifiers,
    )


def _denied_license_finding(
    snapshot: ArtifactSnapshot,
    metadata: LicenseMetadata,
    raw_license: str,
    normalized_license: str,
    matched_deny: str,
) -> Finding:
    direct = snapshot.package.dependency_kind in {"direct", "project"}
    action = "block" if direct else "investigate"
    severity = "high" if direct else "medium"
    reason = f"license {raw_license!r} matches denied license {matched_deny!r}"
    source = SourceEvidence(
        source="package artifact metadata",
        path=f"{snapshot.archive_path}!{metadata.file_path}",
        reader="ca9 license-policy analyzer",
        detail="denied_license",
    )
    evidence = Evidence(
        kind="license_policy",
        description=reason,
        source=source,
        metadata={
            "file_path": metadata.file_path,
            "raw_license": raw_license,
            "normalized_license": normalized_license,
            "matched_denied_license": matched_deny,
            "license_expression": metadata.license_expression,
            "license": metadata.license_field,
            "classifiers": list(metadata.classifiers),
        },
    )
    return _finding(
        snapshot,
        signal_type="denied_license",
        title=f"Denied license for {snapshot.package.name}",
        severity=severity,
        action=action,
        reason=reason,
        evidence=evidence,
    )


def _unknown_license_finding(
    snapshot: ArtifactSnapshot,
    metadata_file: ArtifactFile | None,
    reason: str,
) -> Finding:
    if metadata_file is None:
        path = str(snapshot.archive_path)
        file_path = None
    else:
        path = f"{snapshot.archive_path}!{metadata_file.relative_path}"
        file_path = metadata_file.relative_path
    source = SourceEvidence(
        source="package artifact metadata",
        path=path,
        reader="ca9 license-policy analyzer",
        detail="unknown_license",
    )
    evidence = Evidence(
        kind="license_policy",
        description=reason,
        source=source,
        metadata={"file_path": file_path},
    )
    return _finding(
        snapshot,
        signal_type="unknown_license",
        title=f"Unknown license for {snapshot.package.name}",
        severity="low",
        action="warn",
        reason=reason,
        evidence=evidence,
    )


def _finding(
    snapshot: ArtifactSnapshot,
    *,
    signal_type: str,
    title: str,
    severity: str,
    action: str,
    reason: str,
    evidence: Evidence,
) -> Finding:
    signal = RiskSignal(
        signal_type=signal_type,
        package_key=snapshot.package.key,
        severity=severity,
        confidence="high" if signal_type == "denied_license" else "medium",
        evidence=(evidence,),
        metadata={
            "package": snapshot.package.name,
            "version": snapshot.package.version,
            "dependency_kind": snapshot.package.dependency_kind,
        },
    )
    return Finding(
        title=title,
        signal_type=signal_type,
        package_key=snapshot.package.key,
        severity=severity,
        signals=(signal,),
        evidence=(evidence,),
        metadata={
            "action": action,
            "reason": reason,
            "package": snapshot.package.name,
            "version": snapshot.package.version,
            "dependency_kind": snapshot.package.dependency_kind,
            "policy_id": f"ca9.{signal_type}",
        },
    )


def _clean_license_value(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned or cleaned.upper() in {"UNKNOWN", "UNKNOWN LICENSE"}:
        return None
    return cleaned


def _normalize_license(value: str) -> str:
    text = value.strip()
    if not text:
        return ""
    if text.startswith("License ::"):
        text = text.rsplit("::", 1)[-1].strip()

    lowered = text.lower()
    aliases = {
        "mit license": "MIT",
        "apache software license": "APACHE-2.0",
        "apache license 2.0": "APACHE-2.0",
        "bsd license": "BSD",
        "gnu general public license v3 (gplv3)": "GPL-3.0",
        "gnu affero general public license v3": "AGPL-3.0",
        "gnu lesser general public license v3 (lgplv3)": "LGPL-3.0",
    }
    if lowered in aliases:
        return aliases[lowered]

    normalized = text.upper().replace("_", "-").replace(" ", "-")
    normalized = normalized.replace("-LICENSE", "")
    return normalized


def _matched_denied_license(normalized: str, denied: tuple[str, ...]) -> str | None:
    if not normalized:
        return None
    for denied_license in denied:
        if not denied_license:
            continue
        if normalized == denied_license:
            return denied_license
        if normalized.startswith(f"{denied_license}-"):
            return denied_license
        if f" {denied_license} " in f" {normalized} ":
            return denied_license
    return None


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    deduped: dict[str, Finding] = {}
    for finding in findings:
        deduped[finding.fingerprint] = finding
    return sorted(
        deduped.values(),
        key=lambda finding: (finding.signal_type, finding.package_key, finding.title),
    )
