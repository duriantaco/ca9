from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ca9.advisory import metadata_from_osv, normalize_advisory_aliases, normalize_ecosystem
from ca9.models import VersionRange, Vulnerability, finding_key
from ca9.scanner import (
    _extract_references,
    _extract_severity,
    _extract_version_ranges,
    _is_malicious_osv,
)

_SEVERITY_RANK = {
    "unknown": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _is_official_result_shape(result: Any) -> bool:
    if not isinstance(result, dict):
        return False

    source = result.get("source")
    packages = result.get("packages")
    if not isinstance(source, dict) or not isinstance(packages, list):
        return False

    if not isinstance(source.get("path"), str) or not isinstance(source.get("type"), str):
        return False

    for entry in packages:
        if not isinstance(entry, dict):
            return False
        package = entry.get("package")
        vulnerabilities = entry.get("vulnerabilities", [])
        if not isinstance(package, dict) or not isinstance(vulnerabilities, list):
            return False
        if not all(isinstance(package.get(key), str) for key in ("name", "version", "ecosystem")):
            return False
        commit = package.get("commit")
        if commit is not None and not isinstance(commit, str):
            return False
        if not package.get("name") and not commit:
            return False
        if not all(
            isinstance(vulnerability, dict) and isinstance(vulnerability.get("id"), str)
            for vulnerability in vulnerabilities
        ):
            return False

    return True


def _string(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _safe_severity(record: dict[str, Any]) -> str:
    try:
        return _extract_severity(record)
    except (AttributeError, TypeError, ValueError):
        return "unknown"


def _safe_references(record: dict[str, Any]) -> tuple[str, ...]:
    try:
        return _extract_references(record)
    except (AttributeError, TypeError, ValueError):
        return ()


def _safe_ranges(
    record: dict[str, Any],
    package_name: str,
    ecosystem: str,
) -> tuple[VersionRange, ...]:
    if not ecosystem:
        # The shared OSV helper defaults an unknown ecosystem to PyPI for
        # CA9's native Python scan. A mixed-ecosystem report adapter must not.
        return ()
    try:
        return _extract_version_ranges(record, package_name, ecosystem)
    except (AttributeError, TypeError, ValueError):
        return ()


def _ordered_unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))


def _affected_package_name(entry: dict[str, Any], ecosystem: str) -> str:
    raw_vulnerabilities = entry.get("vulnerabilities")
    if not isinstance(raw_vulnerabilities, list):
        return ""

    for record in raw_vulnerabilities:
        if not isinstance(record, dict):
            continue
        affected_entries = record.get("affected")
        if not isinstance(affected_entries, list):
            continue
        for affected in affected_entries:
            if not isinstance(affected, dict):
                continue
            affected_package = affected.get("package")
            if not isinstance(affected_package, dict):
                continue

            candidate = _string(affected_package.get("name"))
            if not candidate:
                continue
            candidate_ecosystem = normalize_ecosystem(affected_package.get("ecosystem"))
            if ecosystem and candidate_ecosystem and candidate_ecosystem != ecosystem:
                continue
            return candidate

    return ""


def _group_records(entry: dict[str, Any]) -> list[list[dict[str, Any]]]:
    raw_vulnerabilities = entry.get("vulnerabilities")
    if not isinstance(raw_vulnerabilities, list):
        return []

    records: list[dict[str, Any]] = []
    records_by_id: dict[str, dict[str, Any]] = {}
    for raw_record in raw_vulnerabilities:
        if not isinstance(raw_record, dict):
            continue
        record_id = _string(raw_record.get("id"))
        if not record_id or record_id in records_by_id:
            continue
        records.append(raw_record)
        records_by_id[record_id] = raw_record

    grouped: list[list[dict[str, Any]]] = []
    consumed: set[str] = set()
    raw_groups = entry.get("groups")
    if isinstance(raw_groups, list):
        for raw_group in raw_groups:
            if not isinstance(raw_group, dict):
                continue
            raw_ids = raw_group.get("ids")
            if not isinstance(raw_ids, list):
                continue

            group: list[dict[str, Any]] = []
            for raw_id in raw_ids:
                record_id = _string(raw_id)
                if not record_id or record_id in consumed:
                    continue
                record = records_by_id.get(record_id)
                if record is not None:
                    group.append(record)
                    consumed.add(record_id)
            if group:
                grouped.append(group)

    for record in records:
        record_id = _string(record.get("id"))
        if record_id not in consumed:
            grouped.append([record])

    return grouped


def _build_vulnerability(
    records: list[dict[str, Any]],
    *,
    package_name: str,
    package_version: str,
    ecosystem: str,
) -> Vulnerability | None:
    if not records:
        return None

    primary = records[0]
    vuln_id = _string(primary.get("id"))
    if not vuln_id:
        return None

    alias_values: list[Any] = []
    severity = "unknown"
    title = ""
    description = ""
    ranges: list[VersionRange] = []
    references: list[str] = []
    cwes: list[str] = []
    cpes: list[str] = []
    published_at: str | None = None
    modified_at: str | None = None
    malicious = False

    for index, record in enumerate(records):
        record_id = _string(record.get("id"))
        if index > 0 and record_id:
            alias_values.append(record_id)

        raw_aliases = record.get("aliases")
        if isinstance(raw_aliases, list):
            alias_values.extend(raw_aliases)

        record_severity = _safe_severity(record)
        if _SEVERITY_RANK.get(record_severity, 0) > _SEVERITY_RANK.get(severity, 0):
            severity = record_severity

        summary = _string(record.get("summary"))
        details = _string(record.get("details"))
        if not title:
            title = summary or details[:120]
        if not description and details:
            description = details

        ranges.extend(_safe_ranges(record, package_name, ecosystem))
        references.extend(_safe_references(record))

        metadata = metadata_from_osv(record, record_id or vuln_id)
        cwes.extend(metadata.cwes)
        cpes.extend(metadata.cpes)
        if published_at is None:
            published_at = metadata.published_at
        if modified_at is None:
            modified_at = metadata.modified_at

        malicious = malicious or _is_malicious_osv(record, record_id or vuln_id)

    primary_metadata = metadata_from_osv(primary, vuln_id)
    return Vulnerability(
        id=vuln_id,
        package_name=package_name,
        package_version=package_version,
        severity=severity,
        title=title or vuln_id,
        description=description,
        affected_ranges=tuple(dict.fromkeys(ranges)),
        references=_ordered_unique(references),
        ecosystem=ecosystem,
        aliases=normalize_advisory_aliases(vuln_id, alias_values),
        cwes=_ordered_unique(cwes),
        cpes=_ordered_unique(cpes),
        advisory_source="osv-scanner",
        advisory_url=primary_metadata.source_url,
        published_at=published_at,
        modified_at=modified_at,
        malicious=malicious,
    )


class OsvScannerParser:
    """Parse the native JSON output from ``osv-scanner --format json``."""

    def can_parse(self, data: Any) -> bool:
        if not isinstance(data, dict):
            return False
        results = data.get("results")
        if not isinstance(results, list) or not results:
            # An empty ``results`` list has no OSV-Scanner-specific marker and is
            # indistinguishable from many generic JSON reports.
            return False
        return all(_is_official_result_shape(result) for result in results)

    def parse(self, data: Any) -> list[Vulnerability]:
        if not isinstance(data, dict):
            return []
        results = data.get("results")
        if not isinstance(results, list):
            return []

        vulnerabilities: list[Vulnerability] = []
        seen: set[tuple[str, str, str]] = set()

        for result in results:
            if not isinstance(result, dict):
                continue
            packages = result.get("packages")
            if not isinstance(packages, list):
                continue

            for entry in packages:
                if not isinstance(entry, dict):
                    continue
                package = entry.get("package")
                if not isinstance(package, dict):
                    continue

                ecosystem = normalize_ecosystem(package.get("ecosystem"))
                package_name = _string(package.get("name")) or _affected_package_name(
                    entry,
                    ecosystem,
                )
                if not package_name:
                    continue
                package_version = _string(package.get("version")) or _string(package.get("commit"))

                for records in _group_records(entry):
                    vulnerability = _build_vulnerability(
                        records,
                        package_name=package_name,
                        package_version=package_version,
                        ecosystem=ecosystem,
                    )
                    if vulnerability is None:
                        continue

                    key = finding_key(
                        vulnerability.id,
                        vulnerability.package_name,
                        vulnerability.package_version,
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    vulnerabilities.append(vulnerability)

        return vulnerabilities
