from __future__ import annotations

from typing import Any

from ca9.advisory import extract_cwes, normalize_advisory_aliases, normalize_ecosystem
from ca9.models import Vulnerability, finding_key
from ca9.parsers.base import normalize_dependency_chain, parse_package_ref


def _snyk_identifier_values(vuln: dict) -> list[str]:
    values: list[str] = []
    identifiers = vuln.get("identifiers", {})
    if isinstance(identifiers, dict):
        for key, raw in identifiers.items():
            if str(key).upper() not in ("CVE", "GHSA", "PYSEC"):
                continue
            if isinstance(raw, list):
                values.extend(str(v) for v in raw if v)
            elif isinstance(raw, str) and raw:
                values.append(raw)
    for key in ("id", "cve", "CVE", "ghsa", "GHSA"):
        value = vuln.get(key)
        if isinstance(value, str) and value:
            values.append(value)
    return values


class SnykParser:
    def can_parse(self, data: Any) -> bool:
        if isinstance(data, list):
            if data:
                data = data[0]
            else:
                data = {}
        return (
            isinstance(data, dict)
            and "vulnerabilities" in data
            and ("projectName" in data or "packageManager" in data)
        )

    def parse(self, data: Any) -> list[Vulnerability]:
        if isinstance(data, list):
            entries = data
        else:
            entries = [data]

        vulns: list[Vulnerability] = []
        seen: set[tuple[str, str, str]] = set()

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            project_name = entry.get("projectName")
            if not isinstance(project_name, str):
                project_name = None
            project_package_manager = entry.get("packageManager")
            for v in entry.get("vulnerabilities", []):
                if not isinstance(v, dict):
                    continue
                vuln_id = v.get("id", "")
                if not vuln_id:
                    continue
                pkg_name = v.get("packageName", v.get("moduleName", ""))
                pkg_version = v.get("version", "")
                ecosystem = normalize_ecosystem(v.get("packageManager", project_package_manager))
                key = finding_key(vuln_id, pkg_name, pkg_version)
                if key in seen:
                    continue
                seen.add(key)

                report_dependency_chain: tuple[str, ...] = ()
                report_dependency_kind: str | None = None
                raw_from = v.get("from")
                if isinstance(raw_from, list):
                    chain = []
                    for item in raw_from:
                        name = parse_package_ref(item)
                        if name:
                            chain.append(name)
                    report_dependency_chain = normalize_dependency_chain(
                        chain,
                        pkg_name,
                        project_name=project_name,
                    )
                    if report_dependency_chain:
                        if len(report_dependency_chain) == 1:
                            report_dependency_kind = "direct"
                        else:
                            report_dependency_kind = "transitive"

                vulns.append(
                    Vulnerability(
                        id=vuln_id,
                        package_name=pkg_name,
                        package_version=pkg_version,
                        severity=v.get("severity", "unknown"),
                        title=v.get("title", ""),
                        description=v.get("description", ""),
                        ecosystem=ecosystem,
                        aliases=normalize_advisory_aliases(vuln_id, _snyk_identifier_values(v)),
                        cwes=extract_cwes(v),
                        advisory_source="snyk",
                        advisory_url=v.get("url", ""),
                        published_at=v.get("publicationTime"),
                        modified_at=v.get("modificationTime"),
                        report_dependency_kind=report_dependency_kind,
                        report_dependency_chain=report_dependency_chain,
                    )
                )

        return vulns
