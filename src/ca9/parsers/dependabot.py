from __future__ import annotations

from typing import Any

from ca9.advisory import extract_cwes, normalize_advisory_aliases, normalize_ecosystem
from ca9.models import Vulnerability, finding_key


def _github_identifier_values(advisory: dict) -> list[str]:
    values: list[str] = []
    for item in advisory.get("identifiers", []):
        if isinstance(item, dict):
            value = item.get("value")
            if isinstance(value, str) and value:
                values.append(value)
    for key in ("ghsa_id", "cve_id"):
        value = advisory.get(key)
        if isinstance(value, str) and value:
            values.append(value)
    return values


class DependabotParser:
    def can_parse(self, data: Any) -> bool:
        if not isinstance(data, list) or not data:
            return False
        first = data[0]
        return isinstance(first, dict) and (
            "security_advisory" in first or "security_vulnerability" in first
        )

    def parse(self, data: Any) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        seen: set[tuple[str, str, str]] = set()

        for alert in data:
            if not isinstance(alert, dict):
                continue
            advisory = alert.get("security_advisory", {})
            sec_vuln = alert.get("security_vulnerability", {})
            dep = alert.get("dependency", {})

            pkg = sec_vuln.get("package", dep.get("package", {}))
            vuln_id = advisory.get(
                "ghsa_id", advisory.get("cve_id", f"ALERT-{alert.get('number', '?')}")
            )
            pkg_name = pkg.get("name", "")
            pkg_version = sec_vuln.get("vulnerable_version_range", "")
            ecosystem = normalize_ecosystem(pkg.get("ecosystem", ""))
            relationship = dep.get("relationship")
            if relationship == "indirect":
                relationship = "transitive"
            if relationship not in ("direct", "transitive"):
                relationship = None

            if relationship == "direct":
                report_dependency_chain = (pkg_name,)
            else:
                report_dependency_chain = ()

            key = finding_key(vuln_id, pkg_name, pkg_version)
            if key in seen:
                continue
            seen.add(key)

            vulns.append(
                Vulnerability(
                    id=vuln_id,
                    package_name=pkg_name,
                    package_version=pkg_version,
                    severity=advisory.get("severity", "unknown"),
                    title=advisory.get("summary", ""),
                    description=advisory.get("description", ""),
                    ecosystem=ecosystem,
                    aliases=normalize_advisory_aliases(
                        vuln_id, _github_identifier_values(advisory)
                    ),
                    cwes=extract_cwes(advisory),
                    advisory_source="github_advisory",
                    advisory_url=advisory.get("html_url", "") or advisory.get("url", ""),
                    published_at=advisory.get("published_at"),
                    modified_at=advisory.get("updated_at"),
                    report_dependency_kind=relationship,
                    report_dependency_chain=report_dependency_chain,
                )
            )

        return vulns
