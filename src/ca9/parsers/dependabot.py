from __future__ import annotations

from typing import Any

from ca9.models import Vulnerability, finding_key


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
                    report_dependency_kind=relationship,
                    report_dependency_chain=report_dependency_chain,
                )
            )

        return vulns
