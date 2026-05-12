from __future__ import annotations

from typing import Any

from ca9.advisory import extract_cwes, normalize_advisory_aliases
from ca9.models import Vulnerability, finding_key


class PipAuditParser:
    def can_parse(self, data: Any) -> bool:
        if not isinstance(data, dict):
            return False
        return "dependencies" in data and isinstance(data.get("dependencies"), list)

    def parse(self, data: Any) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        seen: set[tuple[str, str, str]] = set()

        for dep in data.get("dependencies", []):
            if not isinstance(dep, dict):
                continue
            pkg_name = dep.get("name", "")
            pkg_version = dep.get("version", "")

            for v in dep.get("vulns", []):
                if not isinstance(v, dict):
                    continue
                vuln_id = v.get("id", "")
                if not vuln_id:
                    continue
                key = finding_key(vuln_id, pkg_name, pkg_version)
                if key in seen:
                    continue
                seen.add(key)

                description = v.get("description", "")
                fix_versions = v.get("fix_versions", [])

                if description:
                    title = description[:120]
                else:
                    title = vuln_id
                if fix_versions:
                    title = f"{title} (fix: {', '.join(fix_versions)})"

                vulns.append(
                    Vulnerability(
                        id=vuln_id,
                        package_name=pkg_name,
                        package_version=pkg_version,
                        severity="unknown",
                        title=title,
                        description=description,
                        ecosystem="pypi",
                        aliases=normalize_advisory_aliases(vuln_id, v.get("aliases", [])),
                        cwes=extract_cwes(v),
                        advisory_source="pip-audit",
                    )
                )

        return vulns
