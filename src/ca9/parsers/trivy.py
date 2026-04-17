from __future__ import annotations

from pathlib import Path
from typing import Any

from ca9.models import Vulnerability, finding_key
from ca9.parsers.base import normalize_dependency_chain, parse_package_ref

_DIRECT_MANIFEST_TARGETS = {
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-prod.txt",
    "requirements.in",
    "setup.py",
    "pyproject.toml",
    "pipfile",
}


def _trivy_dependency_chain(vuln: dict, pkg_name: str) -> tuple[str, ...]:
    dependency_path = vuln.get("DependencyPath")
    if isinstance(dependency_path, list):
        chain = []
        for item in dependency_path:
            name = parse_package_ref(item)
            if name:
                chain.append(name)
        return normalize_dependency_chain(chain, pkg_name)

    pkg_path = vuln.get("PkgPath")
    if isinstance(pkg_path, str) and pkg_path:
        raw_parts = [part.strip() for part in pkg_path.replace("->", ">").split(">")]
        chain = []
        for part in raw_parts:
            name = parse_package_ref(part)
            if name:
                chain.append(name)
        return normalize_dependency_chain(chain, pkg_name)

    return ()


def _target_implies_direct_dependency(target: str) -> bool:
    if not target:
        return False
    return Path(target).name.lower() in _DIRECT_MANIFEST_TARGETS


class TrivyParser:
    def can_parse(self, data: Any) -> bool:
        if not isinstance(data, dict):
            return False
        return "Results" in data or (
            "SchemaVersion" in data and "results" in {k.lower() for k in data}
        )

    def parse(self, data: Any) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        seen: set[tuple[str, str, str]] = set()

        for result in data.get("Results", []):
            if not isinstance(result, dict):
                continue
            target = result.get("Target", "")
            for v in result.get("Vulnerabilities", []):
                if not isinstance(v, dict):
                    continue
                vuln_id = v.get("VulnerabilityID", "")
                if not vuln_id:
                    continue
                pkg_name = v.get("PkgName", "")
                pkg_version = v.get("InstalledVersion", "")
                key = finding_key(vuln_id, pkg_name, pkg_version)
                if key in seen:
                    continue
                seen.add(key)

                report_dependency_chain = _trivy_dependency_chain(v, pkg_name)
                if report_dependency_chain:
                    if len(report_dependency_chain) == 1:
                        report_dependency_kind = "direct"
                    else:
                        report_dependency_kind = "transitive"
                elif _target_implies_direct_dependency(target):
                    report_dependency_kind = "direct"
                    report_dependency_chain = (pkg_name,)
                else:
                    report_dependency_kind = None

                vulns.append(
                    Vulnerability(
                        id=vuln_id,
                        package_name=pkg_name,
                        package_version=pkg_version,
                        severity=v.get("Severity", "unknown").lower(),
                        title=v.get("Title", ""),
                        description=v.get("Description", ""),
                        report_dependency_kind=report_dependency_kind,
                        report_dependency_chain=report_dependency_chain,
                    )
                )

        return vulns
