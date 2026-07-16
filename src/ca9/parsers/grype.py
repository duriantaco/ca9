from __future__ import annotations

from typing import Any
from urllib.parse import unquote

from ca9.advisory import (
    extract_cpes,
    extract_cwes,
    normalize_advisory_aliases,
    normalize_ecosystem,
)
from ca9.models import Vulnerability, finding_key

_GRYPE_SCHEMA_MARKERS = (
    "github.com/anchore/grype/",
    "raw.githubusercontent.com/anchore/grype/",
)

_ARTIFACT_ECOSYSTEMS = {
    "python": "pypi",
    "python-package": "pypi",
    "npm": "npm",
    "node": "npm",
    "nodejs": "npm",
    "java": "maven",
    "java-archive": "maven",
    "maven": "maven",
    "go": "go",
    "go-module": "go",
    "golang": "go",
    "rust": "cargo",
    "rust-crate": "cargo",
    "cargo": "cargo",
    "ruby": "gem",
    "gem": "gem",
    "dotnet": "nuget",
    "nuget": "nuget",
    "php-composer": "composer",
    "composer": "composer",
    "deb": "deb",
    "rpm": "rpm",
    "apk": "apk",
}

_PURL_ECOSYSTEMS = {
    "pypi": "pypi",
    "npm": "npm",
    "maven": "maven",
    "golang": "go",
    "go": "go",
    "cargo": "cargo",
    "gem": "gem",
    "nuget": "nuget",
    "composer": "composer",
    "deb": "deb",
    "rpm": "rpm",
    "apk": "apk",
}

_NORMALIZED_ECOSYSTEMS = {
    "pypi",
    "npm",
    "maven",
    "go",
    "cargo",
    "oci",
    "deb",
    "rpm",
    "apk",
}


def _text(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()


def _schema_url(data: dict) -> str:
    schema = data.get("schema")
    if isinstance(schema, dict):
        return _text(schema.get("url"))
    return _text(schema)


def _has_grype_identity(data: dict) -> bool:
    descriptor = data.get("descriptor")
    if isinstance(descriptor, dict) and _text(descriptor.get("name")).lower() == "grype":
        return True

    schema_url = _schema_url(data).lower()
    return any(marker in schema_url for marker in _GRYPE_SCHEMA_MARKERS)


def _parse_purl(value: Any) -> tuple[str, str, str]:
    """Return (name, version, ecosystem) from the useful core of a purl.

    This intentionally does not try to implement the complete purl specification. Grype
    already supplies a normalized package name and version in normal reports; the purl is
    only a conservative fallback and a stronger ecosystem signal.
    """

    purl = _text(value)
    if not purl.lower().startswith("pkg:"):
        return "", "", ""

    body = purl[4:].split("#", 1)[0].split("?", 1)[0]
    if "/" not in body:
        return "", "", ""

    purl_type, package_ref = body.split("/", 1)
    ecosystem = _PURL_ECOSYSTEMS.get(purl_type.lower(), "")
    if not ecosystem or not package_ref:
        return "", "", ""

    # A standards-compliant npm purl percent-encodes the scope's leading @, but
    # accepting the common unencoded spelling is cheap and avoids treating the
    # scope as a version when no version suffix exists.
    if ecosystem == "npm" and package_ref.startswith("@") and package_ref.count("@") == 1:
        name, version = package_ref, ""
    elif "@" in package_ref:
        name, version = package_ref.rsplit("@", 1)
    else:
        name, version = package_ref, ""

    name = unquote(name).strip()
    version = unquote(version).strip()
    if not name:
        return "", "", ""
    return name, version, ecosystem


def _artifact_type_ecosystem(artifact: dict) -> str:
    artifact_type = _text(artifact.get("type")).lower()
    if artifact_type in _ARTIFACT_ECOSYSTEMS:
        return _ARTIFACT_ECOSYSTEMS[artifact_type]

    normalized_type = normalize_ecosystem(artifact_type)
    if normalized_type in _NORMALIZED_ECOSYSTEMS:
        return normalized_type

    language = _text(artifact.get("language")).lower()
    if language in _ARTIFACT_ECOSYSTEMS:
        return _ARTIFACT_ECOSYSTEMS[language]

    normalized_language = normalize_ecosystem(language)
    if normalized_language in _NORMALIZED_ECOSYSTEMS:
        return normalized_language
    return ""


def _artifact_identity(artifact: dict) -> tuple[str, str, str]:
    purl_name, purl_version, purl_ecosystem = _parse_purl(artifact.get("purl"))
    package_name = _text(artifact.get("name")) or purl_name
    package_version = _text(artifact.get("version")) or purl_version
    type_ecosystem = _artifact_type_ecosystem(artifact)

    # Conflicting metadata is not safe evidence that this is a Python distribution.
    # Preserve the package, but leave its ecosystem unknown so callers do not silently
    # apply PyPI-specific reasoning.
    if purl_ecosystem and type_ecosystem and purl_ecosystem != type_ecosystem:
        ecosystem = ""
    else:
        ecosystem = purl_ecosystem or type_ecosystem

    return package_name, package_version, ecosystem


def _severity(value: Any) -> str:
    severity = _text(value).lower()
    return severity or "unknown"


def _alias_values(match: dict, vulnerability: dict) -> list[str]:
    aliases: list[str] = []

    raw_aliases = vulnerability.get("aliases")
    if isinstance(raw_aliases, list):
        aliases.extend(_text(alias) for alias in raw_aliases if _text(alias))

    related = match.get("relatedVulnerabilities")
    if isinstance(related, list):
        for item in related:
            if isinstance(item, dict):
                related_id = _text(item.get("id"))
                if related_id:
                    aliases.append(related_id)

    advisories = vulnerability.get("advisories")
    if isinstance(advisories, list):
        for advisory in advisories:
            if isinstance(advisory, dict):
                advisory_id = _text(advisory.get("id"))
                if advisory_id:
                    aliases.append(advisory_id)
            elif _text(advisory):
                aliases.append(_text(advisory))

    return aliases


def _reference_values(match: dict, vulnerability: dict) -> tuple[str, ...]:
    references: list[str] = []

    urls = vulnerability.get("urls")
    if isinstance(urls, list):
        references.extend(_text(url) for url in urls if _text(url))

    advisories = vulnerability.get("advisories")
    if isinstance(advisories, list):
        for advisory in advisories:
            if not isinstance(advisory, dict):
                continue
            for key in ("link", "url"):
                url = _text(advisory.get(key))
                if url:
                    references.append(url)

    known_exploited = vulnerability.get("knownExploited")
    if isinstance(known_exploited, list):
        for record in known_exploited:
            if not isinstance(record, dict):
                continue
            record_urls = record.get("urls")
            if isinstance(record_urls, list):
                references.extend(_text(url) for url in record_urls if _text(url))

    related = match.get("relatedVulnerabilities")
    if isinstance(related, list):
        for item in related:
            if not isinstance(item, dict):
                continue
            related_urls = item.get("urls")
            if isinstance(related_urls, list):
                references.extend(_text(url) for url in related_urls if _text(url))

    # dict.fromkeys keeps Grype's source order while removing duplicate URLs.
    return tuple(dict.fromkeys(references))


class GrypeParser:
    def can_parse(self, data: Any) -> bool:
        return (
            isinstance(data, dict)
            and isinstance(data.get("matches"), list)
            and _has_grype_identity(data)
        )

    def parse(self, data: Any) -> list[Vulnerability]:
        if not isinstance(data, dict) or not isinstance(data.get("matches"), list):
            return []

        vulns: list[Vulnerability] = []
        seen: set[tuple[str, str, str]] = set()

        for match in data["matches"]:
            if not isinstance(match, dict):
                continue
            vulnerability = match.get("vulnerability")
            artifact = match.get("artifact")
            if not isinstance(vulnerability, dict) or not isinstance(artifact, dict):
                continue

            vuln_id = _text(vulnerability.get("id"))
            package_name, package_version, ecosystem = _artifact_identity(artifact)
            if not vuln_id or not package_name:
                continue

            key = finding_key(vuln_id, package_name, package_version)
            if key in seen:
                continue
            seen.add(key)

            description = _text(vulnerability.get("description"))
            title = (
                _text(vulnerability.get("title"))
                or _text(vulnerability.get("summary"))
                or description[:120]
                or vuln_id
            )
            advisory_url = _text(vulnerability.get("dataSource"))
            references = _reference_values(match, vulnerability)
            if not advisory_url and references:
                advisory_url = references[0]

            published_at = _text(vulnerability.get("publishedDate", vulnerability.get("published")))
            modified_at = _text(
                vulnerability.get("lastModifiedDate", vulnerability.get("modified"))
            )

            vulns.append(
                Vulnerability(
                    id=vuln_id,
                    package_name=package_name,
                    package_version=package_version,
                    severity=_severity(vulnerability.get("severity")),
                    title=title,
                    description=description,
                    ecosystem=ecosystem,
                    aliases=normalize_advisory_aliases(
                        vuln_id, _alias_values(match, vulnerability)
                    ),
                    cwes=extract_cwes(vulnerability),
                    cpes=extract_cpes({"vulnerability": vulnerability, "artifact": artifact}),
                    advisory_source="grype",
                    advisory_url=advisory_url,
                    published_at=published_at or None,
                    modified_at=modified_at or None,
                    references=references,
                )
            )

        return vulns
