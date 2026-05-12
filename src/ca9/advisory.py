from __future__ import annotations

import re
import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

if TYPE_CHECKING:
    from ca9.models import Vulnerability


_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_GHSA_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$", re.I)
_CWE_RE = re.compile(r"\bCWE[-_ ]?(\d+)\b", re.I)
_CPE_RE = re.compile(r"\bcpe:(?:2\.3:|/)[^\s\"')\],;]+", re.I)

_CA9_CACHE_KEY = "_ca9_cache"


@dataclass(frozen=True)
class AdvisoryMetadata:
    aliases: tuple[str, ...] = ()
    cwes: tuple[str, ...] = ()
    cpes: tuple[str, ...] = ()
    source: str = ""
    source_url: str = ""
    published_at: str | None = None
    modified_at: str | None = None
    fetched_at: str | None = None
    cache_stale: bool | None = None


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_advisory_id(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if _CVE_RE.match(text) or _GHSA_RE.match(text) or text.upper().startswith("PYSEC-"):
        return text.upper()
    return text


def _advisory_sort_key(value: str) -> tuple[int, str]:
    upper = value.upper()
    if upper.startswith("CVE-"):
        return (0, upper)
    if upper.startswith("GHSA-"):
        return (1, upper)
    if upper.startswith("PYSEC-"):
        return (2, upper)
    return (3, upper)


def normalize_advisory_aliases(primary_id: str, aliases: Iterable[Any]) -> tuple[str, ...]:
    primary = normalize_advisory_id(primary_id)
    normalized: set[str] = set()
    for alias in aliases:
        value = normalize_advisory_id(alias)
        if value and value != primary:
            normalized.add(value)
    return tuple(sorted(normalized, key=_advisory_sort_key))


def advisory_ids_for_matching(vuln: Vulnerability) -> frozenset[str]:
    ids = {vuln.id, *vuln.aliases}
    return frozenset(v for v in (normalize_advisory_id(i) for i in ids) if v)


def extract_cwes(data: Any) -> tuple[str, ...]:
    cwes: set[str] = set()

    def visit(value: Any, key_hint: str = "") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                visit(child, str(key).lower())
            return
        if isinstance(value, list | tuple | set):
            for child in value:
                visit(child, key_hint)
            return
        if isinstance(value, int) and "cwe" in key_hint:
            cwes.add(f"CWE-{value}")
            return
        if not isinstance(value, str):
            return

        for match in _CWE_RE.findall(value):
            cwes.add(f"CWE-{int(match)}")
        if "cwe" in key_hint and value.isdigit():
            cwes.add(f"CWE-{int(value)}")

    visit(data)
    return tuple(sorted(cwes, key=lambda cwe: int(cwe.split("-", 1)[1])))


def extract_cpes(data: Any) -> tuple[str, ...]:
    cpes: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for child in value.values():
                visit(child)
            return
        if isinstance(value, list | tuple | set):
            for child in value:
                visit(child)
            return
        if not isinstance(value, str):
            return
        cpes.update(match.group(0) for match in _CPE_RE.finditer(value))

    visit(data)
    return tuple(sorted(cpes))


def attach_cache_freshness(
    data: dict,
    *,
    source: str,
    ttl_seconds: int,
    path: Path | None = None,
    fetched_at: str | None = None,
) -> dict:
    enriched = dict(data)
    cache_info: dict[str, Any] = {
        "source": source,
        "ttl_seconds": ttl_seconds,
    }

    if path is not None:
        try:
            stat = path.stat()
            fetched_ts = stat.st_mtime
            age_seconds = max(0, int(time.time() - fetched_ts))
            cache_info["fetched_at"] = (
                datetime.fromtimestamp(fetched_ts, timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z")
            )
            cache_info["age_seconds"] = age_seconds
            cache_info["cache_stale"] = age_seconds > ttl_seconds
            cache_info["cache_path"] = str(path)
        except OSError:
            cache_info["fetched_at"] = fetched_at or utc_now_iso()
            cache_info["cache_stale"] = None
    else:
        cache_info["fetched_at"] = fetched_at or utc_now_iso()
        cache_info["cache_stale"] = False

    enriched[_CA9_CACHE_KEY] = cache_info
    return enriched


def metadata_from_osv(data: dict, primary_id: str) -> AdvisoryMetadata:
    cache = data.get(_CA9_CACHE_KEY)
    if not isinstance(cache, dict):
        cache = {}

    source = str(cache.get("source") or "osv.dev")
    source_id = _string_or_none(data.get("id")) or normalize_advisory_id(primary_id)
    if source_id:
        source_url = f"https://osv.dev/vulnerability/{source_id}"
    else:
        source_url = ""

    aliases = data.get("aliases", [])
    if not isinstance(aliases, list):
        aliases = []

    return AdvisoryMetadata(
        aliases=normalize_advisory_aliases(primary_id, aliases),
        cwes=extract_cwes(data),
        cpes=extract_cpes(data),
        source=source,
        source_url=source_url,
        published_at=_string_or_none(data.get("published")),
        modified_at=_string_or_none(data.get("modified")),
        fetched_at=_string_or_none(cache.get("fetched_at")),
        cache_stale=cache.get("cache_stale")
        if isinstance(cache.get("cache_stale"), bool)
        else None,
    )


def normalize_ecosystem(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    if text in ("python", "python-pkg", "pip", "pypi"):
        return "pypi"
    if text in ("node", "nodejs", "npm", "yarn", "pnpm"):
        return "npm"
    if text in ("maven", "gradle", "java"):
        return "maven"
    if text in ("go", "golang", "go-module"):
        return "go"
    if text in ("rust", "cargo"):
        return "cargo"
    if text in ("docker", "container", "oci"):
        return "oci"
    if text in ("debian", "ubuntu", "deb"):
        return "deb"
    if text in ("redhat", "red hat", "rhel", "centos", "fedora", "rpm"):
        return "rpm"
    if text in ("alpine", "apk"):
        return "apk"
    return text


def ecosystem_to_purl_type(ecosystem: str) -> str:
    normalized = normalize_ecosystem(ecosystem)
    return {
        "pypi": "pypi",
        "npm": "npm",
        "maven": "maven",
        "go": "golang",
        "cargo": "cargo",
        "oci": "oci",
        "deb": "deb",
        "rpm": "rpm",
        "apk": "apk",
    }.get(normalized, normalized or "generic")


def _quote_purl_segment(value: str) -> str:
    return quote(value, safe="")


def _quote_purl_path(value: str) -> str:
    return "/".join(_quote_purl_segment(part) for part in value.split("/") if part)


def package_purl(package_name: str, package_version: str, ecosystem: str = "pypi") -> str:
    purl_type = ecosystem_to_purl_type(ecosystem)
    version_part = f"@{quote(package_version, safe='.+-_:~')}" if package_version else ""

    if purl_type == "pypi":
        return f"pkg:pypi/{_quote_purl_segment(package_name.lower())}{version_part}"

    if purl_type == "npm":
        if package_name.startswith("@") and "/" in package_name:
            namespace, name = package_name.split("/", 1)
            return (
                f"pkg:npm/{_quote_purl_segment(namespace)}/"
                f"{_quote_purl_segment(name)}{version_part}"
            )
        return f"pkg:npm/{_quote_purl_segment(package_name)}{version_part}"

    if purl_type == "maven":
        if ":" in package_name:
            namespace, name = package_name.split(":", 1)
            return (
                f"pkg:maven/{_quote_purl_segment(namespace)}/"
                f"{_quote_purl_segment(name)}{version_part}"
            )
        if "/" in package_name:
            namespace, name = package_name.rsplit("/", 1)
            return (
                f"pkg:maven/{_quote_purl_path(namespace)}/{_quote_purl_segment(name)}{version_part}"
            )
        return f"pkg:maven/{_quote_purl_segment(package_name)}{version_part}"

    return f"pkg:{purl_type}/{_quote_purl_path(package_name)}{version_part}"


def _string_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None
