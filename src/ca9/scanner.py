from __future__ import annotations

import importlib.metadata
import json
import os
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from ca9.advisory import attach_cache_freshness, metadata_from_osv, normalize_ecosystem
from ca9.analysis.ast_scanner import discover_declared_dependency_inventory
from ca9.models import VersionRange, Vulnerability, finding_key

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"

CACHE_DIR = Path(os.environ.get("CA9_CACHE_DIR", Path.home() / ".cache" / "ca9" / "osv"))
CACHE_TTL_SECONDS = 24 * 60 * 60  # 24 hours
DEFAULT_MAX_WORKERS = 8
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 0.5
OSV_ECOSYSTEM_NAMES = {
    "pypi": "PyPI",
    "npm": "npm",
}
# OSV rejects querybatch requests with more than 1000 queries (HTTP 400).
OSV_BATCH_MAX_QUERIES = 1000
OSV_BATCH_MAX_ATTEMPTS = 5
OSV_BATCH_MAX_BACKOFF_SECONDS = 8.0
# Bound next_page_token follow-ups so a misbehaving server cannot loop forever.
OSV_BATCH_MAX_PAGES = 50
_RETRYABLE_HTTP_CODES = (429, 500, 502, 503, 504)
_VERSION_RANGE_TYPES = ("ECOSYSTEM", "SEMVER")


@dataclass(frozen=True)
class ScanInventory:
    packages: tuple[tuple[str, str], ...]
    source: str
    warnings: tuple[str, ...] = ()
    declared_dependencies: int = 0
    pinned_dependencies: int = 0
    environment_fallbacks: int = 0
    unresolved_dependencies: tuple[str, ...] = ()


def get_installed_packages() -> list[tuple[str, str]]:
    packages: list[tuple[str, str]] = []
    for dist in importlib.metadata.distributions():
        name = dist.metadata["Name"]
        version = dist.metadata["Version"]
        if name and version:
            packages.append((name, version))
    return packages


def resolve_scan_inventory(
    repo_path: Path,
    *,
    allow_environment_fallback: bool = False,
) -> ScanInventory:
    declared = discover_declared_dependency_inventory(repo_path)
    installed_packages = get_installed_packages()

    if not declared:
        if not allow_environment_fallback:
            return ScanInventory(
                packages=(),
                source="none",
                warnings=("no declared dependencies with exact versions were found",),
            )
        return ScanInventory(
            packages=tuple(installed_packages),
            source="environment",
            warnings=(
                "no declared dependencies were found in the target repo; fell back to installed environment packages",
            ),
        )

    installed_by_name = {
        canonicalize_name(name): (name, version)
        for name, version in installed_packages
        if name and version
    }

    packages: list[tuple[str, str]] = []
    unresolved: list[str] = []
    pinned = 0
    env_fallbacks = 0

    for key, (name, version) in sorted(declared.items()):
        if version:
            packages.append((name, version))
            pinned += 1
            continue

        installed = installed_by_name.get(key) if allow_environment_fallback else None
        if installed is not None:
            packages.append((name, installed[1]))
            env_fallbacks += 1
            continue

        unresolved.append(name)

    warnings: list[str] = []
    if env_fallbacks:
        warnings.append(
            "used installed environment versions for "
            f"{env_fallbacks} declared package(s) without exact manifest pins"
        )
    if unresolved:
        sample = ", ".join(sorted(unresolved)[:5])
        suffix = " ..." if len(unresolved) > 5 else ""
        warnings.append(
            "skipped declared package(s) with no exact version and no matching installed distribution: "
            f"{sample}{suffix}"
        )

    if packages:
        return ScanInventory(
            packages=tuple(packages),
            source="repo",
            warnings=tuple(warnings),
            declared_dependencies=len(declared),
            pinned_dependencies=pinned,
            environment_fallbacks=env_fallbacks,
            unresolved_dependencies=tuple(sorted(unresolved)),
        )

    if allow_environment_fallback:
        return ScanInventory(
            packages=tuple(installed_packages),
            source="environment",
            warnings=(
                "declared dependencies were found, but none had resolvable versions; "
                "fell back to installed environment packages",
            ),
            declared_dependencies=len(declared),
            unresolved_dependencies=tuple(sorted(unresolved)),
        )

    return ScanInventory(
        packages=(),
        source="none",
        warnings=tuple(warnings)
        or ("declared dependencies were found, but none had exact versions to scan",),
        declared_dependencies=len(declared),
        unresolved_dependencies=tuple(sorted(unresolved)),
    )


def _extract_severity(osv_vuln: dict) -> str:
    db_specific = osv_vuln.get("database_specific", {})
    if isinstance(db_specific, dict):
        sev = db_specific.get("severity")
        if isinstance(sev, str) and sev.lower() in ("critical", "high", "medium", "low"):
            return sev.lower()

    for sev in osv_vuln.get("severity", []):
        score_str = sev.get("score", "")
        if sev.get("type") in ("CVSS_V3", "CVSS_V4"):
            score = _parse_cvss_score(score_str)
            if score is not None:
                return _cvss_to_level(score)

    for affected in osv_vuln.get("affected", []):
        eco = affected.get("ecosystem_specific", {})
        if isinstance(eco, dict):
            sev = eco.get("severity")
            if isinstance(sev, str) and sev.lower() in ("critical", "high", "medium", "low"):
                return sev.lower()

    return "unknown"


def _parse_cvss_score(vector: str) -> float | None:
    if not isinstance(vector, str) or not vector:
        return None

    try:
        return float(vector)
    except ValueError:
        pass

    if not vector.startswith("CVSS:3"):
        return None

    return _compute_cvss3_base_score(vector)


_CVSS3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_CVSS3_AC = {"L": 0.77, "H": 0.44}
_CVSS3_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_CVSS3_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_CVSS3_UI = {"N": 0.85, "R": 0.62}
_CVSS3_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _compute_cvss3_base_score(vector: str) -> float | None:
    import math

    parts = vector.split("/")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            return None
        key, val = part.split(":", 1)
        metrics[key] = val

    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not required.issubset(metrics):
        return None

    av = _CVSS3_AV.get(metrics["AV"])
    ac = _CVSS3_AC.get(metrics["AC"])
    ui = _CVSS3_UI.get(metrics["UI"])
    scope_changed = metrics["S"] == "C"

    if scope_changed:
        pr_table = _CVSS3_PR_CHANGED
    else:
        pr_table = _CVSS3_PR_UNCHANGED
    pr = pr_table.get(metrics["PR"])

    c = _CVSS3_CIA.get(metrics["C"])
    i = _CVSS3_CIA.get(metrics["I"])
    a = _CVSS3_CIA.get(metrics["A"])

    if any(v is None for v in (av, ac, pr, ui, c, i, a)):
        return None

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui

    if scope_changed:
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)

    return math.ceil(base * 10) / 10


def _cvss_to_level(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "unknown"


def _extract_version_ranges(
    osv_vuln: dict,
    package_name: str,
    ecosystem: str = "pypi",
) -> tuple[VersionRange, ...]:
    ranges: list[VersionRange] = []
    normalized_ecosystem = normalize_ecosystem(ecosystem) or "pypi"
    for affected in osv_vuln.get("affected", []):
        pkg = affected.get("package", {})
        if normalize_ecosystem(pkg.get("ecosystem", "")) != normalized_ecosystem:
            continue
        if pkg.get("name", "").lower() != package_name.lower():
            continue
        for r in affected.get("ranges", []):
            if r.get("type") != "ECOSYSTEM":
                continue
            introduced = ""
            for event in r.get("events", []):
                if "introduced" in event:
                    introduced = event["introduced"]
                elif "fixed" in event:
                    if introduced:
                        ranges.append(
                            VersionRange(
                                introduced=introduced,
                                fixed=event["fixed"],
                            )
                        )
                        introduced = ""
                elif "last_affected" in event:
                    if introduced:
                        ranges.append(
                            VersionRange(
                                introduced=introduced,
                                last_affected=event["last_affected"],
                            )
                        )
                        introduced = ""
            if introduced:
                ranges.append(VersionRange(introduced=introduced))
    return tuple(ranges)


def _extract_references(osv_vuln: dict) -> tuple[str, ...]:
    urls: list[str] = []
    for ref in osv_vuln.get("references", []):
        url = ref.get("url", "")
        if url:
            urls.append(url)
    return tuple(urls)


def _osv_ecosystem_name(ecosystem: str) -> str:
    normalized = normalize_ecosystem(ecosystem) or "pypi"
    return OSV_ECOSYSTEM_NAMES.get(normalized, ecosystem)


def _is_malicious_osv(data: dict, vuln_id: str = "") -> bool:
    """Classify an OSV record as malware from structured markers only.

    Free text is not evidence: ordinary advisories routinely say "malicious" or
    "exfiltrate" (SSRF, XSS, ...). Only ``MAL-`` ids/aliases (OpenSSF
    malicious-packages) and OSV's explicit malicious markers count.
    """
    aliases = data.get("aliases", [])
    if not isinstance(aliases, list):
        aliases = []
    advisory_ids = {vuln_id, str(data.get("id") or ""), *[str(a) for a in aliases]}
    if any(_is_malware_advisory_id(advisory_id) for advisory_id in advisory_ids):
        return True

    return _has_explicit_malicious_marker(data)


def _has_explicit_malicious_marker(data: dict) -> bool:
    database_specific = data.get("database_specific")
    if not isinstance(database_specific, dict):
        return False
    origins = database_specific.get("malicious-packages-origins")
    if isinstance(origins, list) and origins:
        return True
    return database_specific.get("malicious") is True


def _is_malware_advisory_id(value: str) -> bool:
    upper = value.upper()
    return upper.startswith("MAL-") or upper.startswith("PYSEC-MAL-")


def _cache_path(vuln_id: str) -> Path:
    safe_id = vuln_id.replace("/", "_").replace("\\", "_")
    return CACHE_DIR / f"{safe_id}.json"


def _read_cache(vuln_id: str, *, allow_stale: bool = False) -> dict | None:
    path = _cache_path(vuln_id)
    if not path.exists():
        return None
    try:
        stat = path.stat()
        is_stale = time.time() - stat.st_mtime > CACHE_TTL_SECONDS
        if is_stale and not allow_stale:
            return None
        data = json.loads(path.read_text())
        return attach_cache_freshness(
            data,
            source="osv.dev",
            ttl_seconds=CACHE_TTL_SECONDS,
            path=path,
        )
    except (OSError, json.JSONDecodeError):
        return None


def _write_cache(vuln_id: str, data: dict) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _cache_path(vuln_id).write_text(json.dumps(data))
    except OSError:
        pass


def _is_retryable(exc: Exception) -> bool:
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in (429, 500, 502, 503, 504)
    return isinstance(exc, urllib.error.URLError | OSError)


def _fetch_vuln_details(vuln_id: str, offline: bool = False) -> dict:
    cached = _read_cache(vuln_id)
    if cached is not None:
        return cached

    if offline:
        return _read_cache(vuln_id, allow_stale=True) or {}

    url = f"{OSV_VULN_URL}/{vuln_id}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})

    for attempt in range(MAX_RETRIES):
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
            _write_cache(vuln_id, data)
            return attach_cache_freshness(
                data,
                source="osv.dev",
                ttl_seconds=CACHE_TTL_SECONDS,
            )
        except Exception as exc:
            if attempt < MAX_RETRIES - 1 and _is_retryable(exc):
                time.sleep(RETRY_BACKOFF_BASE * (2**attempt))
                continue
            return _read_cache(vuln_id, allow_stale=True) or {}

    return {}


def _query_osv_batch_results(queries: list[dict]) -> list[list[dict]]:
    """Run OSV querybatch for any number of queries; return vulns per query, in order.

    Queries are sent in chunks of at most ``OSV_BATCH_MAX_QUERIES`` and any
    per-query ``next_page_token`` is followed until OSV reports no more pages.
    """
    results: list[list[dict]] = [[] for _ in queries]
    for start in range(0, len(queries), OSV_BATCH_MAX_QUERIES):
        pending = [
            (index, queries[index])
            for index in range(start, min(start + OSV_BATCH_MAX_QUERIES, len(queries)))
        ]
        pages = 0
        while pending:
            pages += 1
            if pages > OSV_BATCH_MAX_PAGES:
                raise ValueError(
                    f"OSV.dev returned more than {OSV_BATCH_MAX_PAGES} result pages; "
                    "refusing to continue with incomplete results"
                )
            data = _post_osv_batch([query for _, query in pending])
            batch_results = data.get("results") if isinstance(data, dict) else None
            if not isinstance(batch_results, list):
                batch_results = []
            next_pending: list[tuple[int, dict]] = []
            for (index, query), result in zip(pending, batch_results, strict=False):
                if not isinstance(result, dict):
                    continue
                vulns = result.get("vulns") or []
                if isinstance(vulns, list):
                    results[index].extend(v for v in vulns if isinstance(v, dict))
                token = result.get("next_page_token")
                if isinstance(token, str) and token:
                    next_pending.append((index, {**query, "page_token": token}))
            pending = next_pending
    return results


def _post_osv_batch(queries: list[dict]) -> dict:
    """POST one querybatch request, retrying 429/5xx with bounded exponential backoff."""
    payload = json.dumps({"queries": queries}).encode()
    for attempt in range(OSV_BATCH_MAX_ATTEMPTS):
        req = urllib.request.Request(
            OSV_BATCH_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code in _RETRYABLE_HTTP_CODES and attempt < OSV_BATCH_MAX_ATTEMPTS - 1:
                time.sleep(_osv_retry_delay(attempt, e))
                continue
            raise ConnectionError(f"OSV.dev API request failed: {e}") from e
        except (urllib.error.URLError, OSError) as e:
            raise ConnectionError(f"OSV.dev API request failed: {e}") from e
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError(f"OSV.dev returned malformed JSON: {e}") from e
    raise ConnectionError("OSV.dev API request failed: retries exhausted")


def _osv_retry_delay(attempt: int, error: urllib.error.HTTPError) -> float:
    delay = RETRY_BACKOFF_BASE * (2**attempt)
    retry_after = error.headers.get("Retry-After") if error.headers is not None else None
    if isinstance(retry_after, str) and retry_after.strip().isdigit():
        delay = max(delay, float(retry_after.strip()))
    return min(delay, OSV_BATCH_MAX_BACKOFF_SECONDS)


def query_osv_batch(
    packages: list[tuple[str, str]],
    offline: bool = False,
    refresh_cache: bool = False,
    max_workers: int = DEFAULT_MAX_WORKERS,
    ecosystem: str = "pypi",
) -> list[Vulnerability]:
    if not packages:
        return []

    normalized_ecosystem = normalize_ecosystem(ecosystem) or "pypi"

    if refresh_cache:
        try:
            if CACHE_DIR.exists():
                for f in CACHE_DIR.iterdir():
                    if f.suffix == ".json":
                        f.unlink(missing_ok=True)
        except OSError:
            pass

    if offline:
        return _query_from_cache_only(packages, ecosystem=normalized_ecosystem)

    osv_ecosystem = _osv_ecosystem_name(normalized_ecosystem)
    queries = [
        {"package": {"name": name, "ecosystem": osv_ecosystem}, "version": version}
        for name, version in packages
    ]

    seen_keys: set[tuple[str, str, str]] = set()
    vuln_refs: list[tuple[str, str, str]] = []

    for i, result_vulns in enumerate(_query_osv_batch_results(queries)):
        pkg_name, pkg_version = packages[i]

        for osv_vuln in result_vulns:
            vuln_id = osv_vuln.get("id", "")
            if not vuln_id:
                continue
            key = finding_key(vuln_id, pkg_name, pkg_version)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            vuln_refs.append((vuln_id, pkg_name, pkg_version))

    details_map: dict[str, dict] = {}
    unique_ids = list({vid for vid, _, _ in vuln_refs})

    if unique_ids:
        effective_workers = min(max_workers, len(unique_ids))
    else:
        effective_workers = 1
    with ThreadPoolExecutor(max_workers=effective_workers) as executor:
        future_to_id = {
            executor.submit(_fetch_vuln_details, vid, offline): vid for vid in unique_ids
        }
        for future in as_completed(future_to_id):
            vid = future_to_id[future]
            try:
                details_map[vid] = future.result()
            except Exception:
                details_map[vid] = {}

    vulns: list[Vulnerability] = []
    for vuln_id, pkg_name, pkg_version in vuln_refs:
        details = details_map.get(vuln_id, {})
        if details and "_ca9_cache" not in details:
            details = attach_cache_freshness(
                details,
                source="osv.dev",
                ttl_seconds=CACHE_TTL_SECONDS,
            )
        if details:
            severity = _extract_severity(details)
            title = details.get("summary", "") or details.get("details", "No description")[:120]
            description = details.get("details", "")
            affected_ranges = _extract_version_ranges(details, pkg_name, normalized_ecosystem)
            references = _extract_references(details)
            metadata = metadata_from_osv(details, vuln_id)
            malicious = _is_malicious_osv(details, vuln_id)
        else:
            severity = "unknown"
            title = vuln_id
            description = ""
            affected_ranges = ()
            references = ()
            metadata = metadata_from_osv({}, vuln_id)
            malicious = _is_malware_advisory_id(vuln_id)

        vulns.append(
            Vulnerability(
                id=vuln_id,
                package_name=pkg_name,
                package_version=pkg_version,
                severity=severity,
                title=title,
                description=description,
                ecosystem=normalized_ecosystem,
                aliases=metadata.aliases,
                cwes=metadata.cwes,
                cpes=metadata.cpes,
                advisory_source=metadata.source,
                advisory_url=metadata.source_url,
                published_at=metadata.published_at,
                modified_at=metadata.modified_at,
                fetched_at=metadata.fetched_at,
                cache_stale=metadata.cache_stale,
                affected_ranges=affected_ranges,
                references=references,
                malicious=malicious,
            )
        )

    return vulns


def _query_from_cache_only(
    packages: list[tuple[str, str]],
    ecosystem: str = "pypi",
) -> list[Vulnerability]:
    if not CACHE_DIR.exists():
        return []

    cached_vulns: dict[str, dict] = {}
    try:
        for path in CACHE_DIR.iterdir():
            if path.suffix != ".json":
                continue
            try:
                data = attach_cache_freshness(
                    json.loads(path.read_text()),
                    source="osv.dev",
                    ttl_seconds=CACHE_TTL_SECONDS,
                    path=path,
                )
                vuln_id = data.get("id", "")
                if vuln_id:
                    cached_vulns[vuln_id] = data
            except (json.JSONDecodeError, OSError):
                continue
    except OSError:
        return []

    if not cached_vulns:
        return []

    vulns: list[Vulnerability] = []
    seen_keys: set[tuple[str, str, str]] = set()
    normalized_ecosystem = normalize_ecosystem(ecosystem) or "pypi"

    for pkg_name, pkg_version in packages:
        for vuln_id, details in cached_vulns.items():
            if not _cached_advisory_affects(details, pkg_name, pkg_version, normalized_ecosystem):
                continue

            key = finding_key(vuln_id, pkg_name, pkg_version)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            metadata = metadata_from_osv(details, vuln_id)

            vulns.append(
                Vulnerability(
                    id=vuln_id,
                    package_name=pkg_name,
                    package_version=pkg_version,
                    severity=_extract_severity(details),
                    title=details.get("summary", "") or vuln_id,
                    description=details.get("details", ""),
                    ecosystem=normalized_ecosystem,
                    aliases=metadata.aliases,
                    cwes=metadata.cwes,
                    cpes=metadata.cpes,
                    advisory_source=metadata.source,
                    advisory_url=metadata.source_url,
                    published_at=metadata.published_at,
                    modified_at=metadata.modified_at,
                    fetched_at=metadata.fetched_at,
                    cache_stale=metadata.cache_stale,
                    affected_ranges=_extract_version_ranges(
                        details, pkg_name, normalized_ecosystem
                    ),
                    references=_extract_references(details),
                    malicious=_is_malicious_osv(details, vuln_id),
                )
            )

    return vulns


def _cached_advisory_affects(
    details: dict,
    package_name: str,
    package_version: str,
    ecosystem: str,
) -> bool:
    """Offline stand-in for OSV's server-side version matching.

    An ``affected`` entry matches when the version is listed explicitly, falls in
    an ECOSYSTEM/SEMVER range, or the entry has no version constraints at all
    (whole-package records). Versions ca9 cannot compare are kept, so offline
    mode errs toward reporting rather than silently dropping an advisory.
    """
    target = _comparable_package_name(package_name, ecosystem)
    for affected in details.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        pkg = affected.get("package") or {}
        if normalize_ecosystem(pkg.get("ecosystem", "")) != ecosystem:
            continue
        if _comparable_package_name(str(pkg.get("name") or ""), ecosystem) != target:
            continue
        if _affected_entry_includes(affected, package_version):
            return True
    return False


def _comparable_package_name(name: str, ecosystem: str) -> str:
    if ecosystem == "pypi":
        return str(canonicalize_name(name))
    return name.strip().lower()


def _affected_entry_includes(affected: dict, version: str) -> bool:
    versions = [str(v) for v in affected.get("versions") or []]
    ranges = [r for r in affected.get("ranges") or [] if isinstance(r, dict)]
    if not versions and not ranges:
        return True
    if version in versions:
        return True
    for osv_range in ranges:
        if osv_range.get("type") not in _VERSION_RANGE_TYPES:
            continue
        included = _osv_range_includes(osv_range.get("events") or [], version)
        if included is None or included:
            return True
    return False


def _osv_range_includes(events: list, version: str) -> bool | None:
    """Evaluate OSV range events for ``version``; None when versions cannot be compared."""
    installed = _parse_osv_version(version)
    if installed is None:
        return None
    bounds: list[tuple[str, Version | None]] = []
    limits: list[Version | None] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        for kind in ("introduced", "fixed", "last_affected", "limit"):
            if kind not in event:
                continue
            raw = str(event[kind])
            if (kind == "introduced" and raw == "0") or (kind == "limit" and raw == "*"):
                parsed = None
            else:
                parsed = _parse_osv_version(raw)
                if parsed is None:
                    return None
            if kind == "limit":
                limits.append(parsed)
            else:
                bounds.append((kind, parsed))

    # OSV evaluation: walk events in version order (introduced "0" first).
    affected = False
    for kind, bound in sorted(bounds, key=lambda item: (item[1] is not None, item[1] or 0)):
        if kind == "introduced":
            if bound is None or installed >= bound:
                affected = True
        elif kind == "fixed":
            if bound is not None and installed >= bound:
                affected = False
        elif bound is not None and installed > bound:
            affected = False
    if affected and limits:
        affected = any(limit is None or installed < limit for limit in limits)
    return affected


def _parse_osv_version(value: str) -> Version | None:
    try:
        return Version(value)
    except InvalidVersion:
        return None


def scan_installed(
    offline: bool = False,
    refresh_cache: bool = False,
    max_workers: int = DEFAULT_MAX_WORKERS,
) -> list[Vulnerability]:
    packages = get_installed_packages()
    return query_osv_batch(
        packages, offline=offline, refresh_cache=refresh_cache, max_workers=max_workers
    )


def scan_repository(
    repo_path: Path,
    offline: bool = False,
    refresh_cache: bool = False,
    max_workers: int = DEFAULT_MAX_WORKERS,
    allow_environment_fallback: bool = False,
) -> tuple[list[Vulnerability], ScanInventory]:
    inventory = resolve_scan_inventory(
        repo_path,
        allow_environment_fallback=allow_environment_fallback,
    )
    vulnerabilities = query_osv_batch(
        list(inventory.packages),
        offline=offline,
        refresh_cache=refresh_cache,
        max_workers=max_workers,
    )
    return vulnerabilities, inventory
