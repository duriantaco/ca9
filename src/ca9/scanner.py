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

from ca9.analysis.ast_scanner import discover_declared_dependency_inventory
from ca9.models import VersionRange, Vulnerability, finding_key

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"

CACHE_DIR = Path(os.environ.get("CA9_CACHE_DIR", Path.home() / ".cache" / "ca9" / "osv"))
CACHE_TTL_SECONDS = 24 * 60 * 60  # 24 hours
DEFAULT_MAX_WORKERS = 8
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 0.5


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


def resolve_scan_inventory(repo_path: Path) -> ScanInventory:
    declared = discover_declared_dependency_inventory(repo_path)
    installed_packages = get_installed_packages()

    if not declared:
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

        installed = installed_by_name.get(key)
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

    return ScanInventory(
        packages=tuple(installed_packages),
        source="environment",
        warnings=(
            "declared dependencies were found, but none had resolvable versions; fell back to installed environment packages",
        ),
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


def _extract_version_ranges(osv_vuln: dict, package_name: str) -> tuple[VersionRange, ...]:
    ranges: list[VersionRange] = []
    for affected in osv_vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem", "").lower() != "pypi":
            continue
        if pkg.get("name", "").lower() != package_name.lower():
            continue
        for r in affected.get("ranges", []):
            if r.get("type") != "ECOSYSTEM":
                continue
            introduced = ""
            fixed = ""
            last_affected = ""
            for event in r.get("events", []):
                if "introduced" in event:
                    introduced = event["introduced"]
                elif "fixed" in event:
                    fixed = event["fixed"]
                elif "last_affected" in event:
                    last_affected = event["last_affected"]
            if introduced:
                ranges.append(
                    VersionRange(
                        introduced=introduced,
                        fixed=fixed,
                        last_affected=last_affected,
                    )
                )
    return tuple(ranges)


def _extract_references(osv_vuln: dict) -> tuple[str, ...]:
    urls: list[str] = []
    for ref in osv_vuln.get("references", []):
        url = ref.get("url", "")
        if url:
            urls.append(url)
    return tuple(urls)


def _cache_path(vuln_id: str) -> Path:
    safe_id = vuln_id.replace("/", "_").replace("\\", "_")
    return CACHE_DIR / f"{safe_id}.json"


def _read_cache(vuln_id: str) -> dict | None:
    path = _cache_path(vuln_id)
    if not path.exists():
        return None
    try:
        stat = path.stat()
        if time.time() - stat.st_mtime > CACHE_TTL_SECONDS:
            return None
        return json.loads(path.read_text())
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
        return {}

    url = f"{OSV_VULN_URL}/{vuln_id}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})

    for attempt in range(MAX_RETRIES):
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
            _write_cache(vuln_id, data)
            return data
        except Exception as exc:
            if attempt < MAX_RETRIES - 1 and _is_retryable(exc):
                time.sleep(RETRY_BACKOFF_BASE * (2**attempt))
                continue
            return {}

    return {}


def query_osv_batch(
    packages: list[tuple[str, str]],
    offline: bool = False,
    refresh_cache: bool = False,
    max_workers: int = DEFAULT_MAX_WORKERS,
) -> list[Vulnerability]:
    if not packages:
        return []

    if refresh_cache:
        try:
            if CACHE_DIR.exists():
                for f in CACHE_DIR.iterdir():
                    if f.suffix == ".json":
                        f.unlink(missing_ok=True)
        except OSError:
            pass

    if offline:
        return _query_from_cache_only(packages)

    queries = [
        {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
        for name, version in packages
    ]

    payload = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        OSV_BATCH_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
        raise ConnectionError(f"OSV.dev API request failed: {e}") from e
    except json.JSONDecodeError as e:
        raise ValueError(f"OSV.dev returned malformed JSON: {e}") from e

    seen_keys: set[tuple[str, str, str]] = set()
    vuln_refs: list[tuple[str, str, str]] = []

    for i, result in enumerate(data.get("results", [])):
        if i < len(packages):
            pkg_name = packages[i][0]
        else:
            pkg_name = "unknown"
        if i < len(packages):
            pkg_version = packages[i][1]
        else:
            pkg_version = "unknown"

        for osv_vuln in result.get("vulns", []):
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
        if details:
            severity = _extract_severity(details)
        else:
            severity = "unknown"
        if details:
            title = details.get("summary", "") or details.get("details", "No description")[:120]
        else:
            title = vuln_id

        if details:
            description = details.get("details", "")
        else:
            description = ""

        if details:
            affected_ranges = _extract_version_ranges(details, pkg_name)
        else:
            affected_ranges = ()

        if details:
            references = _extract_references(details)
        else:
            references = ()

        vulns.append(
            Vulnerability(
                id=vuln_id,
                package_name=pkg_name,
                package_version=pkg_version,
                severity=severity,
                title=title,
                description=description,
                affected_ranges=affected_ranges,
                references=references,
            )
        )

    return vulns


def _query_from_cache_only(packages: list[tuple[str, str]]) -> list[Vulnerability]:
    if not CACHE_DIR.exists():
        return []

    cached_vulns: dict[str, dict] = {}
    try:
        for path in CACHE_DIR.iterdir():
            if path.suffix != ".json":
                continue
            if time.time() - path.stat().st_mtime > CACHE_TTL_SECONDS:
                continue
            try:
                data = json.loads(path.read_text())
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

    for pkg_name, pkg_version in packages:
        for vuln_id, details in cached_vulns.items():
            affected_pkgs = set()
            for affected in details.get("affected", []):
                pkg = affected.get("package", {})
                if pkg.get("ecosystem", "").lower() == "pypi":
                    affected_pkgs.add(pkg.get("name", "").lower())

            if pkg_name.lower() not in affected_pkgs:
                continue

            key = finding_key(vuln_id, pkg_name, pkg_version)
            if key in seen_keys:
                continue
            seen_keys.add(key)

            vulns.append(
                Vulnerability(
                    id=vuln_id,
                    package_name=pkg_name,
                    package_version=pkg_version,
                    severity=_extract_severity(details),
                    title=details.get("summary", "") or vuln_id,
                    description=details.get("details", ""),
                    affected_ranges=_extract_version_ranges(details, pkg_name),
                    references=_extract_references(details),
                )
            )

    return vulns


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
) -> tuple[list[Vulnerability], ScanInventory]:
    inventory = resolve_scan_inventory(repo_path)
    vulnerabilities = query_osv_batch(
        list(inventory.packages),
        offline=offline,
        refresh_cache=refresh_cache,
        max_workers=max_workers,
    )
    return vulnerabilities, inventory
