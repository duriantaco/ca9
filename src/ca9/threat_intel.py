from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

from ca9 import __version__
from ca9.models import ThreatIntelData

EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

CACHE_DIR = Path(os.environ.get("CA9_CACHE_DIR", Path.home() / ".cache" / "ca9" / "threat_intel"))
CACHE_TTL_SECONDS = 24 * 60 * 60  # 24 hours
EPSS_BATCH_SIZE = 100


def _ensure_cache_dir() -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _cache_path(name: str) -> Path:
    return CACHE_DIR / name


def _read_cache(name: str) -> dict | None:
    path = _cache_path(name)
    if not path.is_file():
        return None
    try:
        stat = path.stat()
        if time.time() - stat.st_mtime > CACHE_TTL_SECONDS:
            return None
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _read_stale_cache(name: str) -> dict | None:
    path = _cache_path(name)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _write_cache(name: str, data: dict) -> None:
    _ensure_cache_dir()
    import contextlib

    with contextlib.suppress(OSError):
        _cache_path(name).write_text(json.dumps(data))


def _http_get(url: str, timeout: int = 15) -> bytes | None:
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": f"ca9-security-tool/{__version__}"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except (urllib.error.URLError, OSError, TimeoutError):
        return None


def _fetch_epss_batch(cve_ids: list[str]) -> dict[str, tuple[float, float]]:
    """Fetch EPSS scores for a batch of CVE IDs. Returns {cve_id: (score, percentile)}."""
    results: dict[str, tuple[float, float]] = {}

    for i in range(0, len(cve_ids), EPSS_BATCH_SIZE):
        batch = cve_ids[i : i + EPSS_BATCH_SIZE]
        cve_param = ",".join(batch)
        url = f"{EPSS_API_URL}?cve={cve_param}"

        raw = _http_get(url)
        if raw is None:
            continue

        try:
            data = json.loads(raw)
            for item in data.get("data", []):
                cve = item.get("cve", "")
                score = float(item.get("epss", 0))
                percentile = float(item.get("percentile", 0))
                results[cve] = (score, percentile)
        except (json.JSONDecodeError, ValueError, TypeError):
            continue

    return results


def _fetch_kev_catalog() -> dict[str, str]:
    """Fetch CISA KEV catalog. Returns {cve_id: due_date}."""
    cache_name = "kev_catalog.json"
    cached = _read_cache(cache_name)
    if cached is not None:
        return cached

    raw = _http_get(KEV_URL, timeout=30)
    if raw is None:
        stale = _read_stale_cache(cache_name)
        return stale or {}

    try:
        data = json.loads(raw)
        kev_index: dict[str, str] = {}
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "")
            due_date = vuln.get("dueDate", "")
            if cve_id:
                kev_index[cve_id] = due_date

        _write_cache(cache_name, kev_index)
        return kev_index
    except (json.JSONDecodeError, ValueError):
        stale = _read_stale_cache(cache_name)
        return stale or {}


def fetch_threat_intel_batch(cve_ids: list[str]) -> dict[str, ThreatIntelData]:
    """Fetch EPSS + KEV data for a batch of CVE IDs."""
    if not cve_ids:
        return {}

    # Check EPSS cache
    epss_cache_name = "epss_batch.json"
    epss_cached = _read_cache(epss_cache_name) or {}

    uncached_cves = [c for c in cve_ids if c not in epss_cached]
    if uncached_cves:
        fresh_epss = _fetch_epss_batch(uncached_cves)
        for cve, (score, pctl) in fresh_epss.items():
            epss_cached[cve] = [score, pctl]
        _write_cache(epss_cache_name, epss_cached)

    kev_index = _fetch_kev_catalog()

    results: dict[str, ThreatIntelData] = {}
    for cve_id in cve_ids:
        epss_entry = epss_cached.get(cve_id)
        epss_score = epss_entry[0] if epss_entry else None
        epss_pctl = epss_entry[1] if epss_entry else None

        in_kev = cve_id in kev_index
        kev_due = kev_index.get(cve_id) or None

        results[cve_id] = ThreatIntelData(
            epss_score=epss_score,
            epss_percentile=epss_pctl,
            in_kev=in_kev,
            kev_due_date=kev_due,
        )

    return results
