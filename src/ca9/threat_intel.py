"""Legacy adapter for dated EPSS/KEV context.

Undated numeric/map helper results are retained for compatibility, and cannot
establish freshness. Production batch lookup uses the dated contract only.
"""

from __future__ import annotations

import json
import time
from urllib.parse import parse_qs, urlsplit

from ca9 import risk_context as risk
from ca9.models import ThreatIntelData

EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_BATCH_SIZE = 16


def _read_cache(name: str) -> dict | None:
    """Undated legacy cache files are intentionally ignored, never migrated."""
    return None


def _read_stale_cache(name: str) -> dict | None:
    """Undated legacy cache files cannot establish provider freshness."""
    return None


def _write_cache(name: str, data: dict) -> None:
    """Only the dated risk-context cache is written by production lookups."""


def _http_get(url: str, timeout: int = 15) -> bytes | None:
    """Compatibility transport restricted to the two fixed provider endpoints."""
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.fragment or parsed.username or parsed.password:
        return None
    if parsed.netloc == "api.first.org" and parsed.path == "/data/v1/epss":
        query = parse_qs(parsed.query)
        if set(query) != {"cve"} or len(query["cve"]) != 1:
            return None
        ids = query["cve"][0].split(",")
        if len(ids) > EPSS_BATCH_SIZE or risk.canonical_cves(ids) != sorted(set(ids)):
            return None
        limit = 256 * 1024
    elif parsed.netloc == "www.cisa.gov" and parsed.path == risk._KEV_PATH and not parsed.query:
        limit = risk.MAX_CACHE_BYTES
    else:
        return None
    payload = risk._fetch_json(
        parsed.netloc,
        parsed.path + ("?" + parsed.query if parsed.query else ""),
        limit,
        time.monotonic() + max(0, min(15, timeout)),
    )
    return json.dumps(payload, allow_nan=False).encode() if payload is not None else None


def _fetch_epss_batch(cve_ids: list[str]) -> dict[str, tuple[float, float]]:
    """Legacy undated observations; never used for confidence boosts."""
    ids = risk.canonical_cves(cve_ids)
    if not ids:
        return {}
    raw = _http_get(f"{EPSS_API_URL}?cve={','.join(ids)}")
    if raw is None:
        return {}
    try:
        data = json.loads(raw)
        rows = data.get("data") if isinstance(data, dict) else None
        if not isinstance(rows, list) or len(rows) > EPSS_BATCH_SIZE:
            return {}
        results, duplicates, seen = {}, set(), set()
        for item in rows:
            if not isinstance(item, dict) or not isinstance(item.get("cve"), str):
                continue
            cve = item["cve"]
            if cve not in ids:
                continue
            if cve in seen:
                duplicates.add(cve)
            seen.add(cve)
            score, percentile = risk._number(item.get("epss")), risk._number(item.get("percentile"))
            if score is not None and percentile is not None:
                results[cve] = (score, percentile)
        return {cve: value for cve, value in results.items() if cve not in duplicates}
    except (ValueError, TypeError, RecursionError):
        return {}


def _fetch_kev_catalog() -> dict[str, str]:
    """Legacy positive observations; no claim of current catalog coverage."""
    cached = _read_cache("kev_catalog.json")
    if cached is not None:
        return cached
    raw = _http_get(KEV_URL)
    if raw is None:
        return _read_stale_cache("kev_catalog.json") or {}
    try:
        data = json.loads(raw)
        rows = data.get("vulnerabilities") if isinstance(data, dict) else None
        if not isinstance(rows, list) or len(rows) > 100000:
            return {}
        result = {}
        for row in rows:
            if not isinstance(row, dict):
                return {}
            cve, due = row.get("cveID"), row.get("dueDate")
            if (
                not isinstance(cve, str)
                or not risk._CVE.fullmatch(cve)
                or risk._date(due, risk.dt.date.today(), future=True) is None
                or cve in result
            ):
                return {}
            result[cve] = due
        return result
    except (ValueError, TypeError, RecursionError):
        return {}


def fetch_threat_intel_batch(
    cve_ids: list[str], *, project_root=None
) -> dict[str, ThreatIntelData]:
    """Use the same bounded dated lookup as api.threat_context.

    Missing KEV evidence is nullable, never false. Stale observations stay
    visible, and cannot receive a confidence or priority boost.
    """
    if not cve_ids:
        return {}
    ids = sorted(
        {
            cve
            for offset in range(0, len(cve_ids), EPSS_BATCH_SIZE)
            for cve in risk.canonical_cves(cve_ids[offset : offset + EPSS_BATCH_SIZE])
        }
    )
    results = {}
    deadline = time.monotonic() + 15
    for offset in range(0, len(ids), EPSS_BATCH_SIZE):
        remaining = max(0.0, deadline - time.monotonic())
        context = risk.threat_context(
            ids[offset : offset + EPSS_BATCH_SIZE],
            network=remaining > 0,
            timeout=remaining,
            project_root=project_root,
        )
        for row in context["cves"]:
            epss, kev = row["epss"], row["kev"]
            results[row["cve_id"]] = ThreatIntelData(
                epss_score=epss["score"],
                epss_percentile=epss["percentile"],
                in_kev=kev["in_catalog"],
                kev_due_date=kev["due_date"],
                epss_status=epss["status"],
                epss_score_date=epss["score_date"],
                epss_retrieved_at=epss["retrieved_at"],
                kev_status=kev["status"],
                kev_date_added=kev["date_added"],
                kev_catalog_date=kev["catalog_date"],
                kev_retrieved_at=kev["retrieved_at"],
            )
    return results
