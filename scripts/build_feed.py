"""Build a ``ca9.feed.v1`` malware bundle from OSV data.

The malicious-package records (OSV ``MAL-`` IDs) originate from the OpenSSF
``malicious-packages`` project (Apache-2.0), surfaced through the OSV.dev
per-ecosystem export. This script downloads those exports, keeps only the
malicious records, and maps them into ca9's feed dataset shape.

v1 ships malware only; the ``*-releases`` datasets are emitted empty (package-age
is opt-in and off by default, so this does not change default behaviour). A later
revision can fill a recent-window releases dataset — see
``docs/proposals/default-feed.md``.

Usage:
    python scripts/build_feed.py -o feed_build/latest.json
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import urllib.request
import zipfile
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name

FEED_SCHEMA = "ca9.feed.v1"
DEFAULT_TTL_DAYS = 7
SUMMARY_MAX = 300

# OSV ecosystem name -> ca9 dataset ecosystem prefix.
OSV_ECOSYSTEMS = {"npm": "npm", "PyPI": "pypi"}
OSV_EXPORT_URL = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"


def fetch_osv_export(osv_ecosystem: str, *, source_url: str | None = None) -> list[dict[str, Any]]:
    """Download an OSV per-ecosystem ``all.zip`` and return its records."""
    url = source_url or OSV_EXPORT_URL.format(ecosystem=osv_ecosystem)
    with urllib.request.urlopen(url, timeout=180) as response:  # noqa: S310 - fixed https host
        raw = response.read()
    return records_from_zip(raw)


def records_from_zip(raw: bytes) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for name in archive.namelist():
            if not name.endswith(".json"):
                continue
            with archive.open(name) as handle:
                records.append(json.loads(handle.read().decode("utf-8")))
    return records


def is_malicious(record: dict[str, Any]) -> bool:
    """OSV records flagged as malicious carry a ``MAL-`` id (or alias/marker)."""
    if str(record.get("id", "")).startswith("MAL-"):
        return True
    if any(str(alias).startswith("MAL-") for alias in record.get("aliases") or []):
        return True
    database_specific = record.get("database_specific")
    return isinstance(database_specific, dict) and database_specific.get("malicious") is True


def malware_entries(records: Iterable[dict[str, Any]], ca9_ecosystem: str) -> list[dict[str, Any]]:
    """Map malicious OSV records to ca9 malware-dataset entries.

    Records that enumerate specific affected versions become one entry per
    version; records that flag the whole package (no explicit versions) become a
    single name-only entry, which ca9 matches against any version.
    """
    seen: set[tuple[str, str]] = set()
    entries: list[dict[str, Any]] = []
    for record in records:
        if not is_malicious(record):
            continue
        record_id = str(record.get("id") or "")
        summary = _summary(record)
        for affected in record.get("affected") or []:
            package = affected.get("package") or {}
            name = package.get("name")
            if not name:
                continue
            normalized = normalize_name(ca9_ecosystem, str(name))
            versions = [str(v) for v in (affected.get("versions") or [])]
            ranges = affected.get("ranges") or []
            if versions:
                targets: list[str | None] = versions
            elif ranges:
                # Do not collapse bounded OSV ranges into a whole-package block.
                # Range-aware matching can be added later without risking false positives.
                continue
            else:
                targets = [None]
            for version in targets:
                key = (normalized, version or "")
                if key in seen:
                    continue
                seen.add(key)
                entry: dict[str, Any] = {"name": normalized, "id": record_id}
                if version is not None:
                    entry["version"] = version
                if summary:
                    entry["summary"] = summary
                entries.append(entry)
    entries.sort(key=lambda item: (item["name"], item.get("version", ""), item["id"]))
    return entries


def normalize_name(ca9_ecosystem: str, name: str) -> str:
    if ca9_ecosystem == "npm":
        return name.strip().lower()
    return str(canonicalize_name(name))


def build_releases_dataset(
    release_map: dict[str, dict[str, str]],
    covers_since: str | None = None,
) -> dict[str, Any]:
    """Build a releases dataset, recording ``covers_since`` when the window is complete.

    ``covers_since`` must only be set when ``release_map`` contains *every* release
    published since that timestamp; ca9 then treats a missing version as provably
    older than the window. Omit it for best-effort data so absent versions stay
    "unknown" rather than being wrongly cleared.
    """
    dataset: dict[str, Any] = {
        "packages": {name: dict(versions) for name, versions in release_map.items()}
    }
    if covers_since:
        dataset["covers_since"] = covers_since
    return dataset


def build_datasets(
    records_by_osv_ecosystem: dict[str, list[dict[str, Any]]],
    *,
    releases_by_ecosystem: dict[str, dict[str, dict[str, str]]] | None = None,
    covers_since: str | None = None,
) -> dict[str, Any]:
    releases = releases_by_ecosystem or {}
    datasets: dict[str, Any] = {}
    for osv_ecosystem, ca9_ecosystem in OSV_ECOSYSTEMS.items():
        records = records_by_osv_ecosystem.get(osv_ecosystem, [])
        datasets[f"{ca9_ecosystem}-malware"] = {"packages": malware_entries(records, ca9_ecosystem)}
    for ca9_ecosystem in OSV_ECOSYSTEMS.values():
        datasets[f"{ca9_ecosystem}-releases"] = build_releases_dataset(
            releases.get(ca9_ecosystem, {}), covers_since
        )
    return datasets


def build_bundle_from_records(
    records_by_osv_ecosystem: dict[str, list[dict[str, Any]]],
    *,
    now: datetime | None = None,
    ttl_days: int = DEFAULT_TTL_DAYS,
    releases_by_ecosystem: dict[str, dict[str, dict[str, str]]] | None = None,
    covers_since: str | None = None,
) -> dict[str, Any]:
    moment = now or datetime.now(timezone.utc)
    return {
        "schema": FEED_SCHEMA,
        "created_at": _iso(moment),
        "expires_at": _iso(moment + timedelta(days=ttl_days)),
        "datasets": build_datasets(
            records_by_osv_ecosystem,
            releases_by_ecosystem=releases_by_ecosystem,
            covers_since=covers_since,
        ),
    }


def build_bundle(
    *,
    now: datetime | None = None,
    ttl_days: int = DEFAULT_TTL_DAYS,
    source_urls: dict[str, str] | None = None,
) -> dict[str, Any]:
    overrides = source_urls or {}
    records_by_osv_ecosystem = {
        osv_ecosystem: fetch_osv_export(osv_ecosystem, source_url=overrides.get(osv_ecosystem))
        for osv_ecosystem in OSV_ECOSYSTEMS
    }
    return build_bundle_from_records(records_by_osv_ecosystem, now=now, ttl_days=ttl_days)


def _summary(record: dict[str, Any]) -> str:
    text = str(record.get("summary") or record.get("details") or "").strip()
    if len(text) > SUMMARY_MAX:
        text = text[: SUMMARY_MAX - 3] + "..."
    return text


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def malware_counts(bundle: dict[str, Any]) -> dict[str, int]:
    """Return per-ecosystem malware entry counts for a bundle."""
    counts: dict[str, int] = {}
    for name, dataset in bundle.get("datasets", {}).items():
        packages = dataset.get("packages") if isinstance(dataset, dict) else None
        if name.endswith("-malware") and isinstance(packages, list):
            counts[name] = len(packages)
    return counts


def resolved_source_urls(source_urls: dict[str, str] | None = None) -> dict[str, str]:
    overrides = source_urls or {}
    return {
        osv_ecosystem: overrides.get(osv_ecosystem, OSV_EXPORT_URL.format(ecosystem=osv_ecosystem))
        for osv_ecosystem in OSV_ECOSYSTEMS
    }


def build_manifest(
    bundle: dict[str, Any],
    *,
    source_urls: dict[str, str] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """A small, human-readable record of what this build produced."""
    return {
        "schema": bundle.get("schema"),
        "built_at": _iso(now or datetime.now(timezone.utc)),
        "expires_at": bundle.get("expires_at"),
        "malware_counts": malware_counts(bundle),
        "sources": dict(source_urls or {}),
    }


def count_guard_errors(
    counts: dict[str, int],
    *,
    minimum: int = 0,
    previous: dict[str, int] | None = None,
    collapse_ratio: float = 0.5,
) -> list[str]:
    """Catch bad builds: counts below a floor, or collapsed vs. the previous build."""
    errors: list[str] = []
    for name, count in sorted(counts.items()):
        if count < minimum:
            errors.append(f"{name} count {count} is below the minimum of {minimum}")
        prior = (previous or {}).get(name, 0)
        if prior and count < prior * collapse_ratio:
            errors.append(
                f"{name} count {count} collapsed below {collapse_ratio:.0%} of the previous {prior}"
            )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a ca9.feed.v1 malware bundle.")
    parser.add_argument(
        "-o", "--output", type=Path, required=True, help="Where to write the bundle."
    )
    parser.add_argument(
        "--manifest", type=Path, default=None, help="Also write a build manifest JSON."
    )
    parser.add_argument(
        "--ttl-days", type=int, default=DEFAULT_TTL_DAYS, help="Feed validity window."
    )
    parser.add_argument(
        "--min-malware",
        type=int,
        default=0,
        help="Fail if any ecosystem's malware count is below this floor.",
    )
    parser.add_argument(
        "--compare-manifest",
        type=Path,
        default=None,
        help="Previous manifest JSON; fail if counts collapse below 50%% of it.",
    )
    parser.add_argument(
        "--npm-source", default=None, help="Override URL for the npm OSV export zip."
    )
    parser.add_argument(
        "--pypi-source", default=None, help="Override URL for the PyPI OSV export zip."
    )
    args = parser.parse_args(argv)

    source_overrides: dict[str, str] = {}
    if args.npm_source:
        source_overrides["npm"] = args.npm_source
    if args.pypi_source:
        source_overrides["PyPI"] = args.pypi_source

    bundle = build_bundle(ttl_days=args.ttl_days, source_urls=source_overrides)
    manifest = build_manifest(bundle, source_urls=resolved_source_urls(source_overrides))
    bundle["build_info"] = manifest
    counts = manifest["malware_counts"]

    previous = None
    if args.compare_manifest and args.compare_manifest.is_file():
        try:
            loaded = json.loads(args.compare_manifest.read_text()).get("malware_counts")
            previous = loaded if isinstance(loaded, dict) else None
        except (OSError, json.JSONDecodeError):
            previous = None

    print("feed built: " + "  ".join(f"{name}={count}" for name, count in sorted(counts.items())))

    errors = count_guard_errors(counts, minimum=args.min_malware, previous=previous)
    if errors:
        for error in errors:
            print(f"feed guard failed: {error}", file=sys.stderr)
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(bundle, sort_keys=True, indent=2) + "\n")
    if args.manifest:
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
