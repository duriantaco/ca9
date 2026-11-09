"""Build a ``ca9.feed.v1`` malware bundle from OSV data.

The malicious-package records (OSV ``MAL-`` IDs) originate from the OpenSSF
``malicious-packages`` project (Apache-2.0), surfaced through the OSV.dev
per-ecosystem export. GitHub advisories (``GHSA-``) tagged CWE-506 "Embedded
Malicious Code" are malicious too. This script downloads those exports, keeps
only the malicious records, and maps them into ca9's feed dataset shape.

Exact versions and whole-package records go to ``<ecosystem>-malware``. Records
that only give bounded version ranges go, with their OSV events kept verbatim,
to the optional ``<ecosystem>-malware-ranges`` datasets; clients that predate
them ignore unknown datasets, and a range is never widened to a whole-package
entry. The ``*-releases`` datasets are still emitted empty so older clients keep
loading the bundle; release age now comes from registry metadata (see
``ca9.release_age``).

The bundle records ``osv_built_at``, when its OSV-derived datasets (malware,
malware ranges, releases) were built, and expires ``--ttl-days`` after that.
With ``--previous`` (the last published bundle) those datasets are carried over
unchanged while they are younger than ``--osv-rebuild-hours`` (default 6, or the
``CA9_OSV_REBUILD_HOURS`` environment variable; 0 rebuilds every run), so an
hourly job downloads the OSV exports only every few hours. A previous bundle that
cannot be read, records no ``osv_built_at``, or lacks a valid OSV dataset forces a
full rebuild.

Usage:
    python scripts/build_feed.py -o feed_build/latest.json
    python scripts/build_feed.py -o feed_build/latest.json --previous prev-latest.json
"""

from __future__ import annotations

import argparse
import io
import json
import math
import os
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
# Range types whose events describe package versions (GIT ranges describe commits).
VERSION_RANGE_TYPES = {"SEMVER", "ECOSYSTEM"}
UPPER_BOUND_EVENTS = ("fixed", "last_affected", "limit")
RANGE_EVENT_KEYS = ("introduced", "fixed", "last_affected", "limit")
MALICIOUS_CWE = "CWE-506"
# Per-ecosystem build statistics reported in the build summary and manifest.
STAT_KEYS = (
    "malicious_records",
    "cwe506_records",
    "withdrawn_skipped",
    "whole_package",
    "versioned",
    "bounded_skipped",
)
RANGE_STAT_KEYS = ("ranged", "range_unusable")
OSV_DATASETS = tuple(
    f"{ecosystem}-{kind}"
    for ecosystem in OSV_ECOSYSTEMS.values()
    for kind in ("malware", "malware-ranges", "releases")
)
OSV_REBUILD_ENV = "CA9_OSV_REBUILD_HOURS"
DEFAULT_OSV_REBUILD_HOURS = "6"
OSV_CLOCK_SKEW = timedelta(hours=1)


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
    """OSV records flagged as malicious: a ``MAL-`` id, alias, marker, or CWE-506."""
    return _is_mal_record(record) or has_malicious_cwe(record)


def has_malicious_cwe(record: dict[str, Any]) -> bool:
    """True when the record, or one of its affected entries, carries CWE-506."""
    sources = [record.get("database_specific")]
    sources.extend(
        affected.get("database_specific")
        for affected in record.get("affected") or []
        if isinstance(affected, dict)
    )
    return any(_cwe_ids(source) & {MALICIOUS_CWE} for source in sources)


def _cwe_ids(database_specific: Any) -> set[str]:
    if not isinstance(database_specific, dict):
        return set()
    found: set[str] = set()
    cwe_ids = database_specific.get("cwe_ids")
    if isinstance(cwe_ids, list):
        found.update(str(item).strip().upper() for item in cwe_ids if isinstance(item, str))
    cwes = database_specific.get("cwes")
    if isinstance(cwes, list):
        for item in cwes:
            if isinstance(item, dict) and isinstance(item.get("cweId"), str):
                found.add(item["cweId"].strip().upper())
    return found


def _is_mal_record(record: dict[str, Any]) -> bool:
    if str(record.get("id", "")).startswith("MAL-"):
        return True
    if any(str(alias).startswith("MAL-") for alias in record.get("aliases") or []):
        return True
    database_specific = record.get("database_specific")
    return isinstance(database_specific, dict) and database_specific.get("malicious") is True


def malware_entries(
    records: Iterable[dict[str, Any]],
    ca9_ecosystem: str,
    *,
    stats: dict[str, int] | None = None,
) -> list[dict[str, Any]]:
    """Map malicious OSV records to ca9 malware-dataset entries.

    Records that enumerate specific affected versions become one entry per
    version; records that flag the whole package (no versions or ranges, or a
    range that starts at ``introduced: "0"`` with no upper bound) become a single
    name-only entry, which ca9 matches against any version. Bounded ranges use the
    explicit versions OpenSSF lists in ``malicious-packages-origins``; when no such
    versions exist they are counted as ``bounded_skipped`` here and kept only in
    the ranges dataset (see ``malware_range_entries``). Withdrawn records are
    skipped.
    """
    counts = stats if stats is not None else {}
    for key in STAT_KEYS:
        counts.setdefault(key, 0)
    seen: set[tuple[str, str]] = set()
    entries: list[dict[str, Any]] = []
    for record in records:
        if not is_malicious(record):
            continue
        if record.get("withdrawn"):
            counts["withdrawn_skipped"] += 1
            continue
        counts["malicious_records"] += 1
        if not _is_mal_record(record):
            counts["cwe506_records"] += 1
        record_id = str(record.get("id") or "")
        summary = _summary(record)
        affected_entries = [item for item in record.get("affected") or [] if isinstance(item, dict)]
        for affected in affected_entries:
            package = affected.get("package") or {}
            name = package.get("name")
            if not name:
                continue
            normalized = normalize_name(ca9_ecosystem, str(name))
            versions = [str(v) for v in (affected.get("versions") or [])]
            ranges = [item for item in affected.get("ranges") or [] if isinstance(item, dict)]
            targets: list[str | None]
            if (not versions and not ranges) or any(_is_whole_package_range(r) for r in ranges):
                targets = [None]
                counts["whole_package"] += 1
            else:
                # Never collapse a bounded range into a whole-package block. OpenSSF
                # lists the concrete versions behind a range in its origins metadata;
                # those only describe this package when the record has one target.
                explicit = list(versions)
                if ranges and len(affected_entries) == 1:
                    explicit.extend(_origin_versions(record))
                if not explicit:
                    counts["bounded_skipped"] += 1
                    continue
                targets = list(dict.fromkeys(explicit))
                counts["versioned"] += 1
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


def malware_range_entries(
    records: Iterable[dict[str, Any]],
    ca9_ecosystem: str,
    *,
    stats: dict[str, int] | None = None,
) -> list[dict[str, Any]]:
    """Map bounded malicious ranges to ``<ecosystem>-malware-ranges`` entries.

    Every malicious, non-withdrawn affected entry with a bounded ``SEMVER`` or
    ``ECOSYSTEM`` range is kept, events verbatim, even when explicit versions
    were also listed: OSV enumerates versions from what the registry still
    serves, so unpublished malicious versions are often only described by the
    range. Whole-package records already live in ``<ecosystem>-malware`` and are
    not repeated here. Entries carry no ``version`` key, and clients match them
    only when a version falls inside a range.
    """
    counts: dict[str, int] = {}
    if stats is not None:
        counts = stats
    for key in RANGE_STAT_KEYS:
        counts.setdefault(key, 0)
    seen: set[tuple[str, str, str]] = set()
    entries: list[dict[str, Any]] = []
    for record in records:
        if not is_malicious(record) or record.get("withdrawn"):
            continue
        record_id = str(record.get("id") or "")
        summary = _summary(record)
        for affected in record.get("affected") or []:
            if not isinstance(affected, dict):
                continue
            package = affected.get("package") or {}
            name = package.get("name")
            raw_ranges = [item for item in affected.get("ranges") or [] if isinstance(item, dict)]
            if not name or not raw_ranges:
                continue
            if any(_is_whole_package_range(item) for item in raw_ranges):
                continue
            ranges = [kept for kept in map(_verbatim_version_range, raw_ranges) if kept]
            if not ranges:
                if not affected.get("versions"):
                    counts["range_unusable"] += 1
                continue
            normalized = normalize_name(ca9_ecosystem, str(name))
            key = (normalized, record_id, json.dumps(ranges, sort_keys=True))
            if key in seen:
                continue
            seen.add(key)
            entry: dict[str, Any] = {"name": normalized, "id": record_id, "ranges": ranges}
            if summary:
                entry["summary"] = summary
            entries.append(entry)
            counts["ranged"] += 1
    entries.sort(key=lambda item: (item["name"], item["id"], json.dumps(item["ranges"])))
    return entries


def _verbatim_version_range(osv_range: dict[str, Any]) -> dict[str, Any] | None:
    """A ``SEMVER``/``ECOSYSTEM`` range with its version events copied unchanged."""
    if osv_range.get("type") not in VERSION_RANGE_TYPES:
        return None
    events = []
    for event in osv_range.get("events") or []:
        if not isinstance(event, dict):
            continue
        kept = {
            key: str(event[key])
            for key in RANGE_EVENT_KEYS
            if key in event and isinstance(event[key], (str, int, float))
        }
        if kept:
            events.append(kept)
    if not any("introduced" in event for event in events):
        return None
    return {"type": osv_range["type"], "events": events}


def _is_whole_package_range(osv_range: dict[str, Any]) -> bool:
    """True for OpenSSF's whole-package shape: ``introduced: "0"`` and no upper bound."""
    if osv_range.get("type") not in VERSION_RANGE_TYPES:
        return False
    events = [event for event in osv_range.get("events") or [] if isinstance(event, dict)]
    if not events:
        return False
    if any(key in event for event in events for key in UPPER_BOUND_EVENTS):
        return False
    return all(str(event.get("introduced")) == "0" for event in events)


def _origin_versions(record: dict[str, Any]) -> list[str]:
    """Explicit versions OpenSSF recorded for each report merged into this record."""
    database_specific = record.get("database_specific")
    if not isinstance(database_specific, dict):
        return []
    origins = database_specific.get("malicious-packages-origins")
    if not isinstance(origins, list):
        return []
    versions: list[str] = []
    for origin in origins:
        if not isinstance(origin, dict):
            continue
        for version in origin.get("versions") or []:
            if isinstance(version, str) and version.strip():
                versions.append(version.strip())
    return list(dict.fromkeys(versions))


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
    stats: dict[str, dict[str, int]] | None = None,
) -> dict[str, Any]:
    releases = releases_by_ecosystem or {}
    datasets: dict[str, Any] = {}
    for osv_ecosystem, ca9_ecosystem in OSV_ECOSYSTEMS.items():
        records = records_by_osv_ecosystem.get(osv_ecosystem, [])
        dataset_name = f"{ca9_ecosystem}-malware"
        dataset_stats = stats.setdefault(dataset_name, {}) if stats is not None else None
        datasets[dataset_name] = {
            "packages": malware_entries(records, ca9_ecosystem, stats=dataset_stats)
        }
        ranges_name = f"{ca9_ecosystem}-malware-ranges"
        ranges_stats = None
        if stats is not None:
            ranges_stats = stats.setdefault(ranges_name, {})
        datasets[ranges_name] = {
            "packages": malware_range_entries(records, ca9_ecosystem, stats=ranges_stats)
        }
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
    stats: dict[str, dict[str, int]] | None = None,
) -> dict[str, Any]:
    moment = now or datetime.now(timezone.utc)
    return {
        "schema": FEED_SCHEMA,
        "created_at": _iso(moment),
        "expires_at": _iso(moment + timedelta(days=ttl_days)),
        "osv_built_at": _iso(moment),
        "datasets": build_datasets(
            records_by_osv_ecosystem,
            releases_by_ecosystem=releases_by_ecosystem,
            covers_since=covers_since,
            stats=stats,
        ),
    }


def build_bundle(
    *,
    now: datetime | None = None,
    ttl_days: int = DEFAULT_TTL_DAYS,
    source_urls: dict[str, str] | None = None,
    stats: dict[str, dict[str, int]] | None = None,
) -> dict[str, Any]:
    overrides = source_urls or {}
    records_by_osv_ecosystem = {
        osv_ecosystem: fetch_osv_export(osv_ecosystem, source_url=overrides.get(osv_ecosystem))
        for osv_ecosystem in OSV_ECOSYSTEMS
    }
    return build_bundle_from_records(
        records_by_osv_ecosystem, now=now, ttl_days=ttl_days, stats=stats
    )


def reusable_osv_datasets(
    previous: Any,
    *,
    now: datetime,
    rebuild_hours: float,
    ttl_days: int = DEFAULT_TTL_DAYS,
) -> tuple[dict[str, Any] | None, str]:
    """The previous bundle's OSV datasets when they may be carried over, and why.

    Returns ``(None, reason)`` when a rebuild is needed: ``rebuild_hours`` is 0, the
    previous bundle is unreadable or records no valid ``osv_built_at``, its OSV data
    is at least ``rebuild_hours`` (or ``ttl_days``) old, or an OSV dataset is missing
    or malformed.
    """
    if rebuild_hours <= 0:
        return None, "the OSV datasets are rebuilt every run (rebuild interval 0)"
    if not isinstance(previous, dict) or previous.get("schema") != FEED_SCHEMA:
        return None, "the previous bundle could not be read"
    built_at = _parse_iso(previous.get("osv_built_at"))
    if built_at is None:
        return None, "the previous bundle records no OSV build time"
    if built_at > now + OSV_CLOCK_SKEW:
        return None, "the previous OSV build time is in the future"
    age_hours = (now - built_at).total_seconds() / 3600
    if age_hours >= min(rebuild_hours, ttl_days * 24):
        return (
            None,
            f"the previous OSV data is {age_hours:.1f}h old (rebuild every {rebuild_hours:g}h)",
        )
    datasets = previous.get("datasets")
    if not isinstance(datasets, dict):
        return None, "the previous bundle has no datasets"
    carried: dict[str, Any] = {}
    for name in OSV_DATASETS:
        payload = datasets.get(name)
        packages = None
        if isinstance(payload, dict):
            packages = payload.get("packages")
        expected: type = list
        if name.endswith("-releases"):
            expected = dict
        if not isinstance(packages, expected):
            return None, f"the previous bundle has no valid {name} dataset"
        carried[name] = payload
    return carried, (
        f"the previous OSV data is {age_hours:.1f}h old, under the {rebuild_hours:g}h rebuild "
        "interval"
    )


def carried_forward_bundle(
    previous: dict[str, Any],
    datasets: dict[str, Any],
    *,
    now: datetime,
    ttl_days: int = DEFAULT_TTL_DAYS,
) -> dict[str, Any]:
    """A new bundle that reuses ``datasets`` unchanged and keeps their ``osv_built_at``.

    It expires ``ttl_days`` after the OSV data was built, not after this bundle, so
    carrying data forward never extends how long stale OSV data stays current.
    """
    built_at = _parse_iso(previous.get("osv_built_at"))
    if built_at is None:
        raise ValueError("the previous bundle records no OSV build time")
    return {
        "schema": FEED_SCHEMA,
        "created_at": _iso(now),
        "expires_at": _iso(built_at + timedelta(days=ttl_days)),
        "osv_built_at": previous["osv_built_at"],
        "datasets": {name: datasets[name] for name in OSV_DATASETS},
    }


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _read_bundle(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def _rebuild_hours(value: str) -> float:
    try:
        hours = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number of hours: {value!r}") from None
    if math.isnan(hours) or hours < 0:
        raise argparse.ArgumentTypeError(f"rebuild hours must be 0 or more: {value!r}")
    return hours


def _summary(record: dict[str, Any]) -> str:
    text = str(record.get("summary") or record.get("details") or "").strip()
    if len(text) > SUMMARY_MAX:
        text = text[: SUMMARY_MAX - 3] + "..."
    return text


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def malware_counts(bundle: dict[str, Any]) -> dict[str, int]:
    """Return per-ecosystem malware entry counts for a bundle."""
    return _dataset_counts(bundle, "-malware")


def malware_range_counts(bundle: dict[str, Any]) -> dict[str, int]:
    """Return per-ecosystem malware range entry counts for a bundle."""
    return _dataset_counts(bundle, "-malware-ranges")


def _dataset_counts(bundle: dict[str, Any], suffix: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for name, dataset in bundle.get("datasets", {}).items():
        packages = dataset.get("packages") if isinstance(dataset, dict) else None
        if name.endswith(suffix) and isinstance(packages, list):
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
    stats: dict[str, dict[str, int]] | None = None,
) -> dict[str, Any]:
    """A small, human-readable record of what this build produced."""
    manifest: dict[str, Any] = {
        "schema": bundle.get("schema"),
        "built_at": _iso(now or datetime.now(timezone.utc)),
        "expires_at": bundle.get("expires_at"),
        "osv_built_at": bundle.get("osv_built_at"),
        "malware_counts": malware_counts(bundle),
        "malware_range_counts": malware_range_counts(bundle),
        "sources": dict(source_urls or {}),
    }
    if stats is not None:
        manifest["malware_stats"] = {name: dict(values) for name, values in sorted(stats.items())}
    return manifest


def format_build_stats(stats: dict[str, dict[str, int]]) -> list[str]:
    """One summary line per dataset, so skipped records are visible in build logs."""
    lines: list[str] = []
    for name, values in sorted(stats.items()):
        keys = STAT_KEYS
        if name.endswith("-malware-ranges"):
            keys = RANGE_STAT_KEYS
        details = "  ".join(f"{key}={values.get(key, 0)}" for key in keys)
        lines.append(f"{name}: {details}")
    return lines


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
    parser.add_argument(
        "--previous",
        type=Path,
        default=None,
        help="Previously published bundle; its OSV datasets are reused while young enough.",
    )
    parser.add_argument(
        "--osv-rebuild-hours",
        type=_rebuild_hours,
        default=os.environ.get(OSV_REBUILD_ENV) or DEFAULT_OSV_REBUILD_HOURS,
        help=f"Rebuild OSV datasets older than this (default 6, or ${OSV_REBUILD_ENV}; 0 = always).",
    )
    args = parser.parse_args(argv)

    source_overrides: dict[str, str] = {}
    if args.npm_source:
        source_overrides["npm"] = args.npm_source
    if args.pypi_source:
        source_overrides["PyPI"] = args.pypi_source

    now = datetime.now(timezone.utc)
    stats: dict[str, dict[str, int]] = {}
    previous = None
    reused = None
    reason = "no previous bundle was given"
    if args.previous is not None:
        previous = _read_bundle(args.previous)
        reused, reason = reusable_osv_datasets(
            previous, now=now, rebuild_hours=args.osv_rebuild_hours, ttl_days=args.ttl_days
        )
    if reused is not None and isinstance(previous, dict):
        bundle = carried_forward_bundle(previous, reused, now=now, ttl_days=args.ttl_days)
        previous_info = previous.get("build_info")
        if not isinstance(previous_info, dict):
            previous_info = {}
        sources = previous_info.get("sources")
        if not isinstance(sources, dict):
            sources = resolved_source_urls(source_overrides)
        previous_stats = previous_info.get("malware_stats")
        if isinstance(previous_stats, dict):
            stats = previous_stats
        manifest = build_manifest(bundle, source_urls=sources, now=now, stats=stats or None)
        print(f"feed OSV datasets reused: {reason}; built at {bundle['osv_built_at']}")
    else:
        bundle = build_bundle(
            now=now, ttl_days=args.ttl_days, source_urls=source_overrides, stats=stats
        )
        manifest = build_manifest(
            bundle, source_urls=resolved_source_urls(source_overrides), now=now, stats=stats
        )
        print(f"feed OSV datasets rebuilt: {reason}")
    manifest["osv_rebuilt"] = reused is None
    manifest["osv_reason"] = reason
    bundle["build_info"] = manifest
    counts = manifest["malware_counts"]

    range_counts = manifest["malware_range_counts"]
    previous = None
    previous_ranges = None
    if args.compare_manifest and args.compare_manifest.is_file():
        try:
            loaded_manifest = json.loads(args.compare_manifest.read_text())
        except (OSError, json.JSONDecodeError):
            loaded_manifest = {}
        if isinstance(loaded_manifest, dict):
            loaded = loaded_manifest.get("malware_counts")
            if isinstance(loaded, dict):
                previous = loaded
            loaded_ranges = loaded_manifest.get("malware_range_counts")
            if isinstance(loaded_ranges, dict):
                previous_ranges = loaded_ranges

    print(
        "feed built: "
        + "  ".join(f"{name}={count}" for name, count in sorted({**counts, **range_counts}.items()))
    )
    for line in format_build_stats(stats):
        print(f"feed stats: {line}")

    errors = count_guard_errors(counts, minimum=args.min_malware, previous=previous)
    errors.extend(count_guard_errors(range_counts, previous=previous_ranges))
    if errors:
        for error in errors:
            print(f"feed guard failed: {error}", file=sys.stderr)
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    # The bundle holds hundreds of thousands of entries; keep it compact so it stays
    # well under GitHub's per-file limits on the feed branch.
    args.output.write_text(json.dumps(bundle, sort_keys=True, separators=(",", ":")) + "\n")
    if args.manifest:
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
