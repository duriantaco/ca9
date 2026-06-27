from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timezone

from click.testing import CliRunner
from scripts.build_feed import (
    build_bundle_from_records,
    is_malicious,
    malware_entries,
    normalize_name,
    records_from_zip,
)

from ca9.cli import main
from ca9.package_feed import lookup_malware

NPM_RECORDS = [
    {
        "id": "MAL-2025-1",
        "summary": "malicious left-pad",
        "affected": [{"package": {"ecosystem": "npm", "name": "left-pad"}, "versions": ["1.3.0"]}],
    },
    {
        "id": "MAL-2025-2",
        "summary": "whole package is malicious",
        "affected": [{"package": {"ecosystem": "npm", "name": "Evil-Pkg"}}],
    },
    {
        "id": "CVE-2024-9",
        "summary": "ordinary vulnerability, not malware",
        "affected": [{"package": {"ecosystem": "npm", "name": "safe-pkg"}, "versions": ["1.0.0"]}],
    },
]

PYPI_RECORDS = [
    {
        "id": "MAL-2025-3",
        "details": "bad lib",
        "affected": [
            {"package": {"ecosystem": "PyPI", "name": "Bad_Lib"}, "versions": ["1.0.0", "1.0.1"]}
        ],
    },
]


def test_is_malicious_detects_mal_ids_and_markers():
    assert is_malicious({"id": "MAL-2025-1"})
    assert is_malicious({"id": "GHSA-x", "aliases": ["MAL-2025-2"]})
    assert is_malicious({"id": "X", "database_specific": {"malicious": True}})
    assert not is_malicious({"id": "CVE-2024-9"})


def test_normalize_name_per_ecosystem():
    assert normalize_name("npm", "Left-Pad") == "left-pad"
    assert normalize_name("pypi", "Bad_Lib") == "bad-lib"


def test_malware_entries_versioned_whole_package_and_filtering():
    entries = malware_entries(NPM_RECORDS, "npm")
    by_name = {entry["name"]: entry for entry in entries}

    assert "safe-pkg" not in by_name  # CVE record is not malware
    assert by_name["left-pad"]["version"] == "1.3.0"
    assert by_name["left-pad"]["id"] == "MAL-2025-1"
    # whole-package record has no version => matches any installed version
    assert "version" not in by_name["evil-pkg"]
    # entries are sorted by (name, version, id)
    assert entries == sorted(entries, key=lambda e: (e["name"], e.get("version", ""), e["id"]))


def test_malware_entries_emits_one_entry_per_version():
    entries = malware_entries(PYPI_RECORDS, "pypi")
    versions = sorted(entry["version"] for entry in entries)
    assert versions == ["1.0.0", "1.0.1"]
    assert all(entry["name"] == "bad-lib" for entry in entries)


def test_malware_entries_do_not_treat_ranges_as_whole_package():
    entries = malware_entries(
        [
            {
                "id": "MAL-2025-RANGE",
                "affected": [
                    {
                        "package": {"ecosystem": "npm", "name": "range-pkg"},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [{"introduced": "1.0.0"}, {"fixed": "1.0.2"}],
                            }
                        ],
                    }
                ],
            }
        ],
        "npm",
    )

    assert entries == []


def test_records_from_zip_roundtrip():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("MAL-2025-1.json", json.dumps(NPM_RECORDS[0]))
        archive.writestr("ignore.txt", "not json")
    records = records_from_zip(buffer.getvalue())
    assert len(records) == 1
    assert records[0]["id"] == "MAL-2025-1"


def test_build_bundle_roundtrips_through_feed_engine(tmp_path):
    bundle = build_bundle_from_records(
        {"npm": NPM_RECORDS, "PyPI": PYPI_RECORDS},
        now=datetime(2026, 6, 27, tzinfo=timezone.utc),
    )
    assert bundle["schema"] == "ca9.feed.v1"
    assert bundle["datasets"]["npm-releases"] == {"packages": {}}

    bundle_path = tmp_path / "latest.json"
    bundle_path.write_text(json.dumps(bundle))
    cache_dir = tmp_path / "cache" / "feed"

    from ca9.package_feed import update_feed_from_source

    update_feed_from_source(str(bundle_path), cache_dir=cache_dir)

    assert lookup_malware("npm", "left-pad", "1.3.0", cache_dir=cache_dir)[0]["id"] == "MAL-2025-1"
    # whole-package entry matches an arbitrary version
    assert lookup_malware("npm", "evil-pkg", "9.9.9", cache_dir=cache_dir)
    assert lookup_malware("pypi", "bad-lib", "1.0.1", cache_dir=cache_dir)
    assert lookup_malware("npm", "safe-pkg", "1.0.0", cache_dir=cache_dir) == ()


def test_build_releases_dataset_records_covers_since():
    from scripts.build_feed import build_releases_dataset

    dataset = build_releases_dataset(
        {"left-pad": {"1.0.0": "2026-06-01T00:00:00Z"}}, "2026-05-01T00:00:00Z"
    )
    assert dataset["covers_since"] == "2026-05-01T00:00:00Z"
    assert dataset["packages"]["left-pad"]["1.0.0"] == "2026-06-01T00:00:00Z"
    # best-effort data (no complete window) must not claim coverage
    assert "covers_since" not in build_releases_dataset({})


def test_malware_counts_and_manifest():
    from scripts.build_feed import build_manifest, malware_counts

    bundle = build_bundle_from_records(
        {"npm": NPM_RECORDS, "PyPI": PYPI_RECORDS},
        now=datetime(2026, 6, 27, tzinfo=timezone.utc),
    )
    counts = malware_counts(bundle)
    assert counts == {"npm-malware": 2, "pypi-malware": 2}

    manifest = build_manifest(
        bundle,
        source_urls={"npm": "u1", "PyPI": "u2"},
        now=datetime(2026, 6, 27, tzinfo=timezone.utc),
    )
    assert manifest["schema"] == "ca9.feed.v1"
    assert manifest["malware_counts"] == counts
    assert manifest["sources"] == {"npm": "u1", "PyPI": "u2"}
    assert manifest["built_at"].endswith("Z")


def test_count_guard_floor_and_collapse():
    from scripts.build_feed import count_guard_errors

    assert count_guard_errors({"npm-malware": 50, "pypi-malware": 50}, minimum=10) == []
    assert count_guard_errors({"npm-malware": 5}, minimum=10)
    # collapse: 10 is below 50% of the previous 100
    assert count_guard_errors({"npm-malware": 10}, previous={"npm-malware": 100})
    # stable: 80 is above 50% of 100
    assert count_guard_errors({"npm-malware": 80}, previous={"npm-malware": 100}) == []


def test_feed_update_zero_arg_uses_env_url(tmp_path):
    bundle = build_bundle_from_records({"npm": NPM_RECORDS, "PyPI": PYPI_RECORDS})
    bundle_path = tmp_path / "latest.json"
    bundle_path.write_text(json.dumps(bundle))
    cache_root = tmp_path / "cache"
    runner = CliRunner()

    update = runner.invoke(
        main,
        ["feed", "update"],
        env={"CA9_CACHE_DIR": str(cache_root), "CA9_FEED_URL": str(bundle_path)},
    )
    status = runner.invoke(
        main,
        ["feed", "status", "-f", "json"],
        env={"CA9_CACHE_DIR": str(cache_root)},
    )

    assert update.exit_code == 0, update.output
    assert str(bundle_path) in update.output
    assert json.loads(status.output)["state"] == "ready"


def test_feed_update_reports_download_errors_cleanly(tmp_path):
    runner = CliRunner()

    update = runner.invoke(
        main,
        ["feed", "update"],
        env={
            "CA9_CACHE_DIR": str(tmp_path / "cache"),
            "CA9_FEED_URL": "http://127.0.0.1:9/no-feed.json",
        },
    )

    assert update.exit_code == 1
    assert "cannot download feed" in update.output
