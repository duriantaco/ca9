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
            "CA9_FEED_URL": "https://127.0.0.1:9/no-feed.json",
        },
    )

    assert update.exit_code == 1
    assert "cannot download feed" in update.output


def _openssf_record(
    record_id: str,
    name: str,
    *,
    ecosystem: str = "npm",
    ranges: list[dict] | None = None,
    versions: list[str] | None = None,
    origins: list[dict] | None = None,
    withdrawn: str | None = None,
) -> dict:
    """A record shaped like ossf/malicious-packages entries in the OSV export."""
    affected: dict = {"package": {"ecosystem": ecosystem, "name": name}}
    if ranges is not None:
        affected["ranges"] = ranges
    if versions is not None:
        affected["versions"] = versions
    record: dict = {
        "schema_version": "1.5.0",
        "id": record_id,
        "modified": "2026-09-30T00:00:00Z",
        "published": "2026-09-01T00:00:00Z",
        "summary": f"Malicious code in {name} ({ecosystem})",
        "details": "\n---\n_-= Per source details. Do not edit below this line.=-_\n",
        "affected": [affected],
        "database_specific": {
            "malicious-packages-origins": origins
            or [{"source": "ghsa-malware", "id": "GHSA-xxxx-yyyy-zzzz"}]
        },
    }
    if withdrawn:
        record["withdrawn"] = withdrawn
    return record


WHOLE_PACKAGE_SEMVER = [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
WHOLE_PACKAGE_ECOSYSTEM = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
BOUNDED_RANGE = [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.0.2"}]}]


def test_malware_entries_whole_package_ranges_become_name_only_entries():
    stats: dict[str, int] = {}
    entries = malware_entries(
        [_openssf_record("MAL-2026-1", "Whole-Semver", ranges=WHOLE_PACKAGE_SEMVER)],
        "npm",
        stats=stats,
    )
    pypi_entries = malware_entries(
        [
            _openssf_record(
                "MAL-2026-2", "Whole_Eco", ecosystem="PyPI", ranges=WHOLE_PACKAGE_ECOSYSTEM
            )
        ],
        "pypi",
    )

    assert entries == [
        {
            "name": "whole-semver",
            "id": "MAL-2026-1",
            "summary": "Malicious code in Whole-Semver (npm)",
        }
    ]
    assert pypi_entries == [
        {"name": "whole-eco", "id": "MAL-2026-2", "summary": "Malicious code in Whole_Eco (PyPI)"}
    ]
    assert stats["whole_package"] == 1
    assert stats["bounded_skipped"] == 0


def test_malware_entries_bounded_range_uses_origin_versions():
    record = _openssf_record(
        "MAL-2026-3",
        "bounded-pkg",
        ranges=BOUNDED_RANGE,
        origins=[
            {"source": "ghsa-malware", "versions": ["1.0.0"]},
            {"source": "ossf-package-analysis", "versions": ["1.0.1", "1.0.0"]},
        ],
    )

    entries = malware_entries([record], "npm")

    assert [(entry["name"], entry["version"]) for entry in entries] == [
        ("bounded-pkg", "1.0.0"),
        ("bounded-pkg", "1.0.1"),
    ]


def test_malware_entries_skip_and_count_bounded_range_without_versions():
    stats: dict[str, int] = {}
    entries = malware_entries(
        [
            _openssf_record("MAL-2026-4", "bounded-only", ranges=BOUNDED_RANGE),
            _openssf_record(
                "MAL-2026-5",
                "open-ended",
                ranges=[{"type": "SEMVER", "events": [{"introduced": "2.0.0"}]}],
            ),
            _openssf_record(
                "MAL-2026-6",
                "last-affected",
                ranges=[
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"last_affected": "1.0.0"}]}
                ],
            ),
            _openssf_record(
                "MAL-2026-7",
                "git-only",
                ranges=[{"type": "GIT", "repo": "https://x", "events": [{"introduced": "0"}]}],
            ),
        ],
        "npm",
        stats=stats,
    )

    assert entries == []
    assert stats["bounded_skipped"] == 4
    assert stats["malicious_records"] == 4


def test_malware_entries_versions_plus_ranges():
    entries = malware_entries(
        [
            _openssf_record(
                "MAL-2026-8",
                "listed-and-bounded",
                ranges=BOUNDED_RANGE,
                versions=["1.0.0", "1.0.1"],
            ),
            # An unbounded range from "0" covers every version, listed or not.
            _openssf_record(
                "MAL-2026-9",
                "listed-and-whole",
                ranges=WHOLE_PACKAGE_SEMVER,
                versions=["3.0.0"],
            ),
        ],
        "npm",
    )

    assert [(entry["name"], entry.get("version")) for entry in entries] == [
        ("listed-and-bounded", "1.0.0"),
        ("listed-and-bounded", "1.0.1"),
        ("listed-and-whole", None),
    ]


def test_malware_entries_skip_withdrawn_records():
    stats: dict[str, int] = {}
    entries = malware_entries(
        [
            _openssf_record(
                "MAL-2024-1398",
                "false-positive",
                ranges=WHOLE_PACKAGE_SEMVER,
                withdrawn="2024-05-01T00:00:00Z",
            ),
            _openssf_record("MAL-2026-10", "still-bad", ranges=WHOLE_PACKAGE_SEMVER),
        ],
        "npm",
        stats=stats,
    )

    assert [entry["name"] for entry in entries] == ["still-bad"]
    assert stats["withdrawn_skipped"] == 1
    assert stats["malicious_records"] == 1


def test_whole_package_record_blocks_any_version_through_feed_engine(tmp_path):
    from ca9.package_feed import update_feed_from_source

    bundle = build_bundle_from_records(
        {"npm": [_openssf_record("MAL-2026-11", "whole-semver", ranges=WHOLE_PACKAGE_SEMVER)]}
    )
    bundle_path = tmp_path / "latest.json"
    bundle_path.write_text(json.dumps(bundle))
    cache_dir = tmp_path / "cache" / "feed"
    update_feed_from_source(str(bundle_path), cache_dir=cache_dir)

    matches = lookup_malware("npm", "whole-semver", "4.5.6", cache_dir=cache_dir)
    assert [match["id"] for match in matches] == ["MAL-2026-11"]


def test_build_stats_reach_manifest_and_summary():
    from scripts.build_feed import build_manifest, format_build_stats

    stats: dict[str, dict[str, int]] = {}
    bundle = build_bundle_from_records(
        {
            "npm": [
                _openssf_record("MAL-2026-12", "bounded-only", ranges=BOUNDED_RANGE),
                _openssf_record("MAL-2026-13", "whole", ranges=WHOLE_PACKAGE_SEMVER),
            ]
        },
        now=datetime(2026, 10, 2, tzinfo=timezone.utc),
        stats=stats,
    )
    manifest = build_manifest(bundle, stats=stats)

    assert manifest["malware_stats"]["npm-malware"]["bounded_skipped"] == 1
    assert manifest["malware_stats"]["npm-malware"]["whole_package"] == 1
    lines = format_build_stats(stats)
    assert any(line.startswith("npm-malware:") and "bounded_skipped=1" in line for line in lines)


def test_feed_update_rejects_plain_http_url(tmp_path):
    runner = CliRunner()

    update = runner.invoke(
        main,
        ["feed", "update", "--from", "http://example.invalid/latest.json"],
        env={"CA9_CACHE_DIR": str(tmp_path / "cache")},
    )

    assert update.exit_code == 1
    assert "insecure http://" in update.output


SOLANA_RECORD = {
    "id": "MAL-2024-11183",
    "aliases": ["GHSA-2mhj-xmf4-pr8m"],
    "summary": "Malicious code in @solana/web3.js (npm)",
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "@solana/web3.js"},
            "ranges": [
                {"type": "SEMVER", "events": [{"introduced": "1.95.6"}, {"fixed": "1.95.8"}]}
            ],
        }
    ],
}
XRPL_RECORD = {
    "id": "GHSA-33qr-m49q-rxfx",
    "aliases": ["CVE-2025-32965"],
    "summary": "Compromised xrpl.js versions 4.2.1, 4.2.2, 4.2.3, 4.2.4, and 2.14.2",
    "database_specific": {"cwe_ids": ["CWE-506"], "severity": "CRITICAL"},
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "xrpl"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "4.2.1"}, {"fixed": "4.2.5"}]}],
        },
        {
            "package": {"ecosystem": "npm", "name": "xrpl"},
            "ranges": [
                {"type": "SEMVER", "events": [{"introduced": "2.14.2"}, {"fixed": "2.14.3"}]}
            ],
            "versions": ["2.14.2"],
        },
    ],
}


def test_cwe_506_advisories_are_malicious_but_other_cwes_are_not():
    assert is_malicious(XRPL_RECORD)
    assert is_malicious(
        {
            "id": "GHSA-aff-level",
            "affected": [{"database_specific": {"cwes": [{"cweId": "CWE-506"}]}}],
        }
    )
    assert not is_malicious(
        {"id": "GHSA-plain", "database_specific": {"cwe_ids": ["CWE-79", "CWE-5060"]}}
    )


def test_range_only_records_are_kept_as_ranges_never_as_whole_package():
    stats: dict[str, dict[str, int]] = {}
    bundle = build_bundle_from_records({"npm": [SOLANA_RECORD, XRPL_RECORD]}, stats=stats)

    exact = bundle["datasets"]["npm-malware"]["packages"]
    ranges = bundle["datasets"]["npm-malware-ranges"]["packages"]
    assert [(entry["name"], entry.get("version")) for entry in exact] == [("xrpl", "2.14.2")]
    assert sorted(
        (entry["name"], entry["ranges"][0]["events"][0]["introduced"]) for entry in ranges
    ) == [
        ("@solana/web3.js", "1.95.6"),
        ("xrpl", "2.14.2"),
        ("xrpl", "4.2.1"),
    ]
    assert all("version" not in entry for entry in ranges)
    assert ranges[0]["ranges"] == SOLANA_RECORD["affected"][0]["ranges"]
    assert stats["npm-malware"]["cwe506_records"] == 1
    assert stats["npm-malware-ranges"]["ranged"] == 3


def test_withdrawn_cwe_506_and_git_only_ranges_stay_out_of_every_dataset():
    withdrawn = {**XRPL_RECORD, "id": "GHSA-withdrawn", "withdrawn": "2025-05-01T00:00:00Z"}
    git_only = _openssf_record(
        "MAL-2026-20",
        "git-only",
        ranges=[{"type": "GIT", "repo": "https://x", "events": [{"introduced": "abc"}]}],
    )
    stats: dict[str, dict[str, int]] = {}
    bundle = build_bundle_from_records({"npm": [withdrawn, git_only]}, stats=stats)

    assert bundle["datasets"]["npm-malware"]["packages"] == []
    assert bundle["datasets"]["npm-malware-ranges"]["packages"] == []
    assert stats["npm-malware"]["withdrawn_skipped"] == 1
    assert stats["npm-malware-ranges"]["range_unusable"] == 1


def test_range_counts_are_reported_but_not_held_to_the_malware_floor():
    from scripts.build_feed import build_manifest, count_guard_errors

    bundle = build_bundle_from_records({"npm": [SOLANA_RECORD], "PyPI": PYPI_RECORDS})
    manifest = build_manifest(bundle)

    assert manifest["malware_range_counts"] == {"npm-malware-ranges": 1, "pypi-malware-ranges": 0}
    assert "npm-malware-ranges" not in manifest["malware_counts"]
    assert count_guard_errors(manifest["malware_range_counts"], previous={}) == []
    assert count_guard_errors({"npm-malware-ranges": 10}, previous={"npm-malware-ranges": 100})
