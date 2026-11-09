from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

import pytest

from ca9 import api, package_feed
from ca9.package_feed import (
    FeedError,
    load_current_snapshot,
    lookup_malware,
    update_feed_from_source,
)

UTC = timezone.utc
STATUS_KEYS = {"status", "reason", "source", "created_at", "snapshot_id", "previous_created_at"}


def _iso(moment):
    return moment.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _suspicious(name, version, verdict, kinds, previous):
    return {
        "name": name,
        "version": version,
        "previous": previous,
        "kinds": kinds,
        "verdict": verdict,
        "evidence": [f"{kinds[0]} package/index.js:3: payload()"],
        "reviewed_at": "2026-11-07T12:00:00Z",
        "published_at": "2026-11-07T11:00:00Z",
    }


def _write_bundle(path, *, created_at=None, suspicious=True, npm_entries=None):
    created = created_at or datetime.now(UTC) - timedelta(hours=1)
    datasets = {
        "npm-malware": {"packages": [{"name": "left-pad", "version": "1.3.0", "id": "MAL-1"}]},
        "pypi-malware": {"packages": []},
        "npm-releases": {"packages": {}},
        "pypi-releases": {"packages": {}},
        "npm-malware-ranges": {"packages": []},
        "pypi-malware-ranges": {"packages": []},
    }
    if suspicious:
        datasets["npm-suspicious"] = {
            "packages": npm_entries
            if npm_entries is not None
            else [_suspicious("chalk", "5.6.1", "block", ["new_install_hook"], "5.6.0")],
            "sentinel": {"schema": "ca9.sentinel.state.v1", "watermark": "2026-11-07T11:40:00Z"},
        }
        datasets["pypi-suspicious"] = {
            "packages": [
                _suspicious(
                    "urllib3",
                    "2.2.1",
                    "warn",
                    ["new_import_time_network", "publisher_change"],
                    "2.2.0",
                )
            ]
        }
    path.write_text(
        json.dumps(
            {
                "schema": "ca9.feed.v1",
                "created_at": _iso(created),
                "expires_at": _iso(created + timedelta(days=7)),
                "datasets": datasets,
            }
        )
    )
    return path


def test_old_client_ignores_the_suspicious_datasets(tmp_path, monkeypatch):
    bundle = _write_bundle(tmp_path / "latest.json")
    old_optional = ("npm-malware-ranges", "pypi-malware-ranges")
    monkeypatch.setattr(package_feed, "OPTIONAL_DATASETS", old_optional)

    snapshot = update_feed_from_source(bundle, cache_dir=tmp_path / "old")

    assert set(snapshot.content_hashes) == {
        "npm-malware",
        "pypi-malware",
        "npm-releases",
        "pypi-releases",
        *old_optional,
    }
    assert lookup_malware("npm", "left-pad", "1.3.0", cache_dir=tmp_path / "old")
    with pytest.raises(api.FeedUnavailable):
        api.suspicious_matches(
            [{"ecosystem": "npm", "name": "chalk", "version": "5.6.1"}], feed_dir=tmp_path / "old"
        )

    monkeypatch.undo()
    current = update_feed_from_source(bundle, cache_dir=tmp_path / "new")
    assert {"npm-suspicious", "pypi-suspicious"} <= set(current.content_hashes)


def test_suspicious_matches_roundtrip(tmp_path):
    feed_dir = tmp_path / "feed"
    update_feed_from_source(_write_bundle(tmp_path / "latest.json"), cache_dir=feed_dir)

    matches = api.suspicious_matches(
        [
            {
                "ecosystem": "npm",
                "name": "chalk",
                "version": "5.6.1",
                "file": "package-lock.json",
                "line": 7,
            },
            {"ecosystem": "npm", "name": "chalk", "version": "5.6.0"},
            {"ecosystem": "npm", "name": "chalk"},
            {"ecosystem": "pypi", "name": "URLLib3", "version": "2.2.1"},
            "not a package",
        ],
        feed_dir=feed_dir,
    )

    assert [
        (item["signal_type"], item["severity"], item["action"], item["name"], item["version"])
        for item in matches
    ] == [
        ("suspicious_release", "HIGH", "block", "chalk", "5.6.1"),
        ("suspicious_release", "MEDIUM", "warn", "URLLib3", "2.2.1"),
    ]
    chalk = matches[0]
    assert (chalk["file"], chalk["line"]) == ("package-lock.json", 7)
    assert chalk["evidence"]["kinds"] == ["new_install_hook"]
    assert chalk["evidence"]["previous"] == "5.6.0"
    assert chalk["evidence"]["verdict"] == "block"
    assert chalk["evidence"]["evidence"] == ["new_install_hook package/index.js:3: payload()"]
    assert chalk["evidence"]["reviewed_at"] == "2026-11-07T12:00:00Z"
    assert chalk["remediation"]
    assert set(chalk) == {
        "signal_type",
        "severity",
        "action",
        "ecosystem",
        "name",
        "version",
        "title",
        "reason",
        "remediation",
        "evidence",
        "file",
        "line",
    }


def test_suspicious_matches_raises_when_the_feed_or_dataset_is_missing(tmp_path):
    with pytest.raises(api.FeedUnavailable):
        api.suspicious_matches(
            [{"ecosystem": "npm", "name": "chalk", "version": "5.6.1"}], feed_dir=tmp_path / "none"
        )
    feed_dir = tmp_path / "feed"
    update_feed_from_source(
        _write_bundle(tmp_path / "latest.json", suspicious=False), cache_dir=feed_dir
    )
    with pytest.raises(api.FeedUnavailable):
        api.suspicious_matches(
            [{"ecosystem": "pypi", "name": "urllib3", "version": "2.2.1"}], feed_dir=feed_dir
        )


@pytest.mark.parametrize(
    "bad",
    [
        {"name": "chalk", "version": "5.6.1", "verdict": "maybe", "kinds": ["x"]},
        {"name": "chalk", "verdict": "block", "kinds": ["x"]},
        {"name": "", "version": "5.6.1", "verdict": "block", "kinds": ["x"]},
        {"name": "chalk", "version": "5.6.1", "verdict": "block", "kinds": "x"},
    ],
)
def test_malformed_suspicious_dataset_is_rejected(tmp_path, bad):
    bundle = _write_bundle(tmp_path / "latest.json", npm_entries=[bad])

    with pytest.raises(FeedError):
        update_feed_from_source(bundle, cache_dir=tmp_path / "feed")


def test_refresh_feed_only_downloads_when_the_installed_feed_is_stale(tmp_path):
    now = datetime.now(UTC)
    fresh_dir = tmp_path / "fresh-feed"
    update_feed_from_source(
        _write_bundle(tmp_path / "fresh.json", created_at=now - timedelta(hours=1)),
        cache_dir=fresh_dir,
    )

    fresh = api.refresh_feed(feed_dir=fresh_dir, source=str(tmp_path / "does-not-exist.json"))

    assert set(fresh) >= STATUS_KEYS
    assert fresh["status"] == "fresh"

    stale_dir = tmp_path / "stale-feed"
    old_created = now - timedelta(hours=10)
    update_feed_from_source(
        _write_bundle(tmp_path / "old.json", created_at=old_created), cache_dir=stale_dir
    )
    newer_created = now - timedelta(minutes=30)
    newer = _write_bundle(tmp_path / "newer.json", created_at=newer_created)

    updated = api.refresh_feed(feed_dir=stale_dir, source=str(newer), max_age_hours=6)

    assert updated["status"] == "updated"
    assert updated["created_at"] == _iso(newer_created)
    assert updated["previous_created_at"] == _iso(old_created)
    assert load_current_snapshot(cache_dir=stale_dir).created_at == _iso(newer_created)
    again = api.refresh_feed(feed_dir=stale_dir, source=str(tmp_path / "does-not-exist.json"))
    assert again["status"] == "fresh"

    installed = api.refresh_feed(feed_dir=tmp_path / "missing-feed", source=str(newer))
    assert installed["status"] == "updated"
    assert installed["previous_created_at"] is None


def test_refresh_feed_failures_never_raise_and_back_off(tmp_path):
    stale_dir = tmp_path / "feed"
    old_created = datetime.now(UTC) - timedelta(hours=10)
    update_feed_from_source(
        _write_bundle(tmp_path / "old.json", created_at=old_created), cache_dir=stale_dir
    )
    garbage = tmp_path / "garbage.json"
    garbage.write_text("{not json")
    good = _write_bundle(tmp_path / "good.json", created_at=datetime.now(UTC))

    failed = api.refresh_feed(feed_dir=stale_dir, source=str(garbage))
    retried = api.refresh_feed(feed_dir=stale_dir, source=str(good))

    assert failed["status"] == "failed"
    assert failed["reason"]
    assert retried["status"] == "recently_checked"
    assert load_current_snapshot(cache_dir=stale_dir).created_at == _iso(old_created)
    assert api.refresh_feed(max_age_hours="6", feed_dir=stale_dir)["status"] == "failed"


def test_refresh_feed_does_not_install_an_older_source(tmp_path):
    feed_dir = tmp_path / "feed"
    installed_created = datetime.now(UTC) - timedelta(hours=10)
    update_feed_from_source(
        _write_bundle(tmp_path / "installed.json", created_at=installed_created),
        cache_dir=feed_dir,
    )
    older = _write_bundle(tmp_path / "older.json", created_at=installed_created - timedelta(days=1))

    result = api.refresh_feed(feed_dir=feed_dir, source=str(older))

    assert result["status"] == "current"
    assert load_current_snapshot(cache_dir=feed_dir).created_at == _iso(installed_created)


def test_refresh_feed_times_out_without_installing(tmp_path, monkeypatch):
    feed_dir = tmp_path / "feed"
    installed_created = datetime.now(UTC) - timedelta(hours=10)
    update_feed_from_source(
        _write_bundle(tmp_path / "installed.json", created_at=installed_created),
        cache_dir=feed_dir,
    )
    newer = _write_bundle(tmp_path / "newer.json", created_at=datetime.now(UTC))
    original = package_feed.update_feed_from_source

    def slow(*args, **kwargs):
        time.sleep(0.6)
        return original(*args, **kwargs)

    monkeypatch.setattr(package_feed, "update_feed_from_source", slow)
    started = time.monotonic()

    result = api.refresh_feed(feed_dir=feed_dir, source=str(newer), timeout_seconds=0.1)

    assert result["status"] == "timeout"
    assert time.monotonic() - started < 0.5
    time.sleep(1.0)
    assert load_current_snapshot(cache_dir=feed_dir).created_at == _iso(installed_created)
    assert not [path for path in feed_dir.iterdir() if path.name.startswith(".refresh-")]


def test_a_package_listed_twice_gets_one_match_per_entry(tmp_path):
    feed_dir = tmp_path / "feed"
    update_feed_from_source(_write_bundle(tmp_path / "latest.json"), cache_dir=feed_dir)
    twice = [
        {"ecosystem": "npm", "name": "left-pad", "version": "1.3.0", "file": "a/package-lock.json"},
        {"ecosystem": "npm", "name": "left-pad", "version": "1.3.0", "file": "b/package-lock.json"},
        {"ecosystem": "npm", "name": "chalk", "version": "5.6.1", "file": "a/package-lock.json"},
        {"ecosystem": "npm", "name": "chalk", "version": "5.6.1", "file": "b/package-lock.json"},
    ]

    malware = api.malware_matches(twice, feed_dir=feed_dir)
    suspicious = api.suspicious_matches(twice, feed_dir=feed_dir)
    evaluated = api.evaluate_packages(twice, options={"feed_dir": str(feed_dir)})

    assert sorted((item["name"], item["file"]) for item in malware) == [
        ("left-pad", "a/package-lock.json"),
        ("left-pad", "b/package-lock.json"),
    ]
    assert sorted((item["name"], item["file"]) for item in suspicious) == [
        ("chalk", "a/package-lock.json"),
        ("chalk", "b/package-lock.json"),
    ]
    assert len([item for item in evaluated["findings"] if item["signal_type"] == "malware"]) == 2
