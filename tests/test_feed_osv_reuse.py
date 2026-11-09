from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from scripts import build_feed
from scripts.build_feed import build_bundle_from_records
from scripts.sentinel import Probe, Release
from scripts.sentinel import main as sentinel_main

from ca9 import api, package_feed
from ca9.package_feed import FeedError, update_feed_from_source

UTC = timezone.utc
OSV_DATASETS = (
    "npm-malware",
    "npm-malware-ranges",
    "npm-releases",
    "pypi-malware",
    "pypi-malware-ranges",
    "pypi-releases",
)
RECORDS = {
    "npm": [
        {
            "id": "MAL-2025-1",
            "summary": "malicious left-pad",
            "affected": [
                {"package": {"ecosystem": "npm", "name": "left-pad"}, "versions": ["1.3.0"]}
            ],
        },
        {
            "id": "MAL-2025-2",
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "@solana/web3.js"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [{"introduced": "1.95.6"}, {"fixed": "1.95.8"}],
                        }
                    ],
                }
            ],
        },
    ],
    "PyPI": [
        {
            "id": "MAL-2025-3",
            "affected": [
                {"package": {"ecosystem": "PyPI", "name": "Bad_Lib"}, "versions": ["1.0"]}
            ],
        }
    ],
}


def _iso(moment):
    return moment.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _previous_bundle(path, *, osv_age_hours=2.0, osv_built_at=True):
    built = datetime.now(UTC).replace(microsecond=0) - timedelta(hours=osv_age_hours)
    bundle = build_bundle_from_records(RECORDS, now=built)
    if not osv_built_at:
        bundle.pop("osv_built_at")
    state = {"schema": "ca9.sentinel.state.v1", "watermark": _iso(built)}
    bundle["datasets"]["npm-suspicious"] = {"packages": [], "sentinel": dict(state)}
    bundle["datasets"]["pypi-suspicious"] = {"packages": [], "sentinel": dict(state)}
    bundle["build_info"] = {"sources": {"npm": "u1", "PyPI": "u2"}}
    path.write_text(json.dumps(bundle, sort_keys=True, separators=(",", ":")) + "\n")
    return bundle


def _compact(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


class _Registry:
    def __init__(self, releases):
        self.data = releases

    def probe(self, ecosystem, name):
        releases = self.data.get((ecosystem, name), [])
        return Probe(modified=max((item.published for item in releases), default=None))

    def releases(self, ecosystem, name):
        return list(self.data.get((ecosystem, name), []))

    def marker(self, ecosystem):
        return None


def _flagging_review(pair, options):
    return {
        **pair,
        "status": "reviewed",
        "block": [
            {
                "kind": "new_install_hook",
                "path": "package/package.json",
                "line": 4,
                "snippet": '"postinstall": "node x.js"',
                "detail": "adds an install script",
            }
        ],
        "warn": [],
        "complete": True,
    }


def test_an_hour_without_osv_rebuild_keeps_osv_datasets_and_refreshes_only_suspicious(
    tmp_path, monkeypatch
):
    previous_path = tmp_path / "prev-latest.json"
    previous = _previous_bundle(previous_path, osv_age_hours=2)
    out = tmp_path / "latest.json"
    manifest_path = tmp_path / "manifest.json"

    def no_download(*args, **kwargs):
        raise AssertionError("OSV must not be downloaded in an hour without a rebuild")

    monkeypatch.setattr(build_feed, "fetch_osv_export", no_download)

    code = build_feed.main(
        [
            "-o",
            str(out),
            "--manifest",
            str(manifest_path),
            "--previous",
            str(previous_path),
            "--osv-rebuild-hours",
            "6",
        ]
    )

    assert code == 0
    built = json.loads(out.read_text())
    for name in OSV_DATASETS:
        assert _compact(built["datasets"][name]) == _compact(previous["datasets"][name])
        assert f'"{name}":{_compact(previous["datasets"][name])}' in out.read_text()
    assert built["osv_built_at"] == previous["osv_built_at"]
    assert built["created_at"] > previous["created_at"]
    assert built["expires_at"] == _iso(_parse(previous["osv_built_at"]) + timedelta(days=7))
    assert "npm-suspicious" not in built["datasets"]
    manifest = json.loads(manifest_path.read_text())
    assert manifest["osv_rebuilt"] is False
    assert manifest["osv_built_at"] == previous["osv_built_at"]
    assert manifest["sources"] == {"npm": "u1", "PyPI": "u2"}

    watch = tmp_path / "watch"
    watch.mkdir()
    for ecosystem, names in (("npm", ["left-pad"]), ("pypi", [])):
        (watch / f"watch-{ecosystem}.json").write_text(
            json.dumps(
                {
                    "schema": "ca9.sentinel.watchlist.v1",
                    "ecosystem": ecosystem,
                    "source": "https://example.test/list",
                    "license": "MIT",
                    "packages": names,
                }
            )
        )
    allow = tmp_path / "allow.json"
    allow.write_text(json.dumps({"schema": "ca9.sentinel.allow.v1", "entries": []}))
    now = datetime.now(UTC)
    registry = _Registry(
        {
            ("npm", "left-pad"): [
                Release("1.3.1", now - timedelta(days=400)),
                Release("1.3.2", now - timedelta(hours=1)),
            ]
        }
    )

    code = sentinel_main(
        [
            "run",
            "--previous",
            str(previous_path),
            "--bundle",
            str(out),
            "--manifest",
            str(manifest_path),
            "--watchlist-dir",
            str(watch),
            "--allowlist",
            str(allow),
            "--workers",
            "1",
            "--review-workers",
            "1",
        ],
        registry=registry,
        review=_flagging_review,
    )

    assert code == 0
    published = json.loads(out.read_text())
    for name in OSV_DATASETS:
        assert _compact(published["datasets"][name]) == _compact(previous["datasets"][name])
    assert [item["version"] for item in published["datasets"]["npm-suspicious"]["packages"]] == [
        "1.3.2"
    ]
    assert published["osv_built_at"] == previous["osv_built_at"]

    old_snapshot = update_feed_from_source(previous_path, cache_dir=tmp_path / "old-feed")
    new_snapshot = update_feed_from_source(out, cache_dir=tmp_path / "new-feed")
    for name in OSV_DATASETS:
        assert (
            new_snapshot.content_hashes[name]["sha256"]
            == (old_snapshot.content_hashes[name]["sha256"])
        )
    assert (
        new_snapshot.content_hashes["npm-suspicious"]["sha256"]
        != (old_snapshot.content_hashes["npm-suspicious"]["sha256"])
    )
    status = api.feed_status(feed_dir=tmp_path / "new-feed")
    assert status["osv_built_at"] == previous["osv_built_at"]
    assert status["state"] == "ready"


@pytest.mark.parametrize(
    "case",
    ["unreadable", "missing", "older_than_interval", "no_osv_time", "rebuild_every_run"],
)
def test_osv_datasets_are_rebuilt_when_the_previous_ones_cannot_be_reused(
    tmp_path, monkeypatch, case
):
    previous_path = tmp_path / "prev-latest.json"
    hours = "6"
    if case == "unreadable":
        previous_path.write_text("not json{")
    elif case == "older_than_interval":
        _previous_bundle(previous_path, osv_age_hours=7)
    elif case == "no_osv_time":
        _previous_bundle(previous_path, osv_age_hours=1, osv_built_at=False)
    elif case == "rebuild_every_run":
        _previous_bundle(previous_path, osv_age_hours=1)
        hours = "0"
    calls = []

    def fake_fetch(osv_ecosystem, *, source_url=None):
        calls.append(osv_ecosystem)
        return RECORDS[osv_ecosystem]

    monkeypatch.setattr(build_feed, "fetch_osv_export", fake_fetch)
    out = tmp_path / "latest.json"
    manifest_path = tmp_path / "manifest.json"
    started = datetime.now(UTC).replace(microsecond=0)

    code = build_feed.main(
        [
            "-o",
            str(out),
            "--manifest",
            str(manifest_path),
            "--previous",
            str(previous_path),
            "--osv-rebuild-hours",
            hours,
        ]
    )

    assert code == 0
    assert sorted(calls) == ["PyPI", "npm"]
    built = json.loads(out.read_text())
    assert _parse(built["osv_built_at"]) >= started
    assert built["osv_built_at"] == built["created_at"]
    manifest = json.loads(manifest_path.read_text())
    assert manifest["osv_rebuilt"] is True
    assert manifest["osv_reason"]


def test_the_rebuild_interval_comes_from_the_environment(tmp_path, monkeypatch):
    previous_path = tmp_path / "prev-latest.json"
    _previous_bundle(previous_path, osv_age_hours=2)
    calls = []

    def fake_fetch(osv_ecosystem, *, source_url=None):
        calls.append(osv_ecosystem)
        return RECORDS[osv_ecosystem]

    monkeypatch.setattr(build_feed, "fetch_osv_export", fake_fetch)
    monkeypatch.setenv("CA9_OSV_REBUILD_HOURS", "1")
    arguments = ["-o", str(tmp_path / "latest.json"), "--previous", str(previous_path)]

    assert build_feed.main(arguments) == 0
    assert sorted(calls) == ["PyPI", "npm"]

    monkeypatch.setenv("CA9_OSV_REBUILD_HOURS", "soon")
    with pytest.raises(SystemExit):
        build_feed.main(arguments)


def _bundle_file(path, **extra):
    created = datetime.now(UTC).replace(microsecond=0) - timedelta(hours=1)
    bundle = build_bundle_from_records(RECORDS, now=created)
    bundle.update(extra)
    path.write_text(json.dumps(bundle))
    return bundle


def test_feed_status_shows_when_the_osv_datasets_were_built(tmp_path):
    bundle = _bundle_file(tmp_path / "latest.json")
    feed_dir = tmp_path / "feed"

    snapshot = update_feed_from_source(tmp_path / "latest.json", cache_dir=feed_dir)

    assert snapshot.osv_built_at == bundle["osv_built_at"]
    assert snapshot.snapshot_id == package_feed._snapshot_id(
        {
            "schema": snapshot.schema,
            "created_at": snapshot.created_at,
            "expires_at": snapshot.expires_at,
            "content_hashes": snapshot.content_hashes,
        }
    )
    status = package_feed.feed_status(cache_dir=feed_dir)
    assert status.to_dict()["snapshot"]["osv_built_at"] == bundle["osv_built_at"]
    assert f"OSV data built: {bundle['osv_built_at']}" in package_feed.format_feed_status(status)
    assert api.feed_status(feed_dir=feed_dir)["osv_built_at"] == bundle["osv_built_at"]

    older = _bundle_file(tmp_path / "older.json")
    older.pop("osv_built_at")
    (tmp_path / "older.json").write_text(json.dumps(older))
    legacy = update_feed_from_source(tmp_path / "older.json", cache_dir=tmp_path / "legacy")
    assert legacy.osv_built_at is None
    assert api.feed_status(feed_dir=tmp_path / "legacy")["osv_built_at"] is None


@pytest.mark.parametrize("value", ["yesterday", 17, "2099-01-01T00:00:00Z"])
def test_an_invalid_osv_build_time_is_refused(tmp_path, value):
    _bundle_file(tmp_path / "latest.json", osv_built_at=value)

    with pytest.raises(FeedError):
        update_feed_from_source(tmp_path / "latest.json", cache_dir=tmp_path / "feed")
