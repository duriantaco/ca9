from __future__ import annotations

import io
import json
from datetime import datetime, timedelta, timezone

import pytest
from click.testing import CliRunner

from ca9 import package_feed
from ca9.cli import main
from ca9.core.models import Package
from ca9.package_feed import (
    FeedError,
    FeedSnapshot,
    FeedTamperError,
    feed_status,
    load_current_snapshot,
    lookup_malware,
    lookup_release_time,
    package_malware_findings,
    update_feed_from_source,
)
from ca9.package_policy import MalwarePolicy, ModePolicy, PackagePolicy


def test_feed_update_status_and_lookup(tmp_path):
    bundle = _write_feed_bundle(tmp_path)
    cache_dir = tmp_path / "cache" / "feed"

    snapshot = update_feed_from_source(bundle, cache_dir=cache_dir)
    status = feed_status(cache_dir=cache_dir)

    assert snapshot.snapshot_id
    assert status.state == "ready"
    assert status.action == "pass"
    assert lookup_malware("pypi", "Bad_Lib", "1.0.0", cache_dir=cache_dir)[0]["id"] == "MAL-1"
    assert (
        lookup_release_time("npm", "left-pad", "1.3.0", cache_dir=cache_dir)
        == "2026-06-25T00:00:00Z"
    )


def test_feed_status_expiry_is_controlled_by_policy(tmp_path):
    bundle = _write_feed_bundle(
        tmp_path,
        created_at="2026-06-01T00:00:00Z",
        expires_at="2026-06-02T00:00:00Z",
    )
    cache_dir = tmp_path / "cache" / "feed"
    update_feed_from_source(bundle, cache_dir=cache_dir)
    now = datetime(2026, 6, 3, tzinfo=timezone.utc)

    warn_status = feed_status(
        cache_dir=cache_dir,
        now=now,
        policy=PackagePolicy(mode=ModePolicy(offline="warn")),
    )
    block_status = feed_status(
        cache_dir=cache_dir,
        now=now,
        policy=PackagePolicy(mode=ModePolicy(offline="block")),
    )

    assert warn_status.state == "stale"
    assert warn_status.action == "warn"
    assert block_status.state == "stale"
    assert block_status.action == "block"


def test_feed_tamper_is_rejected(tmp_path):
    bundle = _write_feed_bundle(tmp_path)
    cache_dir = tmp_path / "cache" / "feed"
    snapshot = update_feed_from_source(bundle, cache_dir=cache_dir)
    dataset = snapshot.snapshot_dir / "pypi-malware.json"
    dataset.write_text('{"packages": []}\n')

    with pytest.raises(FeedTamperError):
        load_current_snapshot(cache_dir=cache_dir)

    status = feed_status(cache_dir=cache_dir)
    assert status.state == "tampered"
    assert status.action == "block"


def test_feed_snapshot_metadata_tamper_is_rejected(tmp_path):
    bundle = _write_feed_bundle(tmp_path)
    cache_dir = tmp_path / "cache" / "feed"
    snapshot = update_feed_from_source(bundle, cache_dir=cache_dir)
    snapshot_path = snapshot.snapshot_dir / "snapshot.json"
    metadata = json.loads(snapshot_path.read_text())
    metadata["expires_at"] = "2999-01-01T00:00:00Z"
    snapshot_path.write_text(json.dumps(metadata))

    with pytest.raises(FeedTamperError):
        load_current_snapshot(cache_dir=cache_dir)


def test_feed_cli_update_and_status_json(tmp_path):
    bundle = _write_feed_bundle(tmp_path)
    cache_root = tmp_path / "cache"
    runner = CliRunner()

    update = runner.invoke(
        main,
        ["feed", "update", "--from", str(bundle), "-f", "json"],
        env={"CA9_CACHE_DIR": str(cache_root)},
    )
    status = runner.invoke(
        main,
        ["feed", "status", "-f", "json"],
        env={"CA9_CACHE_DIR": str(cache_root)},
    )

    assert update.exit_code == 0
    update_data = json.loads(update.output)
    assert update_data["snapshot"]["schema"] == "ca9.feed.v1"
    assert status.exit_code == 0
    status_data = json.loads(status.output)
    assert status_data["state"] == "ready"
    assert status_data["snapshot"]["datasets"]["pypi-malware"]["sha256"]


def test_vet_package_age_blocks_new_release_from_feed(tmp_path):
    released_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    bundle = _write_feed_bundle(
        tmp_path,
        pypi_releases={"packages": {"badlib": {"1.0.0": released_at}}},
    )
    cache_root = tmp_path / "cache"
    update_feed_from_source(bundle, cache_dir=cache_root / "feed")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("badlib==1.0.0\n")
    policy_path = tmp_path / "ca9.toml"
    policy_path.write_text(
        """
[package_age]
enabled = true
minimum_hours = 48
"""
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["vet", "--repo", str(repo), "--policy", str(policy_path), "-f", "json"],
        env={"CA9_CACHE_DIR": str(cache_root)},
    )

    assert result.exit_code == 1
    data = json.loads(result.output)
    assert any(finding["signal_type"] == "new_package_version" for finding in data["findings"])
    assert any(decision["policy_id"] == "ca9.package_age" for decision in data["decisions"])


def test_vet_uses_local_malware_feed_without_osv_query(tmp_path):
    bundle = _write_feed_bundle(tmp_path)
    cache_root = tmp_path / "cache"
    update_feed_from_source(bundle, cache_dir=cache_root / "feed")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("bad-lib==1.0.0\n")
    policy_path = tmp_path / "ca9.toml"
    policy_path.write_text("")

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["vet", "--repo", str(repo), "--policy", str(policy_path), "-f", "json"],
        env={"CA9_CACHE_DIR": str(cache_root)},
    )

    assert result.exit_code == 1
    data = json.loads(result.output)
    assert any(finding["signal_type"] == "malware" for finding in data["findings"])
    assert any(decision["policy_id"] == "ca9.malware" for decision in data["decisions"])


def test_vet_package_age_blocks_unknown_release_when_offline_blocks(tmp_path):
    bundle = _write_feed_bundle(tmp_path, pypi_releases={"packages": {}})
    cache_root = tmp_path / "cache"
    update_feed_from_source(bundle, cache_dir=cache_root / "feed")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("unknownlib==1.0.0\n")
    policy_path = tmp_path / "ca9.toml"
    policy_path.write_text(
        """
[mode]
offline = "block"

[package_age]
enabled = true
minimum_hours = 48
"""
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["vet", "--repo", str(repo), "--policy", str(policy_path), "-f", "json"],
        env={"CA9_CACHE_DIR": str(cache_root)},
    )

    assert result.exit_code == 1
    data = json.loads(result.output)
    assert any(finding["signal_type"] == "package_age_unknown" for finding in data["findings"])
    assert any(decision["policy_id"] == "ca9.package_age_unknown" for decision in data["decisions"])


def test_vet_package_age_honors_offline_block_when_feed_missing(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("badlib==1.0.0\n")
    policy_path = tmp_path / "ca9.toml"
    policy_path.write_text(
        """
[mode]
default = "warn"
offline = "block"

[package_age]
enabled = true
minimum_hours = 48
"""
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["vet", "--repo", str(repo), "--policy", str(policy_path), "-f", "json"],
        env={"CA9_CACHE_DIR": str(tmp_path / "empty-cache")},
    )

    assert result.exit_code == 1
    data = json.loads(result.output)
    assert any(finding["signal_type"] == "feed_unavailable" for finding in data["findings"])
    assert any(decision["policy_id"] == "ca9.feed_unavailable" for decision in data["decisions"])
    assert any(decision["action"] == "block" for decision in data["decisions"])


BAD_LIB = (Package(ecosystem="pypi", name="bad-lib", version="1.0.0"),)


def _install_stale_feed(tmp_path):
    bundle = _write_feed_bundle(
        tmp_path,
        created_at=_hours_from_now(-24 * 10),
        expires_at=_hours_from_now(-24 * 3),
    )
    cache_dir = tmp_path / "cache" / "feed"
    update_feed_from_source(bundle, cache_dir=cache_dir)
    return cache_dir


def test_missing_malware_feed_warns_instead_of_silently_skipping(tmp_path):
    findings, warnings = package_malware_findings(
        BAD_LIB, PackagePolicy(), cache_dir=tmp_path / "no-feed"
    )

    assert findings == []
    assert len(warnings) == 1
    assert "malware feed is missing" in warnings[0]
    assert "ca9 feed update" in warnings[0]


def test_stale_malware_feed_still_matches_and_warns_with_age(tmp_path):
    cache_dir = _install_stale_feed(tmp_path)

    findings, warnings = package_malware_findings(BAD_LIB, PackagePolicy(), cache_dir=cache_dir)

    assert [finding.signal_type for finding in findings] == ["malware"]
    assert findings[0].metadata["malware_id"] == "MAL-1"
    assert len(warnings) == 1
    assert "malware feed is stale" in warnings[0]
    assert "3 days ago" in warnings[0]
    assert "10 days old" in warnings[0]
    assert "ca9 feed update" in warnings[0]


def test_fail_closed_malware_policy_still_blocks_missing_and_stale_feed(tmp_path):
    policy = PackagePolicy(malware=MalwarePolicy(enabled=True, fail_closed=True))
    stale_cache = _install_stale_feed(tmp_path)

    for cache_dir in (tmp_path / "no-feed", stale_cache):
        findings, warnings = package_malware_findings(BAD_LIB, policy, cache_dir=cache_dir)
        assert [finding.metadata["policy_id"] for finding in findings] == [
            "ca9.malware_feed_unavailable"
        ]
        assert findings[0].metadata["action"] == "block"
        assert warnings == []


def test_vet_surfaces_missing_feed_warning_in_json_and_table(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("bad-lib==1.0.0\n")
    policy_path = tmp_path / "ca9.toml"
    policy_path.write_text("")
    env = {"CA9_CACHE_DIR": str(tmp_path / "empty-cache")}
    runner = CliRunner()

    as_json = runner.invoke(
        main, ["vet", "--repo", str(repo), "--policy", str(policy_path), "-f", "json"], env=env
    )
    as_table = runner.invoke(
        main, ["vet", "--repo", str(repo), "--policy", str(policy_path)], env=env
    )

    data = json.loads(as_json.output)
    assert any("malware feed is missing" in warning for warning in data["warnings"])
    assert "malware feed is missing" in as_table.output
    assert "ca9 feed update" in as_table.output


def test_vet_blocks_from_stale_feed_and_warns(tmp_path):
    cache_dir = _install_stale_feed(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("bad-lib==1.0.0\n")
    policy_path = tmp_path / "ca9.toml"
    policy_path.write_text("")

    result = CliRunner().invoke(
        main,
        ["vet", "--repo", str(repo), "--policy", str(policy_path), "-f", "json"],
        env={"CA9_CACHE_DIR": str(cache_dir.parent)},
    )

    assert result.exit_code == 1
    data = json.loads(result.output)
    assert any(finding["signal_type"] == "malware" for finding in data["findings"])
    assert any("malware feed is stale" in warning for warning in data["warnings"])


def test_protect_reports_stale_feed_warning_and_match(tmp_path):
    from ca9.protect import build_protect_report, protect_report_to_json, protect_report_to_table

    cache_dir = _install_stale_feed(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("bad-lib==1.0.0\n")

    report = build_protect_report(
        repo, PackagePolicy(), scan_workflows=False, feed_cache_dir=cache_dir
    )

    data = json.loads(protect_report_to_json(report))
    assert any("malware feed is stale" in w for w in data["supply_chain"]["warnings"])
    assert any(f["signal_type"] == "malware" for f in data["supply_chain"]["findings"])
    table = protect_report_to_table(report)
    assert "[WARN] Package intelligence feed: feed snapshot expired at" in table
    assert "ca9 feed update" in table


def test_lookup_malware_parses_dataset_once_across_lookups(tmp_path, monkeypatch):
    cache_dir = tmp_path / "cache" / "feed"
    snapshot = update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_dir)
    parsed: list[str] = []
    original = package_feed._parse_dataset

    def counting_parse(path, data):
        parsed.append(path.name)
        return original(path, data)

    monkeypatch.setattr(package_feed, "_parse_dataset", counting_parse)

    for index in range(200):
        lookup_malware("pypi", "bad-lib", f"1.0.{index}", snapshot=snapshot)
    for _ in range(20):
        assert lookup_malware("pypi", "Bad_Lib", "1.0.0", cache_dir=cache_dir)[0]["id"] == "MAL-1"

    assert parsed == ["pypi-malware.json"]


def test_feed_status_hashes_each_dataset_once_until_it_changes(tmp_path, monkeypatch):
    cache_dir = tmp_path / "cache" / "feed"
    snapshot = update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_dir)
    package_feed._clear_feed_caches()
    hashed: list[int] = []
    original = package_feed._sha256_bytes

    def counting_hash(data):
        hashed.append(len(data))
        return original(data)

    monkeypatch.setattr(package_feed, "_sha256_bytes", counting_hash)

    for _ in range(25):
        assert feed_status(cache_dir=cache_dir).state == "ready"
    assert len(hashed) == len(package_feed.REQUIRED_DATASETS)

    # A rewritten dataset is a new file version: it is re-hashed and rejected.
    (snapshot.snapshot_dir / "pypi-malware.json").write_text('{"packages": []}\n')
    assert feed_status(cache_dir=cache_dir).state == "tampered"
    with pytest.raises(FeedTamperError):
        lookup_malware("pypi", "bad-lib", "1.0.0", snapshot=snapshot)


def test_feed_update_refuses_rollback_unless_allowed(tmp_path):
    cache_dir = tmp_path / "cache" / "feed"
    newer = _write_feed_bundle(tmp_path, created_at=_hours_from_now(-24), filename="new.json")
    older = _write_feed_bundle(tmp_path, created_at=_hours_from_now(-72), filename="old.json")
    installed = update_feed_from_source(newer, cache_dir=cache_dir)

    with pytest.raises(FeedError, match="rollback"):
        update_feed_from_source(older, cache_dir=cache_dir)
    assert load_current_snapshot(cache_dir=cache_dir).snapshot_id == installed.snapshot_id

    downgraded = update_feed_from_source(older, cache_dir=cache_dir, allow_downgrade=True)
    assert load_current_snapshot(cache_dir=cache_dir).snapshot_id == downgraded.snapshot_id
    # Re-installing the same snapshot is not a rollback.
    update_feed_from_source(older, cache_dir=cache_dir)


def test_feed_cli_update_allow_downgrade_flag(tmp_path):
    env = {"CA9_CACHE_DIR": str(tmp_path / "cache")}
    newer = _write_feed_bundle(tmp_path, created_at=_hours_from_now(-24), filename="new.json")
    older = _write_feed_bundle(tmp_path, created_at=_hours_from_now(-72), filename="old.json")
    runner = CliRunner()

    assert runner.invoke(main, ["feed", "update", "--from", str(newer)], env=env).exit_code == 0
    refused = runner.invoke(main, ["feed", "update", "--from", str(older)], env=env)
    allowed = runner.invoke(
        main, ["feed", "update", "--from", str(older), "--allow-downgrade"], env=env
    )

    assert refused.exit_code == 1
    assert "--allow-downgrade" in refused.output
    assert allowed.exit_code == 0, allowed.output


def test_feed_update_rejects_created_at_far_in_the_future(tmp_path):
    cache_dir = tmp_path / "cache" / "feed"
    future = _write_feed_bundle(
        tmp_path,
        created_at=_hours_from_now(48),
        expires_at=_hours_from_now(72),
        filename="future.json",
    )
    slightly_ahead = _write_feed_bundle(
        tmp_path, created_at=_hours_from_now(1), filename="skew.json"
    )

    with pytest.raises(FeedError, match="in the future"):
        update_feed_from_source(future, cache_dir=cache_dir)
    assert update_feed_from_source(slightly_ahead, cache_dir=cache_dir).snapshot_id


def test_feed_update_caps_lifetime_at_thirty_days(tmp_path):
    cache_dir = tmp_path / "cache" / "feed"
    created = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=1)
    bundle = _write_feed_bundle(
        tmp_path, created_at=created.isoformat(), expires_at="9999-12-31T00:00:00Z"
    )

    snapshot = update_feed_from_source(bundle, cache_dir=cache_dir)

    capped = created + timedelta(days=30)
    assert snapshot.expires_at == capped.isoformat().replace("+00:00", "Z")
    assert feed_status(cache_dir=cache_dir).state == "ready"
    later = feed_status(cache_dir=cache_dir, now=capped + timedelta(seconds=1))
    assert later.state == "stale"


def test_snapshot_expiry_is_capped_even_if_stored_lifetime_is_longer(tmp_path):
    snapshot = FeedSnapshot(
        cache_dir=tmp_path,
        snapshot_dir=tmp_path,
        snapshot_id="legacy",
        schema="ca9.feed.v1",
        created_at="2026-01-01T00:00:00Z",
        expires_at="9999-12-31T00:00:00Z",
        content_hashes={},
    )

    assert snapshot.is_expired(now=datetime(2026, 2, 1, tzinfo=timezone.utc))
    assert not snapshot.is_expired(now=datetime(2026, 1, 30, tzinfo=timezone.utc))


def test_feed_download_aborts_once_stream_exceeds_size_cap(tmp_path, monkeypatch):
    url = "https://feed.example/latest.json"
    download = _FakeDownload(b"x" * 10_000, url=url)
    monkeypatch.setattr(package_feed, "MAX_FEED_DOWNLOAD_BYTES", 2048)
    monkeypatch.setattr(package_feed, "_DOWNLOAD_CHUNK_BYTES", 1024)
    monkeypatch.setattr(package_feed.urllib.request, "urlopen", lambda *a, **k: download)

    with pytest.raises(FeedError, match="size limit"):
        update_feed_from_source(url, cache_dir=tmp_path / "cache" / "feed")
    assert download.reads == 3


def test_feed_download_rejects_declared_oversize_and_http_redirects(tmp_path, monkeypatch):
    url = "https://feed.example/latest.json"
    monkeypatch.setattr(package_feed, "MAX_FEED_DOWNLOAD_BYTES", 2048)
    oversized = _FakeDownload(b"{}", url=url, headers={"Content-Length": "999999"})
    monkeypatch.setattr(package_feed.urllib.request, "urlopen", lambda *a, **k: oversized)
    with pytest.raises(FeedError, match="size limit"):
        update_feed_from_source(url, cache_dir=tmp_path / "cache" / "feed")
    assert oversized.reads == 0

    redirected = _FakeDownload(b"{}", url="http://feed.example/latest.json")
    monkeypatch.setattr(package_feed.urllib.request, "urlopen", lambda *a, **k: redirected)
    with pytest.raises(FeedError, match="non-https"):
        update_feed_from_source(url, cache_dir=tmp_path / "cache" / "feed")


def test_feed_download_over_https_installs_bundle(tmp_path, monkeypatch):
    url = "https://feed.example/latest.json"
    body = _write_feed_bundle(tmp_path).read_bytes()
    monkeypatch.setattr(package_feed, "_DOWNLOAD_CHUNK_BYTES", 64)
    monkeypatch.setattr(
        package_feed.urllib.request, "urlopen", lambda *a, **k: _FakeDownload(body, url=url)
    )

    snapshot = update_feed_from_source(url, cache_dir=tmp_path / "cache" / "feed")

    assert snapshot.source == url
    assert lookup_malware("pypi", "bad-lib", "1.0.0", snapshot=snapshot)


def test_feed_update_rejects_plain_http(tmp_path):
    with pytest.raises(FeedError, match="insecure http"):
        update_feed_from_source(
            "http://feed.example/latest.json", cache_dir=tmp_path / "cache" / "feed"
        )


def _write_feed_bundle(
    tmp_path,
    *,
    created_at: str | None = None,
    expires_at: str | None = None,
    pypi_releases: dict | None = None,
    filename: str = "feed.json",
):
    created_at = (
        created_at
        or (datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=1)).isoformat()
    )
    expires = (
        expires_at
        or (datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=1)).isoformat()
    )
    bundle = {
        "schema": "ca9.feed.v1",
        "created_at": created_at,
        "expires_at": expires,
        "datasets": {
            "pypi-malware": {
                "packages": [
                    {
                        "name": "bad-lib",
                        "version": "1.0.0",
                        "id": "MAL-1",
                        "summary": "known malicious test package",
                    }
                ]
            },
            "npm-malware": {
                "packages": [
                    {
                        "name": "left-pad",
                        "version": "1.3.0",
                        "id": "MAL-NPM-1",
                    }
                ]
            },
            "pypi-releases": pypi_releases
            or {"packages": {"bad-lib": {"1.0.0": "2026-06-25T00:00:00Z"}}},
            "npm-releases": {"packages": {"left-pad": {"1.3.0": "2026-06-25T00:00:00Z"}}},
        },
    }
    path = tmp_path / filename
    path.write_text(json.dumps(bundle))
    return path


def _hours_from_now(hours: float) -> str:
    return (datetime.now(timezone.utc).replace(microsecond=0) + timedelta(hours=hours)).isoformat()


class _FakeDownload:
    def __init__(self, body: bytes, *, url: str, headers: dict | None = None):
        self._body = io.BytesIO(body)
        self._url = url
        self.headers = headers or {}
        self.reads = 0

    def read(self, size: int = -1) -> bytes:
        self.reads += 1
        return self._body.read(size)

    def geturl(self) -> str:
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False
