from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from click.testing import CliRunner

from ca9.cli import main
from ca9.package_feed import (
    FeedTamperError,
    feed_status,
    load_current_snapshot,
    lookup_malware,
    lookup_release_time,
    update_feed_from_source,
)
from ca9.package_policy import ModePolicy, PackagePolicy


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


def _write_feed_bundle(
    tmp_path,
    *,
    created_at: str = "2026-06-26T00:00:00Z",
    expires_at: str | None = None,
    pypi_releases: dict | None = None,
):
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
    path = tmp_path / "feed.json"
    path.write_text(json.dumps(bundle))
    return path
