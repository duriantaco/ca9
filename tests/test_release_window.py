from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from scripts.build_feed import build_bundle_from_records

from ca9.package_feed import load_current_snapshot, release_window_covers, update_feed_from_source
from ca9.package_policy import ModePolicy, PackageAgePolicy, PackagePolicy
from ca9.runtime.preflight import evaluate_runtime_preflight

NOW = datetime(2026, 6, 27, tzinfo=timezone.utc)


def _install_feed(tmp_path, *, covers_since=None, releases=None):
    bundle = build_bundle_from_records(
        {"npm": [], "PyPI": []},
        now=NOW,
        releases_by_ecosystem=releases or {},
        covers_since=covers_since,
    )
    path = tmp_path / "feed.json"
    path.write_text(json.dumps(bundle))
    cache = tmp_path / "cache" / "feed"
    update_feed_from_source(str(path), cache_dir=cache)
    return cache


def test_release_window_covers_true_when_window_old_enough(tmp_path):
    cache = _install_feed(tmp_path, covers_since=(NOW - timedelta(days=10)).isoformat())
    snapshot = load_current_snapshot(cache_dir=cache)
    assert release_window_covers(snapshot, "pypi", now=NOW, minimum_hours=48) is True


def test_release_window_covers_false_when_window_too_recent(tmp_path):
    cache = _install_feed(tmp_path, covers_since=(NOW - timedelta(hours=10)).isoformat())
    snapshot = load_current_snapshot(cache_dir=cache)
    assert release_window_covers(snapshot, "pypi", now=NOW, minimum_hours=48) is False


def test_release_window_covers_false_without_covers_since(tmp_path):
    cache = _install_feed(tmp_path)
    snapshot = load_current_snapshot(cache_dir=cache)
    assert release_window_covers(snapshot, "npm", now=NOW, minimum_hours=48) is False


def test_preflight_absent_version_passes_when_window_covers(tmp_path):
    cache = _install_feed(tmp_path, covers_since=(NOW - timedelta(days=10)).isoformat())
    policy = PackagePolicy(
        package_age=PackageAgePolicy(enabled=True, minimum_hours=48),
        mode=ModePolicy(offline="block"),
    )
    preflight = evaluate_runtime_preflight(
        ("pip", "install", "oldpkg==1.0.0"),
        policy,
        env={},
        feed_cache_dir=cache,
        now=NOW,
    )
    assert preflight.action == "pass"
    assert all(d.policy_id != "ca9.package_age_unknown" for d in preflight.decisions)


def test_preflight_absent_version_unknown_without_window(tmp_path):
    cache = _install_feed(tmp_path)
    policy = PackagePolicy(
        package_age=PackageAgePolicy(enabled=True, minimum_hours=48),
        mode=ModePolicy(offline="block"),
    )
    preflight = evaluate_runtime_preflight(
        ("pip", "install", "oldpkg==1.0.0"),
        policy,
        env={},
        feed_cache_dir=cache,
        now=NOW,
    )
    assert any(d.policy_id == "ca9.package_age_unknown" for d in preflight.decisions)
