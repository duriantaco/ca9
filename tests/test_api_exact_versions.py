from __future__ import annotations

import sys
import types

import pytest

from ca9 import api, npm_publisher
from ca9.core.models import Finding


def _skips(result):
    return {item["reason"]: item["count"] for item in result["receipt"]["skipped"]}


@pytest.fixture
def matcher(monkeypatch):
    import ca9.package_feed as package_feed

    seen = []

    def find(packages, *, cache_dir=None):
        seen.extend((package.name, package.version) for package in packages)
        return [
            Finding(
                title="Malicious package",
                signal_type="malware",
                package_key=f"npm:{package.name}",
                severity="critical",
                metadata={"action": "block", "advisory_id": "MAL-1"},
            )
            for package in packages
            if package.name == "evil-everywhere"
        ]

    monkeypatch.setattr(package_feed, "find_malware_matches", find, raising=False)
    return seen


@pytest.mark.parametrize(
    ("ecosystem", "name", "version"),
    [
        ("npm", "@solana/web3.js", "npm:@solana/web3.js@1.95.6"),
        ("npm", "chalk", "^5.6.1"),
        ("npm", "chalk", "5.6.1 || 5.6.0"),
        ("npm", "chalk", "latest"),
        ("pypi", "requests", ">=2.0"),
        ("pypi", "requests", "2.*"),
        ("pypi", "requests", "==2.32.3"),
    ],
)
def test_non_exact_versions_are_undecided_not_clean(matcher, ecosystem, name, version):
    result = api.evaluate_packages([{"ecosystem": ecosystem, "name": name, "version": version}])

    assert result["findings"] == []
    assert _skips(result) == {"malware_version_not_exact": 1}
    assert result["receipt"]["complete"] is False


@pytest.mark.parametrize(
    ("ecosystem", "version"),
    [
        ("npm", "5.6.1"),
        ("npm", "1.0.0-beta.1"),
        ("pypi", "2.32.3"),
        ("pypi", "1.0.post1"),
        ("pypi", "1.0+cpu"),
        ("pypi", "1!2.0"),
    ],
)
def test_exact_and_unpinned_versions_keep_a_complete_receipt(matcher, ecosystem, version):
    exact = api.evaluate_packages([{"ecosystem": ecosystem, "name": "chalk", "version": version}])
    unpinned = api.evaluate_packages([{"ecosystem": ecosystem, "name": "chalk"}])

    assert exact["receipt"]["complete"] is True
    assert unpinned["receipt"]["complete"] is True


def test_whole_package_malware_still_reports_for_a_range(matcher):
    result = api.evaluate_packages(
        [{"ecosystem": "npm", "name": "evil-everywhere", "version": "^1.0.0"}]
    )

    assert [finding["signal_type"] for finding in result["findings"]] == ["malware"]
    assert result["receipt"]["complete"] is False


def test_release_age_and_provenance_skip_non_exact_versions_without_lookups(monkeypatch, matcher):
    calls = []

    def check(ecosystem, name, version, *, min_hours, cache_dir=None):
        calls.append(version)
        return {"status": "old_enough", "source": "registry"}

    module = types.ModuleType("ca9.release_age")
    module.check_release_age = check
    monkeypatch.setitem(sys.modules, "ca9.release_age", module)
    fetched = []
    monkeypatch.setattr(
        npm_publisher, "_fetch_json", lambda url, *, max_bytes, **kw: fetched.append(url) or {}
    )

    result = api.evaluate_packages(
        [{"ecosystem": "npm", "name": "chalk", "version": "^5.6.1"}],
        options={"min_release_age_hours": 24, "check_provenance": True, "network": True},
    )

    assert calls == [] and fetched == []
    assert _skips(result) == {
        "malware_version_not_exact": 1,
        "provenance_version_not_exact": 1,
        "release_age_version_not_exact": 1,
    }
