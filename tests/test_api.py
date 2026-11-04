from __future__ import annotations

import sys
import types

import pytest

from ca9 import api, npm_publisher
from ca9.core.models import Finding

PRIVATE = "https://pypi.acme-internal.example/simple"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def _pkg(name, version="1.0.0", **extra):
    return {"ecosystem": "pypi", "name": name, "version": version, "direct": True, **extra}


def _by_signal(result):
    return {(finding["signal_type"], finding["name"]): finding for finding in result["findings"]}


def _skips(result):
    return {item["reason"]: item["count"] for item in result["receipt"]["skipped"]}


@pytest.fixture(autouse=True)
def no_feed_or_age(monkeypatch):
    """Model an installation without the feed matcher or release-age module."""
    monkeypatch.setitem(sys.modules, "ca9.release_age", None)
    import ca9.package_feed as package_feed

    monkeypatch.delattr(package_feed, "find_malware_matches", raising=False)


def test_malformed_input_is_counted_never_raised():
    result = api.evaluate_packages(
        [
            "not a dict",
            {"name": "x"},
            {"ecosystem": "cargo", "name": "serde"},
            _pkg("ok", source_kind="svn"),
            _pkg("ok", registry_mode="weird"),
            _pkg("ok", version=3),
            _pkg("requests"),
        ],
        options={"max_lookups": -1, "network": "yes"},
    )

    assert result["receipt"]["checked"] == 1
    skips = _skips(result)
    assert skips["malformed_package"] == 5
    assert skips["unsupported_ecosystem"] == 1
    assert skips["invalid_option"] == 2
    assert result["receipt"]["complete"] is False
    assert api.evaluate_packages(None)["receipt"]["skipped"] == [
        {"reason": "malformed_input", "count": 1}
    ]


def test_merged_registry_internal_package_is_critical_confusion_and_public_is_not():
    options = {"internal_packages": ["acme-*"], "private_registries": [PRIVATE]}
    merged = {"registry": PRIVATE, "registry_mode": "merged"}

    result = api.evaluate_packages(
        [
            _pkg("acme-billing", **merged),
            _pkg("ACME_Ledger", direct=False, **merged),
            _pkg("requests", **merged),
        ],
        options=options,
    )

    findings = _by_signal(result)
    assert findings[("dependency_confusion", "acme-billing")]["severity"] == "CRITICAL"
    assert findings[("dependency_confusion", "acme-billing")]["action"] == "block"
    assert findings[("dependency_confusion", "ACME_Ledger")]["severity"] == "HIGH"
    assert not [key for key in findings if key[1] == "requests"]


def test_exclusive_private_registry_is_not_confusion():
    result = api.evaluate_packages(
        [_pkg("acme-billing", registry=PRIVATE, registry_mode="exclusive")],
        options={"internal_packages": ["acme-*"], "private_registries": [PRIVATE]},
    )

    assert not result["findings"]


def test_untrusted_registry_only_when_trusted_registries_are_configured():
    package = _pkg("requests", registry="https://mirror.example/simple")

    assert not api.evaluate_packages([package])["findings"]
    configured = api.evaluate_packages(
        [package], options={"trusted_registries": ["https://pypi.org/simple"]}
    )
    assert ("untrusted_registry", "requests") in _by_signal(configured)


def test_git_and_url_sources_carry_mutability_evidence():
    result = api.evaluate_packages(
        [
            _pkg("pinned", source_kind="git", source_url=f"git+https://h/o/p@{COMMIT}"),
            _pkg("branch", source_kind="git", source_url="git+https://h/o/b@main"),
            _pkg("fake", source_kind="git", source_url="git+https://h/o/f@" + "z" * 40),
            _pkg(
                "hashed",
                source_kind="url",
                source_url="https://f/h.tgz",
                integrity="sha256:" + "a" * 64,
            ),
            _pkg("empty", source_kind="url", source_url="https://f/e.tgz", integrity="sha256:"),
            _pkg("local", source_kind="path", source_url="./vendor/local"),
        ]
    )

    findings = _by_signal(result)
    assert findings[("git_dependency", "pinned")]["evidence"]["mutable"] is False
    assert findings[("git_dependency", "pinned")]["severity"] == "LOW"
    assert findings[("git_dependency", "branch")]["evidence"]["mutable"] is True
    assert findings[("git_dependency", "fake")]["evidence"]["pinned_commit"] is False
    assert findings[("direct_url_dependency", "hashed")]["evidence"]["has_hash"] is True
    assert findings[("direct_url_dependency", "empty")]["evidence"]["has_hash"] is False
    assert findings[("direct_url_dependency", "empty")]["severity"] == "MEDIUM"
    assert ("mutable_source", "local") in findings


def test_missing_integrity_only_for_lockfile_registry_entries():
    result = api.evaluate_packages(
        [
            {
                "ecosystem": "npm",
                "name": "left-pad",
                "version": "1.3.0",
                "file": "a/package-lock.json",
            },
            {
                "ecosystem": "npm",
                "name": "ok",
                "version": "1.0.0",
                "file": "package-lock.json",
                "integrity": "sha512-abc",
            },
            _pkg("requests", file="requirements.txt"),
            _pkg("forced", lockfile=True),
        ]
    )

    names = {name for signal, name in _by_signal(result) if signal == "missing_integrity"}
    assert names == {"left-pad", "forced"}


def test_malware_uses_the_feed_matcher_and_reports_file_and_line(monkeypatch):
    import ca9.package_feed as package_feed

    def find(packages, *, cache_dir=None):
        return [
            Finding(
                title="Malicious package",
                signal_type="malware",
                package_key=package.key,
                severity="critical",
                metadata={"action": "block", "advisory_id": "MAL-1"},
            )
            for package in packages
            if package.name == "chalk"
        ]

    monkeypatch.setattr(package_feed, "find_malware_matches", find, raising=False)
    packages = [
        {
            "ecosystem": "npm",
            "name": "chalk",
            "version": "5.6.1",
            "file": "package-lock.json",
            "line": 7,
        },
        {
            "ecosystem": "npm",
            "name": "ansi-styles",
            "version": "6.2.1",
            "file": "package-lock.json",
        },
    ]

    result = api.evaluate_packages(packages)

    malware = [finding for finding in result["findings"] if finding["signal_type"] == "malware"]
    assert [(m["name"], m["severity"], m["line"]) for m in malware] == [("chalk", "CRITICAL", 7)]
    assert malware[0]["evidence"]["advisory_id"] == "MAL-1"
    assert result["receipt"]["complete"] is True
    assert api.malware_matches(packages)[0]["name"] == "chalk"


def test_missing_feed_is_a_skip_in_evaluate_and_an_error_in_malware_matches():
    result = api.evaluate_packages([_pkg("requests")])

    assert _skips(result) == {"malware_feed_unsupported": 1}
    with pytest.raises(api.FeedUnavailable):
        api.malware_matches([_pkg("requests")])


def _release_age_module(monkeypatch, statuses):
    calls = []

    def check(ecosystem, name, version, *, min_hours, cache_dir=None):
        calls.append((ecosystem, name, version, min_hours))
        return {
            "status": statuses.get(name, "old_enough"),
            "published_at": "2026-11-04T00:00:00Z",
            "age_hours": 2.0,
            "suggested_version": "1.0.0",
            "source": "registry",
        }

    module = types.ModuleType("ca9.release_age")
    module.check_release_age = check
    monkeypatch.setitem(sys.modules, "ca9.release_age", module)
    return calls


def test_release_age_needs_network_and_respects_max_lookups(monkeypatch):
    calls = _release_age_module(monkeypatch, {"fresh": "too_new"})
    packages = [_pkg("fresh", "2.0.0"), _pkg("old"), _pkg("third"), _pkg("unpinned", None)]

    offline = api.evaluate_packages(packages, options={"min_release_age_hours": 24})
    assert calls == []
    assert _skips(offline)["network_disabled"] == 3

    online = api.evaluate_packages(
        packages, options={"min_release_age_hours": 24, "network": True, "max_lookups": 2}
    )

    finding = _by_signal(online)[("new_package_version", "fresh")]
    assert finding["severity"] == "HIGH"
    assert finding["action"] == "block"
    assert "1.0.0" in finding["remediation"]
    assert len(calls) == 2
    assert online["receipt"]["lookups"] == 2
    assert _skips(online)["max_lookups"] == 1
    assert _skips(online)["release_age_no_version"] == 1
    assert api.check_release_age("pypi", "fresh", "2.0.0", min_hours=24)["status"] == "too_new"


def test_release_age_wrapper_is_unknown_without_the_module():
    result = api.check_release_age("npm", "left-pad", "1.3.0", min_hours=24)

    assert result["status"] == "unknown"
    assert set(result) >= {"published_at", "age_hours", "suggested_version", "source"}


def test_provenance_check_is_npm_only():
    assert api.check_provenance("pypi", "six", "1.16.0")["status"] == "not_applicable"


def test_provenance_regression_is_a_blocking_npm_finding(monkeypatch):
    document = {
        "name": "pkg",
        "time": {
            "1.0.0": "2025-01-01T00:00:00Z",
            "1.1.0": "2025-02-01T00:00:00Z",
            "1.2.0": "2025-03-01T00:00:00Z",
        },
        "versions": {
            "1.0.0": {"dist": {"attestations": {"url": "https://registry.npmjs.org/a"}}},
            "1.1.0": {"dist": {"attestations": {"url": "https://registry.npmjs.org/b"}}},
            "1.2.0": {"dist": {}},
        },
    }
    fetched = []

    def fetch(url, *, max_bytes):
        fetched.append(url)
        return document

    monkeypatch.setattr(npm_publisher, "_fetch_json", fetch)
    packages = [
        {
            "ecosystem": "npm",
            "name": "pkg",
            "version": "1.2.0",
            "file": "package-lock.json",
            "integrity": "sha512-x",
        },
        {
            "ecosystem": "npm",
            "name": "pkg",
            "version": "1.1.0",
            "file": "package-lock.json",
            "integrity": "sha512-y",
        },
        {
            "ecosystem": "npm",
            "name": "@acme/internal",
            "version": "1.0.0",
            "registry": "https://npm.acme.dev",
            "integrity": "sha512-z",
        },
    ]

    result = api.evaluate_packages(packages, options={"check_provenance": True, "network": True})

    regression = _by_signal(result)[("provenance_regression", "pkg")]
    assert regression["version"] == "1.2.0"
    assert regression["severity"] == "HIGH"
    assert regression["action"] == "block"
    assert regression["evidence"]["previous_with_provenance"] == ["1.1.0", "1.0.0"]
    assert len(fetched) == 1
    assert result["receipt"]["lookups"] == 1
    assert _skips(result)["provenance_private_registry"] == 1
