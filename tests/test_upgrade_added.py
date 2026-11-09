"""Packages new to a project (``added: true``) are compared with the release before them on
the registry; only a package with no earlier release is a first release."""

from __future__ import annotations

import json

from tests.test_upgrade_review import NPM, _kinds, registry

from ca9 import api
from ca9.artifacts import fetch

__all__ = ["registry"]

BINARY_INSTALL = (
    "const https = require('https');\nconst fs = require('fs');\n"
    "const version = '{version}';\n"
    "https.get(`https://registry.npmjs.org/@fastbundle/darwin-arm64/-/darwin-arm64-${{version}}.tgz`,\n"
    "  (r) => r.pipe(fs.createWriteStream('bin.tgz')).on('finish', () => fs.chmodSync('bin.tgz', 0o755)));\n"
)


def _packument(registry, name, times):
    registry.documents[f"{NPM}/{name}"] = json.dumps(
        {
            "name": name,
            "versions": {version: {"version": version} for version in times},
            "time": {"created": "2024-01-01T00:00:00.000Z", **times},
        }
    ).encode()


def _fastbundle(registry, version):
    registry.npm(
        "fastbundle",
        version,
        {
            "index.js": "module.exports = require('./lib/main.js');\n",
            "lib/main.js": "module.exports = { build: (o) => o };\n",
            "install.js": BINARY_INSTALL.format(version=version),
        },
        manifest={
            "scripts": {"postinstall": "node install.js"},
            "optionalDependencies": {"@fastbundle/darwin-arm64": version},
        },
    )


def _added(ecosystem, name, version, **options):
    pair = {"ecosystem": ecosystem, "name": name, "old": None, "new": version, "added": True}
    report = api.review_upgrades([pair], options=options or None)
    return report["results"][0], report["receipt"]


def test_install_hook_that_the_previous_release_already_had_is_not_blocked(registry):
    _fastbundle(registry, "0.19.12")
    _fastbundle(registry, "0.20.0")
    _packument(
        registry,
        "fastbundle",
        {
            "0.19.11": "2025-01-01T00:00:00.000Z",
            "0.19.12": "2025-02-01T00:00:00.000Z",
            "0.20.0": "2025-03-01T00:00:00.000Z",
        },
    )
    registry.documents.pop(f"{NPM}/fastbundle/0.19.11", None)

    result, receipt = _added("npm", "fastbundle", "0.20.0")

    assert result["status"] == "reviewed"
    assert result["basis"] == "registry_previous"
    assert result["old"] is None and result["old_resolved"] == "0.19.12"
    assert result["added"] is True
    assert result["block"] == []
    assert "first_release" not in result
    assert receipt["first_release_reviews"] == 0 and receipt["complete"] is True


def test_added_package_whose_new_release_adds_a_hook_blocks(registry):
    registry.npm("quietlib", "2.0.0", {"index.js": "module.exports = 1;\n"})
    registry.npm(
        "quietlib",
        "2.1.0",
        {"index.js": "module.exports = 1;\n", "setup.js": "console.log('hi');\n"},
        manifest={"scripts": {"postinstall": "node setup.js"}},
    )
    _packument(
        registry,
        "quietlib",
        {"2.0.0": "2025-01-01T00:00:00.000Z", "2.1.0": "2025-02-01T00:00:00.000Z"},
    )

    result, _ = _added("npm", "quietlib", "2.1.0")

    assert result["old_resolved"] == "2.0.0"
    assert "new_install_hook" in _kinds(result, "block")


def test_added_package_with_no_earlier_release_is_a_first_release(registry):
    registry.npm(
        "brandnew",
        "1.0.0",
        {"index.js": "module.exports = 1;\n", "setup.js": "console.log('hi');\n"},
        manifest={"scripts": {"postinstall": "node setup.js"}},
    )
    _packument(registry, "brandnew", {"1.0.0": "2025-02-01T00:00:00.000Z"})

    result, receipt = _added("npm", "brandnew", "1.0.0")

    assert result["first_release"] is True and result["basis"] == "new_package"
    assert "new_install_hook" in _kinds(result, "block")
    assert receipt["first_release_reviews"] == 1


def test_previous_release_skips_prereleases_yanked_and_later_uploads(registry):
    for version in ("0.9", "1.0", "1.1rc1", "1.1", "1.0.1"):
        registry.pypi("pickme", version, wheel={"pickme/__init__.py": f"V = '{version}'\n"})
    registry.documents["https://pypi.org/pypi/pickme/json"] = json.dumps(
        {
            "info": {"name": "pickme"},
            "releases": {
                "0.9": [{"upload_time_iso_8601": "2025-01-01T00:00:00Z", "yanked": False}],
                "1.0": [{"upload_time_iso_8601": "2025-02-01T00:00:00Z", "yanked": True}],
                "1.1rc1": [{"upload_time_iso_8601": "2025-03-01T00:00:00Z", "yanked": False}],
                "1.1": [{"upload_time_iso_8601": "2025-04-01T00:00:00Z", "yanked": False}],
                "1.0.1": [{"upload_time_iso_8601": "2025-05-01T00:00:00Z", "yanked": False}],
            },
        }
    ).encode()

    result, _ = _added("pypi", "pickme", "1.1")

    assert result["old_resolved"] == "0.9"


def test_registry_failures_are_incomplete_never_a_silent_pass(registry, monkeypatch):
    registry.npm("lostlib", "1.0.0", {"index.js": "1;\n"})
    missing, missing_receipt = _added("npm", "lostlib", "1.0.0")

    original = registry.document

    def broken(url, config, accept="application/json"):
        if url == f"{NPM}/lostlib":
            raise ValueError(f"HTTP 503 from {url}")
        return original(url, config, accept)

    monkeypatch.setattr(fetch, "_fetch_registry_json", broken)
    failed, failed_receipt = _added("npm", "lostlib", "1.0.0")

    assert missing["status"] == "skipped" and missing_receipt["complete"] is False
    assert failed["status"] == "skipped" and failed["reason"] == "registry_unreachable"
    assert failed_receipt["complete"] is False


def test_added_is_discoverable_offline_and_old_none_keeps_its_meaning(registry):
    probe = api.review_upgrades(
        [
            {"ecosystem": "npm", "name": "probe", "old": None, "new": "1.0.2", "added": True},
            {"ecosystem": "npm", "name": "probe", "old": None, "new": "1.0.0"},
            {"ecosystem": "npm", "name": "probe", "old": None, "new": "1.0.3", "added": "yes"},
        ],
        options={"network": False},
    )
    added, plain, bad = probe["results"]

    assert added["reason"] == "network_disabled" and added["added"] is True
    assert "old_resolved" not in added and added.get("basis") != "new_package"
    assert plain["reason"] == "network_disabled" and "added" not in plain
    assert plain["basis"] == "new_package"
    assert bad["reason"] == "invalid_pair"
    assert registry.requests == []


def test_skylos_capability_probe_shape_is_answered_offline(registry):
    report = api.review_upgrades(
        [
            {
                "ecosystem": "npm",
                "name": "skylos-capability-probe",
                "old": None,
                "new": "1.0.2",
                "added": True,
            }
        ],
        options={"network": False},
    )
    result = report["results"][0]

    assert result["status"] == "skipped" and result["reason"] == "network_disabled"
    assert result["added"] is True
    assert result["old"] is None and result["new"] == "1.0.2"
    assert registry.requests == []


def test_added_with_an_explicit_old_version_is_an_upgrade_that_echoes_added(registry):
    registry.npm("pinned", "1.0.0", {"index.js": "1;\n"})
    registry.npm("pinned", "1.0.1", {"index.js": "2;\n"})

    report = api.review_upgrades(
        [{"ecosystem": "npm", "name": "pinned", "old": "1.0.0", "new": "1.0.1", "added": True}]
    )
    result = report["results"][0]

    assert result["basis"] == "upgrade" and result["old"] == "1.0.0"
    assert result["added"] is True
    assert not any(url.endswith("/pinned") for url in registry.requests)
