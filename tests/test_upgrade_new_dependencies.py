"""A release that adds a brand-new or young dependency also gets that dependency reviewed
as a first release (one level, bounded), so a two-stage package cannot hide its payload."""

from __future__ import annotations

import base64
import json

import pytest
from tests.test_upgrade_review import NPM, _one, registry

from ca9 import api
from ca9.artifacts import fetch
from ca9.review.dependencies import npm_satisfies

__all__ = ["registry"]

DROPPER = (
    "const s = Buffer.from('"
    + base64.b64encode(b"require('child_process').execSync('id')").decode()
    + "', 'base64').toString();\neval(s);\nmodule.exports = 1;\n"
)


def _packument(registry, name, times):
    registry.documents[f"{NPM}/{name}"] = json.dumps(
        {"name": name, "versions": {v: {"version": v} for v in times}, "time": times}
    ).encode()


def _project(registry, name, times):
    registry.documents[f"https://pypi.org/pypi/{name}/json"] = json.dumps(
        {
            "info": {"name": name},
            "releases": {
                version: [{"upload_time_iso_8601": stamp, "yanked": False}]
                for version, stamp in times.items()
            },
        }
    ).encode()


def _parent(registry, dependencies):
    registry.npm("parentlib", "1.0.0", {"index.js": "module.exports = 1;\n"})
    registry.npm(
        "parentlib",
        "1.0.1",
        {"index.js": "module.exports = 2;\n"},
        manifest={"dependencies": dependencies},
    )


def test_upgrade_that_adds_a_brand_new_dependency_reviews_it(registry):
    registry.npm("stagetwo", "1.0.0", {"index.js": DROPPER})
    _packument(registry, "stagetwo", {"1.0.0": "2025-03-01T00:00:00.000Z"})
    _parent(registry, {"stagetwo": "^1.0.0"})

    result, receipt = _one("npm", "parentlib", "1.0.0", "1.0.1")

    blocked = [delta for delta in result["block"] if delta["kind"] == "new_decode_exec"]
    assert blocked and blocked[0]["path"].startswith("stagetwo@1.0.0: ")
    assert result["dependency_reviews"] == [
        {
            "name": "stagetwo",
            "version": "1.0.0",
            "status": "reviewed",
            "why": "first release",
            "block": len(blocked),
            "warn": 0,
            "complete": True,
        }
    ]
    assert receipt["dependency_reviews"] == 1


def test_first_release_that_requires_a_young_dependency_reviews_it(registry):
    registry.pypi(
        "typoparent",
        "1.0",
        wheel={
            "typoparent/__init__.py": "from colorhelper import *\n",
            "typoparent-1.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: typoparent\nVersion: 1.0\nRequires-Dist: colorhelper>=0.1\n",
        },
    )
    for version in ("0.1.0", "0.1.1"):
        registry.pypi(
            "colorhelper",
            version,
            wheel={
                "colorhelper/__init__.py": "X = 1\n",
                "colorhelper.pth": "import os; os.system('id')\n",
            },
        )
    _project(
        registry, "colorhelper", {"0.1.0": "2025-03-01T00:00:00Z", "0.1.1": "2025-03-06T00:00:00Z"}
    )

    report = api.review_upgrades(
        [{"ecosystem": "pypi", "name": "typoparent", "old": None, "new": "1.0"}]
    )
    result = report["results"][0]

    assert result["dependency_reviews"][0]["version"] == "0.1.1"
    assert result["dependency_reviews"][0]["why"] == "young: first release 5 days earlier"
    assert any(delta["path"].startswith("colorhelper@0.1.1: ") for delta in result["block"])


def test_established_or_internal_dependencies_are_not_reviewed(registry):
    registry.npm("oldfriend", "4.2.0", {"index.js": DROPPER})
    _packument(
        registry,
        "oldfriend",
        {
            "1.0.0": "2019-01-01T00:00:00.000Z",
            "4.1.0": "2024-01-01T00:00:00.000Z",
            "4.2.0": "2025-03-01T00:00:00.000Z",
        },
    )
    _parent(registry, {"oldfriend": "~4.2.0", "corp-auth": "^2.0.0", "gitdep": "github:o/r"})

    report = api.review_upgrades(
        [{"ecosystem": "npm", "name": "parentlib", "old": "1.0.0", "new": "1.0.1"}],
        options={"internal_packages": ["corp-*"]},
    )
    result = report["results"][0]

    assert not any(delta["path"].startswith("oldfriend@") for delta in result["block"])
    assert [(item["name"], item["status"]) for item in result["dependency_reviews"]] == [
        ("oldfriend", "established")
    ]
    assert not any("corp-auth" in url for url in registry.requests)


def test_dependency_reviews_are_bounded_and_failures_are_noted(registry, monkeypatch):
    for name in ("depa", "depb"):
        registry.npm(name, "1.0.0", {"index.js": "module.exports = 1;\n"})
        _packument(registry, name, {"1.0.0": "2025-03-01T00:00:00.000Z"})
    _parent(registry, {"depa": "1.0.0", "depb": "1.0.0", "depc": "1.0.0"})
    original = registry.document

    def broken(url, config, accept="application/json"):
        if url == f"{NPM}/depc":
            raise ValueError(f"HTTP 503 from {url}")
        return original(url, config, accept)

    monkeypatch.setattr(fetch, "_fetch_registry_json", broken)
    bounded = api.review_upgrades(
        [{"ecosystem": "npm", "name": "parentlib", "old": "1.0.0", "new": "1.0.1"}],
        options={"max_dependency_reviews": 1},
    )["results"][0]
    unbounded = api.review_upgrades(
        [{"ecosystem": "npm", "name": "parentlib", "old": "1.0.0", "new": "1.0.1"}]
    )["results"][0]

    assert [item["status"] for item in bounded["dependency_reviews"]] == [
        "reviewed",
        "over_limit",
        "over_limit",
    ]
    assert bounded["status"] == "reviewed"
    statuses = {item["name"]: item["status"] for item in unbounded["dependency_reviews"]}
    assert statuses == {"depa": "reviewed", "depb": "reviewed", "depc": "lookup_failed"}
    assert any("depc" in item for item in unbounded["limitations"])


@pytest.mark.parametrize(
    ("version", "spec", "expected"),
    [
        ("1.4.2", "^1.2.0", True),
        ("2.0.0", "^1.2.0", False),
        ("0.2.5", "^0.2.1", True),
        ("0.3.0", "^0.2.1", False),
        ("1.2.9", "~1.2.3", True),
        ("1.3.0", "~1.2.3", False),
        ("1.9.0", "1.x", True),
        ("3.1.0", ">=2.0.0 <3.0.0 || >=3.1.0", True),
        ("2.5.0", "1.0.0 - 2.4.0", False),
        ("5.0.0", "*", True),
        ("1.0.0", "github:o/r", None),
    ],
)
def test_npm_range_matching(version, spec, expected):
    assert npm_satisfies(version, spec) is expected
