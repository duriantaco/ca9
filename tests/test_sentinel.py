from __future__ import annotations

import gzip
import io
import json
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

import pytest
from scripts.sentinel import (
    AllowlistError,
    HttpRegistry,
    MetadataTooLarge,
    PackageNotFound,
    Probe,
    RegistryError,
    Release,
    SentinelConfig,
    classify,
    load_allowlist,
    load_watchlist,
    main,
    read_previous_bundle,
    run_sentinel,
)

from ca9 import api
from ca9.package_feed import lookup_malware, update_feed_from_source

UTC = timezone.utc
NOW = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
OLD = datetime(2025, 1, 1, tzinfo=UTC)
REPO = Path(__file__).resolve().parents[1]


def at(hour, minute=0, day=7, month=11, year=2026):
    return datetime(year, month, day, hour, minute, tzinfo=UTC)


def delta(kind, path="package/index.js", line=1, snippet="run()"):
    return {"kind": kind, "path": path, "line": line, "snippet": snippet, "detail": f"{kind} added"}


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class FakeRegistry:
    def __init__(self, packages=None, *, serials=None, marker=None, clock=None, probe_cost=0.0):
        self.packages = packages or {}
        self.serials = serials or {}
        self.marker_value = marker
        self.clock = clock
        self.probe_cost = probe_cost
        self.errors = set()
        self.missing = set()
        self.probes = []
        self.fetches = []

    def probe(self, ecosystem, name):
        self.probes.append((ecosystem, name))
        if self.clock is not None:
            self.clock.now += self.probe_cost
        if (ecosystem, name) in self.errors:
            raise RegistryError("registry answered HTTP 503")
        if (ecosystem, name) in self.missing:
            raise PackageNotFound(name)
        releases = self.packages.get((ecosystem, name), [])
        modified = None
        if releases and ecosystem == "npm":
            modified = max(release.published for release in releases)
        return Probe(modified=modified, serial=self.serials.get((ecosystem, name)))

    def releases(self, ecosystem, name):
        self.fetches.append((ecosystem, name))
        return list(self.packages.get((ecosystem, name), []))

    def marker(self, ecosystem):
        if ecosystem == "pypi":
            return self.marker_value
        return None


class FakeReview:
    def __init__(self, outcomes=None, *, clock=None, cost=0.0):
        self.outcomes = outcomes or {}
        self.clock = clock
        self.cost = cost
        self.calls = []
        self.options = []

    def __call__(self, pair, options):
        self.calls.append((pair["ecosystem"], pair["name"], pair["old"], pair["new"]))
        self.options.append(dict(options))
        if self.clock is not None:
            self.clock.now += self.cost
        outcome = self.outcomes.get((pair["ecosystem"], pair["name"], pair["new"]), {})
        if outcome.get("status") == "skipped":
            return {
                **pair,
                "status": "skipped",
                "reason": outcome["reason"],
                "block": [],
                "warn": [],
            }
        return {
            **pair,
            "status": "reviewed",
            "block": outcome.get("block", []),
            "warn": outcome.get("warn", []),
            "complete": outcome.get("complete", True),
        }


def release(version, published, **extra):
    return Release(version=version, published=published, **extra)


def state(watermark="2026-11-07T10:40:00Z", **extra):
    return {"schema": "ca9.sentinel.state.v1", "watermark": watermark, **extra}


def previous_bundle(npm=None, pypi=None, npm_state=None, pypi_state=None):
    return {
        "schema": "ca9.feed.v1",
        "created_at": "2026-11-07T11:00:00Z",
        "expires_at": "2026-11-14T11:00:00Z",
        "datasets": {
            "npm-suspicious": {"packages": npm or [], "sentinel": npm_state or state()},
            "pypi-suspicious": {"packages": pypi or [], "sentinel": pypi_state or state()},
        },
    }


def entry(name, version, reviewed_at, kinds=("new_install_hook",), verdict="block"):
    return {
        "name": name,
        "version": version,
        "previous": None,
        "kinds": list(kinds),
        "verdict": verdict,
        "evidence": [f"{kinds[0]} package/package.json:1: x"],
        "reviewed_at": reviewed_at,
        "published_at": reviewed_at,
    }


def run(watch, previous, registry, review, **kwargs):
    config = kwargs.pop("config", None) or SentinelConfig(review_workers=1, workers=1)
    return run_sentinel(
        watch,
        previous,
        registry=registry,
        review=review,
        config=config,
        now=kwargs.pop("now", NOW),
        **kwargs,
    )


def coverage(datasets, ecosystem):
    return datasets[f"{ecosystem}-suspicious"]["sentinel"]["coverage"]


def flagged(datasets, ecosystem):
    return {
        (item["name"], item["version"]): item["verdict"]
        for item in datasets[f"{ecosystem}-suspicious"]["packages"]
    }


def test_new_version_with_a_block_kind_is_flagged():
    registry = FakeRegistry(
        {("npm", "left-pad"): [release("1.3.0", OLD), release("1.3.1", at(11))]}
    )
    review = FakeReview(
        {
            ("npm", "left-pad", "1.3.1"): {
                "block": [
                    delta(
                        "new_install_hook", "package/package.json", 5, '"postinstall": "node x.js"'
                    )
                ]
            }
        }
    )

    datasets = run({"npm": ["left-pad"], "pypi": []}, previous_bundle(), registry, review)

    assert review.calls == [("npm", "left-pad", "1.3.0", "1.3.1")]
    assert datasets["npm-suspicious"]["packages"] == [
        {
            "name": "left-pad",
            "version": "1.3.1",
            "previous": "1.3.0",
            "kinds": ["new_install_hook"],
            "verdict": "block",
            "evidence": ['new_install_hook package/package.json:5: "postinstall": "node x.js"'],
            "reviewed_at": "2026-11-07T12:00:00Z",
            "published_at": "2026-11-07T11:00:00Z",
        }
    ]
    stats = coverage(datasets, "npm")
    assert {key: stats[key] for key in ("watched", "checked", "new_versions")} == {
        "watched": 1,
        "checked": 1,
        "new_versions": 1,
    }
    assert {key: stats[key] for key in ("reviewed", "incomplete", "flagged", "complete")} == {
        "reviewed": 1,
        "incomplete": 0,
        "flagged": 1,
        "complete": True,
    }
    assert datasets["npm-suspicious"]["sentinel"]["watermark"] == "2026-11-07T11:40:00Z"
    assert datasets["pypi-suspicious"]["packages"] == []
    assert coverage(datasets, "pypi")["watched"] == 0
    assert review.options[0]["network"] is True
    assert review.options[0]["max_pairs"] == 1


def test_benign_versions_are_not_flagged_and_only_strong_combinations_warn():
    registry = FakeRegistry(
        {
            ("npm", "chalk"): [release("5.6.0", OLD), release("5.6.1", at(11))],
            ("npm", "debug"): [release("4.4.0", OLD), release("4.4.1", at(11, 5))],
            ("npm", "esbuild"): [release("0.25.0", OLD), release("0.25.1", at(11, 10))],
            ("npm", "axios"): [release("1.7.0", OLD), release("1.7.1", at(11, 15))],
            ("pypi", "requests"): [release("2.32.3", OLD), release("2.32.4", at(11, 20))],
            ("pypi", "urllib3"): [release("2.2.0", OLD), release("2.2.1", at(11, 25))],
        }
    )
    review = FakeReview(
        {
            ("npm", "chalk", "5.6.1"): {
                "warn": [delta("obfuscation_growth"), delta("new_import_time_network")]
            },
            ("npm", "debug", "4.4.1"): {"warn": [delta("publisher_change")]},
            ("npm", "esbuild", "0.25.1"): {"block": [delta("rule_from_a_newer_ca9")]},
            ("npm", "axios", "1.7.1"): {
                "block": [delta("new_decode_exec")],
                "warn": [delta("publisher_change")],
            },
            ("pypi", "requests", "2.32.4"): {"warn": [delta("new_native_binary")]},
            ("pypi", "urllib3", "2.2.1"): {
                "warn": [delta("publisher_change"), delta("new_import_time_network")]
            },
        }
    )

    datasets = run(
        {"npm": ["chalk", "debug", "esbuild", "axios"], "pypi": ["requests", "urllib3"]},
        previous_bundle(),
        registry,
        review,
    )

    assert flagged(datasets, "npm") == {
        ("axios", "1.7.1"): "block",
        ("chalk", "5.6.1"): "warn",
        ("esbuild", "0.25.1"): "warn",
    }
    assert flagged(datasets, "pypi") == {("urllib3", "2.2.1"): "warn"}
    kinds = {item["name"]: item["kinds"] for item in datasets["npm-suspicious"]["packages"]}
    assert kinds == {
        "axios": ["new_decode_exec"],
        "chalk": ["new_import_time_network", "obfuscation_growth"],
        "esbuild": ["rule_from_a_newer_ca9"],
    }
    assert (coverage(datasets, "npm")["reviewed"], coverage(datasets, "npm")["flagged"]) == (4, 3)
    assert (coverage(datasets, "pypi")["reviewed"], coverage(datasets, "pypi")["flagged"]) == (2, 1)


def test_classify_matches_the_documented_policy():
    assert classify({"status": "reviewed", "block": [], "warn": []}) is None
    assert classify({"status": "skipped", "reason": "timeout", "block": [], "warn": []}) is None
    verdict, kinds, _evidence = classify(
        {"status": "reviewed", "block": [delta("new_pth_code")], "warn": []}
    )
    assert (verdict, kinds) == ("block", ["new_pth_code"])
    verdict, kinds, _evidence = classify(
        {"status": "reviewed", "block": [delta("ambiguous_package_contents")], "warn": []}
    )
    assert (verdict, kinds) == ("warn", ["ambiguous_package_contents"])
    verdict, kinds, _evidence = classify(
        {
            "status": "reviewed",
            "block": [],
            "warn": [delta("publisher_change"), delta("new_import_time_exec")],
        }
    )
    assert (verdict, kinds) == ("warn", ["new_import_time_exec", "publisher_change"])
    assert (
        classify(
            {
                "status": "reviewed",
                "block": [],
                "warn": [delta("new_import_time_network"), delta("new_native_binary")],
            }
        )
        is None
    )


def test_evidence_lines_drop_control_characters_and_are_bounded():
    hostile = delta(
        "new_pth_code", "pkg.pth", 1, "import os\x1b[2J;\x07 os.system('x')\u009b" + "y" * 400
    )

    _verdict, _kinds, evidence = classify({"status": "reviewed", "block": [hostile], "warn": []})

    assert evidence[0].startswith("new_pth_code pkg.pth:1: import os[2J; os.system('x')y")
    assert len(evidence[0]) == 200
    assert not any(ord(char) < 32 or 127 <= ord(char) < 160 for char in evidence[0])


def test_previous_is_the_highest_earlier_stable_and_prereleases_are_skipped():
    registry = FakeRegistry(
        {
            ("npm", "pkg"): [
                release("3.2.0", OLD),
                release("4.0.0", at(0, day=1, month=1)),
                release("3.2.1", at(11)),
                release("5.0.0-beta.1", at(11, 5)),
                release("4.0.1", at(11, 10), available=False),
            ],
            ("pypi", "lib"): [
                release("1.0", OLD),
                release("1.1", at(0, day=1, month=6), yanked=True),
                release("1.2", at(11)),
            ],
        }
    )
    review = FakeReview()

    datasets = run({"npm": ["pkg"], "pypi": ["lib"]}, previous_bundle(), registry, review)

    assert review.calls == [("npm", "pkg", "3.2.0", "3.2.1"), ("pypi", "lib", "1.0", "1.2")]
    stats = coverage(datasets, "npm")
    assert (stats["new_versions"], stats["prereleases_skipped"], stats["unpublished"]) == (3, 1, 1)
    assert stats["reviewed"] == 1


def test_allowlisted_versions_are_never_emitted(tmp_path):
    allow = tmp_path / "allow.json"
    allow.write_text(
        json.dumps(
            {
                "schema": "ca9.sentinel.allow.v1",
                "entries": [
                    {
                        "ecosystem": "npm",
                        "name": "left-pad",
                        "version": "1.3.1",
                        "reason": "postinstall prints a funding message; reviewed the script",
                        "reviewed_by": "maintainer-a",
                    },
                    {
                        "ecosystem": "npm",
                        "name": "legacy-hook",
                        "version": "*",
                        "kinds": ["new_install_hook"],
                        "reason": "downloads its own prebuilt binary from its GitHub releases",
                        "reviewed_by": "maintainer-b",
                    },
                ],
            }
        )
    )
    registry = FakeRegistry(
        {
            ("npm", "left-pad"): [release("1.3.0", OLD), release("1.3.1", at(11))],
            ("npm", "legacy-hook"): [
                release("2.0.0", OLD),
                release("2.0.1", at(11, 5)),
                release("2.0.2", at(11, 10)),
            ],
        }
    )
    review = FakeReview(
        {
            ("npm", "left-pad", "1.3.1"): {"block": [delta("new_install_hook")]},
            ("npm", "legacy-hook", "2.0.1"): {"block": [delta("new_install_hook")]},
            ("npm", "legacy-hook", "2.0.2"): {"block": [delta("new_decode_exec")]},
        }
    )
    previous = previous_bundle(
        npm=[
            entry("legacy-hook", "2.0.0", "2026-11-06T00:00:00Z"),
            entry("evil", "1.0.0", "2026-11-06T00:00:00Z", kinds=("new_decode_exec",)),
        ]
    )

    datasets = run(
        {"npm": ["left-pad", "legacy-hook"], "pypi": []},
        previous,
        registry,
        review,
        allowlist=load_allowlist(allow),
    )

    assert sorted(flagged(datasets, "npm")) == [("evil", "1.0.0"), ("legacy-hook", "2.0.2")]
    assert coverage(datasets, "npm")["allowlisted"] == 2


@pytest.mark.parametrize(
    "bad",
    [
        {"ecosystem": "npm", "name": "x", "version": "*", "reason": "", "reviewed_by": "a"},
        {"ecosystem": "npm", "name": "x", "version": "*", "reviewed_by": "a"},
        {"ecosystem": "npm", "name": "x", "version": "1.0.0", "reason": "fine"},
        {"ecosystem": "npm", "name": "x", "version": "1.*", "reason": "fine", "reviewed_by": "a"},
        {"ecosystem": "cargo", "name": "x", "version": "1", "reason": "fine", "reviewed_by": "a"},
        {"ecosystem": "npm", "name": "", "version": "1", "reason": "fine", "reviewed_by": "a"},
    ],
)
def test_allowlist_rejects_entries_without_reason_reviewer_or_exact_version(tmp_path, bad):
    allow = tmp_path / "allow.json"
    allow.write_text(json.dumps({"schema": "ca9.sentinel.allow.v1", "entries": [bad]}))

    with pytest.raises(AllowlistError):
        load_allowlist(allow)


def test_shipped_allowlist_and_watchlists_load():
    load_allowlist(REPO / "sentinel" / "allow.json")
    npm = load_watchlist(REPO / "sentinel" / "watch-npm.json", top=5000)
    pypi = load_watchlist(REPO / "sentinel" / "watch-pypi.json", top=5000)

    assert len(npm) == 5000
    assert len(pypi) == 5000
    assert len(set(npm)) == len(npm)
    assert "chalk" in npm
    assert "requests" in pypi
    for path in ("watch-npm.json", "watch-pypi.json"):
        meta = json.loads((REPO / "sentinel" / path).read_text())
        assert meta["license"] in {"MIT", "CC-BY-SA-4.0"}
        assert meta["source"].startswith("https://")


def test_watermark_resumes_and_old_entries_expire():
    registry = FakeRegistry(
        {
            ("npm", "a"): [
                release("1.0.0", OLD),
                release("1.0.1", at(10, 30)),
                release("1.0.2", at(11)),
                release("1.0.3", at(11, 50)),
            ]
        }
    )
    review = FakeReview()
    previous = previous_bundle(
        npm=[
            entry("old-flag", "1.0.0", "2026-11-01T00:00:00Z"),
            entry("ancient", "1.0.0", "2026-09-01T00:00:00Z"),
        ]
    )

    first = run({"npm": ["a"], "pypi": []}, previous, registry, review)

    assert review.calls == [("npm", "a", "1.0.1", "1.0.2")]
    assert sorted(flagged(first, "npm")) == [("old-flag", "1.0.0")]
    assert first["npm-suspicious"]["sentinel"]["watermark"] == "2026-11-07T11:40:00Z"

    resumed = {**previous, "datasets": first}
    second = run({"npm": ["a"], "pypi": []}, resumed, registry, review, now=at(13))

    assert review.calls[1:] == [("npm", "a", "1.0.2", "1.0.3")]
    assert second["npm-suspicious"]["sentinel"]["watermark"] == "2026-11-07T12:40:00Z"
    assert coverage(second, "npm")["window"] == {
        "since": "2026-11-07T11:40:00Z",
        "until": "2026-11-07T12:40:00Z",
    }


def test_unreadable_previous_bundle_reviews_only_the_last_hours(tmp_path):
    broken = tmp_path / "prev.json"
    broken.write_text("not json{")
    registry = FakeRegistry(
        {
            ("npm", "a"): [
                release("1.0.0", OLD),
                release("1.0.1", at(9, day=5)),
                release("1.0.2", at(10)),
            ]
        }
    )
    review = FakeReview()

    assert read_previous_bundle(broken) is None
    assert read_previous_bundle(tmp_path / "missing.json") is None
    datasets = run({"npm": ["a"], "pypi": []}, None, registry, review)

    assert review.calls == [("npm", "a", "1.0.1", "1.0.2")]
    stats = coverage(datasets, "npm")
    assert stats["watermark_source"] == "fallback"
    assert stats["window"]["since"] == "2026-11-07T09:00:00Z"

    review.calls.clear()
    initial = run({"npm": ["a"], "pypi": []}, {}, registry, review)
    assert review.calls == [("npm", "a", "1.0.1", "1.0.2")]
    assert coverage(initial, "npm")["watermark_source"] == "initial"


def test_old_watermark_is_clamped_and_the_gap_is_recorded():
    registry = FakeRegistry({("npm", "a"): [release("1.0.0", OLD), release("1.0.1", at(9, day=1))]})
    review = FakeReview()
    previous = previous_bundle(npm_state=state("2026-10-01T00:00:00Z"))

    datasets = run({"npm": ["a"], "pypi": []}, previous, registry, review)

    assert review.calls == []
    stats = coverage(datasets, "npm")
    assert stats["watermark_source"] == "clamped"
    assert stats["gap"] == {"since": "2026-10-01T00:00:00Z", "until": "2026-11-05T12:00:00Z"}
    assert stats["complete"] is False


def test_review_budget_hit_is_recorded_and_the_rest_resumes():
    clock = FakeClock()
    versions = [
        release("1.0.0", OLD),
        release("1.0.1", at(10, 50)),
        release("1.0.2", at(11)),
        release("1.0.3", at(11, 10)),
        release("1.0.4", at(11, 20)),
    ]
    registry = FakeRegistry({("npm", "a"): versions})
    review = FakeReview(clock=clock, cost=100)
    config = SentinelConfig(
        time_budget_seconds=250, min_review_seconds=30, review_workers=1, workers=1
    )

    first = run(
        {"npm": ["a"], "pypi": []}, previous_bundle(), registry, review, config=config, clock=clock
    )

    assert [call[3] for call in review.calls] == ["1.0.1", "1.0.2", "1.0.3"]
    stats = coverage(first, "npm")
    assert (stats["reviewed"], stats["deferred"], stats["budget_hit"], stats["complete"]) == (
        3,
        1,
        True,
        False,
    )
    pending = first["npm-suspicious"]["sentinel"]["pending"]
    assert [(item["name"], item["version"], item["previous"]) for item in pending] == [
        ("a", "1.0.4", "1.0.3")
    ]
    assert first["npm-suspicious"]["sentinel"]["watermark"] == "2026-11-07T11:40:00Z"

    review.calls.clear()
    second = run(
        {"npm": ["a"], "pypi": []},
        {**previous_bundle(), "datasets": first},
        registry,
        review,
        config=config,
        clock=FakeClock(),
        now=at(13),
    )

    assert review.calls == [("npm", "a", "1.0.3", "1.0.4")]
    assert second["npm-suspicious"]["sentinel"]["pending"] == []
    assert coverage(second, "npm")["complete"] is True


def test_discovery_budget_leaves_unchecked_packages_lagging():
    clock = FakeClock()
    registry = FakeRegistry(
        {
            ("npm", name): [release("1.0.0", OLD), release("1.0.1", at(11))]
            for name in ("a", "b", "c")
        },
        clock=clock,
        probe_cost=100,
    )
    review = FakeReview()
    config = SentinelConfig(
        time_budget_seconds=250, discovery_share=0.5, review_workers=1, workers=1
    )

    first = run(
        {"npm": ["a", "b", "c"], "pypi": []},
        previous_bundle(),
        registry,
        review,
        config=config,
        clock=clock,
    )

    assert [call[1] for call in review.calls] == ["a", "b"]
    stats = coverage(first, "npm")
    assert (stats["checked"], stats["not_reached"], stats["complete"]) == (2, 1, False)
    assert first["npm-suspicious"]["sentinel"]["lagging"] == {"c": "2026-11-07T10:40:00Z"}

    review.calls.clear()
    second = run(
        {"npm": ["a", "b", "c"], "pypi": []},
        {**previous_bundle(), "datasets": first},
        registry,
        review,
        now=at(13),
    )

    assert review.calls == [("npm", "c", "1.0.0", "1.0.1")]
    assert second["npm-suspicious"]["sentinel"]["lagging"] == {}


def test_registry_errors_lag_and_missing_packages_are_counted():
    registry = FakeRegistry({("npm", "a"): [release("1.0.0", OLD), release("1.0.1", at(11))]})
    registry.errors.add(("npm", "a"))
    registry.missing.add(("npm", "gone"))

    datasets = run({"npm": ["a", "gone"], "pypi": []}, previous_bundle(), registry, FakeReview())

    stats = coverage(datasets, "npm")
    assert (stats["metadata_errors"], stats["not_found"], stats["complete"]) == (1, 1, False)
    assert datasets["npm-suspicious"]["sentinel"]["lagging"] == {"a": "2026-11-07T10:40:00Z"}


def test_failed_reviews_are_retried_then_given_up():
    registry = FakeRegistry(
        {
            ("npm", "flaky"): [release("1.0.0", OLD), release("1.0.1", at(11))],
            ("npm", "huge"): [release("1.0.0", OLD), release("1.0.1", at(11, 5))],
        }
    )
    review = FakeReview(
        {
            ("npm", "flaky", "1.0.1"): {"status": "skipped", "reason": "registry_unreachable"},
            ("npm", "huge", "1.0.1"): {"status": "skipped", "reason": "artifact_too_large"},
        }
    )
    config = SentinelConfig(max_attempts=2, review_workers=1, workers=1)

    first = run(
        {"npm": ["flaky", "huge"], "pypi": []}, previous_bundle(), registry, review, config=config
    )

    stats = coverage(first, "npm")
    assert (stats["reviewed"], stats["incomplete"]) == (0, 2)
    assert stats["failed_reasons"] == {"artifact_too_large": 1, "registry_unreachable": 1}
    pending = first["npm-suspicious"]["sentinel"]["pending"]
    assert [(item["name"], item["attempts"]) for item in pending] == [("flaky", 1)]

    second = run(
        {"npm": ["flaky", "huge"], "pypi": []},
        {**previous_bundle(), "datasets": first},
        registry,
        review,
        config=config,
        now=at(13),
    )

    assert second["npm-suspicious"]["sentinel"]["pending"] == []
    assert coverage(second, "npm")["abandoned"] == 1


def test_pypi_serial_marks_skip_projects_unchanged_since_the_watermark():
    registry = FakeRegistry(
        {
            ("pypi", "idle"): [release("1.0", OLD)],
            ("pypi", "busy"): [release("1.0", OLD), release("2.0", at(11))],
        },
        serials={("pypi", "idle"): 90, ("pypi", "busy"): 150},
        marker=200,
    )
    previous = previous_bundle(pypi_state=state(serial_marks=[["2026-11-07T10:00:00Z", 100]]))
    review = FakeReview()

    datasets = run({"npm": [], "pypi": ["idle", "busy"]}, previous, registry, review)

    assert registry.fetches == [("pypi", "busy")]
    assert review.calls == [("pypi", "busy", "1.0", "2.0")]
    marks = datasets["pypi-suspicious"]["sentinel"]["serial_marks"]
    assert marks[-1] == ["2026-11-07T12:00:00Z", 200]
    assert coverage(datasets, "pypi")["unchanged"] == 1


def test_npm_packages_unchanged_since_the_watermark_are_not_fetched():
    registry = FakeRegistry(
        {
            ("npm", "idle"): [release("1.0.0", OLD)],
            ("npm", "busy"): [release("1.0.0", OLD), release("1.0.1", at(11))],
        }
    )

    datasets = run({"npm": ["idle", "busy"], "pypi": []}, previous_bundle(), registry, FakeReview())

    assert registry.fetches == [("npm", "busy")]
    assert coverage(datasets, "npm")["unchanged"] == 1


def test_entries_are_bounded_by_count():
    registry = FakeRegistry({("npm", "a"): [release("1.0.0", OLD), release("1.0.1", at(11))]})
    review = FakeReview({("npm", "a", "1.0.1"): {"block": [delta("new_install_hook")]}})
    previous = previous_bundle(
        npm=[entry(f"old-{day}", "1.0.0", f"2026-11-0{day}T00:00:00Z") for day in (1, 2, 3)]
    )
    config = SentinelConfig(max_entries=2, review_workers=1, workers=1)

    datasets = run({"npm": ["a"], "pypi": []}, previous, registry, review, config=config)

    assert sorted(flagged(datasets, "npm")) == [("a", "1.0.1"), ("old-3", "1.0.0")]
    assert coverage(datasets, "npm")["dropped_entries"] == 2


class _Response:
    def __init__(self, status=200, headers=None, body=b""):
        self.status = status
        self.headers = headers or {}
        self._body = io.BytesIO(body)

    def read(self, size=-1):
        return self._body.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Opener:
    def __init__(self, routes):
        self.routes = routes
        self.requests = []

    def __call__(self, request, timeout=None):
        self.requests.append((request.get_method(), request.full_url, dict(request.header_items())))
        answer = self.routes[(request.get_method(), request.full_url)]
        if isinstance(answer, list):
            answer = answer.pop(0)
        if isinstance(answer, int):
            raise urllib.error.HTTPError(request.full_url, answer, "error", {}, None)
        return answer


def test_http_registry_uses_head_requests_and_a_polite_user_agent():
    packument = {
        "name": "@scope/pkg",
        "time": {
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2026-11-07T11:00:00.000Z",
            "1.0.0": "2020-01-01T00:00:00.000Z",
            "1.0.1": "2026-11-07T11:00:00.000Z",
            "1.0.2": "2026-11-07T11:05:00.000Z",
        },
        "versions": {"1.0.0": {}, "1.0.1": {}},
    }
    project = {
        "releases": {
            "1.0": [{"upload_time_iso_8601": "2025-01-01T00:00:00.000000Z", "yanked": False}],
            "1.1": [
                {"upload_time_iso_8601": "2026-11-07T11:30:00.000000Z", "yanked": True},
                {"upload_time_iso_8601": "2026-11-07T11:00:00.000000Z", "yanked": True},
            ],
            "1.2": [],
        }
    }
    npm_url = "https://registry.npmjs.org/@scope%2Fpkg"
    pypi_url = "https://pypi.org/pypi/demo/json"
    opener = _Opener(
        {
            ("HEAD", npm_url): _Response(
                headers={"Last-Modified": "Sat, 07 Nov 2026 11:05:01 GMT"}
            ),
            ("GET", npm_url): _Response(
                headers={"Content-Encoding": "gzip"},
                body=gzip.compress(json.dumps(packument).encode()),
            ),
            ("HEAD", pypi_url): _Response(headers={"X-PyPI-Last-Serial": "4242"}),
            ("GET", pypi_url): [503, _Response(body=json.dumps(project).encode())],
            ("HEAD", "https://pypi.org/simple/"): _Response(headers={"X-PyPI-Last-Serial": "9000"}),
            ("HEAD", "https://registry.npmjs.org/gone"): 404,
            ("GET", "https://registry.npmjs.org/big"): _Response(body=b"x" * 2048),
        }
    )
    registry = HttpRegistry(opener=opener, sleep=lambda seconds: None, max_bytes=1024)

    assert registry.probe("npm", "@scope/pkg") == Probe(
        modified=datetime(2026, 11, 7, 11, 5, 1, tzinfo=UTC)
    )
    assert [(item.version, item.available) for item in registry.releases("npm", "@scope/pkg")] == [
        ("1.0.0", True),
        ("1.0.1", True),
        ("1.0.2", False),
    ]
    assert registry.probe("pypi", "demo") == Probe(serial=4242)
    assert registry.marker("pypi") == 9000
    assert registry.marker("npm") is None
    pypi_releases = {item.version: item for item in registry.releases("pypi", "demo")}
    assert sorted(pypi_releases) == ["1.0", "1.1"]
    assert pypi_releases["1.1"].published == at(11)
    assert pypi_releases["1.1"].yanked is True
    with pytest.raises(PackageNotFound):
        registry.probe("npm", "gone")
    with pytest.raises(MetadataTooLarge):
        registry.releases("npm", "big")
    methods = [(method, url) for method, url, _headers in opener.requests]
    assert ("GET", pypi_url) in methods
    assert all("ca9-sentinel" in headers["User-agent"] for _m, _u, headers in opener.requests)
    assert all(method in {"GET", "HEAD"} for method, _url, _headers in opener.requests)


def _osv_bundle(tmp_path):
    bundle = {
        "schema": "ca9.feed.v1",
        "created_at": "2026-11-07T11:50:00Z",
        "expires_at": "2026-11-14T11:50:00Z",
        "datasets": {
            "npm-malware": {"packages": [{"name": "evil", "version": "1.0.0", "id": "MAL-1"}]},
            "pypi-malware": {"packages": []},
            "npm-releases": {"packages": {}},
            "pypi-releases": {"packages": {}},
        },
        "build_info": {"malware_counts": {"npm-malware": 1}},
    }
    path = tmp_path / "latest.json"
    path.write_text(json.dumps(bundle))
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"malware_counts": {"npm-malware": 1}}))
    return path, manifest


def test_cli_merges_the_sentinel_datasets_into_the_built_bundle(tmp_path, capsys):
    bundle_path, manifest_path = _osv_bundle(tmp_path)
    previous_path = tmp_path / "prev.json"
    previous_path.write_text(json.dumps(previous_bundle()))
    watch = tmp_path / "watch"
    watch.mkdir()
    for ecosystem, names in (("npm", ["left-pad"]), ("pypi", ["requests"])):
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
    registry = FakeRegistry(
        {("npm", "left-pad"): [release("1.3.0", OLD), release("1.3.1", at(11))]}
    )
    review = FakeReview({("npm", "left-pad", "1.3.1"): {"block": [delta("new_install_hook")]}})

    code = main(
        [
            "run",
            "--previous",
            str(previous_path),
            "--bundle",
            str(bundle_path),
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
        review=review,
        now=NOW,
    )

    assert code == 0
    bundle = json.loads(bundle_path.read_text())
    assert [item["version"] for item in bundle["datasets"]["npm-suspicious"]["packages"]] == [
        "1.3.1"
    ]
    assert bundle["datasets"]["npm-malware"]["packages"][0]["id"] == "MAL-1"
    assert bundle["build_info"]["sentinel"]["npm"]["flagged"] == 1
    manifest = json.loads(manifest_path.read_text())
    assert manifest["suspicious_counts"] == {"npm-suspicious": 1, "pypi-suspicious": 0}
    assert manifest["sentinel"]["npm"]["reviewed"] == 1
    assert "sentinel npm:" in capsys.readouterr().out

    feed_dir = tmp_path / "feed"
    update_feed_from_source(bundle_path, cache_dir=feed_dir)
    assert lookup_malware("npm", "evil", "1.0.0", cache_dir=feed_dir)
    matches = api.suspicious_matches(
        [{"ecosystem": "npm", "name": "left-pad", "version": "1.3.1"}], feed_dir=feed_dir
    )
    assert [(item["name"], item["action"]) for item in matches] == [("left-pad", "block")]


def test_cli_keeps_the_previous_datasets_when_the_run_crashes(tmp_path, capsys):
    bundle_path, manifest_path = _osv_bundle(tmp_path)
    previous = previous_bundle(npm=[entry("kept", "1.0.0", "2026-11-06T00:00:00Z")])
    previous_path = tmp_path / "prev.json"
    previous_path.write_text(json.dumps(previous))
    allow = tmp_path / "allow.json"
    allow.write_text(json.dumps({"schema": "ca9.sentinel.allow.v1", "entries": []}))

    def broken(pair, options):
        raise AssertionError("unreachable")

    class Exploding(FakeRegistry):
        def marker(self, ecosystem):
            raise RuntimeError("bug in the sentinel")

    code = main(
        [
            "run",
            "--previous",
            str(previous_path),
            "--bundle",
            str(bundle_path),
            "--manifest",
            str(manifest_path),
            "--allowlist",
            str(allow),
        ],
        registry=Exploding(),
        review=broken,
        now=NOW,
    )

    assert code == 0
    bundle = json.loads(bundle_path.read_text())
    assert (
        bundle["datasets"]["npm-suspicious"]["packages"]
        == previous["datasets"]["npm-suspicious"]["packages"]
    )
    assert bundle["datasets"]["npm-suspicious"]["sentinel"]["watermark"] == "2026-11-07T10:40:00Z"
    assert "bug in the sentinel" in bundle["build_info"]["sentinel"]["error"]
    assert "sentinel failed" in capsys.readouterr().err


def test_cli_fails_on_an_invalid_allowlist(tmp_path):
    bundle_path, manifest_path = _osv_bundle(tmp_path)
    allow = tmp_path / "allow.json"
    allow.write_text(json.dumps({"schema": "ca9.sentinel.allow.v1", "entries": [{"name": "x"}]}))

    code = main(
        ["run", "--bundle", str(bundle_path), "--allowlist", str(allow)],
        registry=FakeRegistry(),
        review=FakeReview(),
        now=NOW,
    )

    assert code == 2
