from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from click.testing import CliRunner
from scripts.build_feed import build_bundle_from_records

from ca9 import release_age
from ca9.cli import main
from ca9.core.models import Package
from ca9.package_feed import load_current_snapshot, package_age_findings, update_feed_from_source
from ca9.package_policy import (
    ModePolicy,
    PackageAgePolicy,
    PackagePolicy,
    load_effective_package_policy,
)
from ca9.release_age import check_release_age
from ca9.runtime.preflight import runtime_release_age_policy
from ca9.runtime.pypi_gateway import PyPIGatewayState, _denied_version

NOW = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)
NPM_URL = "https://registry.npmjs.org/fresh-lib"
PYPI_PROJECT_URL = "https://pypi.org/pypi/freshpy/json"


def _registry(now: datetime = NOW):
    return _Registry(_docs(_ago_from(now)))


def _ago(**delta) -> str:
    return (NOW - timedelta(**delta)).isoformat().replace("+00:00", "Z")


def _docs(ago):
    npm_packument = {
        "name": "fresh-lib",
        "versions": {
            "1.0.0": {},
            "1.1.0": {},
            "1.1.5": {"deprecated": "broken build"},
            "1.2.0-beta.1": {},
            "1.2.0": {},
            "3.0.0": {},
        },
        "time": {
            "created": ago(days=90),
            "modified": ago(hours=2),
            "1.0.0": ago(days=60),
            "1.1.0": ago(days=30),
            "1.1.5": ago(days=5),
            "1.1.9": ago(days=3),
            "1.2.0-beta.1": ago(days=10),
            "1.2.0": ago(hours=2),
            "3.0.0": ago(days=20),
        },
    }
    pypi_project = {
        "info": {"name": "freshpy", "version": "2.0.0"},
        "releases": {
            "1.9.0": [{"upload_time_iso_8601": ago(days=40), "yanked": False}],
            "1.9.1": [{"upload_time_iso_8601": ago(days=10), "yanked": True}],
            "2.0.0rc1": [{"upload_time_iso_8601": ago(days=5), "yanked": False}],
            "2.0.0": [
                {"upload_time_iso_8601": ago(hours=1), "yanked": False},
                {"upload_time_iso_8601": ago(hours=2), "yanked": False},
            ],
        },
    }
    version_docs = {
        f"https://pypi.org/pypi/freshpy/{version}/json": {
            "info": {"name": "freshpy", "version": version},
            "urls": files,
        }
        for version, files in pypi_project["releases"].items()
    }
    return {NPM_URL: npm_packument, PYPI_PROJECT_URL: pypi_project, **version_docs}


class _Registry:
    def __init__(self, docs):
        self.docs = docs
        self.calls: list[str] = []

    def __call__(self, url):
        self.calls.append(url)
        if url not in self.docs:
            raise OSError(f"404 {url}")
        return self.docs[url]


def test_fresh_npm_version_is_held_and_names_an_older_stable_version(tmp_path):
    result = check_release_age(
        "npm", "fresh-lib", "1.2.0", min_hours=24, cache_dir=tmp_path, fetch=_registry(), now=NOW
    )

    assert result["status"] == "too_new"
    assert result["age_hours"] == 2.0
    assert result["published_at"] == _ago(hours=2)
    assert result["suggested_version"] == "1.1.0"
    assert result["source"] == "npm"


def test_old_npm_version_is_old_enough_and_then_served_from_cache(tmp_path):
    registry = _registry()
    first = check_release_age(
        "npm", "fresh-lib", "1.1.0", min_hours=24, cache_dir=tmp_path, fetch=registry, now=NOW
    )
    second = check_release_age(
        "npm", "fresh-lib", "1.1.0", min_hours=24, cache_dir=tmp_path, fetch=registry, now=NOW
    )

    assert first["status"] == second["status"] == "old_enough"
    assert first["age_hours"] == 720.0
    assert (first["source"], second["source"]) == ("npm", "cache")
    assert registry.calls == [NPM_URL]


def test_fresh_pypi_version_skips_yanked_and_prerelease_suggestions(tmp_path):
    result = check_release_age(
        "pypi", "FreshPy", "2.0.0", min_hours=24, cache_dir=tmp_path, fetch=_registry(), now=NOW
    )

    assert result["status"] == "too_new"
    assert result["published_at"] == _ago(hours=1)
    assert result["suggested_version"] == "1.9.0"


def test_old_pypi_version_uses_the_small_per_version_document(tmp_path):
    registry = _registry()
    result = check_release_age(
        "pypi", "freshpy", "1.9.0", min_hours=24, cache_dir=tmp_path, fetch=registry, now=NOW
    )

    assert result["status"] == "old_enough"
    assert registry.calls == ["https://pypi.org/pypi/freshpy/1.9.0/json"]


def test_registry_down_is_unknown_and_never_cached(tmp_path):
    def down(url):
        raise OSError("connection refused")

    result = check_release_age(
        "npm", "fresh-lib", "1.2.0", min_hours=24, cache_dir=tmp_path, fetch=down, now=NOW
    )
    later = check_release_age(
        "npm", "fresh-lib", "1.2.0", min_hours=24, cache_dir=tmp_path, fetch=_registry(), now=NOW
    )

    assert result == {
        "status": "unknown",
        "published_at": None,
        "age_hours": None,
        "suggested_version": None,
        "source": "npm",
        "reason": "registry metadata could not be fetched or parsed",
    }
    assert later["status"] == "too_new"


def test_version_missing_from_registry_is_unknown(tmp_path):
    result = check_release_age(
        "npm", "fresh-lib", "9.9.9", min_hours=24, cache_dir=tmp_path, fetch=_registry(), now=NOW
    )

    assert result["status"] == "unknown"


def test_unpublished_version_keeps_its_time_but_is_never_suggested(tmp_path):
    result = check_release_age(
        "npm", "fresh-lib", "1.1.9", min_hours=24, cache_dir=tmp_path, fetch=_registry(), now=NOW
    )

    assert result["status"] == "old_enough"
    held = check_release_age(
        "npm", "fresh-lib", "1.2.0", min_hours=48, cache_dir=tmp_path, fetch=_registry(), now=NOW
    )
    assert held["suggested_version"] == "1.1.0"


def test_symlinked_cache_directory_is_not_used(tmp_path):
    target = tmp_path / "elsewhere"
    target.mkdir()
    (tmp_path / "root").mkdir()
    os.symlink(target, tmp_path / "root" / "release-times")

    result = check_release_age(
        "npm",
        "fresh-lib",
        "1.1.0",
        min_hours=24,
        cache_dir=tmp_path / "root",
        fetch=_registry(),
        now=NOW,
    )

    assert result["status"] == "old_enough"
    assert list(target.iterdir()) == []


def test_vet_style_age_findings_fall_back_to_registry(tmp_path):
    policy = PackagePolicy(package_age=PackageAgePolicy(enabled=True, minimum_hours=48))
    packages = (
        Package(name="freshpy", version="2.0.0", ecosystem="pypi", dependency_kind="direct"),
        Package(name="fresh-lib", version="1.1.0", ecosystem="npm"),
    )

    findings, warnings = package_age_findings(
        packages, policy, cache_dir=tmp_path / "feed", now=NOW, fetch=_registry()
    )
    offline, _ = package_age_findings(
        packages, policy, cache_dir=tmp_path / "cold" / "feed", now=NOW, network=False
    )

    assert [(item.signal_type, item.metadata.get("suggested_version")) for item in findings] == [
        ("new_package_version", "1.9.0")
    ]
    assert any("could not use feed data" in warning for warning in warnings)
    assert [item.signal_type for item in offline] == ["package_age_unknown"] * 2


def _pypi_state(tmp_path, *, defaulted, offline="warn", registry=None):
    return PyPIGatewayState(
        upstream_base="https://pypi.org",
        policy=PackagePolicy(
            mode=ModePolicy(offline=offline),
            package_age=PackageAgePolicy(enabled=True, minimum_hours=24),
        ),
        feed_cache_dir=tmp_path / "cache" / "feed",
        now=NOW,
        release_age_defaulted=defaulted,
        release_fetch=registry,
    )


def test_pypi_gateway_drops_fresh_files_and_keeps_old_ones(tmp_path):
    update_feed_from_source(_empty_feed(tmp_path), cache_dir=tmp_path / "cache" / "feed", now=NOW)
    snapshot = load_current_snapshot(cache_dir=tmp_path / "cache" / "feed")
    registry = _registry()
    state = _pypi_state(tmp_path, defaulted=True, registry=registry)
    blocked = _pypi_state(tmp_path, defaulted=False, offline="block", registry=_Registry({}))

    def check(gateway_state, name, version):
        return _denied_version(
            name, version, f"{name}-{version}.tar.gz", gateway_state.policy, snapshot, gateway_state
        )

    fresh = check(state, "freshpy", "2.0.0")
    old = check(state, "freshpy", "1.9.0")
    unknown_default = check(state, "private-pkg", "1.0.0")
    unknown_explicit = check(blocked, "private-pkg", "1.0.0")

    assert fresh is not None and fresh.policy_id == "ca9.package_age"
    assert old is None
    assert registry.calls.count(PYPI_PROJECT_URL) == 1
    assert unknown_default is None
    assert unknown_explicit is not None and unknown_explicit.policy_id == "ca9.package_age_unknown"


def _empty_feed(tmp_path):
    bundle = build_bundle_from_records({}, now=NOW - timedelta(hours=1))
    path = tmp_path / "feed.json"
    path.write_text(json.dumps(bundle))
    return str(path)


def _run(tmp_path, monkeypatch, *args, cwd=None):
    monkeypatch.setattr(release_age, "_default_fetch", _registry(datetime.now(timezone.utc)))
    if cwd is not None:
        monkeypatch.chdir(cwd)
    return CliRunner().invoke(
        main,
        [
            "run",
            *args,
            "--dry-run",
            "-f",
            "json",
            "--",
            "npm",
            "install",
            "--ignore-scripts",
            "fresh-lib@1.2.0",
        ],
        env={"CA9_CACHE_DIR": str(tmp_path / "cache"), "HOME": str(tmp_path / "home")},
    )


def test_ca9_run_holds_fresh_versions_by_default(tmp_path, monkeypatch):
    result = _run(tmp_path, monkeypatch)

    assert result.exit_code == 1, result.output
    decision = next(
        item
        for item in json.loads(result.output)["decisions"]
        if item["policy_id"] == "ca9.package_age"
    )
    assert decision["action"] == "block"
    assert decision["evidence"]["suggested_version"] == "1.1.0"
    assert "use 1.1.0" in decision["reason"]


@pytest.mark.parametrize(
    "policy_text",
    ["[package_age]\nenabled = false\n", "[package_age]\nminimum_hours = 0\n"],
)
def test_trusted_policy_turns_the_runtime_hold_off(tmp_path, monkeypatch, policy_text):
    policy = tmp_path / "policy.toml"
    policy.write_text(policy_text)

    result = _run(tmp_path, monkeypatch, "--policy", str(policy))

    assert result.exit_code == 0, result.output
    assert all(
        item["policy_id"] != "ca9.package_age" for item in json.loads(result.output)["decisions"]
    )


def test_repository_policy_cannot_turn_the_runtime_hold_off(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "ca9.toml").write_text("[package_age]\nenabled = false\nminimum_hours = 0\n")

    result = _run(tmp_path, monkeypatch, cwd=repo)

    assert result.exit_code == 1, result.output


def test_npm_gateway_tarball_check_reuses_the_shared_release_cache(tmp_path):
    from ca9.runtime.npm_gateway import NpmGatewayState, _tarball_decision

    now = datetime.now(timezone.utc)
    feed_dir = tmp_path / "cache" / "feed"
    update_feed_from_source(_empty_feed(tmp_path), cache_dir=feed_dir)
    upstream = "http://127.0.0.1:9"
    check_release_age(
        "npm",
        "fresh-lib",
        "1.2.0",
        min_hours=24,
        cache_dir=tmp_path / "cache",
        fetch=_Registry({f"{upstream}/fresh-lib": _docs(_ago_from(now))[NPM_URL]}),
        registry=upstream,
        now=now,
    )

    def state(defaulted):
        return NpmGatewayState(
            upstream_registry=upstream,
            policy=PackagePolicy(
                mode=ModePolicy(offline="block"),
                package_age=PackageAgePolicy(enabled=True, minimum_hours=24),
            ),
            feed_cache_dir=feed_dir,
            release_age_defaulted=defaulted,
        )

    fresh = _tarball_decision("fresh-lib", "1.2.0", state(False))
    uncached_default = _tarball_decision("other-lib", "1.0.0", state(True))
    uncached_explicit = _tarball_decision("other-lib", "1.0.0", state(False))

    assert fresh is not None and fresh.policy_id == "ca9.package_age"
    assert uncached_default is None
    assert uncached_explicit is not None
    assert uncached_explicit.policy_id == "ca9.package_age_unknown"


def _ago_from(now):
    def ago(**delta) -> str:
        return (now - timedelta(**delta)).isoformat().replace("+00:00", "Z")

    return ago


OLD = "2020-01-01T00:00:00Z"


def _pypi_release(files):
    return _Registry(
        {
            "https://pypi.org/pypi/pkg/1.0.0/json": {
                "info": {"name": "pkg", "version": "1.0.0"},
                "urls": files,
            },
            "https://pypi.org/pypi/pkg/json": {
                "info": {"name": "pkg"},
                "releases": {"0.9.0": [{"upload_time_iso_8601": OLD}], "1.0.0": files},
            },
        }
    )


def test_new_file_in_an_old_pypi_release_is_held(tmp_path):
    files = [
        {"filename": "pkg-1.0.0.tar.gz", "upload_time_iso_8601": OLD, "yanked": False},
        {
            "filename": "pkg-1.0.0-1-py3-none-any.whl",
            "upload_time_iso_8601": _ago(minutes=30),
            "yanked": False,
        },
    ]

    result = check_release_age(
        "pypi",
        "pkg",
        "1.0.0",
        min_hours=24,
        cache_dir=tmp_path,
        fetch=_pypi_release(files),
        now=NOW,
    )

    assert result["status"] == "too_new"
    assert result["published_at"] == _ago(minutes=30)
    assert result["suggested_version"] == "0.9.0"


def test_yanked_new_file_does_not_hold_an_old_pypi_release(tmp_path):
    files = [
        {"filename": "pkg-1.0.0.tar.gz", "upload_time_iso_8601": OLD, "yanked": False},
        {
            "filename": "pkg-1.0.0-py3-none-any.whl",
            "upload_time_iso_8601": _ago(minutes=30),
            "yanked": True,
        },
    ]

    result = check_release_age(
        "pypi",
        "pkg",
        "1.0.0",
        min_hours=24,
        cache_dir=tmp_path,
        fetch=_pypi_release(files),
        now=NOW,
    )

    assert result["status"] == "old_enough"


def test_cached_pypi_release_is_rechecked_for_new_files(tmp_path):
    old_files = [{"filename": "pkg-1.0.0.tar.gz", "upload_time_iso_8601": OLD, "yanked": False}]
    first = check_release_age(
        "pypi",
        "pkg",
        "1.0.0",
        min_hours=24,
        cache_dir=tmp_path,
        fetch=_pypi_release(old_files),
        now=NOW,
    )
    later = NOW + timedelta(minutes=11)
    new_file = {
        "filename": "pkg-1.0.0-1-py3-none-any.whl",
        "upload_time_iso_8601": (later - timedelta(minutes=1)).isoformat(),
        "yanked": False,
    }
    second = check_release_age(
        "pypi",
        "pkg",
        "1.0.0",
        min_hours=24,
        cache_dir=tmp_path,
        fetch=_pypi_release([*old_files, new_file]),
        now=later,
    )
    within_window = check_release_age(
        "pypi",
        "pkg",
        "1.0.0",
        min_hours=24,
        cache_dir=tmp_path,
        fetch=_Registry({}),
        now=later + timedelta(minutes=1),
    )

    assert first["status"] == "old_enough"
    assert second["status"] == "too_new"
    assert (within_window["status"], within_window["source"]) == ("too_new", "cache")


@pytest.mark.parametrize(
    "min_hours", [None, "24", -1, -0.5, float("nan"), float("inf"), True, 1e30]
)
def test_invalid_min_hours_is_unknown_not_old_enough(tmp_path, min_hours):
    registry = _registry()

    result = check_release_age(
        "npm",
        "fresh-lib",
        "1.2.0",
        min_hours=min_hours,
        cache_dir=tmp_path,
        fetch=registry,
        now=NOW,
    )

    assert result["status"] == "unknown"
    assert "min_hours" in result["reason"]
    assert registry.calls == []


def test_zero_min_hours_still_answers_from_the_registry(tmp_path):
    result = check_release_age(
        "npm", "fresh-lib", "1.2.0", min_hours=0, cache_dir=tmp_path, fetch=_registry(), now=NOW
    )

    assert (result["status"], result["reason"]) == ("old_enough", None)


@pytest.mark.parametrize(
    "repo_policy",
    [
        "[package_age]\nenabled = true\nminimum_hours = 0\n",
        "[package_age]\nminimum_hours = 1\n",
        '[package_age]\nenabled = true\nexclusions = ["*"]\n',
        '[package_age]\nexclusions = ["fresh-*"]\n',
        '[package_age]\nenabled = false\nexclusions = ["fresh-lib"]\n',
    ],
)
def test_repository_policy_cannot_relax_the_runtime_hold(tmp_path, monkeypatch, repo_policy):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "ca9.toml").write_text(repo_policy)

    result = _run(tmp_path, monkeypatch, cwd=repo)

    assert result.exit_code == 1, result.output
    data = json.loads(result.stdout)
    assert any(item["policy_id"] == "ca9.package_age" for item in data["decisions"])
    assert any("ignored relaxing setting package_age" in item for item in data["policy_warnings"])


def test_repository_policy_can_raise_the_runtime_hold(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "ca9.toml").write_text("[package_age]\nminimum_hours = 72\n")
    policy = load_effective_package_policy(cwd=repo, env={}, home=tmp_path / "home")

    effective, _ = runtime_release_age_policy(policy)

    assert (effective.package_age.enabled, effective.package_age.minimum_hours) == (True, 72)


@pytest.mark.parametrize(
    "user_policy",
    ['[package_age]\nexclusions = ["fresh-*"]\n', "[package_age]\nminimum_hours = 1\n"],
)
def test_trusted_user_policy_may_exclude_or_lower_the_hold(tmp_path, monkeypatch, user_policy):
    config = tmp_path / "home" / ".config" / "ca9"
    config.mkdir(parents=True)
    (config / "policy.toml").write_text(user_policy)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "ca9.toml").write_text("[package_age]\nminimum_hours = 0\n")

    result = _run(tmp_path, monkeypatch, cwd=repo)

    assert result.exit_code == 0, result.output


def test_pypi_gateway_holds_an_old_release_that_gained_a_new_file(tmp_path):
    update_feed_from_source(_empty_feed(tmp_path), cache_dir=tmp_path / "cache" / "feed", now=NOW)
    snapshot = load_current_snapshot(cache_dir=tmp_path / "cache" / "feed")
    files = [
        {"filename": "pkg-1.0.0.tar.gz", "upload_time_iso_8601": OLD, "yanked": False},
        {
            "filename": "pkg-1.0.0-1-py3-none-any.whl",
            "upload_time_iso_8601": _ago(minutes=30),
            "yanked": False,
        },
    ]
    state = _pypi_state(tmp_path, defaulted=True, registry=_pypi_release(files))

    decision = _denied_version("pkg", "1.0.0", "pkg-1.0.0.tar.gz", state.policy, snapshot, state)

    assert decision is not None and decision.policy_id == "ca9.package_age"
