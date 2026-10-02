from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from click.testing import CliRunner

from ca9.cli import main
from ca9.package_feed import update_feed_from_source
from ca9.package_policy import MalwarePolicy, PackagePolicy
from ca9.runtime.preflight import (
    evaluate_runtime_preflight,
    format_preflight,
    parse_install_command,
)

NO_FEED_CHECKS = PackagePolicy(malware=MalwarePolicy(enabled=False))


def _lock(repo, packages, *, root_dependencies=None):
    data = {
        "name": "demo-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "demo-app",
                "version": "1.0.0",
                "dependencies": root_dependencies
                if root_dependencies is not None
                else {path.rsplit("node_modules/", 1)[-1]: "*" for path in packages},
            },
            **packages,
        },
    }
    (repo / "package-lock.json").write_text(json.dumps(data))


def _entry(version, resolved, **extra):
    return {"version": version, "resolved": resolved, "integrity": "sha512-test", **extra}


def test_npm_ci_blocks_resolved_tarball_for_a_different_package(tmp_path):
    _lock(
        tmp_path,
        {
            "node_modules/lodash": _entry(
                "4.17.21", "https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.0.0.tgz"
            )
        },
    )

    preflight = evaluate_runtime_preflight(("npm", "ci"), NO_FEED_CHECKS, env={}, cwd=tmp_path)

    assert preflight.action == "block"
    assert preflight.decisions[0].policy_id == "ca9.runtime.lockfile_unavailable"
    assert "does not match lodash@4.17.21" in preflight.decisions[0].reason


@pytest.mark.parametrize(
    ("name", "version", "resolved"),
    [
        ("lodash", "4.17.21", "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"),
        ("lodash", "4.17.21", "https://registry.npmjs.org/lodash/-/evil-4.17.21.tgz"),
        ("lodash", "4.17.21", "https://registry.npmjs.org/evil-lodash/-/lodash-4.17.21.tgz"),
        ("lodash", "4.17.21", "https://registry.npmjs.org/x/../lodash/-/lodash-4.17.21.tgz"),
        ("lodash", "4.17.21", "https://attacker.example/payload.tgz"),
        ("@scope/pkg", "1.0.0", "https://registry.npmjs.org/@evil/pkg/-/pkg-1.0.0.tgz"),
        ("@scope/pkg", "1.0.0", "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"),
        (
            "@scope/pkg",
            "1.0.0",
            "https://npm.pkg.github.com/download/@evil/pkg/1.0.0/" + "a" * 40,
        ),
        (
            "@scope/pkg",
            "1.0.0",
            "https://npm.pkg.github.com/download/@scope/pkg/1.0.1/" + "a" * 40,
        ),
        ("lodash", "4.17.21", "https://npm.pkg.github.com/download/lodash/4.17.21/" + "a" * 40),
    ],
)
def test_npm_ci_blocks_mismatched_resolved_paths(name, version, resolved, tmp_path):
    _lock(tmp_path, {f"node_modules/{name}": _entry(version, resolved)})

    preflight = evaluate_runtime_preflight(("npm", "ci"), NO_FEED_CHECKS, env={}, cwd=tmp_path)

    assert preflight.action == "block"
    assert preflight.decisions[0].policy_id == "ca9.runtime.lockfile_unavailable"


@pytest.mark.parametrize(
    ("name", "resolved"),
    [
        ("lodash", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"),
        ("lodash", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz?cache=1"),
        ("lodash", "https://registry.npmjs.org/api/npm/npm-remote/lodash/-/lodash-4.17.21.tgz"),
        ("@scope/pkg", "https://registry.npmjs.org/@scope/pkg/-/pkg-4.17.21.tgz"),
        ("@scope/pkg", "https://registry.npmjs.org/@scope%2fpkg/-/pkg-4.17.21.tgz"),
        ("@scope/pkg", "https://registry.npmjs.org/repo/@scope/pkg/-/@scope/pkg-4.17.21.tgz"),
        ("@scope/pkg", "https://npm.pkg.github.com/download/@scope/pkg/4.17.21/" + "0f" * 20),
    ],
)
def test_npm_ci_accepts_matching_registry_tarball_paths(name, resolved, tmp_path):
    _lock(tmp_path, {f"node_modules/{name}": _entry("4.17.21", resolved)})

    command = parse_install_command(("npm", "ci"), cwd=tmp_path)

    assert [request.key for request in command.package_requests] == [f"npm:{name}@4.17.21"]


def test_npm_ci_accepts_aliased_lock_entry_resolving_to_real_package(tmp_path):
    _lock(
        tmp_path,
        {
            "node_modules/lodash": _entry(
                "1.0.0",
                "https://registry.npmjs.org/real-pkg/-/real-pkg-1.0.0.tgz",
                name="real-pkg",
            )
        },
    )

    command = parse_install_command(("npm", "ci"), cwd=tmp_path)

    assert [request.key for request in command.package_requests] == ["npm:real-pkg@1.0.0"]


def test_npm_install_with_lockfile_checks_locked_packages(tmp_path):
    _lock(
        tmp_path,
        {
            "node_modules/left-pad": _entry(
                "1.3.0", "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
            )
        },
    )
    cache = _feed(tmp_path)

    preflight = evaluate_runtime_preflight(
        ("npm", "install", "is-number@7.0.0"),
        PackagePolicy(),
        env={},
        feed_cache_dir=cache,
        cwd=tmp_path,
    )

    assert [request.key for request in preflight.command.package_requests] == [
        "npm:is-number@7.0.0",
        "npm:left-pad@1.3.0",
    ]
    assert preflight.action == "block"
    assert any(
        item.policy_id == "ca9.malware" and item.package == "left-pad"
        for item in preflight.decisions
    )


@pytest.mark.parametrize(
    "command", [("npm", "install"), ("npm", "i"), ("npm", "--silent", "install")]
)
def test_bare_npm_install_checks_the_project_lockfile(command, tmp_path):
    (tmp_path / "package.json").write_text('{"name": "demo-app"}\n')
    _lock(
        tmp_path,
        {
            "node_modules/left-pad": _entry(
                "1.3.0", "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
            )
        },
    )
    cache = _feed(tmp_path)

    preflight = evaluate_runtime_preflight(
        command, PackagePolicy(), env={}, feed_cache_dir=cache, cwd=tmp_path
    )

    assert [request.key for request in preflight.command.package_requests] == ["npm:left-pad@1.3.0"]
    assert preflight.action == "block"
    assert any(
        item.policy_id == "ca9.malware" and item.package == "left-pad"
        for item in preflight.decisions
    )


@pytest.mark.parametrize("command", [("npm", "install"), ("npm", "install", "-g")])
def test_bare_npm_install_without_a_project_lockfile_is_blocked(command, tmp_path):
    (tmp_path / "package.json").write_text('{"name": "demo-app"}\n')
    if "-g" in command:
        _lock(tmp_path, {})

    preflight = evaluate_runtime_preflight(command, NO_FEED_CHECKS, env={}, cwd=tmp_path)

    assert preflight.action == "block"
    assert "needs a project package-lock.json" in preflight.decisions[0].reason


def test_npm_install_from_project_subdirectory_uses_project_lockfile(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "demo-app"}\n')
    _lock(
        tmp_path,
        {
            "node_modules/lodash": _entry(
                "4.17.21", "https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.0.0.tgz"
            )
        },
    )
    nested = tmp_path / "src" / "tools"
    nested.mkdir(parents=True)

    preflight = evaluate_runtime_preflight(
        ("npm", "install", "is-number@7.0.0"), NO_FEED_CHECKS, env={}, cwd=nested
    )

    assert preflight.action == "block"
    assert preflight.decisions[0].policy_id == "ca9.runtime.lockfile_unavailable"


def test_npm_global_install_ignores_project_lockfile(tmp_path):
    (tmp_path / "package-lock.json").write_text("not json")

    command = parse_install_command(("npm", "install", "-g", "is-number@7.0.0"), cwd=tmp_path)

    assert [request.key for request in command.package_requests] == ["npm:is-number@7.0.0"]


@pytest.mark.parametrize("args", [("ci",), ("install", "is-number@7.0.0")])
def test_npm_shrinkwrap_is_not_silently_ignored(args, tmp_path):
    _lock(
        tmp_path,
        {
            "node_modules/left-pad": _entry(
                "1.3.0", "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
            )
        },
    )
    (tmp_path / "npm-shrinkwrap.json").write_text("{}")

    preflight = evaluate_runtime_preflight(("npm", *args), NO_FEED_CHECKS, env={}, cwd=tmp_path)

    assert preflight.action == "block"
    assert preflight.decisions[0].policy_id == "ca9.runtime.lockfile_unavailable"
    assert "npm-shrinkwrap.json" in preflight.decisions[0].reason


def test_missing_feed_warns_instead_of_silently_passing(tmp_path):
    preflight = evaluate_runtime_preflight(
        ("npm", "install", "evil-pkg"),
        PackagePolicy(),
        env={},
        feed_cache_dir=tmp_path / "missing",
        cwd=tmp_path,
    )

    assert preflight.action == "warn"
    assert not preflight.blocked
    (decision,) = preflight.decisions
    assert decision.policy_id == "ca9.malware_feed_unavailable"
    assert decision.action == "warn"
    assert "ca9 feed update" in decision.reason
    assert preflight.warnings == (decision.reason,)
    assert preflight.to_dict()["warnings"] == [decision.reason]
    assert "[WARN] ca9.malware_feed_unavailable" in format_preflight(preflight)


def test_missing_feed_blocks_when_malware_policy_fails_closed(tmp_path):
    preflight = evaluate_runtime_preflight(
        ("pip", "install", "evil-pkg"),
        PackagePolicy(malware=MalwarePolicy(fail_closed=True)),
        env={},
        feed_cache_dir=tmp_path / "missing",
        cwd=tmp_path,
    )

    assert preflight.action == "block"
    assert preflight.decisions[0].policy_id == "ca9.malware_feed_unavailable"
    assert "ca9 feed update" in preflight.decisions[0].reason


def test_stale_feed_snapshot_is_still_used_for_checks_with_warning(tmp_path):
    expired = (datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=1)).isoformat()
    cache = _feed(tmp_path, expires_at=expired)

    preflight = evaluate_runtime_preflight(
        ("npm", "install", "left-pad@1.3.0"),
        PackagePolicy(),
        env={},
        feed_cache_dir=cache,
        cwd=tmp_path,
    )

    assert preflight.feed.state == "stale"
    assert preflight.action == "block"
    policy_ids = [item.policy_id for item in preflight.decisions]
    assert "ca9.malware" in policy_ids
    assert "ca9.malware_feed_unavailable" in policy_ids
    assert "stale" in preflight.warnings[0]


def test_disabled_malware_policy_has_no_feed_warning(tmp_path):
    preflight = evaluate_runtime_preflight(
        ("npm", "install", "evil-pkg"),
        NO_FEED_CHECKS,
        env={},
        feed_cache_dir=tmp_path / "missing",
        cwd=tmp_path,
    )

    assert preflight.action == "pass"
    assert preflight.warnings == ()


def test_ca9_run_dry_run_without_feed_warns_on_stderr_json_and_ledger(tmp_path, monkeypatch):
    # --ignore-scripts keeps secrets inherited from the test environment out of the result.
    audit_log = tmp_path / "audit.jsonl"
    monkeypatch.chdir(tmp_path)
    env = {"CA9_CACHE_DIR": str(tmp_path / "cache")}
    runner = CliRunner()

    table = runner.invoke(
        main,
        [
            "run",
            "--dry-run",
            "--audit-log",
            str(audit_log),
            "--",
            "npm",
            "install",
            "--ignore-scripts",
            "evil-pkg",
        ],
        env=env,
    )
    as_json = runner.invoke(
        main,
        ["run", "--dry-run", "-f", "json", "--", "npm", "install", "--ignore-scripts", "evil-pkg"],
        env={**env, "CA9_AUDIT_LOG": str(tmp_path / "json-audit.jsonl")},
    )

    assert table.exit_code == 0
    assert "ca9: warning: malware checks are inactive" in table.stderr
    assert "ca9 feed update" in table.stderr
    assert "ca9 runtime preflight: warn" in table.stdout
    assert as_json.exit_code == 0
    data = json.loads(as_json.stdout)
    assert data["action"] == "warn"
    assert "malware checks are inactive" in data["warnings"][0]
    events = [json.loads(line) for line in audit_log.read_text().splitlines()]
    assert any(
        event["event_kind"] == "decision_emitted"
        and event["payload"]["policy_id"] == "ca9.malware_feed_unavailable"
        and event["payload"]["action"] == "warn"
        for event in events
    )


def _feed(tmp_path, *, expires_at=None):
    expires = (
        expires_at
        or (datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=1)).isoformat()
    )
    bundle = {
        "schema": "ca9.feed.v1",
        "created_at": "2026-06-26T00:00:00Z",
        "expires_at": expires,
        "datasets": {
            "npm-malware": {"packages": [{"name": "left-pad", "version": "1.3.0", "id": "M-1"}]},
            "pypi-malware": {"packages": []},
            "npm-releases": {"packages": {}},
            "pypi-releases": {"packages": {}},
        },
    }
    path = tmp_path / "feed.json"
    path.write_text(json.dumps(bundle))
    cache = tmp_path / "feed-cache" / "feed"
    update_feed_from_source(path, cache_dir=cache)
    return cache
