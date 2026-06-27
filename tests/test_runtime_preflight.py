from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from click.testing import CliRunner

from ca9.cli import main
from ca9.package_feed import update_feed_from_source
from ca9.package_policy import (
    CIPolicy,
    InstallScriptsPolicy,
    MalwarePolicy,
    ModePolicy,
    PackageAgePolicy,
    PackagePolicy,
    RegistriesPolicy,
)
from ca9.runtime.preflight import (
    child_environment,
    detect_secret_env,
    evaluate_runtime_preflight,
    gateway_child_command,
    parse_install_command,
    primary_registry_url,
    redact_sensitive_text,
)


def test_parse_npm_install_direct_specs():
    command = parse_install_command(("npm", "install", "left-pad@1.3.0", "@scope/pkg@2.0.0"))

    assert command.family == "npm"
    assert [request.name for request in command.package_requests] == ["left-pad", "@scope/pkg"]
    assert [request.exact_version for request in command.package_requests] == ["1.3.0", "2.0.0"]


def test_parse_pip_install_direct_specs():
    command = parse_install_command(("python", "-m", "pip", "install", "Requests==2.31.0"))

    assert command.family == "pip"
    assert command.package_requests[0].name == "requests"
    assert command.package_requests[0].exact_version == "2.31.0"


def test_parse_install_records_primary_registry_and_gateway_command_strips_it():
    command = parse_install_command(
        (
            "pip",
            "install",
            "--index-url",
            "https://pypi.org/simple",
            "requests==2.31.0",
        )
    )

    assert primary_registry_url(command) == "https://pypi.org/simple"
    assert gateway_child_command(command) == ("pip", "install", "requests==2.31.0")


def test_runtime_preflight_blocks_untrusted_pip_index_url():
    preflight = evaluate_runtime_preflight(
        (
            "pip",
            "install",
            "--index-url",
            "https://packages.example/simple",
            "requests==2.31.0",
        ),
        PackagePolicy(),
        env={},
    )

    assert preflight.action == "block"
    assert any(decision.policy_id == "ca9.untrusted_registry" for decision in preflight.decisions)


def test_runtime_preflight_blocks_denied_npm_registry():
    preflight = evaluate_runtime_preflight(
        (
            "npm",
            "install",
            "--registry=https://registry.npmjs.org",
            "left-pad@1.3.0",
        ),
        PackagePolicy(registries=RegistriesPolicy(deny=("registry.npmjs.org",))),
        env={},
    )

    assert preflight.action == "block"
    assert any(decision.policy_id == "ca9.denied_registry" for decision in preflight.decisions)


def test_runtime_preflight_rejects_pip_extra_index_until_multi_index_gateway_exists():
    preflight = evaluate_runtime_preflight(
        (
            "pip",
            "install",
            "--extra-index-url",
            "https://packages.example/simple",
            "requests==2.31.0",
        ),
        PackagePolicy(),
        env={},
    )

    assert preflight.action == "block"
    assert preflight.decisions[0].policy_id == "ca9.runtime.unsupported_command"
    assert "source option is not supported" in preflight.decisions[0].reason


def test_runtime_preflight_blocks_untrusted_pip_index_env():
    preflight = evaluate_runtime_preflight(
        ("pip", "install", "requests==2.31.0"),
        PackagePolicy(),
        env={"PIP_INDEX_URL": "https://packages.example/simple"},
    )

    assert preflight.action == "block"
    assert any(decision.policy_id == "ca9.untrusted_registry" for decision in preflight.decisions)


def test_runtime_preflight_blocks_untrusted_npm_registry_env():
    preflight = evaluate_runtime_preflight(
        ("npm", "install", "left-pad@1.3.0"),
        PackagePolicy(),
        env={"NPM_CONFIG_REGISTRY": "https://packages.example"},
    )

    assert preflight.action == "block"
    assert any(decision.policy_id == "ca9.untrusted_registry" for decision in preflight.decisions)


def test_runtime_preflight_blocks_pip_alternate_source_env():
    preflight = evaluate_runtime_preflight(
        ("pip", "install", "requests==2.31.0"),
        PackagePolicy(),
        env={"PIP_EXTRA_INDEX_URL": "https://pypi.org/simple"},
    )

    assert preflight.action == "block"
    assert any(
        decision.policy_id == "ca9.runtime.unsupported_source" for decision in preflight.decisions
    )


def test_runtime_preflight_blocks_config_file_env_sources():
    preflight = evaluate_runtime_preflight(
        ("npm", "install", "left-pad@1.3.0"),
        PackagePolicy(),
        env={"NPM_CONFIG_USERCONFIG": "/tmp/npmrc"},
    )

    assert preflight.action == "block"
    assert any(
        decision.policy_id == "ca9.runtime.unsupported_source" for decision in preflight.decisions
    )


def test_runtime_preflight_blocks_known_malware_from_feed(tmp_path):
    cache_root = tmp_path / "cache"
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_root / "feed")

    preflight = evaluate_runtime_preflight(
        ("npm", "install", "left-pad@1.3.0"),
        PackagePolicy(),
        env={},
        feed_cache_dir=cache_root / "feed",
    )

    assert preflight.action == "block"
    assert any(decision.policy_id == "ca9.malware" for decision in preflight.decisions)
    assert any(decision.package == "left-pad" for decision in preflight.decisions)


def test_runtime_preflight_blocks_new_package_version_from_feed(tmp_path):
    cache_root = tmp_path / "cache"
    released_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    update_feed_from_source(
        _write_feed_bundle(
            tmp_path,
            pypi_releases={"packages": {"badlib": {"1.0.0": released_at}}},
        ),
        cache_dir=cache_root / "feed",
    )

    preflight = evaluate_runtime_preflight(
        ("pip", "install", "badlib==1.0.0"),
        PackagePolicy(package_age=PackageAgePolicy(enabled=True, minimum_hours=48)),
        env={},
        feed_cache_dir=cache_root / "feed",
    )

    assert preflight.action == "block"
    assert any(decision.policy_id == "ca9.package_age" for decision in preflight.decisions)


def test_runtime_preflight_allows_old_package_version_from_feed(tmp_path):
    cache_root = tmp_path / "cache"
    released_at = (
        datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=10)
    ).isoformat()
    update_feed_from_source(
        _write_feed_bundle(
            tmp_path,
            pypi_releases={"packages": {"oldlib": {"1.0.0": released_at}}},
        ),
        cache_dir=cache_root / "feed",
    )

    preflight = evaluate_runtime_preflight(
        ("pip", "install", "oldlib==1.0.0"),
        PackagePolicy(package_age=PackageAgePolicy(enabled=True, minimum_hours=48)),
        env={},
        feed_cache_dir=cache_root / "feed",
    )

    assert preflight.action == "pass"
    assert not preflight.decisions


def test_runtime_preflight_warns_when_release_time_unknown_by_default(tmp_path):
    cache_root = tmp_path / "cache"
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_root / "feed")

    preflight = evaluate_runtime_preflight(
        ("pip", "install", "unknownlib==1.0.0"),
        PackagePolicy(package_age=PackageAgePolicy(enabled=True, minimum_hours=48)),
        env={},
        feed_cache_dir=cache_root / "feed",
    )

    assert preflight.action == "warn"
    assert any(decision.policy_id == "ca9.package_age_unknown" for decision in preflight.decisions)


def test_runtime_preflight_blocks_unknown_release_time_when_offline_blocks(tmp_path):
    cache_root = tmp_path / "cache"
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_root / "feed")

    preflight = evaluate_runtime_preflight(
        ("pip", "install", "unknown-lib==1.0.0"),
        PackagePolicy(
            mode=ModePolicy(offline="block"),
            package_age=PackageAgePolicy(enabled=True, minimum_hours=48),
        ),
        env={},
        feed_cache_dir=cache_root / "feed",
    )

    assert preflight.action == "block"
    assert any(decision.policy_id == "ca9.package_age_unknown" for decision in preflight.decisions)


def test_runtime_preflight_defers_npm_unknown_release_time_to_gateway(tmp_path):
    cache_root = tmp_path / "cache"
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_root / "feed")

    preflight = evaluate_runtime_preflight(
        ("npm", "install", "unknown-lib@1.0.0"),
        PackagePolicy(
            mode=ModePolicy(offline="block"),
            package_age=PackageAgePolicy(enabled=True, minimum_hours=48),
        ),
        env={},
        feed_cache_dir=cache_root / "feed",
    )

    assert preflight.action == "pass"
    assert all(decision.policy_id != "ca9.package_age_unknown" for decision in preflight.decisions)


def test_runtime_preflight_fail_closed_malware_blocks_stale_feed(tmp_path):
    cache_root = tmp_path / "cache"
    expired_at = (datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=1)).isoformat()
    update_feed_from_source(
        _write_feed_bundle(tmp_path, expires_at=expired_at),
        cache_dir=cache_root / "feed",
    )

    preflight = evaluate_runtime_preflight(
        ("npm", "install", "left-pad@1.2.0"),
        PackagePolicy(malware=MalwarePolicy(fail_closed=True)),
        env={},
        feed_cache_dir=cache_root / "feed",
    )

    assert preflight.action == "block"
    assert any(
        decision.policy_id == "ca9.malware_feed_unavailable" for decision in preflight.decisions
    )


def test_runtime_preflight_blocks_secret_bearing_install_env():
    preflight = evaluate_runtime_preflight(
        ("pip", "install", "requests==2.31.0"),
        PackagePolicy(),
        env={"PYPI_TOKEN": "secret-value"},
    )

    assert preflight.action == "block"
    assert preflight.secret_names == ("PYPI_TOKEN",)
    assert any(
        decision.policy_id == "ca9.install_scripts.secrets" for decision in preflight.decisions
    )


def test_runtime_preflight_allows_npm_ignore_scripts_with_secrets():
    preflight = evaluate_runtime_preflight(
        ("npm", "install", "--ignore-scripts", "left-pad@1.3.0"),
        PackagePolicy(),
        env={"NPM_TOKEN": "secret-value"},
    )

    assert preflight.action == "pass"
    assert preflight.secret_names == ("NPM_TOKEN",)
    assert not preflight.decisions


def test_runtime_preflight_blocks_unsupported_requirement_file_install():
    preflight = evaluate_runtime_preflight(
        ("pip", "install", "-r", "requirements.txt"),
        PackagePolicy(),
        env={},
    )

    assert preflight.action == "block"
    assert preflight.decisions[0].policy_id == "ca9.runtime.unsupported_command"


def test_runtime_preflight_can_strip_secrets_in_warn_mode():
    policy = PackagePolicy(
        mode=ModePolicy(default="warn"),
        install_scripts=InstallScriptsPolicy(block_when_secrets_present=True),
        ci=CIPolicy(strip_secret_env_for_installs=True),
    )

    preflight = evaluate_runtime_preflight(
        ("npm", "install", "left-pad@1.3.0"),
        policy,
        env={"NPM_TOKEN": "secret-value", "PATH": "/bin"},
    )
    child_env = child_environment({"NPM_TOKEN": "secret-value", "PATH": "/bin"}, preflight)

    assert preflight.action == "warn"
    assert preflight.stripped_secret_names == ("NPM_TOKEN",)
    assert "NPM_TOKEN" not in child_env
    assert child_env["PATH"] == "/bin"


def test_detect_secret_env_reports_names_not_values():
    names = detect_secret_env({"GITHUB_TOKEN": "ghp_value", "PLAIN": "ok", "AWS_REGION": "us"})

    assert names == ("AWS_REGION", "GITHUB_TOKEN")


def test_redacts_authorization_like_text():
    assert (
        redact_sensitive_text("Authorization: Bearer abc123") == "Authorization: Bearer [redacted]"
    )
    assert (
        redact_sensitive_text("Proxy-Authorization=Basic dXNlcjpwYXNz")
        == "Proxy-Authorization=Basic [redacted]"
    )


def test_ca9_run_blocks_malware_and_does_not_execute_child(tmp_path):
    cache_root = tmp_path / "cache"
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_root / "feed")
    bin_dir = tmp_path / "bin"
    marker = tmp_path / "ran.txt"
    _write_fake_command(bin_dir, "npm", f"#!/bin/sh\necho ran > {marker}\nexit 0\n")

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "run",
            "--dry-run",
            "-f",
            "json",
            "--",
            "npm",
            "install",
            "left-pad@1.3.0",
        ],
        env={"CA9_CACHE_DIR": str(cache_root), "PATH": str(bin_dir)},
    )

    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["action"] == "block"
    assert any(decision["policy_id"] == "ca9.malware" for decision in data["decisions"])
    assert not marker.exists()


def test_ca9_run_preserves_child_exit_code_and_writes_ledger(tmp_path):
    cache_root = tmp_path / "cache"
    audit_log = tmp_path / "audit.jsonl"
    bin_dir = tmp_path / "bin"
    _write_fake_command(bin_dir, "npm", "#!/bin/sh\nexit 7\n")
    policy_path = tmp_path / "ca9.toml"
    policy_path.write_text(
        """
[install_scripts]
block_when_secrets_present = false

[ci]
strip_secret_env_for_installs = false
"""
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "run",
            "--policy",
            str(policy_path),
            "--audit-log",
            str(audit_log),
            "--",
            "npm",
            "install",
            "left-pad@1.3.0",
        ],
        env={"CA9_CACHE_DIR": str(cache_root), "PATH": str(bin_dir)},
    )

    assert result.exit_code == 7
    events = _read_ledger(audit_log)
    event_kinds = [event["event_kind"] for event in events]
    assert event_kinds[:5] == [
        "session_started",
        "command_observed",
        "package_requested",
        "feed_used",
        "offline_fallback",
    ]
    assert event_kinds[-3:] == [
        "child_process_started",
        "child_process_exited",
        "session_ended",
    ]
    assert {event["schema_version"] for event in events} == {"ca9.run.ledger.v1"}
    assert len({event["session_id"] for event in events}) == 1
    assert events[-2]["payload"]["exit_code"] == 7
    assert events[-1]["payload"]["executed"] is True
    assert events[-1]["payload"]["child_exit_code"] == 7


def test_ca9_run_strips_secret_values_from_child_env_and_ledger(tmp_path):
    cache_root = tmp_path / "cache"
    audit_log = tmp_path / "audit.jsonl"
    bin_dir = tmp_path / "bin"
    env_dump = tmp_path / "env.txt"
    _write_fake_command(bin_dir, "pip", f"#!/bin/sh\nenv > {env_dump}\nexit 0\n")
    policy_path = tmp_path / "ca9.toml"
    policy_path.write_text(
        """
[mode]
default = "warn"

[install_scripts]
block_when_secrets_present = true

[ci]
strip_secret_env_for_installs = true
"""
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "run",
            "--policy",
            str(policy_path),
            "--audit-log",
            str(audit_log),
            "--",
            "pip",
            "install",
            "requests==2.31.0",
        ],
        env={
            "CA9_CACHE_DIR": str(cache_root),
            "PATH": str(bin_dir),
            "PYPI_TOKEN": "super-secret-token",
        },
    )

    assert result.exit_code == 0
    assert "PYPI_TOKEN=super-secret-token" not in env_dump.read_text()
    assert "super-secret-token" not in result.output
    assert "super-secret-token" not in result.stderr
    ledger = audit_log.read_text()
    assert "PYPI_TOKEN" in ledger
    assert "super-secret-token" not in ledger


def test_ca9_run_redacts_url_credentials_from_output_and_ledger(tmp_path):
    cache_root = tmp_path / "cache"
    audit_log = tmp_path / "audit.jsonl"

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "run",
            "--dry-run",
            "-f",
            "json",
            "--audit-log",
            str(audit_log),
            "--",
            "pip",
            "install",
            "https://user:secretpass@example.test/pkg.whl",
        ],
        env={"CA9_CACHE_DIR": str(cache_root)},
    )

    assert result.exit_code == 1
    ledger = audit_log.read_text()
    assert "secretpass" not in result.output
    assert "secretpass" not in ledger
    assert "https://[redacted]@example.test/pkg.whl" in result.output


def test_ca9_run_json_output_redacts_secret_values(tmp_path):
    cache_root = tmp_path / "cache"
    audit_log = tmp_path / "audit.jsonl"

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "run",
            "--dry-run",
            "-f",
            "json",
            "--audit-log",
            str(audit_log),
            "--",
            "pip",
            "install",
            "requests==2.31.0",
        ],
        env={
            "CA9_CACHE_DIR": str(cache_root),
            "PYPI_TOKEN": "super-secret-token",
        },
    )

    assert result.exit_code == 1
    data = json.loads(result.output)
    assert "PYPI_TOKEN" in data["secret_names"]
    assert "super-secret-token" not in result.output
    assert "super-secret-token" not in audit_log.read_text()


def test_ca9_run_ledger_records_feed_and_decision_events(tmp_path):
    cache_root = tmp_path / "cache"
    audit_log = tmp_path / "audit.jsonl"
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_root / "feed")

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "run",
            "--dry-run",
            "--audit-log",
            str(audit_log),
            "--",
            "npm",
            "install",
            "left-pad@1.3.0",
        ],
        env={"CA9_CACHE_DIR": str(cache_root)},
    )

    assert result.exit_code == 1
    events = _read_ledger(audit_log)
    event_kinds = [event["event_kind"] for event in events]
    assert "feed_used" in event_kinds
    assert "decision_emitted" in event_kinds
    assert "child_process_started" not in event_kinds
    assert "child_process_exited" not in event_kinds
    feed_event = next(event for event in events if event["event_kind"] == "feed_used")
    decision_event = next(event for event in events if event["event_kind"] == "decision_emitted")
    assert feed_event["payload"]["state"] == "ready"
    assert decision_event["payload"]["policy_id"] == "ca9.malware"


def _write_feed_bundle(
    tmp_path,
    *,
    pypi_releases: dict | None = None,
    expires_at: str | None = None,
):
    expires = (
        expires_at
        or (datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=1)).isoformat()
    )
    bundle = {
        "schema": "ca9.feed.v1",
        "created_at": "2026-06-26T00:00:00Z",
        "expires_at": expires,
        "datasets": {
            "pypi-malware": {"packages": []},
            "npm-malware": {
                "packages": [
                    {
                        "name": "left-pad",
                        "version": "1.3.0",
                        "id": "MAL-NPM-1",
                        "summary": "known malicious npm test package",
                    }
                ]
            },
            "pypi-releases": pypi_releases or {"packages": {}},
            "npm-releases": {"packages": {"left-pad": {"1.3.0": "2026-06-25T00:00:00Z"}}},
        },
    }
    path = tmp_path / "feed.json"
    path.write_text(json.dumps(bundle))
    return path


def _write_fake_command(bin_dir, name: str, content: str):
    bin_dir.mkdir(parents=True, exist_ok=True)
    path = bin_dir / name
    path.write_text(content)
    path.chmod(0o755)
    return path


def _read_ledger(path):
    return [json.loads(line) for line in path.read_text().splitlines()]
