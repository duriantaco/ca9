from __future__ import annotations

import json
import os
import signal
import stat
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

import ca9
from ca9.cli import _ChildProcess, main
from ca9.package_feed import update_feed_from_source
from ca9.package_policy import CIPolicy, InstallScriptsPolicy, ModePolicy, PackagePolicy
from ca9.runtime.preflight import (
    LedgerEvent,
    append_ledger_events,
    child_environment,
    detect_secret_env,
    evaluate_runtime_preflight,
    format_preflight,
    redact_command_args,
    redact_sensitive_text,
)

JWT = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJyZXBvOm9yZy9hcHAiLCJhdWQiOiJzdHMifQ."
    "c2lnbmF0dXJlLXZhbHVlLXRoYXQtaXMtbG9uZw"
)
NPM_TOKEN_VALUE = "npm_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

SECRET_ENV = {
    "PGPASSWORD": "pg-secret-value",
    "TWINE_PASSWORD": "twine-secret-value",
    "TWINE_USERNAME": "__token__",
    "DATABASE_URL": "postgres://app:db-secret-value@db.internal:5432/app",
    "SYSTEM_ACCESSTOKEN": "azure-secret-value",
    "CI_JOB_TOKEN": "gitlab-job-secret-value",
    "CI_JOB_JWT": "gitlab-jwt-secret-value",
    "CI_JOB_JWT_V2": "gitlab-jwt2-secret-value",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "oidc-request-secret-value",
    "ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.actions.example/oidc",
    "ACTIONS_RUNTIME_TOKEN": "runtime-secret-value",
    "NODE_AUTH_TOKEN": "node-auth-secret-value",
    "NPM_CONFIG__AUTH": "npm-auth-secret-value",
    "npm_config__authToken": "npm-authtoken-secret-value",
    "npm_config_//registry.npmjs.org/:_authToken": "npm-scoped-secret-value",
    "LDAP_PASSWORD": "ldap-secret-value",
    "SMTP_PASSWD": "smtp-secret-value",
    "GH_PAT": "pat-secret-value",
    "SERVICE_CREDENTIALS": "creds-secret-value",
    "SENTRY_DSN": "https://public@sentry.example/1",
    "DOCKER_AUTH_CONFIG": '{"auths": {"registry": {"auth": "docker-secret-value"}}}',
    "SSH_AUTH_SOCK": "/tmp/ssh-agent.sock",
    "OIDC_ID": JWT,
    "SOME_SETTING": NPM_TOKEN_VALUE,
}
NON_SECRET_ENV = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/home/runner",
    "DATABASE_HOST": "localhost",
    "REPO_URL": "https://github.com/org/app",
    "GIT_URL": "ssh://git@github.com/org/app.git",
    "CI_PROJECT_URL": "https://gitlab.example/org/app",
    "CA9_SHIM_BYPASS": "1",
}


def test_detect_secret_env_covers_ci_and_value_based_credentials():
    detected = set(detect_secret_env({**SECRET_ENV, **NON_SECRET_ENV}))

    assert detected == set(SECRET_ENV)


def test_preflight_output_names_secrets_without_values():
    policy = PackagePolicy(mode=ModePolicy(default="warn"))
    preflight = evaluate_runtime_preflight(
        ["npm", "install", "left-pad@1.3.0"],
        policy,
        env={**SECRET_ENV, **NON_SECRET_ENV},
    )
    text = format_preflight(preflight) + json.dumps(preflight.to_dict())

    assert set(preflight.stripped_secret_names) == set(SECRET_ENV)
    for value in SECRET_ENV.values():
        if value not in {"__token__", "/tmp/ssh-agent.sock", "https://token.actions.example/oidc"}:
            assert value not in text


def test_child_environment_strips_secrets_and_github_file_commands():
    github_files = {
        "GITHUB_ENV": "/runner/_temp/set_env",
        "GITHUB_PATH": "/runner/_temp/add_path",
        "GITHUB_OUTPUT": "/runner/_temp/set_output",
        "GITHUB_STATE": "/runner/_temp/save_state",
        "GITHUB_STEP_SUMMARY": "/runner/_temp/step_summary",
    }
    env = {
        **SECRET_ENV,
        **NON_SECRET_ENV,
        **github_files,
        "PIP_INDEX_URL": "https://__token__:index-secret@pypi.internal/simple",
        "CA9_PYPI_UPSTREAM_INDEX": "https://__token__:upstream-secret@pypi.internal/simple",
    }
    policy = PackagePolicy(mode=ModePolicy(default="warn"))

    preflight = evaluate_runtime_preflight(["pip", "install", "requests==2.31.0"], policy, env=env)
    child_env = child_environment(env, preflight)

    assert set(preflight.stripped_env_names) == set(github_files)
    assert not set(SECRET_ENV) & set(child_env)
    assert not set(github_files) & set(child_env)
    # The index stays selected (no fallback to public PyPI); only its credentials go.
    assert child_env["PIP_INDEX_URL"] == "https://pypi.internal/simple"
    assert "CA9_PYPI_UPSTREAM_INDEX" not in child_env
    assert "CA9_PYPI_UPSTREAM_INDEX" not in preflight.secret_names
    assert child_env["DATABASE_HOST"] == "localhost"
    assert "upstream-secret" not in format_preflight(preflight)


def test_github_file_commands_kept_when_policy_disables_env_stripping():
    policy = PackagePolicy(
        install_scripts=InstallScriptsPolicy(block_when_secrets_present=False),
        ci=CIPolicy(strip_secret_env_for_installs=False),
    )
    env = {"PATH": "/bin", "GITHUB_ENV": "/runner/_temp/set_env"}

    preflight = evaluate_runtime_preflight(["npm", "install", "left-pad@1.3.0"], policy, env=env)

    assert preflight.stripped_env_names == ()
    assert child_environment(env, preflight)["GITHUB_ENV"] == "/runner/_temp/set_env"


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        (f"--//registry.npmjs.org/:_authToken={NPM_TOKEN_VALUE}", NPM_TOKEN_VALUE),
        ("--//npm.internal/:_authToken=plain-secret-value", "plain-secret-value"),
        ("//npm.internal/:_auth=dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ("--_auth=dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ("//npm.internal/:_password=cGFzc3dvcmQ=", "cGFzc3dvcmQ="),
        ("npm_config__password=cGFzc3dvcmQ=", "cGFzc3dvcmQ="),
        ("--otp=123456", "123456"),
        ("https://gitlab.example/api/v4/packages?private_token=glsecret1", "glsecret1"),
        ("https://host/simple/?token=tok-secret", "tok-secret"),
        ("https://host/simple/?a=1&access_token=acc-secret", "acc-secret"),
        ("https://host/pkg.tgz?auth=auth-secret", "auth-secret"),
        ("https://host/pkg.tgz?password=pw-secret", "pw-secret"),
        ("https://host/pkg.tgz?secret=sec-secret", "sec-secret"),
        ("https://host/pkg.tgz?key=key-secret", "key-secret"),
        ("https://acct.blob.core.windows.net/c/p.whl?sv=1&sig=sas-signature", "sas-signature"),
        (
            "https://dl.cloudsmith.io/AbCdEf1234567890Xy/org/repo/python/simple/",
            "AbCdEf1234567890Xy",
        ),
        ("https://npm.example/ghp_abcdefghijklmnopqrstuvwxyz0123456789/pkg", "ghp_abcdefghij"),
        ("postgres://app:db-secret@db.internal/app", "db-secret"),
        (f"Authorization: Bearer {JWT}", JWT),
        (f"token is {JWT}", JWT),
    ],
)
def test_redact_sensitive_text_removes_registry_credentials(text, secret):
    redacted = redact_sensitive_text(text)

    assert secret not in redacted
    assert "[redacted" in redacted


@pytest.mark.parametrize(
    "text",
    [
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "https://files.pythonhosted.org/packages/3b/00/"
        "2344469e2084fb287c2e0b57b72910309874c3245463acd6cf5e3db69324/"
        "requests-2.31.0-py3-none-any.whl",
        "requests==2.31.0",
        "--registry=https://registry.npmjs.org/",
    ],
)
def test_redact_sensitive_text_keeps_ordinary_package_references(text):
    assert redact_sensitive_text(text) == text


def test_redact_command_args_redacts_separate_secret_option_values():
    assert redact_command_args(["npm", "publish", "--otp", "123456", "--tag", "beta"]) == [
        "npm",
        "publish",
        "--otp",
        "[redacted]",
        "--tag",
        "beta",
    ]


def test_ca9_run_redacts_npm_auth_tokens_from_ledger_and_stderr(tmp_path):
    audit_log = tmp_path / "audit.jsonl"
    secret_url = "https://pkgs.example/AbCdEf1234567890Xy/npm/?private_token=qs-secret"

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--policy",
            str(_write_policy(tmp_path)),
            "--audit-log",
            str(audit_log),
            "--dry-run",
            "--",
            "npm",
            "install",
            f"--//registry.npmjs.org/:_authToken={NPM_TOKEN_VALUE}",
            "--_auth=dXNlcjpwYXNz",
            "--registry",
            secret_url,
            "left-pad@1.3.0",
        ],
        env={"CA9_CACHE_DIR": str(tmp_path / "cache"), "HOME": str(tmp_path)},
    )

    ledger = audit_log.read_text()
    for secret in (NPM_TOKEN_VALUE, "dXNlcjpwYXNz", "AbCdEf1234567890Xy", "qs-secret"):
        assert secret not in ledger
        assert secret not in result.output
    assert "command_observed" in ledger


def test_append_ledger_events_creates_private_ledger(tmp_path):
    ledger = tmp_path / "state" / "ca9" / "audit.jsonl"

    append_ledger_events([LedgerEvent("session_started", {}, "s1")], ledger_path=ledger)

    assert stat.S_IMODE(ledger.stat().st_mode) == 0o600
    assert stat.S_IMODE(ledger.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "state").stat().st_mode) == 0o700


def test_append_ledger_events_tightens_existing_world_readable_ledger(tmp_path):
    ledger = tmp_path / "audit.jsonl"
    ledger.write_text("")
    ledger.chmod(0o644)

    append_ledger_events([LedgerEvent("session_started", {}, "s1")], ledger_path=ledger)

    assert stat.S_IMODE(ledger.stat().st_mode) == 0o600
    assert len(ledger.read_text().splitlines()) == 1


def test_ca9_run_continues_and_keeps_child_exit_code_when_ledger_unwritable(tmp_path):
    bin_dir = tmp_path / "bin"
    marker = tmp_path / "ran.txt"
    _write_fake_command(bin_dir, "npm", f"#!/bin/sh\necho ran > {marker}\nexit 7\n")
    not_a_dir = tmp_path / "file"
    not_a_dir.write_text("")

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--policy",
            str(_write_policy(tmp_path)),
            "--audit-log",
            str(not_a_dir / "audit.jsonl"),
            "--",
            "npm",
            "install",
            "left-pad@1.3.0",
        ],
        env={"CA9_CACHE_DIR": str(tmp_path / "cache"), "PATH": str(bin_dir)},
    )

    assert result.exit_code == 7
    assert marker.read_text().strip() == "ran"
    assert result.stderr.count("cannot write audit ledger") == 1


def test_child_process_kills_child_that_ignores_forwarded_signal(tmp_path):
    ready = tmp_path / "ready"
    previous_handler = signal.getsignal(signal.SIGTERM)
    child = _ChildProcess(grace_seconds=0.3)
    started = time.monotonic()
    sender = threading.Thread(target=_signal_self_when_ready, args=(ready, signal.SIGTERM))
    sender.start()

    child.run(
        ["/bin/sh", "-c", f"trap '' TERM; touch {ready}; exec sleep 30"],
        env={"PATH": os.defpath},
    )
    sender.join()

    assert child.received == [signal.SIGTERM]
    assert child.signal_number == signal.SIGKILL
    assert child.exit_code == 128 + signal.SIGKILL
    assert time.monotonic() - started < 10
    assert signal.getsignal(signal.SIGTERM) == previous_handler


def test_ca9_run_forwards_sigterm_cleans_gateway_and_exits_128_plus_signal(tmp_path):
    cache_root = tmp_path / "cache"
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_root / "feed")
    bin_dir = tmp_path / "bin"
    started = tmp_path / "started"
    got_term = tmp_path / "got-term"
    audit_log = tmp_path / "audit.jsonl"
    _write_fake_command(
        bin_dir,
        "npm",
        "#!/bin/sh\n"
        f'printf "%s" "$NPM_CONFIG_USERCONFIG" > {started}\n'
        f"trap 'echo TERM > {got_term}; trap - TERM; kill -TERM $$' TERM\n"
        "while :; do sleep 0.05; done\n",
    )
    src_dir = Path(ca9.__file__).resolve().parents[1]
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from ca9.cli import main; main()",
            "run",
            "--policy",
            str(_write_policy(tmp_path)),
            "--audit-log",
            str(audit_log),
            "--",
            "npm",
            "install",
            "left-pad@1.3.0",
        ],
        cwd=tmp_path,
        env={
            "PATH": f"{bin_dir}:/usr/bin:/bin",
            "PYTHONPATH": str(src_dir),
            "HOME": str(tmp_path),
            "CA9_CACHE_DIR": str(cache_root),
        },
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_for(started)
        user_config = Path(started.read_text())
        assert user_config.is_file()
        process.send_signal(signal.SIGTERM)
        _, stderr = process.communicate(timeout=20)
    finally:
        if process.poll() is None:
            process.kill()

    assert process.returncode == 128 + signal.SIGTERM, stderr
    assert got_term.read_text().strip() == "TERM"
    assert not user_config.parent.exists()
    events = [json.loads(line) for line in audit_log.read_text().splitlines()]
    kinds = [event["event_kind"] for event in events]
    assert "gateway_used" in kinds
    assert kinds[-2:] == ["child_process_exited", "session_ended"]
    assert events[-2]["payload"] == {
        "exit_code": 128 + signal.SIGTERM,
        "signal": signal.SIGTERM,
        "forwarded_signals": ["SIGTERM"],
    }
    assert events[-1]["payload"]["child_exit_code"] == 128 + signal.SIGTERM


def _signal_self_when_ready(ready: Path, signum: int) -> None:
    _wait_for(ready)
    os.kill(os.getpid(), signum)


def _wait_for(path: Path, timeout: float = 15) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for {path}")
        time.sleep(0.02)


def _write_policy(tmp_path: Path) -> Path:
    policy_path = tmp_path / "policy.toml"
    policy_path.write_text(
        "[install_scripts]\nblock_when_secrets_present = false\n"
        "[ci]\nstrip_secret_env_for_installs = false\n"
    )
    return policy_path


def _write_feed_bundle(tmp_path: Path) -> Path:
    expires = (datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=1)).isoformat()
    bundle = {
        "schema": "ca9.feed.v1",
        "created_at": "2026-06-26T00:00:00Z",
        "expires_at": expires,
        "datasets": {
            "pypi-malware": {"packages": []},
            "npm-malware": {"packages": []},
            "pypi-releases": {"packages": {}},
            "npm-releases": {"packages": {"left-pad": {"1.3.0": "2016-01-01T00:00:00Z"}}},
        },
    }
    path = tmp_path / "feed.json"
    path.write_text(json.dumps(bundle))
    return path


def _write_fake_command(bin_dir: Path, name: str, content: str) -> Path:
    bin_dir.mkdir(parents=True, exist_ok=True)
    path = bin_dir / name
    path.write_text(content)
    path.chmod(0o755)
    return path
