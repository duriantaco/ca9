from __future__ import annotations

import json
from datetime import date

from click.testing import CliRunner

from ca9.cli import main
from ca9.package_policy import (
    ModePolicy,
    PackageAgePolicy,
    PackagePolicy,
    PolicyException,
    find_policy_exception,
    load_effective_package_policy,
    load_package_policy,
    policy_trust_warnings,
)

UNTRUSTED_FYN_LOCK = """
version = 1

[[package]]
name = "demo"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "badlib" }]

[[package]]
name = "badlib"
version = "1.0.0"
source = { registry = "https://packages.example/simple" }
sdist = { url = "https://packages.example/badlib-1.0.0.tar.gz" }
"""


def test_package_policy_validate_and_explain_cli(tmp_path):
    policy_path = tmp_path / "ca9.toml"
    policy_path.write_text(
        """
[mode]
default = "warn"
offline = "block"

[registries]
allow = ["pypi.org", "registry.npmjs.org"]
custom_requires_approval = true
"""
    )

    runner = CliRunner()
    validate = runner.invoke(main, ["policy", "validate", "--policy", str(policy_path)])
    explain = runner.invoke(
        main,
        ["policy", "explain", "--policy", str(policy_path), "-f", "json"],
    )

    assert validate.exit_code == 0
    assert "Policy valid" in validate.output
    assert explain.exit_code == 0
    data = json.loads(explain.output)
    assert data["mode"]["default"] == "warn"
    assert data["mode"]["offline"] == "block"
    assert data["sources"] == [str(policy_path)]


def test_package_policy_validate_rejects_invalid_mode(tmp_path):
    policy_path = tmp_path / "ca9.toml"
    policy_path.write_text('[mode]\ndefault = "panic"\n')

    runner = CliRunner()
    result = runner.invoke(main, ["policy", "validate", "--policy", str(policy_path)])

    assert result.exit_code == 1
    assert "mode.default" in result.output


def test_package_policy_validate_rejects_unknown_keys(tmp_path):
    policy_path = tmp_path / "ca9.toml"
    policy_path.write_text("[registries]\nallowed = ['pypi.org']\n")

    runner = CliRunner()
    result = runner.invoke(main, ["policy", "validate", "--policy", str(policy_path)])

    assert result.exit_code == 1
    assert "unknown policy key registries.allowed" in result.output


def test_package_policy_loads_scoped_expiring_exception(tmp_path):
    policy_path = tmp_path / "ca9.toml"
    policy_path.write_text(
        """
[[exceptions]]
policy_id = "ca9.package_age"
ecosystem = "pypi"
package = "Example_Package"
version = "1.2.*"
action = "warn"
owner = "platform-security"
reason = "Validated emergency release"
expires = 2099-08-01
"""
    )

    policy = load_package_policy(policy_path)

    assert len(policy.exceptions) == 1
    exception = policy.exceptions[0]
    assert exception.expires == "2099-08-01"
    assert exception.source == str(policy_path)
    assert (
        find_policy_exception(
            policy.exceptions,
            policy_id="ca9.package_age",
            ecosystem="pypi",
            package="example-package",
            version="1.2.4",
            now=date(2099, 8, 1),
        )
        == exception
    )


def test_package_policy_exception_does_not_match_after_expiry():
    exception = PolicyException(
        policy_id="ca9.package_age",
        ecosystem="pypi",
        package="requests",
        owner="security",
        reason="Temporary rollout",
        expires="2026-07-24",
    )

    assert (
        find_policy_exception(
            (exception,),
            policy_id="ca9.package_age",
            ecosystem="pypi",
            package="requests",
            version="2.32.0",
            now=date(2026, 7, 25),
        )
        is None
    )


def test_package_policy_validate_rejects_incomplete_and_malware_exceptions(tmp_path):
    policy_path = tmp_path / "ca9.toml"
    policy_path.write_text(
        """
[[exceptions]]
policy_id = "ca9.malware"
reason = ""
expires = "not-a-date"
"""
    )

    result = CliRunner().invoke(
        main,
        ["policy", "validate", "--policy", str(policy_path)],
    )

    assert result.exit_code == 1
    assert "owner is required" in result.output
    assert "reason must be a non-empty string" in result.output
    assert "expires must be an ISO date" in result.output
    assert "cannot override ca9.malware" in result.output


def test_load_package_policy_accepts_tool_ca9_section(tmp_path):
    policy_path = tmp_path / "pyproject.toml"
    policy_path.write_text(
        """
[tool.ca9.mode]
default = "block"

[tool.ca9.registries]
allow = ["packages.example"]
deny = []
"""
    )

    policy = load_package_policy(policy_path)

    assert policy.mode.default == "block"
    assert policy.registries.allow == ("packages.example",)


def test_package_policy_default_mode_matches_vet_blocking_default(tmp_path):
    policy_path = tmp_path / "ca9.toml"
    policy_path.write_text("[registries]\nallow = ['pypi.org', 'registry.npmjs.org']\n")

    policy = load_package_policy(policy_path)

    assert policy.mode.default == "block"


def test_vet_policy_warn_mode_downgrades_blocking_findings(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "fyn.lock").write_text(UNTRUSTED_FYN_LOCK)
    policy_path = tmp_path / "ca9.toml"
    policy_path.write_text(
        """
[mode]
default = "warn"

[registries]
allow = ["pypi.org", "registry.npmjs.org"]
custom_requires_approval = true
"""
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["vet", "--repo", str(repo), "--policy", str(policy_path), "-f", "json"],
    )

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["summary"]["blocking"] == 0
    assert data["summary"]["warnings"] >= 1
    assert any(decision["action"] == "warn" for decision in data["decisions"])
    assert any(decision["policy_id"] == "ca9.untrusted_registry" for decision in data["decisions"])


def test_vet_discovered_repo_policy_cannot_downgrade_mode(tmp_path):
    # A repo-local ca9.toml is untrusted: its mode downgrade is ignored with a warning,
    # while its narrower registry allow list still applies.
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "fyn.lock").write_text(UNTRUSTED_FYN_LOCK)
    (repo / "ca9.toml").write_text(
        """
[mode]
default = "warn"

[registries]
allow = ["pypi.org", "registry.npmjs.org"]
custom_requires_approval = true
"""
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["vet", "--repo", str(repo), "-f", "json"],
        env={"HOME": str(tmp_path / "home"), "CA9_POLICY": ""},
    )

    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["summary"]["blocking"] >= 1
    assert any(
        "mode.default" in warning and "--policy" in warning and "CA9_POLICY=" in warning
        for warning in data["warnings"]
    )


def test_vet_trusts_repo_policy_passed_via_ca9_policy_env(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "fyn.lock").write_text(UNTRUSTED_FYN_LOCK)
    (repo / "ca9.toml").write_text(
        """
[mode]
default = "warn"

[registries]
allow = ["pypi.org", "registry.npmjs.org"]
custom_requires_approval = true
"""
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["vet", "--repo", str(repo), "-f", "json"],
        env={"HOME": str(tmp_path / "home"), "CA9_POLICY": str(repo / "ca9.toml")},
    )

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["summary"]["blocking"] == 0
    assert any(decision["action"] == "warn" for decision in data["decisions"])
    assert not any("ignored relaxing setting" in warning for warning in data["warnings"])


def test_vet_policy_can_deny_registry_by_host(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "fyn.lock").write_text(UNTRUSTED_FYN_LOCK)
    policy_path = tmp_path / "ca9.toml"
    policy_path.write_text(
        """
[mode]
default = "block"

[registries]
allow = ["pypi.org", "registry.npmjs.org", "packages.example"]
deny = ["packages.example"]
"""
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["vet", "--repo", str(repo), "--policy", str(policy_path), "-f", "json"],
    )

    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["summary"]["blocking"] == 1
    assert any(finding["signal_type"] == "denied_registry" for finding in data["findings"])
    assert any(decision["policy_id"] == "ca9.denied_registry" for decision in data["decisions"])


def test_vet_applies_scoped_exception_with_audit_evidence(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "fyn.lock").write_text(UNTRUSTED_FYN_LOCK)
    policy_path = tmp_path / "ca9.toml"
    policy_path.write_text(
        """
[registries]
allow = ["pypi.org", "registry.npmjs.org"]
custom_requires_approval = true

[[exceptions]]
policy_id = "ca9.untrusted_registry"
ecosystem = "pypi"
package = "BadLib"
action = "warn"
owner = "platform-security"
reason = "Private migration window"
expires = 2099-08-01
"""
    )

    result = CliRunner().invoke(
        main,
        ["vet", "--repo", str(repo), "--policy", str(policy_path), "-f", "json"],
    )

    assert result.exit_code == 0
    data = json.loads(result.output)
    decision = next(
        item for item in data["decisions"] if item["policy_id"] == "ca9.untrusted_registry"
    )
    assert decision["action"] == "warn"
    assert decision["evidence"][0]["kind"] == "policy_exception"
    assert decision["evidence"][0]["metadata"]["owner"] == "platform-security"


RELAXING_REPO_POLICY = """
[mode]
default = "off"
offline = "warn"

[registries]
allow = ["pypi.org", "evil.example"]
deny = []
custom_requires_approval = false

[package_age]
enabled = false
minimum_hours = 1
exclusions = ["internal-*", "evil-*"]

[malware]
enabled = false
fail_closed = false

[install_scripts]
block_when_secrets_present = false

[ci]
strip_secret_env_for_installs = false
block_unpinned_exec_tools = false

[[exceptions]]
policy_id = "ca9.untrusted_registry"
package = "evil"
owner = "attacker"
reason = "trust me"
expires = 2099-01-01
"""

STRICT_USER_POLICY = """
[mode]
default = "block"
offline = "block"

[registries]
allow = ["pypi.org", "registry.npmjs.org", "files.pythonhosted.org"]
deny = ["bad.example"]

[package_age]
enabled = true
minimum_hours = 72
exclusions = ["internal-*"]

[malware]
fail_closed = true
"""


def _policy_home(tmp_path, user_policy: str | None = None):
    home = tmp_path / "home"
    (home / ".config" / "ca9").mkdir(parents=True)
    if user_policy is not None:
        (home / ".config" / "ca9" / "policy.toml").write_text(user_policy)
    return home


def test_discovered_repo_policy_cannot_relax_trusted_policy(tmp_path):
    home = _policy_home(tmp_path, STRICT_USER_POLICY)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "ca9.toml").write_text(RELAXING_REPO_POLICY)

    policy = load_effective_package_policy(cwd=repo, env={}, home=home)

    assert policy.mode.default == "block"
    assert policy.mode.offline == "block"
    assert policy.registries.allow == ("pypi.org",)
    assert policy.registries.deny == ("bad.example",)
    assert policy.registries.custom_requires_approval is True
    assert policy.package_age.enabled is True
    assert policy.package_age.minimum_hours == 72
    assert policy.package_age.exclusions == ("internal-*",)
    assert policy.malware.enabled is True
    assert policy.malware.fail_closed is True
    assert policy.install_scripts.block_when_secrets_present is True
    assert policy.ci.strip_secret_env_for_installs is True
    assert policy.ci.block_unpinned_exec_tools is True
    assert policy.exceptions == ()
    assert policy.tighten_only_sources == (str(repo.resolve() / "ca9.toml"),)
    assert {setting.key for setting in policy.ignored_settings} == {
        "mode.default",
        "mode.offline",
        "registries.allow",
        "registries.deny",
        "registries.custom_requires_approval",
        "package_age.enabled",
        "package_age.minimum_hours",
        "package_age.exclusions",
        "malware.enabled",
        "malware.fail_closed",
        "install_scripts.block_when_secrets_present",
        "ci.strip_secret_env_for_installs",
        "ci.block_unpinned_exec_tools",
        "exceptions",
    }
    warnings = policy_trust_warnings(policy)
    assert all("--policy" in warning and "CA9_POLICY=" in warning for warning in warnings)
    assert any('"evil.example"' in warning for warning in warnings)


def test_discovered_repo_policy_cannot_relax_built_in_defaults(tmp_path):
    home = _policy_home(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "ca9.toml").write_text(RELAXING_REPO_POLICY)

    policy = load_effective_package_policy(cwd=repo, env={}, home=home)

    defaults = PackagePolicy()
    assert policy.mode == defaults.mode
    assert policy.malware == defaults.malware
    assert policy.install_scripts == defaults.install_scripts
    assert policy.ci == defaults.ci
    assert policy.registries.custom_requires_approval is True
    assert "evil.example" not in policy.registries.allow
    assert policy.exceptions == ()
    # Package age checks are off by default, so any repo age settings only tighten.
    assert policy.package_age == PackageAgePolicy(
        enabled=False, minimum_hours=1, exclusions=("internal-*", "evil-*")
    )


def test_discovered_repo_policy_can_tighten_trusted_policy(tmp_path):
    home = _policy_home(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "ca9.toml").write_text(
        """
[mode]
default = "strict"
offline = "block"

[registries]
allow = ["https://pypi.org/simple", "registry.npmjs.org"]
deny = ["packages.example"]

[package_age]
enabled = true
minimum_hours = 24

[malware]
fail_closed = true
"""
    )

    policy = load_effective_package_policy(cwd=repo, env={}, home=home)

    assert policy.ignored_settings == ()
    assert policy.mode == ModePolicy(default="strict", offline="block")
    assert policy.registries.allow == ("https://pypi.org/simple", "registry.npmjs.org")
    assert policy.registries.deny == ("packages.example",)
    assert policy.package_age.enabled is True
    assert policy.package_age.minimum_hours == 24
    assert policy.malware.fail_closed is True


def test_discovered_repo_policy_may_narrow_host_wide_allow_entries(tmp_path):
    home = _policy_home(
        tmp_path, '[registries]\nallow = ["https://pypi.org", "registry.npmjs.org:443"]\n'
    )
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "ca9.toml").write_text(
        '[registries]\nallow = ["https://pypi.org/simple/", "https://registry.npmjs.org/"]\n'
    )

    policy = load_effective_package_policy(cwd=repo, env={}, home=home)

    assert policy.ignored_settings == ()
    assert policy.registries.allow == ("https://pypi.org/simple/", "https://registry.npmjs.org/")


def test_ca9_policy_env_and_explicit_path_fully_trust_repo_policy(tmp_path):
    home = _policy_home(tmp_path, STRICT_USER_POLICY)
    repo = tmp_path / "repo"
    repo.mkdir()
    repo_policy = repo / "ca9.toml"
    repo_policy.write_text(RELAXING_REPO_POLICY)

    via_env = load_effective_package_policy(
        cwd=repo, env={"CA9_POLICY": str(repo_policy)}, home=home
    )
    via_flag = load_package_policy(repo_policy)

    for policy in (via_env, via_flag):
        assert policy.mode.default == "off"
        assert policy.malware.enabled is False
        assert "evil.example" in policy.registries.allow
        assert len(policy.exceptions) == 1
        assert policy.ignored_settings == ()
        assert policy.tighten_only_sources == ()


def test_ca9_policy_env_overrides_user_policy_and_repo_still_only_tightens(tmp_path):
    home = _policy_home(tmp_path, STRICT_USER_POLICY)
    team_policy = tmp_path / "team.toml"
    team_policy.write_text('[mode]\ndefault = "warn"\n')
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "ca9.toml").write_text('[mode]\ndefault = "off"\n[malware]\nenabled = false\n')

    policy = load_effective_package_policy(
        cwd=repo, env={"CA9_POLICY": str(team_policy)}, home=home
    )

    assert policy.mode.default == "warn"
    assert policy.malware.enabled is True
    assert policy.sources == (
        str(home / ".config" / "ca9" / "policy.toml"),
        str(team_policy),
        str(repo.resolve() / "ca9.toml"),
    )
    assert [setting.key for setting in policy.ignored_settings] == [
        "mode.default",
        "malware.enabled",
    ]


def test_policy_explain_reports_ignored_repo_relaxations(tmp_path, monkeypatch):
    home = _policy_home(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "ca9.toml").write_text('[mode]\ndefault = "off"\n[malware]\nenabled = false\n')
    monkeypatch.chdir(repo)

    runner = CliRunner()
    env = {"HOME": str(home), "CA9_POLICY": ""}
    table = runner.invoke(main, ["policy", "explain"], env=env)
    as_json = runner.invoke(main, ["policy", "explain", "-f", "json"], env=env)

    assert table.exit_code == 0
    assert "Mode: default=block" in table.output
    assert "Tighten-only repo policy:" in table.output
    assert "Ignored relaxations: 2" in table.output
    assert 'mode.default = "off"' in table.output
    assert "malware.enabled = false" in table.output
    assert "--policy" in table.output and "CA9_POLICY=" in table.output
    data = json.loads(as_json.stdout)
    assert data["mode"]["default"] == "block"
    assert [item["key"] for item in data["ignored_settings"]] == [
        "mode.default",
        "malware.enabled",
    ]


def test_ca9_run_ignores_repo_policy_that_disables_secret_blocking(tmp_path, monkeypatch):
    home = _policy_home(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "ca9.toml").write_text(
        '[mode]\ndefault = "off"\n'
        "[install_scripts]\nblock_when_secrets_present = false\n"
        "[ci]\nstrip_secret_env_for_installs = false\n"
    )
    monkeypatch.chdir(repo)

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--dry-run",
            "--audit-log",
            str(tmp_path / "audit.jsonl"),
            "-f",
            "json",
            "--",
            "npm",
            "install",
            "left-pad@1.3.0",
        ],
        env={
            "HOME": str(home),
            "CA9_POLICY": "",
            "CA9_CACHE_DIR": str(tmp_path / "cache"),
            "NPM_TOKEN": "npm_secret_value",
        },
    )

    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["action"] == "block"
    assert any(
        decision["policy_id"] == "ca9.install_scripts.secrets" and decision["action"] == "block"
        for decision in data["decisions"]
    )
    assert data["policy_warnings"]
    assert "ignored relaxing setting mode.default" in result.stderr
    assert "install_scripts.block_when_secrets_present" in result.stderr
    assert "npm_secret_value" not in result.output
