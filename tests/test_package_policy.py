from __future__ import annotations

import json

from click.testing import CliRunner

from ca9.cli import main
from ca9.package_policy import load_package_policy

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


def test_vet_discovers_repo_policy_without_explicit_flag(tmp_path):
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
    result = runner.invoke(main, ["vet", "--repo", str(repo), "-f", "json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["summary"]["blocking"] == 0
    assert any(decision["action"] == "warn" for decision in data["decisions"])


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
