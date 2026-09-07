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
    PolicyException,
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


def test_parse_npm_boolean_options_cannot_hide_package_specs():
    for option in (
        "--ignore-scripts=left-pad@1.3.0",
        "--audit=left-pad@1.3.0",
        "--dry-run=left-pad@1.3.0",
        "--global=left-pad@1.3.0",
    ):
        preflight = evaluate_runtime_preflight(
            ("npm", "install", "safe-lib@1.0.0", option),
            PackagePolicy(malware=MalwarePolicy(enabled=False)),
            env={},
        )

        assert preflight.action == "block"
        assert preflight.decisions[0].policy_id == "ca9.runtime.unsupported_command"
        assert "only accepts true or false" in preflight.decisions[0].reason


def test_parse_npm_ignore_scripts_boolean_value_controls_script_posture():
    ignored = parse_install_command(("npm", "install", "left-pad@1.3.0", "--ignore-scripts=true"))
    enabled = parse_install_command(("npm", "install", "left-pad@1.3.0", "--ignore-scripts=false"))

    assert ignored.install_scripts_possible is False
    assert enabled.install_scripts_possible is True


def test_runtime_preflight_blocks_scoped_registry_in_project_npmrc(tmp_path):
    (tmp_path / ".npmrc").write_text(
        "# Project npm settings\n"
        "registry=https://registry.npmjs.org/\n"
        "\n"
        "@acme:registry = https://packages.example/\n"
    )

    preflight = evaluate_runtime_preflight(
        ("npm", "install", "@acme/widget@1.0.0"),
        PackagePolicy(),
        env={},
        cwd=tmp_path,
    )

    assert preflight.action == "block"
    decision = next(
        decision
        for decision in preflight.decisions
        if decision.policy_id == "ca9.runtime.unsupported_source"
    )
    assert ".npmrc:4:@acme:registry" in decision.reason
    assert decision.evidence == {
        "ecosystem": "npm",
        "kind": "npm-config-file",
        "url": "https://packages.example/",
        "option": ".npmrc:4:@acme:registry",
    }


def test_runtime_preflight_ignores_comments_and_unscoped_registry_in_project_npmrc(tmp_path):
    (tmp_path / ".npmrc").write_text(
        "# @ignored:registry=https://packages.example/\n"
        "; @also-ignored:registry=https://packages.example/\n"
        "registry=https://registry.npmjs.org/\n"
    )

    preflight = evaluate_runtime_preflight(
        ("npm", "install", "left-pad@1.3.0"),
        PackagePolicy(malware=MalwarePolicy(enabled=False)),
        env={},
        cwd=tmp_path,
    )

    assert preflight.action == "pass"
    assert not preflight.command.registry_sources


def test_runtime_preflight_blocks_npm_ini_variants_of_scoped_registry(tmp_path):
    forms = (
        '"@acme:registry"=https://packages.example/\n',
        "'@acme:registry'=https://packages.example/\n",
        '"@acme\\u003aregistry"=https://packages.example/\n',
        "@acme:registry[]=https://packages.example/\n",
        "@acme:registry#comment=https://packages.example/\n",
        "@acme:registry;comment=https://packages.example/\n",
        "${NPM_CONFIG_KEY}=https://packages.example/\n",
        " \ufeff@acme:registry=https://packages.example/\n",
        "\n\ufeff\ufeff@acme:registry=https://packages.example/\n",
        "@acme:registry\ufeff=https://packages.example/\n",
    )

    for content in forms:
        (tmp_path / ".npmrc").write_text(content)
        preflight = evaluate_runtime_preflight(
            ("npm", "install", "@acme/widget@1.0.0"),
            PackagePolicy(),
            env={"NPM_CONFIG_KEY": "@acme:registry"},
            cwd=tmp_path,
        )

        assert preflight.action == "block", content
        assert preflight.decisions[0].policy_id == "ca9.runtime.unsupported_source"


def test_runtime_preflight_does_not_apply_project_npmrc_to_global_install(tmp_path):
    (tmp_path / ".npmrc").write_text("@acme:registry=https://packages.example/\n")

    preflight = evaluate_runtime_preflight(
        ("npm", "install", "--global", "@acme/widget@1.0.0"),
        PackagePolicy(malware=MalwarePolicy(enabled=False)),
        env={},
        cwd=tmp_path,
    )

    assert preflight.action == "pass"
    assert not preflight.command.registry_sources


def test_runtime_preflight_blocks_scoped_registry_from_ancestor_project_root(tmp_path):
    project_root = tmp_path / "project"
    nested_cwd = project_root / "src" / "tools"
    nested_cwd.mkdir(parents=True)
    (project_root / "package.json").write_text('{"name": "project"}\n')
    (project_root / ".npmrc").write_text("@acme:registry=https://packages.example/\n")

    preflight = evaluate_runtime_preflight(
        ("npm", "install", "@acme/widget@1.0.0"),
        PackagePolicy(),
        env={},
        cwd=nested_cwd,
    )

    assert preflight.action == "block"
    assert preflight.decisions[0].policy_id == "ca9.runtime.unsupported_source"
    assert "../../.npmrc:1:@acme:registry" in preflight.decisions[0].reason


def test_runtime_preflight_blocks_scoped_registry_from_workspace_root(tmp_path):
    workspace = tmp_path / "workspace"
    package_root = workspace / "packages" / "api"
    package_root.mkdir(parents=True)
    (workspace / "package.json").write_text('{"name": "workspace", "workspaces": ["packages/*"]}\n')
    (workspace / ".npmrc").write_text("@acme:registry=https://packages.example/\n")
    (package_root / "package.json").write_text('{"name": "api"}\n')

    preflight = evaluate_runtime_preflight(
        ("npm", "install", "@acme/widget@1.0.0"),
        PackagePolicy(),
        env={},
        cwd=package_root,
    )

    assert preflight.action == "block"
    assert preflight.decisions[0].policy_id == "ca9.runtime.unsupported_source"
    assert "../../.npmrc:1:@acme:registry" in preflight.decisions[0].reason


def test_runtime_preflight_blocks_npm_install_prefix_project_switch(tmp_path):
    for prefix_args in (("--prefix", "other-project"), ("--prefix=other-project",)):
        preflight = evaluate_runtime_preflight(
            ("npm", "install", "left-pad@1.3.0", *prefix_args),
            PackagePolicy(),
            env={},
            cwd=tmp_path,
        )

        assert preflight.action == "block"
        assert preflight.decisions[0].policy_id == "ca9.runtime.unsupported_command"
        assert "different project config or lockfile" in preflight.decisions[0].reason


def test_parse_npm_ci_loads_direct_and_transitive_lock_packages(tmp_path):
    _write_package_lock(tmp_path)

    command = parse_install_command(("npm", "ci"), cwd=tmp_path)

    assert command.family == "npm"
    assert [request.key for request in command.package_requests] == [
        "npm:left-pad@1.3.0",
        "npm:nested-lib@2.0.0",
    ]
    assert command.registry_sources[0].url == "https://registry.npmjs.org"


def test_parse_npm_clean_install_aliases_use_the_same_lock_preflight(tmp_path):
    _write_package_lock(tmp_path)

    for subcommand in ("clean-install", "ic", "install-clean", "isntall-clean"):
        command = parse_install_command(("npm", subcommand), cwd=tmp_path)

        assert [request.key for request in command.package_requests] == [
            "npm:left-pad@1.3.0",
            "npm:nested-lib@2.0.0",
        ]


def test_npm_ci_prefers_configured_registry_over_lockfile_source(tmp_path):
    _write_package_lock(tmp_path)

    preflight = evaluate_runtime_preflight(
        ("npm", "ci"),
        PackagePolicy(
            malware=MalwarePolicy(enabled=False),
            registries=RegistriesPolicy(
                allow=("registry.npmjs.org", "packages.example"),
            ),
        ),
        env={"NPM_CONFIG_REGISTRY": "https://packages.example"},
        cwd=tmp_path,
    )

    assert primary_registry_url(preflight.command) == "https://packages.example"


def test_runtime_preflight_blocks_npm_ci_without_lockfile(tmp_path):
    preflight = evaluate_runtime_preflight(
        ("npm", "ci"),
        PackagePolicy(),
        env={},
        cwd=tmp_path,
    )

    assert preflight.action == "block"
    assert preflight.decisions[0].policy_id == "ca9.runtime.lockfile_unavailable"
    assert "requires package-lock.json" in preflight.decisions[0].reason


def test_runtime_preflight_blocks_unreadable_npm_lockfile(tmp_path):
    (tmp_path / "package-lock.json").write_text("{not-json")

    preflight = evaluate_runtime_preflight(
        ("npm", "ci"),
        PackagePolicy(),
        env={},
        cwd=tmp_path,
    )

    assert preflight.action == "block"
    assert preflight.decisions[0].policy_id == "ca9.runtime.lockfile_unavailable"
    assert "cannot parse package-lock.json" in preflight.decisions[0].reason


def test_runtime_preflight_blocks_non_utf8_npm_lockfile(tmp_path):
    (tmp_path / "package-lock.json").write_bytes(b"\xff\xfe\x00")

    preflight = evaluate_runtime_preflight(
        ("npm", "ci"),
        PackagePolicy(),
        env={},
        cwd=tmp_path,
    )

    assert preflight.action == "block"
    assert preflight.decisions[0].policy_id == "ca9.runtime.lockfile_unavailable"
    assert "cannot parse package-lock.json" in preflight.decisions[0].reason


def test_runtime_preflight_blocks_missing_or_future_lockfile_version(tmp_path):
    for lockfile_version in (None, 4):
        lock = {"packages": {}}
        if lockfile_version is not None:
            lock["lockfileVersion"] = lockfile_version
        (tmp_path / "package-lock.json").write_text(json.dumps(lock))

        preflight = evaluate_runtime_preflight(
            ("npm", "ci"),
            PackagePolicy(),
            env={},
            cwd=tmp_path,
        )

        assert preflight.action == "block"
        assert preflight.decisions[0].policy_id == "ca9.runtime.lockfile_unavailable"
        assert "lockfileVersion" in preflight.decisions[0].reason


def test_runtime_preflight_blocks_missing_or_non_object_packages_table(tmp_path):
    for lock in (
        {"lockfileVersion": 3},
        {"lockfileVersion": 3, "packages": []},
    ):
        (tmp_path / "package-lock.json").write_text(json.dumps(lock))

        preflight = evaluate_runtime_preflight(
            ("npm", "ci"),
            PackagePolicy(),
            env={},
            cwd=tmp_path,
        )

        assert preflight.action == "block"
        assert preflight.decisions[0].policy_id == "ca9.runtime.lockfile_unavailable"
        assert "packages" in preflight.decisions[0].reason


def test_runtime_preflight_blocks_external_lock_entry_without_version(tmp_path):
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"left-pad": "1.3.0"}},
            "node_modules/left-pad": {
                "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
            },
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))

    preflight = evaluate_runtime_preflight(
        ("npm", "ci"),
        PackagePolicy(),
        env={},
        cwd=tmp_path,
    )

    assert preflight.action == "block"
    assert preflight.decisions[0].policy_id == "ca9.runtime.lockfile_unavailable"
    assert "missing a name or exact version" in preflight.decisions[0].reason


def test_runtime_preflight_blocks_root_dependency_missing_from_lock_table(tmp_path):
    lock = {
        "lockfileVersion": 3,
        "packages": {"": {"dependencies": {"left-pad": "1.3.0"}}},
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))

    preflight = evaluate_runtime_preflight(
        ("npm", "ci"),
        PackagePolicy(),
        env={},
        cwd=tmp_path,
    )

    assert preflight.action == "block"
    assert "has no locked package entry" in preflight.decisions[0].reason


def test_runtime_preflight_blocks_malformed_or_unsafe_lock_entries(tmp_path):
    invalid_entries = (
        {"node_modules/left-pad": "not-an-object"},
        {
            "../node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            }
        },
    )

    for entries in invalid_entries:
        lock = {"lockfileVersion": 3, "packages": {"": {}, **entries}}
        (tmp_path / "package-lock.json").write_text(json.dumps(lock))

        preflight = evaluate_runtime_preflight(
            ("npm", "ci"),
            PackagePolicy(),
            env={},
            cwd=tmp_path,
        )

        assert preflight.action == "block"
        assert preflight.decisions[0].policy_id == "ca9.runtime.lockfile_unavailable"


def test_runtime_preflight_blocks_unsupported_or_malformed_locked_sources(tmp_path):
    for resolved in ("file:../left-pad", "git+https://example.test/left-pad.git", "https:///x"):
        lock = {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"left-pad": "1.3.0"}},
                "node_modules/left-pad": {"version": "1.3.0", "resolved": resolved},
            },
        }
        (tmp_path / "package-lock.json").write_text(json.dumps(lock))

        preflight = evaluate_runtime_preflight(
            ("npm", "ci"),
            PackagePolicy(),
            env={},
            cwd=tmp_path,
        )

        assert preflight.action == "block"
        assert preflight.decisions[0].policy_id == "ca9.runtime.lockfile_unavailable"
        assert "unsupported source" in preflight.decisions[0].reason


def test_runtime_preflight_blocks_workspace_link_outside_repository(tmp_path):
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"workspace-tool": "workspace:*"}},
            "node_modules/workspace-tool": {"resolved": "../workspace-tool", "link": True},
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))

    preflight = evaluate_runtime_preflight(
        ("npm", "ci"),
        PackagePolicy(),
        env={},
        cwd=tmp_path,
    )

    assert preflight.action == "block"
    assert preflight.decisions[0].policy_id == "ca9.runtime.lockfile_unavailable"
    assert "unsafe target" in preflight.decisions[0].reason


def test_runtime_preflight_blocks_zero_argument_npm_install_even_with_lock(tmp_path):
    _write_package_lock(tmp_path)

    for subcommand in ("install", "i"):
        preflight = evaluate_runtime_preflight(
            ("npm", subcommand),
            PackagePolicy(),
            env={},
            cwd=tmp_path,
        )

        assert preflight.action == "block"
        assert preflight.decisions[0].policy_id == "ca9.runtime.unsupported_command"
        assert "did not include a direct package spec" in preflight.decisions[0].reason


def test_runtime_preflight_blocks_npm_ci_prefix_lockfile_switch(tmp_path):
    _write_package_lock(tmp_path)

    for prefix_args in (("--prefix", "other-project"), ("--prefix=other-project",)):
        preflight = evaluate_runtime_preflight(
            ("npm", "ci", *prefix_args),
            PackagePolicy(),
            env={},
            cwd=tmp_path,
        )

        assert preflight.action == "block"
        assert preflight.decisions[0].policy_id == "ca9.runtime.unsupported_command"
        assert "different project config or lockfile" in preflight.decisions[0].reason


def test_parse_npm_ci_preserves_workspace_links_without_treating_them_as_registry_packages(
    tmp_path,
):
    lock = {
        "name": "workspace-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "workspace-app",
                "version": "1.0.0",
                "dependencies": {"workspace-tool": "workspace:*"},
            },
            "node_modules/workspace-tool": {
                "resolved": "packages/workspace-tool",
                "link": True,
            },
            "packages/workspace-tool": {
                "name": "workspace-tool",
                "version": "2.0.0",
                "dependencies": {"left-pad": "1.3.0"},
            },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            },
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))

    command = parse_install_command(("npm", "ci"), cwd=tmp_path)

    assert [request.key for request in command.package_requests] == ["npm:left-pad@1.3.0"]


def test_parse_npm_ci_allows_valid_empty_lock(tmp_path):
    lock = {
        "name": "empty-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {"": {"name": "empty-app", "version": "1.0.0"}},
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))

    command = parse_install_command(("npm", "ci"), cwd=tmp_path)

    assert command.package_requests == ()


def test_parse_pip_install_direct_specs():
    command = parse_install_command(("python", "-m", "pip", "install", "Requests==2.31.0"))

    assert command.family == "pip"
    assert command.package_requests[0].name == "requests"
    assert command.package_requests[0].exact_version == "2.31.0"


def test_parse_pip_requirement_files_applies_nested_constraints_and_hashes(tmp_path):
    extras = tmp_path / "requirements"
    extras.mkdir()
    (tmp_path / "requirements.txt").write_text(
        "Requests>=2\n"
        "-r requirements/extras.txt\n"
        "-c constraints.txt\n"
        "urllib3==2.2.2 \\\n"
        "  --hash=sha256:" + ("a" * 64) + "\n"
    )
    (extras / "extras.txt").write_text("httpx\n")
    (tmp_path / "constraints.txt").write_text(
        "requests==2.31.0\nhttpx==0.27.2\nconstraint-only==1.0.0\n"
    )

    command = parse_install_command(
        ("python", "-m", "pip", "install", "-r", "requirements.txt"),
        cwd=tmp_path,
    )

    requests = {request.name: request for request in command.package_requests}
    assert set(requests) == {"requests", "httpx", "urllib3"}
    assert requests["requests"].exact_version == "2.31.0"
    assert requests["requests"].source_path == "requirements.txt"
    assert requests["httpx"].exact_version == "0.27.2"
    assert requests["httpx"].source_path == "requirements/extras.txt"
    assert requests["urllib3"].hashes == (f"sha256:{'a' * 64}",)
    assert not command.registry_sources


def test_parse_pip_requirement_file_rejects_index_url(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "--index-url=https://pypi.org/simple\nrequests==2.31.0\n"
    )

    cache_root = tmp_path / "cache"
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_root / "feed")
    preflight = evaluate_runtime_preflight(
        ("pip", "install", "-r", "requirements.txt"),
        PackagePolicy(),
        env={},
        feed_cache_dir=cache_root / "feed",
        cwd=tmp_path,
    )

    assert preflight.action == "block"
    assert preflight.decisions[0].policy_id == "ca9.runtime.requirements_unavailable"
    assert "requirements.txt:1" in preflight.decisions[0].reason
    assert "--index-url" in preflight.decisions[0].reason


def test_parse_pip_nested_constraint_file_rejects_short_index_url(tmp_path):
    constraints = tmp_path / "constraints"
    constraints.mkdir()
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n-c constraints/base.txt\n")
    (constraints / "base.txt").write_text(
        "# The nested constraint must not be able to replace the gateway.\n"
        "-i https://pypi.org/simple\n"
        "requests==2.31.0\n"
    )

    cache_root = tmp_path / "cache"
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_root / "feed")
    preflight = evaluate_runtime_preflight(
        ("pip", "install", "-r", "requirements.txt"),
        PackagePolicy(),
        env={},
        feed_cache_dir=cache_root / "feed",
        cwd=tmp_path,
    )

    assert preflight.action == "block"
    assert preflight.decisions[0].policy_id == "ca9.runtime.requirements_unavailable"
    assert "constraints/base.txt:2" in preflight.decisions[0].reason
    assert "-i" in preflight.decisions[0].reason


def test_parse_pip_requirement_file_allows_index_when_gateway_is_disabled(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "--index-url=https://pypi.org/simple\nrequests==2.31.0\n"
    )

    preflight = evaluate_runtime_preflight(
        ("pip", "install", "-r", "requirements.txt"),
        PackagePolicy(malware=MalwarePolicy(enabled=False)),
        env={},
        cwd=tmp_path,
    )

    assert preflight.action == "pass"
    assert preflight.command.registry_sources[0].kind == "pypi-requirement-index"


def test_parse_pip_requirement_file_rejects_include_cycle(tmp_path):
    (tmp_path / "requirements.txt").write_text("-r nested.txt\n")
    (tmp_path / "nested.txt").write_text("-r requirements.txt\n")

    preflight = evaluate_runtime_preflight(
        ("pip", "install", "-r", "requirements.txt"),
        PackagePolicy(),
        env={},
        cwd=tmp_path,
    )

    assert preflight.action == "block"
    assert preflight.decisions[0].policy_id == "ca9.runtime.requirements_unavailable"
    assert "cycle" in preflight.decisions[0].reason


def test_parse_pip_requirement_file_rejects_repository_escape(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("-r ../outside.txt\n")
    (tmp_path / "outside.txt").write_text("requests==2.31.0\n")

    preflight = evaluate_runtime_preflight(
        ("pip", "install", "-r", "requirements.txt"),
        PackagePolicy(),
        env={},
        cwd=repo,
    )

    assert preflight.action == "block"
    assert preflight.decisions[0].policy_id == "ca9.runtime.requirements_unavailable"
    assert "escapes the repository" in preflight.decisions[0].reason


def test_parse_pip_requirement_file_rejects_unsupported_source_option(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "--extra-index-url https://packages.example/simple\nrequests==2.31.0\n"
    )

    preflight = evaluate_runtime_preflight(
        ("pip", "install", "-r", "requirements.txt"),
        PackagePolicy(),
        env={},
        cwd=tmp_path,
    )

    assert preflight.action == "block"
    assert preflight.decisions[0].policy_id == "ca9.runtime.requirements_unavailable"
    assert "--extra-index-url" in preflight.decisions[0].reason


def test_parse_pip_rejects_argument_terminator_that_could_bypass_gateway():
    preflight = evaluate_runtime_preflight(
        ("pip", "install", "requests==2.31.0", "--"),
        PackagePolicy(),
        env={},
    )

    assert preflight.action == "block"
    assert preflight.decisions[0].policy_id == "ca9.runtime.unsupported_command"
    assert "argument terminator" in preflight.decisions[0].reason


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
    assert gateway_child_command(command, registry_url="http://127.0.0.1:1234/simple") == (
        "pip",
        "install",
        "requests==2.31.0",
        "--index-url",
        "http://127.0.0.1:1234/simple",
    )


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


def test_runtime_preflight_blocks_untrusted_ca9_npm_gateway_upstream_env():
    preflight = evaluate_runtime_preflight(
        ("npm", "install", "left-pad@1.3.0"),
        PackagePolicy(malware=MalwarePolicy(enabled=False)),
        env={"CA9_NPM_UPSTREAM_REGISTRY": "https://packages.example"},
    )

    assert preflight.action == "block"
    decision = next(
        decision
        for decision in preflight.decisions
        if decision.policy_id == "ca9.untrusted_registry"
    )
    assert decision.evidence == {
        "ecosystem": "npm",
        "kind": "npm-gateway-upstream",
        "url": "https://packages.example",
        "option": "env:CA9_NPM_UPSTREAM_REGISTRY",
    }


def test_runtime_preflight_blocks_denied_ca9_pypi_gateway_upstream_env():
    preflight = evaluate_runtime_preflight(
        ("pip", "install", "requests==2.31.0"),
        PackagePolicy(
            registries=RegistriesPolicy(deny=("pypi.org",)),
            malware=MalwarePolicy(enabled=False),
        ),
        env={"CA9_PYPI_UPSTREAM_INDEX": "https://pypi.org/simple"},
    )

    assert preflight.action == "block"
    decision = next(
        decision for decision in preflight.decisions if decision.policy_id == "ca9.denied_registry"
    )
    assert decision.evidence == {
        "ecosystem": "pypi",
        "kind": "pypi-gateway-upstream",
        "url": "https://pypi.org/simple",
        "option": "env:CA9_PYPI_UPSTREAM_INDEX",
    }


def test_runtime_preflight_allows_trusted_ca9_gateway_upstream_env():
    preflight = evaluate_runtime_preflight(
        ("pip", "install", "requests==2.31.0"),
        PackagePolicy(malware=MalwarePolicy(enabled=False)),
        env={"CA9_PYPI_UPSTREAM_INDEX": "https://pypi.org/simple"},
    )

    assert preflight.action == "pass"
    assert preflight.command.registry_sources[-1].kind == "pypi-gateway-upstream"
    assert not preflight.decisions


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


def test_runtime_preflight_blocks_implicit_pip_requirement_env():
    for name in (
        "PIP_REQUIREMENT",
        "PIP_CONSTRAINT",
        "PIP_BUILD_CONSTRAINT",
        "PIP_REQUIREMENTS_FROM_SCRIPT",
        "PIP_EDITABLE",
        "PIP_GROUP",
    ):
        preflight = evaluate_runtime_preflight(
            ("pip", "install", "requests==2.31.0"),
            PackagePolicy(malware=MalwarePolicy(enabled=False)),
            env={name: "requirements.txt"},
        )

        assert preflight.action == "block"
        decision = next(
            decision
            for decision in preflight.decisions
            if decision.policy_id == "ca9.runtime.unsupported_source"
        )
        assert decision.evidence["kind"] == "pypi-requirement-env"
        assert decision.evidence["option"] == f"env:{name}"


def test_runtime_preflight_checks_pip_index_alias_env():
    preflight = evaluate_runtime_preflight(
        ("pip", "install", "requests==2.31.0"),
        PackagePolicy(malware=MalwarePolicy(enabled=False)),
        env={"PIP_PYPI_URL": "https://packages.example/simple"},
    )

    assert preflight.action == "block"
    decision = next(
        decision
        for decision in preflight.decisions
        if decision.policy_id == "ca9.untrusted_registry"
    )
    assert decision.evidence["option"] == "env:PIP_PYPI_URL"


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


def test_runtime_preflight_checks_npm_ci_lock_packages_against_malware_feed(tmp_path):
    cache_root = tmp_path / "cache"
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_package_lock(repo)
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_root / "feed")

    preflight = evaluate_runtime_preflight(
        ("npm", "ci"),
        PackagePolicy(),
        env={},
        feed_cache_dir=cache_root / "feed",
        cwd=repo,
    )

    assert preflight.action == "block"
    malware = next(
        decision for decision in preflight.decisions if decision.policy_id == "ca9.malware"
    )
    assert malware.package == "left-pad"
    assert malware.version == "1.3.0"


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


def test_runtime_preflight_applies_package_age_exception_with_evidence(tmp_path):
    cache_root = tmp_path / "cache"
    update_feed_from_source(
        _write_feed_bundle(
            tmp_path,
            pypi_releases={"packages": {"requests": {"2.31.0": "2026-06-26T11:00:00+00:00"}}},
        ),
        cache_dir=cache_root / "feed",
    )
    policy = PackagePolicy(
        package_age=PackageAgePolicy(enabled=True, minimum_hours=48),
        exceptions=(
            PolicyException(
                policy_id="ca9.package_age",
                ecosystem="pypi",
                package="Requests",
                version="2.31.*",
                action="warn",
                owner="platform-security",
                reason="Emergency compatibility release",
                expires="2026-06-27",
            ),
        ),
    )

    preflight = evaluate_runtime_preflight(
        ("pip", "install", "requests==2.31.0"),
        policy,
        env={},
        feed_cache_dir=cache_root / "feed",
        now=datetime(2026, 6, 26, 12, 0, tzinfo=timezone.utc),
    )

    decision = next(item for item in preflight.decisions if item.policy_id == "ca9.package_age")
    assert preflight.action == "warn"
    assert decision.action == "warn"
    assert decision.evidence["policy_exception"]["owner"] == "platform-security"
    assert decision.evidence["policy_exception"]["original_action"] == "block"


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


def test_runtime_preflight_blocks_missing_requirement_file_install(tmp_path):
    preflight = evaluate_runtime_preflight(
        ("pip", "install", "-r", "requirements.txt"),
        PackagePolicy(),
        env={},
        cwd=tmp_path,
    )

    assert preflight.action == "block"
    assert preflight.decisions[0].policy_id == "ca9.runtime.requirements_unavailable"
    assert "does not exist" in preflight.decisions[0].reason


def test_runtime_preflight_blocks_malware_pinned_in_requirement_file(tmp_path):
    cache_root = tmp_path / "cache"
    (tmp_path / "requirements.txt").write_text("Bad_Lib==1.0.0\n")
    update_feed_from_source(
        _write_feed_bundle(
            tmp_path,
            pypi_malware=[
                {
                    "name": "bad-lib",
                    "version": "1.0.0",
                    "id": "MAL-PYPI-1",
                    "summary": "known malicious PyPI test package",
                }
            ],
        ),
        cache_dir=cache_root / "feed",
    )

    preflight = evaluate_runtime_preflight(
        ("pip", "install", "-r", "requirements.txt"),
        PackagePolicy(),
        env={},
        feed_cache_dir=cache_root / "feed",
        cwd=tmp_path,
    )

    assert preflight.action == "block"
    assert any(
        decision.policy_id == "ca9.malware"
        and decision.package == "bad-lib"
        and decision.version == "1.0.0"
        for decision in preflight.decisions
    )


def test_runtime_preflight_never_applies_malware_exception(tmp_path):
    cache_root = tmp_path / "cache"
    update_feed_from_source(
        _write_feed_bundle(
            tmp_path,
            pypi_malware=[
                {
                    "name": "bad-lib",
                    "version": "1.0.0",
                    "id": "MAL-PYPI-1",
                    "summary": "known malicious PyPI test package",
                }
            ],
        ),
        cache_dir=cache_root / "feed",
    )
    policy = PackagePolicy(
        exceptions=(
            PolicyException(
                policy_id="ca9.malware",
                package="bad-lib",
                action="pass",
                owner="nobody",
                reason="Must not apply",
                expires="2099-01-01",
            ),
        )
    )

    preflight = evaluate_runtime_preflight(
        ("pip", "install", "bad-lib==1.0.0"),
        policy,
        env={},
        feed_cache_dir=cache_root / "feed",
        cwd=tmp_path,
    )

    decision = next(item for item in preflight.decisions if item.policy_id == "ca9.malware")
    assert preflight.action == "block"
    assert decision.action == "block"
    assert not decision.evidence.get("policy_exception")


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


def test_ca9_run_npm_ci_blocks_locked_malware_before_child_executes(tmp_path, monkeypatch):
    cache_root = tmp_path / "cache"
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_package_lock(repo)
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_root / "feed")
    bin_dir = tmp_path / "bin"
    marker = tmp_path / "ran.txt"
    _write_fake_command(bin_dir, "npm", f"#!/bin/sh\necho ran > {marker}\nexit 0\n")
    monkeypatch.chdir(repo)

    result = CliRunner().invoke(
        main,
        ["run", "-f", "json", "--", "npm", "ci"],
        env={"CA9_CACHE_DIR": str(cache_root), "PATH": str(bin_dir)},
    )

    assert result.exit_code == 1
    data = json.loads(result.output)
    assert any(
        decision["policy_id"] == "ca9.malware"
        and decision["package"] == "left-pad"
        and decision["version"] == "1.3.0"
        for decision in data["decisions"]
    )
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
    pypi_malware: list[dict] | None = None,
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
            "pypi-malware": {"packages": pypi_malware or []},
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


def _write_package_lock(repo):
    lock = {
        "name": "demo-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "demo-app",
                "version": "1.0.0",
                "dependencies": {"left-pad": "1.3.0"},
            },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                "integrity": "sha512-test",
                "dependencies": {"nested-lib": "2.0.0"},
            },
            "node_modules/nested-lib": {
                "version": "2.0.0",
                "resolved": "https://registry.npmjs.org/nested-lib/-/nested-lib-2.0.0.tgz",
                "integrity": "sha512-test",
            },
        },
    }
    path = repo / "package-lock.json"
    path.write_text(json.dumps(lock))
    return path


def _write_fake_command(bin_dir, name: str, content: str):
    bin_dir.mkdir(parents=True, exist_ok=True)
    path = bin_dir / name
    path.write_text(content)
    path.chmod(0o755)
    return path


def _read_ledger(path):
    return [json.loads(line) for line in path.read_text().splitlines()]
