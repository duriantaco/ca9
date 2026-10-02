from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from ca9.package_feed import update_feed_from_source
from ca9.package_policy import MalwarePolicy, PackagePolicy
from ca9.runtime.preflight import (
    RuntimePreflightError,
    evaluate_runtime_preflight,
    gateway_child_command,
    parse_install_command,
    primary_registry_url,
)

NO_FEED_CHECKS = PackagePolicy(malware=MalwarePolicy(enabled=False))


def _blocked(command, tmp_path, policy=NO_FEED_CHECKS, env=None):
    preflight = evaluate_runtime_preflight(command, policy, env=env or {}, cwd=tmp_path)
    assert preflight.action == "block", command
    return preflight.decisions[0]


@pytest.mark.parametrize(
    "spec",
    [
        "foo@https://attacker.example/payload.tgz",
        "foo@http://attacker.example/payload.tgz",
        "foo@github:attacker/repo",
        "foo@gitlab:attacker/repo",
        "foo@bitbucket:attacker/repo",
        "foo@git+https://github.com/attacker/repo",
        "foo@git+ssh://git@github.com/attacker/repo.git",
        "foo@git://github.com/attacker/repo.git",
        "foo@file:../evil",
        "foo@link:../evil",
        "foo@../evil",
        "foo@./evil",
        "foo@evil.tgz",
        "foo@evil.tar.gz",
        "foo@attacker/repo",
        "foo@attacker/repo#main",
        "@scope/foo@https://attacker.example/x.tgz",
        "@scope/foo@github:attacker/repo",
        "gist:11081aaa281",
        "github:attacker/repo",
        "attacker/repo",
        "git@github.com:attacker/repo.git",
        "https://attacker.example/payload.tgz",
        "evil.tar.gz",
        "evil.tgz",
        "evil.tar",
        "./evil",
        "../evil",
        "/tmp/evil",
        "~/evil",
        ".",
        "foo@npm:bar@github:attacker/repo",
        "foo@npm:bar@https://attacker.example/x.tgz",
        "foo@npm:bar@npm:baz@1.0.0",
    ],
)
def test_npm_non_registry_specs_are_blocked_as_unsupported(spec, tmp_path):
    decision = _blocked(("npm", "install", spec), tmp_path)

    assert decision.policy_id == "ca9.runtime.unsupported_command"


@pytest.mark.parametrize(
    ("spec", "name", "version_spec", "exact"),
    [
        ("left-pad", "left-pad", None, None),
        ("left-pad@", "left-pad", None, None),
        ("left-pad@1.3.0", "left-pad", "1.3.0", "1.3.0"),
        ("left-pad@v1.3.0", "left-pad", "v1.3.0", "1.3.0"),
        ("left-pad@=1.3.0", "left-pad", "=1.3.0", "1.3.0"),
        ("left-pad@^1.3.0", "left-pad", "^1.3.0", None),
        ("left-pad@1.x", "left-pad", "1.x", None),
        ("left-pad@>=1.0.0 <2.0.0", "left-pad", ">=1.0.0 <2.0.0", None),
        ("left-pad@latest", "left-pad", "latest", None),
        ("left-pad@1.0.0-beta.1", "left-pad", "1.0.0-beta.1", "1.0.0-beta.1"),
        ("@scope/pkg", "@scope/pkg", None, None),
        ("@scope/pkg@2.0.0", "@scope/pkg", "2.0.0", "2.0.0"),
        ("Legacy_Name@1.0.0", "legacy_name", "1.0.0", "1.0.0"),
    ],
)
def test_npm_registry_specs_still_parse(spec, name, version_spec, exact, tmp_path):
    command = parse_install_command(("npm", "install", spec), cwd=tmp_path)

    (request,) = command.package_requests
    assert (request.name, request.version_spec, request.exact_version) == (
        name,
        version_spec,
        exact,
    )


@pytest.mark.parametrize(
    ("spec", "name", "exact"),
    [
        ("lodash@npm:evil-pkg@1.0.0", "evil-pkg", "1.0.0"),
        ("lodash@NPM:evil-pkg@1.0.0", "evil-pkg", "1.0.0"),
        ("npm:evil-pkg@1.0.0", "evil-pkg", "1.0.0"),
        ("@scope/alias@npm:@evil/pkg@2.0.0", "@evil/pkg", "2.0.0"),
        ("lodash@npm:evil-pkg", "evil-pkg", None),
    ],
)
def test_npm_alias_specs_are_checked_as_the_real_package(spec, name, exact, tmp_path):
    command = parse_install_command(("npm", "install", spec), cwd=tmp_path)

    (request,) = command.package_requests
    assert (request.name, request.exact_version, request.raw_spec) == (name, exact, spec)


def test_npm_alias_to_known_malware_is_blocked(tmp_path):
    cache = _feed(tmp_path, npm_malware=[{"name": "evil-pkg", "version": "1.0.0", "id": "M-1"}])

    preflight = evaluate_runtime_preflight(
        ("npm", "install", "lodash@npm:evil-pkg@1.0.0"),
        PackagePolicy(),
        env={},
        feed_cache_dir=cache,
        cwd=tmp_path,
    )

    assert preflight.action == "block"
    decision = next(item for item in preflight.decisions if item.policy_id == "ca9.malware")
    assert (decision.package, decision.version) == ("evil-pkg", "1.0.0")


@pytest.mark.parametrize(
    "spec",
    [
        "evil-1.0.tar.gz",
        "evil-1.0.tar.bz2",
        "evil-1.0.tar.xz",
        "evil-1.0.tgz",
        "evil-1.0.tar",
        "evil-1.0.zip",
        "evil-1.0-py3-none-any.whl",
        "EVIL-1.0.TAR.GZ",
        "evil-1.0.tar.gz[extra]",
        "./evil",
        "../evil",
        "pkgdir/",
        "/tmp/evil",
        "foo @ file:evil",
        "foo @ file:///tmp/evil",
        "foo @ https://attacker.example/foo-1.0.tar.gz",
        "foo@https://attacker.example/foo-1.0.tar.gz",
        "foo @ git+https://github.com/attacker/repo",
        "git+https://github.com/attacker/repo#egg=foo",
        "https://attacker.example/foo-1.0.tar.gz",
    ],
)
def test_pip_local_and_direct_sources_are_blocked(spec, tmp_path):
    (tmp_path / "pkgdir").mkdir()

    decision = _blocked(("pip", "install", spec), tmp_path)

    assert decision.policy_id == "ca9.runtime.unsupported_command"
    assert "direct or local" in decision.reason


def test_pip_local_archive_in_requirement_file_is_blocked(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nevil-1.0.tar.gz\n")

    decision = _blocked(("pip", "install", "-r", "requirements.txt"), tmp_path)

    assert "evil-1.0.tar.gz" in decision.reason


def test_pip_index_specs_with_extras_and_markers_still_parse(tmp_path):
    command = parse_install_command(
        ("pip", "install", "requests[socks]>=2", "attrs==23.1.0; python_version >= '3.8'"),
        cwd=tmp_path,
    )

    assert [request.name for request in command.package_requests] == ["requests", "attrs"]
    assert command.package_requests[1].exact_version == "23.1.0"


@pytest.mark.parametrize(
    "prefix",
    [
        ("--silent",),
        ("-s",),
        ("-q",),
        ("--quiet",),
        ("-d",),
        ("--loglevel", "silent"),
        ("--loglevel=silent",),
        ("-w", "packages/api"),
        ("--workspace=packages/api",),
        ("--ignore-scripts",),
    ],
)
def test_npm_leading_global_options_are_parsed_before_the_subcommand(prefix, tmp_path):
    command = parse_install_command(("npm", *prefix, "install", "left-pad@1.3.0"), cwd=tmp_path)

    assert [request.key for request in command.package_requests] == ["npm:left-pad@1.3.0"]


def test_npm_leading_registry_option_is_checked_and_stripped(tmp_path):
    command = parse_install_command(
        ("npm", "--registry", "https://packages.example", "install", "left-pad@1.3.0"),
        cwd=tmp_path,
    )

    assert primary_registry_url(command) == "https://packages.example"
    assert gateway_child_command(command) == ("npm", "install", "left-pad@1.3.0")
    preflight = evaluate_runtime_preflight(command.command, NO_FEED_CHECKS, env={}, cwd=tmp_path)
    assert any(item.policy_id == "ca9.untrusted_registry" for item in preflight.decisions)


def test_npm_leading_global_option_skips_project_config(tmp_path):
    (tmp_path / ".npmrc").write_text("@acme:registry=https://packages.example/\n")

    for args in (("-g", "install"), ("--global", "i"), ("install", "-g")):
        preflight = evaluate_runtime_preflight(
            ("npm", *args, "@acme/widget@1.0.0"), NO_FEED_CHECKS, env={}, cwd=tmp_path
        )

        assert preflight.action == "pass", args


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (("--prefix", "../other", "install", "x"), "--prefix is unsupported"),
        (("--prefix=../other", "install", "x"), "--prefix is unsupported"),
        (("-C", "../other", "install", "x"), "--prefix is unsupported"),
        (("install", "-C", "../other", "x"), "--prefix is unsupported"),
        (("--userconfig", "/tmp/npmrc", "install", "x"), "--userconfig is unsupported"),
        (("install", "--globalconfig=/tmp/npmrc", "x"), "--globalconfig is unsupported"),
        (("--silent=true", "install", "x"), "does not take a value"),
        (("--unknown-option", "install", "x"), "unsupported npm install option"),
    ],
)
def test_npm_config_switching_and_unknown_leading_options_are_blocked(args, message, tmp_path):
    decision = _blocked(("npm", *args), tmp_path)

    assert decision.policy_id == "ca9.runtime.unsupported_command"
    assert message in decision.reason


@pytest.mark.parametrize("subcommand", ["add", "isntall", "in", "instal"])
def test_npm_install_aliases_are_parsed_like_install(subcommand, tmp_path):
    command = parse_install_command(("npm", subcommand, "left-pad@1.3.0"), cwd=tmp_path)

    assert command.family == "npm"
    assert [request.name for request in command.package_requests] == ["left-pad"]


@pytest.mark.parametrize(
    "args",
    [
        ("npm", "update"),
        ("npm", "up", "left-pad"),
        ("npm", "exec", "left-pad"),
        ("npm", "x", "left-pad"),
        ("npm", "init", "react-app", "demo"),
        ("npm", "create", "vite"),
        ("npm", "rebuild"),
        ("npm", "dedupe"),
        ("npm", "install-test"),
        ("npm", "it"),
        ("npm", "cit"),
        ("npm", "install-ci-test"),
        ("npm", "--silent", "update"),
        ("npm", "-g", "exec", "left-pad"),
        ("npx", "left-pad"),
        ("npx", "--yes", "create-react-app"),
    ],
)
def test_npm_install_capable_commands_fail_closed(args, tmp_path):
    decision = _blocked(args, tmp_path)

    assert decision.policy_id == "ca9.runtime.unsupported_command"
    assert "not supported by ca9 run" in decision.reason


@pytest.mark.parametrize(
    "args",
    [
        ("pip", "-q", "install", "requests==2.31.0"),
        ("pip", "-v", "install", "requests==2.31.0"),
        ("pip", "--isolated", "install", "requests==2.31.0"),
        (
            "pip",
            "--disable-pip-version-check",
            "--no-input",
            "--no-color",
            "install",
            "requests==2.31.0",
        ),
        ("pip", "--cache-dir", "/tmp/pip-cache", "install", "requests==2.31.0"),
        ("pip", "--cache-dir=/tmp/pip-cache", "install", "requests==2.31.0"),
        ("pip", "install", "-q", "requests==2.31.0"),
        ("pip3", "install", "requests==2.31.0"),
        ("pip3.12", "install", "requests==2.31.0"),
        ("python3", "-m", "pip", "install", "requests==2.31.0"),
        ("python3.12", "-m", "pip", "install", "requests==2.31.0"),
        ("python", "-I", "-m", "pip", "install", "requests==2.31.0"),
        ("python", "-IsSE", "-m", "pip", "install", "requests==2.31.0"),
        ("python", "-OO", "-u", "-B", "-b", "-q", "-m", "pip", "install", "requests==2.31.0"),
        ("python", "-X", "dev", "-W", "ignore", "-m", "pip", "install", "requests==2.31.0"),
        ("python", "-Xutf8", "-Wignore", "-mpip", "install", "requests==2.31.0"),
        ("python", "-Im", "pip", "-q", "install", "requests==2.31.0"),
    ],
)
def test_pip_and_python_leading_options_are_parsed(args, tmp_path):
    command = parse_install_command(args, cwd=tmp_path)

    assert command.family == "pip"
    assert [request.key for request in command.package_requests] == ["pypi:requests@2.31.0"]


def test_pip_gateway_command_keeps_leading_options(tmp_path):
    command = parse_install_command(
        ("python3", "-I", "-m", "pip", "-q", "install", "requests==2.31.0"), cwd=tmp_path
    )

    assert gateway_child_command(command, registry_url="http://127.0.0.1:1/simple") == (
        "python3",
        "-I",
        "-m",
        "pip",
        "-q",
        "install",
        "requests==2.31.0",
        "--index-url",
        "http://127.0.0.1:1/simple",
    )


@pytest.mark.parametrize(
    "args",
    [
        ("pip", "--python", "/usr/bin/python3", "install", "requests"),
        ("pip", "install", "--python=/usr/bin/python3", "requests"),
        ("pip", "--log", "/tmp/log", "install", "requests"),
        ("pip", "-q", "download", "requests"),
        ("python", "-m", "pip", "download", "requests"),
        ("python", "-c", "import pip", "install", "requests"),
        ("python", "-m", "venv", "install"),
        ("python", "script.py", "-m", "pip", "install", "requests"),
        ("python", "-i", "-m", "pip", "install", "requests"),
        ("python", "--version"),
        ("python2", "-m", "pip", "install", "requests"),
    ],
)
def test_unsupported_pip_and_python_forms_are_blocked(args, tmp_path):
    decision = _blocked(args, tmp_path)

    assert decision.policy_id == "ca9.runtime.unsupported_command"


@pytest.mark.parametrize(
    ("args", "scripts_possible", "specs"),
    [
        (("--ignore-scripts", "false", "evil"), True, ["evil"]),
        (("--ignore-scripts", "true", "evil"), False, ["evil"]),
        (("--ignore-scripts=false", "evil"), True, ["evil"]),
        (("--ignore-scripts", "evil"), False, ["evil"]),
        (("evil", "--ignore-scripts", "false"), True, ["evil"]),
        (("--ignore-scripts", "--ignore-scripts=false", "evil"), True, ["evil"]),
        (("--save-dev", "false", "evil"), True, ["evil"]),
        (("-s", "false"), True, ["false"]),
    ],
)
def test_npm_boolean_flags_consume_literal_true_false_like_nopt(
    args, scripts_possible, specs, tmp_path
):
    command = parse_install_command(("npm", "install", *args), cwd=tmp_path)

    assert command.install_scripts_possible is scripts_possible
    assert [request.name for request in command.package_requests] == specs


def test_npm_ignore_scripts_false_value_does_not_skip_secret_gate(tmp_path):
    preflight = evaluate_runtime_preflight(
        ("npm", "install", "--ignore-scripts", "false", "evil"),
        NO_FEED_CHECKS,
        env={"NPM_TOKEN": "secret-value"},
        cwd=tmp_path,
    )

    assert preflight.action == "block"
    assert any(item.policy_id == "ca9.install_scripts.secrets" for item in preflight.decisions)


def test_npm_global_false_value_still_applies_project_config(tmp_path):
    (tmp_path / ".npmrc").write_text("@acme:registry=https://packages.example/\n")

    for args in (("-g", "false"), ("--global", "false"), ("--global=false",)):
        preflight = evaluate_runtime_preflight(
            ("npm", "install", *args, "@acme/widget@1.0.0"), NO_FEED_CHECKS, env={}, cwd=tmp_path
        )

        assert preflight.action == "block", args
        assert preflight.decisions[0].policy_id == "ca9.runtime.unsupported_source"


def test_pip_comment_line_ending_in_backslash_does_not_hide_next_requirement(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "# pinned deps, see docs \\\nevil==1.0\n  # indented note \\\nrequests==2.31.0\n"
    )

    command = parse_install_command(("pip", "install", "-r", "requirements.txt"), cwd=tmp_path)

    assert [request.key for request in command.package_requests] == [
        "pypi:evil@1.0",
        "pypi:requests@2.31.0",
    ]


def test_pip_requirement_continuations_join_like_pip(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "ev\\\nil==1.0\nrequests==2.31.0 \\\n  --hash=sha256:" + "a" * 64 + "\n"
    )

    command = parse_install_command(("pip", "install", "-r", "requirements.txt"), cwd=tmp_path)

    assert [request.key for request in command.package_requests] == [
        "pypi:evil@1.0",
        "pypi:requests@2.31.0",
    ]
    assert command.package_requests[1].hashes == (f"sha256:{'a' * 64}",)


def test_pip_requirements_are_not_dropped_by_environment_markers(tmp_path):
    (tmp_path / "requirements.txt").write_text("other==2.0; python_version < '3.0'\n")
    cache = _feed(tmp_path, pypi_malware=[{"name": "evil", "version": "1.0", "id": "M-1"}])

    preflight = evaluate_runtime_preflight(
        (
            "pip",
            "install",
            "good",
            "evil==1.0; python_version < '3.0'",
            "-r",
            "requirements.txt",
        ),
        PackagePolicy(),
        env={},
        feed_cache_dir=cache,
        cwd=tmp_path,
    )

    assert [request.name for request in preflight.command.package_requests] == [
        "good",
        "evil",
        "other",
    ]
    assert any(
        item.policy_id == "ca9.malware" and item.package == "evil" for item in preflight.decisions
    )


def test_pip_constraint_pins_for_other_environments_are_checked(tmp_path):
    (tmp_path / "constraints.txt").write_text("dep==6.6.6; python_version < '3.0'\n")

    command = parse_install_command(
        ("pip", "install", "dep", "-c", "constraints.txt"), cwd=tmp_path
    )

    assert {request.key for request in command.package_requests} == {"pypi:dep", "pypi:dep@6.6.6"}


def test_parse_errors_raise_runtime_preflight_error(tmp_path):
    with pytest.raises(RuntimePreflightError):
        parse_install_command(("npm", "install", "foo@github:attacker/repo"), cwd=tmp_path)


def _feed(tmp_path, *, npm_malware=None, pypi_malware=None):
    expires = (datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=1)).isoformat()
    bundle = {
        "schema": "ca9.feed.v1",
        "created_at": "2026-06-26T00:00:00Z",
        "expires_at": expires,
        "datasets": {
            "npm-malware": {"packages": npm_malware or []},
            "pypi-malware": {"packages": pypi_malware or []},
            "npm-releases": {"packages": {}},
            "pypi-releases": {"packages": {}},
        },
    }
    path = tmp_path / "feed.json"
    path.write_text(json.dumps(bundle))
    cache = tmp_path / "cache" / "feed"
    update_feed_from_source(path, cache_dir=cache)
    return cache
