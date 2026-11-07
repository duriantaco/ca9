from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

import pytest
from click.testing import CliRunner

from ca9.cli import main
from ca9.runtime.ci import (
    SHIM_NAMES,
    doctor_ci,
    install_ci_shims,
    is_ca9_shim,
    resolve_real_executable,
)

# Run generated shims under every POSIX shell available so bash-isms are caught.
SHELLS = [shell for shell in ("/bin/sh", shutil.which("dash")) if shell]


def test_setup_ci_prints_deterministic_commands():
    runner = CliRunner()

    result = runner.invoke(main, ["setup", "ci", "print"])

    assert result.exit_code == 0
    assert "ca9 setup ci install" in result.output
    assert "ca9 doctor ci" in result.output


def test_setup_ci_install_writes_shims_and_github_path(tmp_path):
    shim_dir = tmp_path / "shims"
    github_path = tmp_path / "github_path"
    runner = CliRunner()

    result = runner.invoke(
        main,
        ["setup", "ci", "install", "--shim-dir", str(shim_dir), "-f", "json"],
        env={
            "CA9_CACHE_DIR": str(tmp_path / "cache"),
            "GITHUB_ACTIONS": "true",
            "GITHUB_PATH": str(github_path),
        },
    )

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["schema_version"] == "ca9.ci.setup.v1"
    assert data["shim_dir"] == str(shim_dir)
    assert set(data["shims"]) == {"npm", "npx", "pip", "pip3", "python", "python3"}
    assert github_path.read_text().splitlines() == [str(shim_dir)]
    assert all((shim_dir / name).is_file() for name in data["shims"])
    assert all(is_ca9_shim(shim_dir / name) for name in data["shims"])


def test_doctor_ci_reports_ok_after_install(tmp_path):
    shim_dir = tmp_path / "shims"
    github_path = tmp_path / "github_path"
    install_ci_shims(
        shim_dir=shim_dir,
        env={"GITHUB_ACTIONS": "true", "GITHUB_PATH": str(github_path)},
    )

    result = doctor_ci(
        shim_dir=shim_dir,
        env={"GITHUB_ACTIONS": "true", "GITHUB_PATH": str(github_path), "PATH": ""},
    )

    assert result.ok is True
    assert result.github_path_contains_shim_dir is True
    assert result.exit_code == 0


def test_doctor_ci_cli_reports_missing_shims(tmp_path):
    runner = CliRunner()

    result = runner.invoke(
        main,
        ["doctor", "ci", "--shim-dir", str(tmp_path / "missing"), "-f", "json"],
        env={"GITHUB_ACTIONS": "true", "GITHUB_PATH": str(tmp_path / "github_path")},
    )

    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["ok"] is False
    assert set(data["missing_shims"]) == set(SHIM_NAMES)


def test_doctor_ci_warns_when_setup_node_or_venv_shadows_shims(tmp_path):
    shim_dir = tmp_path / "shims"
    toolcache = tmp_path / "hostedtoolcache" / "node" / "bin"
    install_ci_shims(shim_dir=shim_dir, env={})
    _write_fake_command(toolcache, "npm", "#!/bin/sh\nexit 0\n")
    _write_fake_command(toolcache, "python", "#!/bin/sh\nexit 0\n")

    shadowed = doctor_ci(
        shim_dir=shim_dir,
        env={"GITHUB_ACTIONS": "true", "PATH": f"{toolcache}:{shim_dir}"},
    )
    fixed = doctor_ci(
        shim_dir=shim_dir,
        env={"GITHUB_ACTIONS": "true", "PATH": f"{shim_dir}:{toolcache}"},
    )

    assert shadowed.ok is False
    assert [name for name, _ in shadowed.shadowed_shims] == ["npm", "python"]
    assert any(
        "`npm` resolves to" in warning and "ca9 setup ci install" in warning
        for warning in shadowed.warnings
    )
    assert shadowed.to_dict()["shadowed_shims"][0]["resolved"] == str(toolcache / "npm")
    assert fixed.ok is True
    assert fixed.shadowed_shims == ()


def test_npm_shim_routes_to_ca9_run_without_recursion(tmp_path):
    shim_dir = tmp_path / "shims"
    bin_dir = tmp_path / "bin"
    record = tmp_path / "record.txt"
    install_ci_shims(shim_dir=shim_dir, env={})
    _write_fake_command(
        bin_dir,
        "ca9",
        f'#!/bin/sh\necho "${{CA9_SHIM_BYPASS:-}}|$*" > {record}\nexit 0\n',
    )

    completed = subprocess.run(
        [str(shim_dir / "npm"), "install", "left-pad@1.3.0"],
        env={"PATH": f"{shim_dir}:{bin_dir}"},
        check=False,
    )

    assert completed.returncode == 0
    # The shim no longer exports CA9_SHIM_BYPASS; ca9 run resolves the real npm itself.
    assert record.read_text().strip() == "|run -- npm install left-pad@1.3.0"


@pytest.mark.parametrize(
    "subcommand",
    ["ci", "clean-install", "ic", "install-clean", "isntall-clean"],
)
def test_npm_shim_routes_clean_install_commands_to_ca9(tmp_path, subcommand):
    shim_dir = tmp_path / "shims"
    bin_dir = tmp_path / "bin"
    record = tmp_path / "record.txt"
    install_ci_shims(shim_dir=shim_dir, env={})
    _write_fake_command(
        bin_dir,
        "ca9",
        f'#!/bin/sh\necho "${{CA9_SHIM_BYPASS:-}}|$*" > {record}\nexit 0\n',
    )

    completed = subprocess.run(
        [str(shim_dir / "npm"), subcommand],
        env={"PATH": f"{shim_dir}:{bin_dir}"},
        check=False,
    )

    assert completed.returncode == 0
    assert record.read_text().strip() == f"|run -- npm {subcommand}"


def test_npm_shim_bypass_execs_real_npm(tmp_path):
    shim_dir = tmp_path / "shims"
    bin_dir = tmp_path / "bin"
    record = tmp_path / "record.txt"
    install_ci_shims(shim_dir=shim_dir, env={})
    _write_fake_command(
        bin_dir,
        "npm",
        f'#!/bin/sh\necho "real npm|$*" > {record}\nexit 0\n',
    )

    completed = subprocess.run(
        [str(shim_dir / "npm"), "install", "left-pad"],
        env={"PATH": f"{shim_dir}:{bin_dir}", "CA9_SHIM_BYPASS": "1"},
        check=False,
    )

    assert completed.returncode == 0
    assert record.read_text().strip() == "real npm|install left-pad"


def test_npm_shim_passes_non_install_commands_to_real_npm(tmp_path):
    shim_dir = tmp_path / "shims"
    bin_dir = tmp_path / "bin"
    record = tmp_path / "record.txt"
    install_ci_shims(shim_dir=shim_dir, env={})
    _write_fake_command(
        bin_dir,
        "npm",
        f'#!/bin/sh\necho "real npm|$*" > {record}\nexit 0\n',
    )

    completed = subprocess.run(
        [str(shim_dir / "npm"), "--version"],
        env={"PATH": f"{shim_dir}:{bin_dir}"},
        check=False,
    )

    assert completed.returncode == 0
    assert record.read_text().strip() == "real npm|--version"


def test_pip_shim_routes_install_and_passes_other_commands(tmp_path):
    shim_dir = tmp_path / "shims"
    bin_dir = tmp_path / "bin"
    record = tmp_path / "record.txt"
    install_ci_shims(shim_dir=shim_dir, env={})
    _write_fake_command(
        bin_dir,
        "ca9",
        f'#!/bin/sh\necho "ca9|${{CA9_SHIM_BYPASS:-}}|$*" > {record}\nexit 0\n',
    )
    _write_fake_command(
        bin_dir,
        "pip",
        f'#!/bin/sh\necho "real pip|$*" > {record}\nexit 0\n',
    )

    routed = subprocess.run(
        [str(shim_dir / "pip"), "install", "requests==2.31.0"],
        env={"PATH": f"{shim_dir}:{bin_dir}"},
        check=False,
    )
    assert routed.returncode == 0
    assert record.read_text().strip() == "ca9||run -- pip install requests==2.31.0"

    passthrough = subprocess.run(
        [str(shim_dir / "pip"), "--version"],
        env={"PATH": f"{shim_dir}:{bin_dir}"},
        check=False,
    )
    assert passthrough.returncode == 0
    assert record.read_text().strip() == "real pip|--version"


def test_python_shim_routes_pip_install_and_passes_other_python_calls(tmp_path):
    shim_dir = tmp_path / "shims"
    bin_dir = tmp_path / "bin"
    record = tmp_path / "record.txt"
    install_ci_shims(shim_dir=shim_dir, env={})
    _write_fake_command(
        bin_dir,
        "ca9",
        f'#!/bin/sh\necho "ca9|${{CA9_SHIM_BYPASS:-}}|$*" > {record}\nexit 0\n',
    )
    _write_fake_command(
        bin_dir,
        "python",
        f'#!/bin/sh\necho "real python|$*" > {record}\nexit 0\n',
    )

    routed = subprocess.run(
        [str(shim_dir / "python"), "-m", "pip", "install", "requests==2.31.0"],
        env={"PATH": f"{shim_dir}:{bin_dir}"},
        check=False,
    )
    assert routed.returncode == 0
    assert record.read_text().strip() == "ca9||run -- python -m pip install requests==2.31.0"

    passthrough = subprocess.run(
        [str(shim_dir / "python"), "-c", "print(1)"],
        env={"PATH": f"{shim_dir}:{bin_dir}"},
        check=False,
    )
    assert passthrough.returncode == 0
    assert record.read_text().strip() == "real python|-c print(1)"


NPM_ROUTED = [
    ["install", "left-pad"],
    ["--silent", "install", "evil"],
    ["-s", "i", "evil"],
    ["-g", "install", "evil"],
    ["--global", "true", "install", "evil"],
    ["-q", "-d", "install", "evil"],
    ["--loglevel", "silent", "install", "evil"],
    ["--prefix", "/tmp/elsewhere", "install", "evil"],
    ["-C", "/tmp/elsewhere", "add", "evil"],
    ["--workspace", "pkg", "update"],
    ["-w", "pkg", "install", "evil"],
    ["--registry", "https://registry.example", "install", "evil"],
    ["--userconfig", "/tmp/npmrc", "ci"],
    ["--registry=https://registry.example", "install", "evil"],
    ["--some-new-flag", "install", "evil"],
    ["--", "install", "evil"],
    *[
        [alias]
        for alias in (
            "i",
            "in",
            "ins",
            "inst",
            "insta",
            "instal",
            "isnt",
            "isnta",
            "isntal",
            "isntall",
            "add",
            "ci",
            "clean-install",
            "ic",
            "install-clean",
            "isntall-clean",
            "install-test",
            "it",
            "install-ci-test",
            "cit",
            "update",
            "up",
            "upgrade",
            "udpate",
            "upd",
            "exec",
            "x",
            "init",
            "create",
            "rebuild",
            "rb",
            "dedupe",
            "ddp",
            "link",
            "uninstall",
            "prune",
            "installTest",
            "some-future-command",
        )
    ],
    ["audit", "fix"],
    ["pack", "evil@1.0.0"],
    ["publish", "https://github.com/evil/pkg"],
    # Unknown flags make the subcommand uncertain, so even read-only commands fail closed.
    ["--unknown-flag", "run", "build"],
    # --cache takes a value: npm runs "install", not "run".
    ["--cache", "run", "install", "evil"],
]

NPM_PASSED = [
    [],
    ["--version"],
    ["-v"],
    ["help", "install"],
    ["run", "build"],
    ["run-script", "build"],
    ["test"],
    ["start"],
    ["ls"],
    ["view", "left-pad"],
    ["config", "get", "registry"],
    ["version", "patch"],
    ["--silent", "run", "build"],
    ["-w", "pkg", "run", "test"],
    ["--prefix", "web", "test"],
    ["--json", "ls"],
    ["--no-color", "outdated"],
    ["audit"],
    ["pack"],
    ["publish", "--tag", "beta"],
    ["whoami"],
]


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("args", NPM_ROUTED, ids=lambda args: " ".join(args))
def test_npm_shim_routes_install_capable_forms_to_ca9(run_shim, shell, args):
    assert run_shim(shell, "npm", args) == "ca9|run -- npm " + " ".join(args)


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("args", NPM_PASSED, ids=lambda args: " ".join(args) or "<none>")
def test_npm_shim_passes_read_only_forms_to_real_npm(run_shim, shell, args):
    assert run_shim(shell, "npm", args) == "real npm|" + " ".join(args)


PIP_ROUTED = [
    ["install", "evil"],
    ["-q", "install", "evil"],
    ["-qq", "install", "evil"],
    ["-v", "install", "evil"],
    ["--isolated", "install", "evil"],
    ["--disable-pip-version-check", "--no-input", "--no-color", "install", "evil"],
    ["--python", "/usr/bin/python3", "install", "evil"],
    ["--cache-dir", "/tmp/cache", "install", "evil"],
    ["--cache-dir=/tmp/cache", "install", "evil"],
    ["download", "evil"],
    ["wheel", "evil"],
    ["lock", "evil"],
    ["--unknown", "list"],
    ["-Z", "list"],
]

PIP_PASSED = [
    [],
    ["--version"],
    ["-V"],
    ["list"],
    ["-q", "list"],
    ["--disable-pip-version-check", "freeze"],
    ["show", "requests"],
    ["uninstall", "-y", "requests"],
    ["--cache-dir", "/tmp/cache", "cache", "purge"],
]


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("name", ["pip", "pip3"])
@pytest.mark.parametrize("args", PIP_ROUTED, ids=lambda args: " ".join(args))
def test_pip_shims_route_install_download_and_wheel_to_ca9(run_shim, shell, name, args):
    assert run_shim(shell, name, args) == f"ca9|run -- {name} " + " ".join(args)


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("name", ["pip", "pip3"])
@pytest.mark.parametrize("args", PIP_PASSED, ids=lambda args: " ".join(args) or "<none>")
def test_pip_shims_pass_read_only_commands_to_real_pip(run_shim, shell, name, args):
    assert run_shim(shell, name, args) == f"real {name}|" + " ".join(args)


PYTHON_ROUTED = [
    ["-m", "pip", "install", "evil"],
    ["-I", "-m", "pip", "install", "evil"],
    ["-IE", "-m", "pip", "install", "evil"],
    ["-I", "-E", "-s", "-S", "-u", "-B", "-b", "-O", "-OO", "-q", "-v", "-m", "pip", "install"],
    ["-Im", "pip", "install", "evil"],
    ["-mpip", "install", "evil"],
    ["-X", "dev", "-m", "pip", "install", "evil"],
    ["-Xdev", "-W", "ignore", "-m", "pip", "install", "evil"],
    ["-Wignore", "-m", "pip", "download", "evil"],
    ["-m", "pip", "wheel", "evil"],
    ["-m", "pip", "-q", "install", "evil"],
    ["-m", "pip", "--isolated", "--cache-dir", "/tmp/c", "install", "evil"],
    ["-m", "pip.__main__", "install", "evil"],
    ["--check-hash-based-pycs", "always", "-m", "pip", "install", "evil"],
    ["--unknown-interpreter-flag", "-m", "pip", "install", "evil"],
]

PYTHON_PASSED = [
    [],
    ["--version"],
    ["-V"],
    ["-c", "print(1)"],
    ["-I", "-c", "print(1)"],
    ["-Ic", "print(1)"],
    ["script.py", "-m", "pip", "install", "evil"],
    ["-m", "pip", "list"],
    ["-m", "pip", "--version"],
    ["-I", "-m", "venv", ".venv"],
    ["-"],
]


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("name", ["python", "python3"])
@pytest.mark.parametrize("args", PYTHON_ROUTED, ids=lambda args: " ".join(args))
def test_python_shims_route_pip_installs_after_interpreter_flags(run_shim, shell, name, args):
    assert run_shim(shell, name, args) == f"ca9|run -- {name} " + " ".join(args)


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("name", ["python", "python3"])
@pytest.mark.parametrize("args", PYTHON_PASSED, ids=lambda args: " ".join(args) or "<none>")
def test_python_shims_pass_other_interpreter_calls(run_shim, shell, name, args):
    assert run_shim(shell, name, args) == f"real {name}|" + " ".join(args)


@pytest.mark.parametrize("shell", SHELLS)
def test_npx_shim_routes_package_execution_to_ca9(run_shim, shell):
    assert run_shim(shell, "npx", ["cowsay", "hi"]) == "ca9|run -- npx cowsay hi"
    assert run_shim(shell, "npx", ["--version"]) == "real npx|--version"


@pytest.mark.parametrize(
    "path_template",
    [
        "{shim}/:{bin}",
        "{shim}//:{bin}",
        "{parent}//shims:{bin}",
        "{link}:{bin}",
        "{shim}:{other_shims}:{bin}",
    ],
)
def test_shim_find_real_skips_shim_dirs_by_inode(tmp_path, path_template):
    shim_dir = tmp_path / "shims"
    other_shims = tmp_path / "other-shims"
    bin_dir = tmp_path / "bin"
    record = tmp_path / "record.txt"
    install_ci_shims(shim_dir=shim_dir, env={})
    install_ci_shims(shim_dir=other_shims, env={})
    (tmp_path / "link").symlink_to(shim_dir)
    _write_fake_command(bin_dir, "npm", f'#!/bin/sh\necho "real npm|$*" > {record}\n')
    path = path_template.format(
        shim=shim_dir,
        parent=tmp_path,
        link=tmp_path / "link",
        other_shims=other_shims,
        bin=bin_dir,
    )

    completed = subprocess.run(
        [str(shim_dir / "npm"), "run", "build"],
        env={"PATH": path},
        check=False,
        timeout=10,
    )

    assert completed.returncode == 0
    assert record.read_text().strip() == "real npm|run build"


def test_shim_exits_127_when_only_shims_are_on_path(tmp_path):
    shim_dir = tmp_path / "shims"
    install_ci_shims(shim_dir=shim_dir, env={})

    completed = subprocess.run(
        [str(shim_dir / "npm"), "run", "build"],
        env={"PATH": f"{shim_dir}/"},
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 127
    assert "cannot find real npm" in completed.stderr


def test_resolve_real_executable_skips_current_and_legacy_shims(tmp_path):
    shim_dir = tmp_path / "shims"
    legacy_dir = tmp_path / "legacy"
    bin_dir = tmp_path / "bin"
    install_ci_shims(shim_dir=shim_dir, env={})
    # Shims written by earlier ca9 versions have no marker line or directory marker.
    _write_fake_command(
        legacy_dir,
        "npm",
        "#!/bin/sh\nset -eu\nCA9_SHIM_DIR=/x\nCA9_SHIM_NAME=npm\nCA9_COMMAND=ca9\n",
    )
    real_npm = _write_fake_command(bin_dir, "npm", "#!/bin/sh\nexit 0\n")
    env = {
        "PATH": f"{shim_dir}/:{legacy_dir}:{bin_dir}",
        "CA9_CACHE_DIR": str(tmp_path / "cache"),
    }

    assert resolve_real_executable("npm", env=env) == str(real_npm)
    assert resolve_real_executable(str(shim_dir / "npm"), env=env) == str(real_npm)
    assert resolve_real_executable(str(real_npm), env=env) == str(real_npm)
    assert resolve_real_executable("npm", env={"PATH": str(shim_dir)}) is None


def test_ca9_run_executes_real_binary_and_nested_installs_reenter_shims(tmp_path, monkeypatch):
    shim_dir = tmp_path / "shims"
    bin_dir = tmp_path / "bin"
    record = tmp_path / "record.txt"
    nested = tmp_path / "nested.txt"
    install_ci_shims(shim_dir=shim_dir, env={})
    policy_path = tmp_path / "policy.toml"
    policy_path.write_text(
        "[install_scripts]\nblock_when_secrets_present = false\n"
        "[ci]\nstrip_secret_env_for_installs = false\n"
    )
    # The fake npm behaves like a lifecycle script that starts a nested install via PATH.
    _write_fake_command(
        bin_dir,
        "npm",
        "#!/bin/sh\n"
        f'echo "real npm|${{CA9_SHIM_BYPASS:-unset}}|$*" >> {record}\n'
        'if [ "$2" = "left-pad@1.3.0" ]; then npm install nested-pkg; fi\n',
    )
    _write_fake_command(bin_dir, "ca9", f'#!/bin/sh\necho "nested ca9|$*" > {nested}\n')
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--policy",
            str(policy_path),
            "--audit-log",
            str(tmp_path / "audit.jsonl"),
            "--",
            "npm",
            "install",
            "left-pad@1.3.0",
        ],
        env={
            "CA9_CACHE_DIR": str(tmp_path / "cache"),
            "PATH": f"{shim_dir}:{bin_dir}:{os.path.dirname(sys.executable)}",
            "CA9_SHIM_BYPASS": "1",
        },
    )

    assert result.exit_code == 0, result.output
    assert record.read_text().splitlines() == ["real npm|unset|install left-pad@1.3.0"]
    assert nested.read_text().strip() == "nested ca9|run -- npm install nested-pkg"


def test_ca9_run_reports_missing_real_binary_without_recursing(tmp_path, monkeypatch):
    shim_dir = tmp_path / "shims"
    install_ci_shims(shim_dir=shim_dir, env={})
    policy_path = tmp_path / "policy.toml"
    policy_path.write_text(
        "[install_scripts]\nblock_when_secrets_present = false\n"
        "[ci]\nstrip_secret_env_for_installs = false\n"
    )
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(
        main,
        [
            "run",
            "--policy",
            str(policy_path),
            "--audit-log",
            str(tmp_path / "audit.jsonl"),
            "--",
            "npm",
            "install",
            "left-pad@1.3.0",
        ],
        env={"CA9_CACHE_DIR": str(tmp_path / "cache"), "PATH": str(shim_dir)},
    )

    assert result.exit_code == 127
    assert "cannot find the real npm" in result.stderr


@pytest.fixture(scope="module")
def shared_shims(tmp_path_factory):
    # Shared across the routing tables: freshly written executables are slow to start
    # the first time on some hosts, and the fakes report through $CA9_TEST_RECORD.
    root = tmp_path_factory.mktemp("shared-shims")
    shim_dir = root / "shims"
    bin_dir = root / "bin"
    install_ci_shims(shim_dir=shim_dir, env={})
    _write_fake_command(bin_dir, "ca9", '#!/bin/sh\necho "ca9|$*" > "$CA9_TEST_RECORD"\n')
    for name in SHIM_NAMES:
        _write_fake_command(
            bin_dir, name, f'#!/bin/sh\necho "real {name}|$*" > "$CA9_TEST_RECORD"\n'
        )
    return shim_dir, bin_dir


@pytest.fixture
def run_shim(shared_shims, tmp_path):
    shim_dir, bin_dir = shared_shims
    record = tmp_path / "record.txt"

    def run(shell, name, args):
        completed = subprocess.run(
            [shell, str(shim_dir / name), *args],
            env={"PATH": f"{shim_dir}:{bin_dir}", "CA9_TEST_RECORD": str(record)},
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert completed.returncode == 0, completed.stderr
        return record.read_text().strip()

    return run


def _write_fake_command(bin_dir, name: str, content: str):
    bin_dir.mkdir(parents=True, exist_ok=True)
    path = bin_dir / name
    path.write_text(content)
    path.chmod(0o755)
    return path
