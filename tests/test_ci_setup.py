from __future__ import annotations

import json
import subprocess

from click.testing import CliRunner

from ca9.cli import main
from ca9.runtime.ci import doctor_ci, install_ci_shims


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
    assert set(data["shims"]) == {"npm", "pip", "python"}
    assert github_path.read_text().splitlines() == [str(shim_dir)]
    assert all((shim_dir / name).is_file() for name in ("npm", "pip", "python"))


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
    assert set(data["missing_shims"]) == {"npm", "pip", "python"}


def test_npm_shim_routes_to_ca9_run_without_recursion(tmp_path):
    shim_dir = tmp_path / "shims"
    bin_dir = tmp_path / "bin"
    record = tmp_path / "record.txt"
    install_ci_shims(shim_dir=shim_dir, env={})
    _write_fake_command(
        bin_dir,
        "ca9",
        f'#!/bin/sh\necho "$CA9_SHIM_BYPASS|$*" > {record}\nexit 0\n',
    )

    completed = subprocess.run(
        [str(shim_dir / "npm"), "install", "left-pad@1.3.0"],
        env={"PATH": f"{shim_dir}:{bin_dir}"},
        check=False,
    )

    assert completed.returncode == 0
    assert record.read_text().strip() == "1|run -- npm install left-pad@1.3.0"


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
        f'#!/bin/sh\necho "ca9|$CA9_SHIM_BYPASS|$*" > {record}\nexit 0\n',
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
    assert record.read_text().strip() == "ca9|1|run -- pip install requests==2.31.0"

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
        f'#!/bin/sh\necho "ca9|$CA9_SHIM_BYPASS|$*" > {record}\nexit 0\n',
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
    assert record.read_text().strip() == "ca9|1|run -- python -m pip install requests==2.31.0"

    passthrough = subprocess.run(
        [str(shim_dir / "python"), "-c", "print(1)"],
        env={"PATH": f"{shim_dir}:{bin_dir}"},
        check=False,
    )
    assert passthrough.returncode == 0
    assert record.read_text().strip() == "real python|-c print(1)"


def _write_fake_command(bin_dir, name: str, content: str):
    bin_dir.mkdir(parents=True, exist_ok=True)
    path = bin_dir / name
    path.write_text(content)
    path.chmod(0o755)
    return path
