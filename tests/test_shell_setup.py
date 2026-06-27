from __future__ import annotations

import json

from click.testing import CliRunner

from ca9.cli import main
from ca9.runtime.shell import (
    MANAGED_BLOCK_END,
    MANAGED_BLOCK_START,
    doctor_shell,
    install_shell_setup,
    shell_setup_print_snippet,
    teardown_shell_setup,
)


def test_setup_shell_print_does_not_modify_profile(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    profile = home / ".zshrc"
    runner = CliRunner()

    result = runner.invoke(
        main,
        [
            "setup",
            "shell",
            "--print",
            "--shim-dir",
            str(tmp_path / "shims"),
        ],
        env={"HOME": str(home), "SHELL": "/bin/zsh"},
    )

    assert result.exit_code == 0
    assert MANAGED_BLOCK_START in result.output
    assert str(tmp_path / "shims") in result.output
    assert not profile.exists()


def test_install_shell_setup_writes_shims_profile_backup_and_is_idempotent(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    profile = home / ".zshrc"
    profile.write_text("export USER_SETTING=1\n")
    shim_dir = tmp_path / "shims"

    result = install_shell_setup(
        profile_path=profile,
        shim_dir=shim_dir,
        env={"HOME": str(home), "SHELL": "/bin/zsh"},
    )

    assert result.changed is True
    assert result.backup_path is not None
    assert result.backup_path.read_text() == "export USER_SETTING=1\n"
    assert all((shim_dir / name).is_file() for name in ("npm", "pip", "python"))
    assert profile.read_text().count(MANAGED_BLOCK_START) == 1
    assert "export USER_SETTING=1" in profile.read_text()

    second = install_shell_setup(
        profile_path=profile,
        shim_dir=shim_dir,
        env={"HOME": str(home), "SHELL": "/bin/zsh"},
    )

    assert second.changed is False
    assert second.backup_path is None
    assert profile.read_text().count(MANAGED_BLOCK_START) == 1


def test_teardown_shell_setup_removes_only_managed_block_and_keeps_other_lines(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    profile = home / ".zshrc"
    unmanaged_line = 'export PATH="$HOME/.cache/ca9/bin:$PATH" # user managed\n'
    profile.write_text(
        "before=1\n"
        f"{shell_setup_print_snippet(shim_dir=tmp_path / 'shims', env={'HOME': str(home)})}"
        f"{unmanaged_line}"
        "after=1\n"
    )

    result = teardown_shell_setup(
        profile_path=profile,
        env={"HOME": str(home), "SHELL": "/bin/zsh"},
    )

    text = profile.read_text()
    assert result.removed is True
    assert result.backup_path is not None
    assert MANAGED_BLOCK_START not in text
    assert MANAGED_BLOCK_END not in text
    assert unmanaged_line.strip() in text
    assert "before=1" in text
    assert "after=1" in text


def test_doctor_shell_reports_ok_after_install(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    profile = home / ".zshrc"
    shim_dir = tmp_path / "shims"
    install_shell_setup(
        profile_path=profile,
        shim_dir=shim_dir,
        env={"HOME": str(home), "SHELL": "/bin/zsh"},
    )

    result = doctor_shell(
        profile_path=profile,
        shim_dir=shim_dir,
        env={"HOME": str(home), "SHELL": "/bin/zsh", "PATH": ""},
    )

    assert result.ok is True
    assert result.profile_contains_block is True
    assert result.shims_installed is True


def test_setup_and_teardown_shell_cli_json(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    profile = home / ".zshrc"
    profile.write_text("existing=1\n")
    shim_dir = tmp_path / "shims"
    runner = CliRunner()

    install = runner.invoke(
        main,
        [
            "setup",
            "shell",
            "--install",
            "--profile",
            str(profile),
            "--shim-dir",
            str(shim_dir),
            "-f",
            "json",
        ],
        env={"HOME": str(home), "SHELL": "/bin/zsh"},
    )

    assert install.exit_code == 0
    data = json.loads(install.output)
    assert data["schema_version"] == "ca9.shell.setup.v1"
    assert data["changed"] is True
    assert profile.read_text().count(MANAGED_BLOCK_START) == 1

    teardown = runner.invoke(
        main,
        ["teardown", "shell", "--profile", str(profile), "-f", "json"],
        env={"HOME": str(home), "SHELL": "/bin/zsh"},
    )

    assert teardown.exit_code == 0
    removed = json.loads(teardown.output)
    assert removed["schema_version"] == "ca9.shell.teardown.v1"
    assert removed["removed"] is True
    assert MANAGED_BLOCK_START not in profile.read_text()
    assert "existing=1" in profile.read_text()


def test_doctor_shell_cli_reports_missing_setup(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    runner = CliRunner()

    result = runner.invoke(
        main,
        [
            "doctor",
            "shell",
            "--profile",
            str(home / ".zshrc"),
            "--shim-dir",
            str(tmp_path / "missing"),
            "-f",
            "json",
        ],
        env={"HOME": str(home), "SHELL": "/bin/zsh"},
    )

    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["ok"] is False
    assert set(data["missing_shims"]) == {"npm", "pip", "python"}
