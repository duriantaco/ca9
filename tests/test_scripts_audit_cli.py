from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from ca9.cli import main
from ca9.scripts_audit import ScriptsAuditError


def test_scripts_audit_positional_path_requires_directory(tmp_path):
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text("{}")

    result = CliRunner().invoke(main, ["scripts", "audit", str(lockfile)])

    assert result.exit_code == 2
    assert "Invalid value for '[DIRECTORY]'" in result.output


def test_scripts_audit_repo_option_requires_directory(tmp_path):
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text("{}")

    result = CliRunner().invoke(main, ["scripts", "audit", "--repo", str(lockfile)])

    assert result.exit_code == 2
    assert "Invalid value for '-r' / '--repo'" in result.output


def test_scripts_audit_max_artifact_size_must_be_positive(tmp_path):
    result = CliRunner().invoke(
        main,
        ["scripts", "audit", str(tmp_path), "--max-artifact-mb", "0"],
    )

    assert result.exit_code == 2
    assert "x>=1" in result.output


def test_scripts_audit_translates_core_error(tmp_path):
    with patch(
        "ca9.scripts_audit.build_scripts_audit_report",
        side_effect=ScriptsAuditError("package-lock.json is malformed"),
    ):
        result = CliRunner().invoke(main, ["scripts", "audit", str(tmp_path)])

    assert result.exit_code == 1
    assert result.output == "Error: package-lock.json is malformed\n"


def test_scripts_audit_rejects_commands_with_json_format(tmp_path):
    result = CliRunner().invoke(
        main,
        ["scripts", "audit", str(tmp_path), "--emit", "commands", "--format", "json"],
    )

    assert result.exit_code == 2
    assert "--emit commands cannot be combined with --format json" in result.output
