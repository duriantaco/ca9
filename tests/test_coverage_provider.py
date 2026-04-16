from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

from click.testing import CliRunner

from ca9.cli import main
from ca9.coverage_provider import discover_coverage, generate_coverage, resolve_coverage


class TestDiscoverCoverage:
    def test_finds_coverage_json(self, tmp_path):
        (tmp_path / "coverage.json").write_text("{}")
        assert discover_coverage(tmp_path) == tmp_path / "coverage.json"

    def test_finds_dot_coverage_json(self, tmp_path):
        (tmp_path / ".coverage.json").write_text("{}")
        assert discover_coverage(tmp_path) == tmp_path / ".coverage.json"

    def test_finds_htmlcov_coverage_json(self, tmp_path):
        (tmp_path / "htmlcov").mkdir()
        (tmp_path / "htmlcov" / "coverage.json").write_text("{}")
        assert discover_coverage(tmp_path) == tmp_path / "htmlcov" / "coverage.json"

    def test_finds_ca9_coverage_json(self, tmp_path):
        (tmp_path / ".ca9").mkdir()
        (tmp_path / ".ca9" / "coverage.json").write_text("{}")
        assert discover_coverage(tmp_path) == tmp_path / ".ca9" / "coverage.json"

    def test_returns_none_when_no_file(self, tmp_path):
        assert discover_coverage(tmp_path) is None

    def test_priority_order(self, tmp_path):
        (tmp_path / "coverage.json").write_text("{}")
        (tmp_path / ".ca9").mkdir()
        (tmp_path / ".ca9" / "coverage.json").write_text("{}")
        assert discover_coverage(tmp_path) == tmp_path / "coverage.json"


class TestGenerateCoverage:
    def test_pytest_not_found(self, tmp_path, capsys):
        with patch("ca9.coverage_provider.shutil.which", return_value=None):
            result = generate_coverage(tmp_path)
        assert result is None
        assert "pytest not found" in capsys.readouterr().err

    def test_pytest_success(self, tmp_path, capsys):
        output_path = tmp_path / ".ca9" / "coverage.json"

        def fake_run(cmd, **kwargs):
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text('{"files": {}}')
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with (
            patch("ca9.coverage_provider.shutil.which", return_value="/usr/bin/pytest"),
            patch("ca9.coverage_provider.subprocess.run", side_effect=fake_run),
        ):
            result = generate_coverage(tmp_path)

        assert result == output_path
        err = capsys.readouterr().err
        assert "Running pytest" in err
        assert "Coverage data written" in err

    def test_pytest_cov_missing(self, tmp_path, capsys):
        with (
            patch("ca9.coverage_provider.shutil.which", return_value="/usr/bin/pytest"),
            patch(
                "ca9.coverage_provider.subprocess.run",
                return_value=subprocess.CompletedProcess(["pytest"], 0, "", ""),
            ),
        ):
            result = generate_coverage(tmp_path)

        assert result is None
        assert "pytest-cov installed" in capsys.readouterr().err

    def test_pytest_timeout(self, tmp_path, capsys):
        with (
            patch("ca9.coverage_provider.shutil.which", return_value="/usr/bin/pytest"),
            patch(
                "ca9.coverage_provider.subprocess.run",
                side_effect=subprocess.TimeoutExpired("pytest", 300),
            ),
        ):
            result = generate_coverage(tmp_path)

        assert result is None
        assert "timed out" in capsys.readouterr().err

    def test_oserror(self, tmp_path, capsys):
        with (
            patch("ca9.coverage_provider.shutil.which", return_value="/usr/bin/pytest"),
            patch(
                "ca9.coverage_provider.subprocess.run",
                side_effect=OSError("exec failed"),
            ),
        ):
            result = generate_coverage(tmp_path)

        assert result is None
        assert "Failed to run pytest" in capsys.readouterr().err

    def test_pytest_failure_does_not_use_stale_coverage_file(self, tmp_path, capsys):
        output_path = tmp_path / ".ca9" / "coverage.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text('{"files": {"stale.py": {"executed_lines": [1]}}}')

        with (
            patch("ca9.coverage_provider.shutil.which", return_value="/usr/bin/pytest"),
            patch(
                "ca9.coverage_provider.subprocess.run",
                return_value=subprocess.CompletedProcess(["pytest"], 1, "", "tests failed"),
            ),
        ):
            result = generate_coverage(tmp_path)

        assert result is None
        assert not output_path.exists()
        assert "pytest failed while generating coverage" in capsys.readouterr().err

    def test_invalid_generated_json_is_rejected(self, tmp_path, capsys):
        output_path = tmp_path / ".ca9" / "coverage.json"

        def fake_run(cmd, **kwargs):
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text("{not-json")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with (
            patch("ca9.coverage_provider.shutil.which", return_value="/usr/bin/pytest"),
            patch("ca9.coverage_provider.subprocess.run", side_effect=fake_run),
        ):
            result = generate_coverage(tmp_path)

        assert result is None
        assert "invalid coverage.json" in capsys.readouterr().err


class TestResolveCoverage:
    def test_explicit_path_wins(self, tmp_path):
        explicit = tmp_path / "explicit.json"
        explicit.write_text("{}")
        (tmp_path / "coverage.json").write_text("{}")
        assert resolve_coverage(explicit, tmp_path) == explicit

    def test_discovers_existing(self, tmp_path, capsys):
        (tmp_path / "coverage.json").write_text("{}")
        result = resolve_coverage(None, tmp_path)
        assert result == tmp_path / "coverage.json"
        assert "Found coverage data" in capsys.readouterr().err

    def test_auto_generates(self, tmp_path, capsys):
        output_path = tmp_path / ".ca9" / "coverage.json"

        def fake_run(cmd, **kwargs):
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text('{"files": {}}')
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with (
            patch("ca9.coverage_provider.shutil.which", return_value="/usr/bin/pytest"),
            patch("ca9.coverage_provider.subprocess.run", side_effect=fake_run),
        ):
            result = resolve_coverage(None, tmp_path)

        assert result == output_path

    def test_no_auto_generate(self, tmp_path):
        result = resolve_coverage(None, tmp_path, auto_generate=False)
        assert result is None

    def test_no_auto_skips_discovery_even_if_file_exists(self, tmp_path):
        (tmp_path / "coverage.json").write_text("{}")
        result = resolve_coverage(None, tmp_path, auto_generate=False)
        assert result is None

    def test_falls_back_to_none(self, tmp_path):
        with patch("ca9.coverage_provider.shutil.which", return_value=None):
            result = resolve_coverage(None, tmp_path)
        assert result is None


class TestCLINoAutoCoverage:
    def test_check_no_auto_coverage_flag(self, snyk_path, sample_repo):
        runner = CliRunner()
        result = runner.invoke(
            main,
            [str(snyk_path), "--repo", str(sample_repo), "--no-auto-coverage", "-f", "json"],
        )
        assert result.exit_code in (0, 1, 2)
        raw = result.output.strip()
        json_start = raw.index("{")
        json_end = raw.rindex("}") + 1
        data = json.loads(raw[json_start:json_end])
        verdicts = set(r["verdict"] for r in data["results"])
        assert "unreachable_dynamic" not in verdicts
        assert verdicts & {"inconclusive", "unreachable_static"}

    def test_check_explicit_coverage_skips_auto(self, snyk_path, sample_repo, coverage_path):
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                str(snyk_path),
                "--repo",
                str(sample_repo),
                "--coverage",
                str(coverage_path),
                "-f",
                "json",
            ],
        )
        data = json.loads(result.output)
        verdicts = {r["package"]: r["verdict"] for r in data["results"]}
        assert verdicts["requests"] == "reachable"
