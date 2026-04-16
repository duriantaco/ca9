from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from ca9.cli import main


class TestCLI:
    def test_table_output(self, snyk_path, sample_repo):
        runner = CliRunner()
        result = runner.invoke(main, [str(snyk_path), "--repo", str(sample_repo)])
        assert result.exit_code in (0, 1, 2)
        assert "requests" in result.output
        assert "UNREACHABLE" in result.output or "INCONCLUSIVE" in result.output

    def test_json_output(self, snyk_path, sample_repo):
        runner = CliRunner()
        result = runner.invoke(
            main, [str(snyk_path), "--repo", str(sample_repo), "-f", "json", "--no-auto-coverage"]
        )
        assert result.exit_code in (0, 1, 2)
        raw = result.output.strip()
        json_start = raw.index("{")
        json_end = raw.rindex("}") + 1
        data = json.loads(raw[json_start:json_end])
        assert "results" in data
        assert "summary" in data
        assert data["summary"]["total"] == 4

    def test_with_coverage(self, snyk_path, sample_repo, coverage_path):
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
        assert verdicts["some-unused-package"] == "unreachable_static"
        assert result.exit_code == 1

    def test_strict_default_downgrades_weak_dynamic_suppression(
        self, snyk_path, sample_repo, coverage_path
    ):
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
        verdicts = {r["package"]: r for r in data["results"]}
        assert verdicts["PyYAML"]["verdict"] == "inconclusive"
        assert verdicts["PyYAML"]["original_verdict"] == "unreachable_dynamic"

    def test_balanced_mode_keeps_dynamic_suppression(self, snyk_path, sample_repo, coverage_path):
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                str(snyk_path),
                "--repo",
                str(sample_repo),
                "--coverage",
                str(coverage_path),
                "--proof-standard",
                "balanced",
                "-f",
                "json",
            ],
        )
        data = json.loads(result.output)
        verdicts = {r["package"]: r["verdict"] for r in data["results"]}
        assert verdicts["PyYAML"] == "unreachable_dynamic"

    def test_output_to_file(self, snyk_path, sample_repo, tmp_path):
        output_file = tmp_path / "report.json"
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                str(snyk_path),
                "--repo",
                str(sample_repo),
                "-f",
                "json",
                "-o",
                str(output_file),
            ],
        )
        assert result.exit_code in (0, 1, 2)
        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert data["summary"]["total"] == 4

    def test_no_vulns(self, tmp_path, sample_repo):
        empty = tmp_path / "empty.json"
        empty.write_text('{"vulnerabilities": [], "projectName": "x"}')
        runner = CliRunner()
        result = runner.invoke(main, [str(empty), "--repo", str(sample_repo)])
        assert result.exit_code == 0
        assert "No vulnerabilities" in result.output

    def test_invalid_json(self, tmp_path, sample_repo):
        bad = tmp_path / "bad.json"
        bad.write_text("not valid json {{{")
        runner = CliRunner()
        result = runner.invoke(main, [str(bad), "--repo", str(sample_repo)])
        assert result.exit_code != 0
        assert "Invalid JSON" in result.output

    def test_unknown_format(self, tmp_path, sample_repo):
        unknown = tmp_path / "unknown.json"
        unknown.write_text('{"random": "data"}')
        runner = CliRunner()
        result = runner.invoke(main, [str(unknown), "--repo", str(sample_repo)])
        assert result.exit_code != 0
        assert "Cannot detect SCA format" in result.output

    def test_output_creates_parent_dir(self, snyk_path, sample_repo, tmp_path):
        output_file = tmp_path / "subdir" / "deep" / "report.json"
        runner = CliRunner()
        runner.invoke(
            main,
            [
                str(snyk_path),
                "--repo",
                str(sample_repo),
                "-f",
                "json",
                "-o",
                str(output_file),
            ],
        )
        assert output_file.exists()

    def test_sarif_output(self, snyk_path, sample_repo):
        runner = CliRunner()
        result = runner.invoke(
            main, [str(snyk_path), "--repo", str(sample_repo), "-f", "sarif", "--no-auto-coverage"]
        )
        raw = result.output.strip()
        json_start = raw.index("{")
        json_end = raw.rindex("}") + 1
        data = json.loads(raw[json_start:json_end])
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) == 4

    def test_exit_code_with_reachable(self, snyk_path, sample_repo, coverage_path):
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
        has_reachable = any(r["verdict"] == "reachable" for r in data["results"])
        if has_reachable:
            assert result.exit_code == 1

    def test_exit_code_no_vulns(self, tmp_path, sample_repo):
        empty = tmp_path / "empty.json"
        empty.write_text('{"vulnerabilities": [], "projectName": "x"}')
        runner = CliRunner()
        result = runner.invoke(main, [str(empty), "--repo", str(sample_repo)])
        assert result.exit_code == 0

    def test_scan_prefers_repo_inventory(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("import requests\n")
        (repo / "requirements.txt").write_text("requests==2.31.0\n")

        runner = CliRunner()
        with (
            patch("ca9.scanner.get_installed_packages", return_value=[("unused", "0.1.0")]),
            patch("ca9.scanner.query_osv_batch", return_value=[]) as mock_query,
        ):
            result = runner.invoke(main, ["scan", "--repo", str(repo), "--no-auto-coverage"])

        assert result.exit_code == 0
        mock_query.assert_called_once_with(
            [("requests", "2.31.0")],
            offline=False,
            refresh_cache=False,
            max_workers=8,
        )
        assert "Scanning repo dependency inventory" in result.output


class TestCLINewCommands:
    def test_capabilities_command(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        mcp_config = {"mcpServers": {"fs": {"command": "node", "allowedRoots": ["/tmp"]}}}
        (repo / "mcp.json").write_text(json.dumps(mcp_config))
        (repo / "app.py").write_text("from anthropic import Anthropic\n")

        runner = CliRunner()
        result = runner.invoke(main, ["capabilities", "--repo", str(repo)])
        assert result.exit_code == 0
        assert "Components" in result.output

    def test_cap_diff_command(self, tmp_path):
        base_bom = {"components": [], "services": [], "metadata": {"properties": []}}
        head_bom = {
            "components": [
                {
                    "bom-ref": "mcp_server:fs",
                    "name": "fs",
                    "type": "service",
                    "version": "1",
                    "properties": [{"name": "ca9.ai.asset.kind", "value": "mcp_server"}],
                }
            ],
            "services": [
                {
                    "name": "ca9.ai.capabilities",
                    "properties": [
                        {
                            "name": "ca9.capability.record",
                            "value": json.dumps(
                                {
                                    "cap": "exec.shell",
                                    "scope": "*",
                                    "asset": "mcp_server:fs",
                                    "evidence": [],
                                }
                            ),
                        }
                    ],
                }
            ],
            "metadata": {"properties": []},
        }
        base_path = tmp_path / "base.json"
        head_path = tmp_path / "head.json"
        base_path.write_text(json.dumps(base_bom))
        head_path.write_text(json.dumps(head_bom))

        runner = CliRunner()
        result = runner.invoke(
            main, ["cap-diff", "--base", str(base_path), "--head", str(head_path)]
        )
        assert result.exit_code == 0
        raw = result.output.strip()
        json_start = raw.index("{")
        json_end = raw.rindex("}") + 1
        data = json.loads(raw[json_start:json_end])
        assert "assets" in data or "assets_added" in data
        assert "capabilities" in data or "capabilities_added" in data

    def test_cap_gate_command_blocks(self, tmp_path):
        diff_data = {
            "assets": {"added": [{"kind": "mcp_server", "id": "fs"}], "removed": [], "changed": []},
            "capabilities": {
                "added": [{"capability": "exec.shell", "scope": "*", "asset": "mcp_server:fs"}],
                "removed": [],
                "widened": [],
            },
            "risk": {"level": "high"},
        }
        diff_path = tmp_path / "diff.json"
        diff_path.write_text(json.dumps(diff_data))

        policy = {
            "version": "1",
            "rules": [
                {
                    "id": "block-shell",
                    "when": {"capability_added": "exec.shell"},
                    "action": "block",
                    "message": "Shell execution not allowed",
                }
            ],
        }
        policy_path = tmp_path / "policy.yaml"
        import yaml

        policy_path.write_text(yaml.dump(policy))

        runner = CliRunner()
        result = runner.invoke(
            main, ["cap-gate", "--diff", str(diff_path), "--policy", str(policy_path)]
        )
        assert result.exit_code == 2

    def test_vex_diff_command_with_regression(self, tmp_path):
        base_vex = {
            "timestamp": "2024-01-01T00:00:00Z",
            "statements": [
                {
                    "vulnerability": {"name": "CVE-2023-0001"},
                    "products": [{"@id": "pkg:pypi/requests@2.19.1"}],
                    "status": "not_affected",
                    "justification": "component_not_present",
                }
            ],
        }
        head_vex = {
            "timestamp": "2024-01-02T00:00:00Z",
            "statements": [
                {
                    "vulnerability": {"name": "CVE-2023-0001"},
                    "products": [{"@id": "pkg:pypi/requests@2.19.1"}],
                    "status": "affected",
                }
            ],
        }
        base_path = tmp_path / "base_vex.json"
        head_path = tmp_path / "head_vex.json"
        base_path.write_text(json.dumps(base_vex))
        head_path.write_text(json.dumps(head_vex))

        runner = CliRunner()
        result = runner.invoke(
            main, ["vex-diff", "--base", str(base_path), "--head", str(head_path)]
        )
        assert result.exit_code == 1

    def test_action_plan_command(self, snyk_path, sample_repo):
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["action-plan", str(snyk_path), "--repo", str(sample_repo)],
        )
        assert result.exit_code in (0, 1, 2)
        raw = result.output.strip()
        json_start = raw.index("{")
        json_end = raw.rindex("}") + 1
        data = json.loads(raw[json_start:json_end])
        assert "decision" in data
        assert "actions" in data

    def test_check_vex_format(self, snyk_path, sample_repo):
        runner = CliRunner()
        result = runner.invoke(
            main,
            [str(snyk_path), "--repo", str(sample_repo), "-f", "vex", "--no-auto-coverage"],
        )
        assert result.exit_code in (0, 1, 2)
        raw = result.output.strip()
        json_start = raw.index("{")
        json_end = raw.rindex("}") + 1
        data = json.loads(raw[json_start:json_end])
        assert "statements" in data
        assert data["@context"] == "https://openvex.dev/ns/v0.2.0"

    def test_check_remediation_format(self, snyk_path, sample_repo):
        runner = CliRunner()
        result = runner.invoke(
            main,
            [str(snyk_path), "--repo", str(sample_repo), "-f", "remediation", "--no-auto-coverage"],
        )
        assert result.exit_code in (0, 1, 2)
        raw = result.output.strip()
        json_start = raw.index("{")
        json_end = raw.rindex("}") + 1
        data = json.loads(raw[json_start:json_end])
        assert "summary" in data
        assert "actions" in data

    def test_check_action_plan_format(self, snyk_path, sample_repo):
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                str(snyk_path),
                "--repo",
                str(sample_repo),
                "-f",
                "action-plan",
                "--no-auto-coverage",
            ],
        )
        assert result.exit_code in (0, 1, 2)
        raw = result.output.strip()
        json_start = raw.index("{")
        json_end = raw.rindex("}") + 1
        data = json.loads(raw[json_start:json_end])
        assert "decision" in data


class TestCLIConfig:
    def test_config_applies_repo_and_output_paths_relative_to_config(self, tmp_path, monkeypatch):
        project_root = tmp_path / "project"
        repo_dir = project_root / "app"
        subdir = project_root / "subdir"
        output_path = project_root / "out" / "report.json"
        project_root.mkdir()
        repo_dir.mkdir()
        subdir.mkdir()

        (repo_dir / "app.py").write_text("import requests\n")
        (project_root / ".ca9.toml").write_text(
            'repo = "app"\noutput = "out/report.json"\nformat = "json"\nno_auto_coverage = true\nproof_standard = "balanced"\n'
        )

        report_path = project_root / "snyk.json"
        report_path.write_text(
            json.dumps(
                {
                    "vulnerabilities": [
                        {
                            "id": "SNYK-PYTHON-REQUESTS-1",
                            "packageName": "requests",
                            "version": "2.19.1",
                            "severity": "high",
                            "title": "Requests issue",
                            "description": "desc",
                        }
                    ],
                    "projectName": "demo",
                    "packageManager": "pip",
                }
            )
        )

        monkeypatch.chdir(subdir)

        runner = CliRunner()
        result = runner.invoke(main, [str(Path("..") / "snyk.json")])

        assert result.exit_code == 2
        assert output_path.exists()
        data = json.loads(output_path.read_text())
        assert data["proof_standard"] == "balanced"
        assert data["results"][0]["verdict"] == "inconclusive"
