from __future__ import annotations

import json


class TestEngineIntegration:
    def test_analyze_with_capabilities(self, tmp_path):
        from ca9.engine import analyze
        from ca9.models import Vulnerability

        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("import requests\n")
        (repo / "mcp.json").write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "shell-runner": {
                            "command": "bash",
                            "tools": [{"name": "run_command"}],
                        }
                    }
                }
            )
        )
        (repo / "requirements.txt").write_text("requests==2.31.0\n")

        cov_path = tmp_path / "coverage.json"
        cov_path.write_text(
            json.dumps(
                {
                    "files": {
                        "/site-packages/requests/__init__.py": {"executed_lines": [1, 2]},
                    },
                    "totals": {"percent_covered": 95.0},
                }
            )
        )

        vulns = [
            Vulnerability(
                id="CVE-TEST-1",
                package_name="requests",
                package_version="2.31.0",
                severity="high",
                title="Test vuln",
            )
        ]

        report = analyze(vulns, repo, cov_path, proof_standard="balanced", scan_capabilities=True)
        assert report.results[0].verdict.value == "reachable"
        assert report.results[0].blast_radius is not None
        assert "exec.shell" in report.results[0].blast_radius.capabilities

    def test_analyze_without_capabilities_has_no_blast_radius(self, tmp_path):
        from ca9.engine import analyze
        from ca9.models import Vulnerability

        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("import requests\n")
        (repo / "requirements.txt").write_text("requests==2.31.0\n")

        cov_path = tmp_path / "coverage.json"
        cov_path.write_text(
            json.dumps(
                {
                    "files": {
                        "/site-packages/requests/__init__.py": {"executed_lines": [1, 2]},
                    },
                    "totals": {"percent_covered": 95.0},
                }
            )
        )

        vulns = [
            Vulnerability(
                id="CVE-TEST-1",
                package_name="requests",
                package_version="2.31.0",
                severity="high",
                title="Test vuln",
            )
        ]

        report = analyze(vulns, repo, cov_path, proof_standard="balanced", scan_capabilities=False)
        assert report.results[0].blast_radius is None


class TestPathMatching:
    def test_exact_match(self):
        from ca9.engine import _paths_match

        assert _paths_match("app.py", "app.py")

    def test_suffix_match_with_boundary(self):
        from ca9.engine import _paths_match

        assert _paths_match("src/app.py", "app.py")
        assert _paths_match("app.py", "src/app.py")

    def test_no_false_match_on_partial_name(self):
        from ca9.engine import _paths_match

        assert not _paths_match("app.py", "myapp.py")
        assert not _paths_match("myapp.py", "app.py")

    def test_path_boundary_match(self):
        from ca9.engine import _paths_match

        assert _paths_match("tests/requests/__init__.py", "requests/__init__.py")
        assert _paths_match("site-packages/requests/__init__.py", "requests/__init__.py")
        assert not _paths_match("fakerequests/__init__.py", "requests/__init__.py")

    def test_normalize_strips_dot_slash(self):
        from ca9.engine import _normalize_path_for_match

        assert _normalize_path_for_match("./src/app.py") == "src/app.py"

    def test_normalize_converts_backslash(self):
        from ca9.engine import _normalize_path_for_match

        assert _normalize_path_for_match("src\\app.py") == "src/app.py"

    def test_blast_radius_not_attached_to_unreachable(self, tmp_path):
        from ca9.engine import analyze
        from ca9.models import Vulnerability

        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("# nothing\n")
        (repo / "mcp.json").write_text(
            json.dumps({"mcpServers": {"shell": {"command": "bash", "tools": [{"name": "exec"}]}}})
        )

        vulns = [
            Vulnerability(
                id="CVE-1",
                package_name="nonexistent",
                package_version="1.0",
                severity="high",
                title="t",
            )
        ]
        report = analyze(vulns, repo, proof_standard="balanced", scan_capabilities=True)
        assert report.results[0].blast_radius is None


class TestCLICapabilities:
    def test_capabilities_command(self, tmp_path):
        from click.testing import CliRunner

        from ca9.cli import main

        (tmp_path / "app.py").write_text("from anthropic import Anthropic\n")

        runner = CliRunner()
        result = runner.invoke(main, ["capabilities", "--repo", str(tmp_path)])

        assert result.exit_code == 0
        assert "Components" in result.output

    def test_capabilities_json_output(self, tmp_path):
        from click.testing import CliRunner

        from ca9.cli import main

        (tmp_path / "mcp.json").write_text(json.dumps({"mcpServers": {"fs": {"command": "node"}}}))

        runner = CliRunner()
        result = runner.invoke(main, ["capabilities", "--repo", str(tmp_path), "-f", "json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["bomFormat"] == "CycloneDX"


class TestVEXEdgeCases:
    def test_vex_with_empty_report(self):
        from ca9.models import Report
        from ca9.vex import write_openvex

        report = Report(results=[], repo_path=".")
        text = write_openvex(report)
        data = json.loads(text)
        assert data["statements"] == []
        assert data["@context"] == "https://openvex.dev/ns/v0.2.0"


class TestRemediationEdgeCases:
    def test_remediation_with_none_blast_radius_on_reachable(self):
        from ca9.models import Report, Verdict, VerdictResult, Vulnerability
        from ca9.remediation import generate_remediation_plan, remediation_plan_to_dict

        vuln = Vulnerability(
            id="CVE-2023-0001",
            package_name="requests",
            package_version="1.0.0",
            severity="high",
            title="Test vuln",
        )
        result = VerdictResult(
            vulnerability=vuln,
            verdict=Verdict.REACHABLE,
            reason="imported and executed",
            blast_radius=None,
        )
        report = Report(results=[result], repo_path=".")
        plan = generate_remediation_plan(report)
        data = remediation_plan_to_dict(plan)
        assert "summary" in data
        assert "actions" in data
        assert len(plan) == 1


class TestActionPlanEdgeCases:
    def test_all_unreachable_gives_pass(self):
        from ca9.action_plan import generate_action_plan
        from ca9.models import Report, Verdict, VerdictResult, Vulnerability

        vuln = Vulnerability(
            id="CVE-2023-0001",
            package_name="requests",
            package_version="1.0.0",
            severity="high",
            title="Test vuln",
        )
        result = VerdictResult(
            vulnerability=vuln,
            verdict=Verdict.UNREACHABLE_STATIC,
            reason="not imported",
        )
        report = Report(results=[result], repo_path=".")
        plan = generate_action_plan(report)
        assert plan.decision == "pass"
        assert plan.exit_code == 0
