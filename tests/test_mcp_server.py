from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from ca9_mcp import server


class TestMCPServer:
    def test_check_reachability_handles_invalid_json(self, tmp_path):
        report = tmp_path / "report.json"
        report.write_text("{invalid json")

        data = json.loads(server.check_reachability(str(report), repo_path=str(tmp_path)))

        assert data["error_type"] == "JSONDecodeError"
        assert "Invalid JSON" in data["error"]

    def test_scan_dependencies_handles_osv_failure(self, tmp_path):
        with (
            patch("ca9.scanner.get_installed_packages", return_value=[("requests", "2.31.0")]),
            patch("ca9.scanner.query_osv_batch", side_effect=ConnectionError("network down")),
        ):
            data = json.loads(server.scan_dependencies(repo_path=str(tmp_path)))

        assert data["error_type"] == "ConnectionError"
        assert "network down" in data["error"]

    def test_scan_dependencies_prefers_repo_inventory(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")

        with (
            patch("ca9.scanner.get_installed_packages", return_value=[("unused", "0.1.0")]),
            patch("ca9.scanner.query_osv_batch", return_value=[]),
        ):
            data = json.loads(server.scan_dependencies(repo_path=str(tmp_path)))

        assert data["packages_scanned"] == 1
        assert data["inventory_source"] == "repo"
        assert data["message"] == "No known vulnerabilities found in scanned packages."

    def test_main_requires_optional_dependency(self, monkeypatch, capsys):
        monkeypatch.setattr(server, "mcp", None)
        monkeypatch.setattr(server, "_MCP_IMPORT_ERROR", ImportError("No module named 'mcp'"))

        with pytest.raises(SystemExit) as excinfo:
            server.main()

        stderr = capsys.readouterr().err
        assert excinfo.value.code == 1
        assert "pip install ca9[mcp]" in stderr
