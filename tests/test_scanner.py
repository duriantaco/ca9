from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from ca9.scanner import (
    ScanInventory,
    _cvss_to_level,
    _extract_severity,
    _parse_cvss_score,
    get_installed_packages,
    query_osv_batch,
    resolve_scan_inventory,
    scan_installed,
    scan_repository,
)


class TestGetInstalledPackages:
    def test_returns_list_of_tuples(self):
        packages = get_installed_packages()
        assert isinstance(packages, list)
        assert len(packages) > 0
        name, version = packages[0]
        assert isinstance(name, str)
        assert isinstance(version, str)

    def test_contains_known_packages(self):
        packages = get_installed_packages()
        names = {name.lower() for name, _ in packages}
        assert "pytest" in names


_BATCH_SINGLE = {"results": [{"vulns": [{"id": "PYSEC-2023-001"}]}]}
_BATCH_MULTIPLE = {
    "results": [
        {"vulns": [{"id": "PYSEC-2023-001"}, {"id": "PYSEC-2023-002"}]},
        {"vulns": []},
    ]
}
_BATCH_EMPTY = {"results": [{"vulns": []}]}
_BATCH_DEDUP = {
    "results": [
        {"vulns": [{"id": "PYSEC-2023-001"}]},
        {"vulns": [{"id": "PYSEC-2023-001"}]},
    ]
}

_VULN_DETAILS = {
    "PYSEC-2023-001": {
        "id": "PYSEC-2023-001",
        "summary": "Remote code execution in example-pkg",
        "severity": [{"type": "CVSS_V3", "score": "9.8"}],
        "database_specific": {"severity": "CRITICAL"},
    },
    "PYSEC-2023-002": {
        "id": "PYSEC-2023-002",
        "summary": "SSRF in requests",
        "database_specific": {"severity": "MEDIUM"},
    },
}


def _mock_urlopen(response_data):
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(response_data).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


class TestQueryOsvBatch:
    @patch("ca9.scanner._fetch_vuln_details")
    @patch("ca9.scanner.urllib.request.urlopen")
    def test_single_vuln(self, mock_urlopen_fn, mock_fetch):
        mock_urlopen_fn.return_value = _mock_urlopen(_BATCH_SINGLE)
        mock_fetch.side_effect = lambda vid, offline=False: _VULN_DETAILS.get(vid, {})

        vulns = query_osv_batch([("example-pkg", "1.0.0")])
        assert len(vulns) == 1
        assert vulns[0].id == "PYSEC-2023-001"
        assert vulns[0].package_name == "example-pkg"
        assert vulns[0].package_version == "1.0.0"
        assert vulns[0].severity == "critical"
        assert "Remote code execution" in vulns[0].title

    @patch("ca9.scanner._fetch_vuln_details")
    @patch("ca9.scanner.urllib.request.urlopen")
    def test_multiple_vulns(self, mock_urlopen_fn, mock_fetch):
        mock_urlopen_fn.return_value = _mock_urlopen(_BATCH_MULTIPLE)
        mock_fetch.side_effect = lambda vid, offline=False: _VULN_DETAILS.get(vid, {})

        vulns = query_osv_batch([("requests", "2.19.1"), ("flask", "2.0.0")])
        assert len(vulns) == 2
        assert vulns[0].id == "PYSEC-2023-001"
        assert vulns[0].severity == "critical"
        assert vulns[1].id == "PYSEC-2023-002"
        assert vulns[1].severity == "medium"

    @patch("ca9.scanner.urllib.request.urlopen")
    def test_empty_response(self, mock_urlopen_fn):
        mock_urlopen_fn.return_value = _mock_urlopen(_BATCH_EMPTY)
        vulns = query_osv_batch([("safe-pkg", "1.0.0")])
        assert vulns == []

    @patch("ca9.scanner._fetch_vuln_details")
    @patch("ca9.scanner.urllib.request.urlopen")
    def test_dedup_same_package(self, mock_urlopen_fn, mock_fetch):
        batch = {
            "results": [
                {"vulns": [{"id": "PYSEC-2023-001"}, {"id": "PYSEC-2023-001"}]},
            ]
        }
        mock_urlopen_fn.return_value = _mock_urlopen(batch)
        mock_fetch.side_effect = lambda vid, offline=False: _VULN_DETAILS.get(vid, {})

        vulns = query_osv_batch([("pkg-a", "1.0")])
        assert len(vulns) == 1

    @patch("ca9.scanner._fetch_vuln_details")
    @patch("ca9.scanner.urllib.request.urlopen")
    def test_same_cve_different_packages_preserved(self, mock_urlopen_fn, mock_fetch):
        mock_urlopen_fn.return_value = _mock_urlopen(_BATCH_DEDUP)
        mock_fetch.side_effect = lambda vid, offline=False: _VULN_DETAILS.get(vid, {})

        vulns = query_osv_batch([("pkg-a", "1.0"), ("pkg-b", "2.0")])
        assert len(vulns) == 2
        pkg_names = {v.package_name for v in vulns}
        assert pkg_names == {"pkg-a", "pkg-b"}

    def test_empty_input(self):
        vulns = query_osv_batch([])
        assert vulns == []

    @patch("ca9.scanner.urllib.request.urlopen")
    def test_network_error(self, mock_urlopen_fn):
        import urllib.error

        mock_urlopen_fn.side_effect = urllib.error.URLError("Connection refused")
        with pytest.raises(ConnectionError, match="OSV.dev API request failed"):
            query_osv_batch([("requests", "2.19.1")])

    @patch("ca9.scanner.urllib.request.urlopen")
    def test_malformed_json(self, mock_urlopen_fn):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"not json at all"
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen_fn.return_value = mock_resp
        with pytest.raises(ValueError, match="malformed JSON"):
            query_osv_batch([("requests", "2.19.1")])

    @patch("ca9.scanner._fetch_vuln_details")
    @patch("ca9.scanner.urllib.request.urlopen")
    def test_fetch_failure_graceful(self, mock_urlopen_fn, mock_fetch):
        mock_urlopen_fn.return_value = _mock_urlopen(_BATCH_SINGLE)
        mock_fetch.return_value = {}

        vulns = query_osv_batch([("example-pkg", "1.0.0")])
        assert len(vulns) == 1
        assert vulns[0].severity == "unknown"


class TestExtractSeverity:
    def test_database_specific_first(self):
        vuln = {
            "database_specific": {"severity": "HIGH"},
            "severity": [{"type": "CVSS_V3", "score": "5.0"}],
        }
        assert _extract_severity(vuln) == "high"

    def test_cvss_v3(self):
        assert _extract_severity({"severity": [{"type": "CVSS_V3", "score": "9.8"}]}) == "critical"

    def test_cvss_v4(self):
        assert _extract_severity({"severity": [{"type": "CVSS_V4", "score": "7.5"}]}) == "high"

    def test_cvss_medium(self):
        assert _extract_severity({"severity": [{"type": "CVSS_V3", "score": "5.0"}]}) == "medium"

    def test_cvss_low(self):
        assert _extract_severity({"severity": [{"type": "CVSS_V3", "score": "2.0"}]}) == "low"

    def test_ecosystem_specific(self):
        vuln = {"affected": [{"ecosystem_specific": {"severity": "Medium"}}]}
        assert _extract_severity(vuln) == "medium"

    def test_cvss_vector_string(self):
        vuln = {
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
            ]
        }
        assert _extract_severity(vuln) == "critical"

    def test_unknown_fallback(self):
        assert _extract_severity({}) == "unknown"
        assert _extract_severity({"severity": []}) == "unknown"


class TestParseCvssScore:
    def test_plain_numeric(self):
        assert _parse_cvss_score("9.8") == 9.8

    def test_cvss_v3_critical_vector(self):
        score = _parse_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score == 9.8

    def test_cvss_v3_high_vector(self):
        score = _parse_cvss_score("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H")
        assert score == 7.2

    def test_cvss_v3_medium_vector(self):
        score = _parse_cvss_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N")
        assert score == 4.2

    def test_cvss_v3_scope_changed(self):
        score = _parse_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert score == 10.0

    def test_cvss_v30(self):
        score = _parse_cvss_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score == 9.8

    def test_cvss_v2_returns_none(self):
        assert _parse_cvss_score("AV:N/AC:L/Au:N/C:P/I:P/A:P") is None

    def test_incomplete_vector_returns_none(self):
        assert _parse_cvss_score("CVSS:3.1/AV:N/AC:L") is None

    def test_empty_returns_none(self):
        assert _parse_cvss_score("") is None

    def test_none_returns_none(self):
        assert _parse_cvss_score(None) is None

    def test_no_impact_returns_zero(self):
        score = _parse_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        assert score == 0.0


class TestCvssToLevel:
    def test_ranges(self):
        assert _cvss_to_level(10.0) == "critical"
        assert _cvss_to_level(9.0) == "critical"
        assert _cvss_to_level(8.0) == "high"
        assert _cvss_to_level(7.0) == "high"
        assert _cvss_to_level(5.0) == "medium"
        assert _cvss_to_level(4.0) == "medium"
        assert _cvss_to_level(1.0) == "low"
        assert _cvss_to_level(0.0) == "unknown"


class TestScanInstalled:
    @patch("ca9.scanner.query_osv_batch")
    @patch("ca9.scanner.get_installed_packages")
    def test_wires_together(self, mock_get, mock_query):
        mock_get.return_value = [("requests", "2.19.1")]
        mock_query.return_value = []
        result = scan_installed()
        mock_get.assert_called_once()
        mock_query.assert_called_once_with(
            [("requests", "2.19.1")],
            offline=False,
            refresh_cache=False,
            max_workers=8,
        )
        assert result == []


class TestOfflineMode:
    def test_offline_returns_cached_vulns(self, tmp_path, monkeypatch):
        from ca9 import scanner

        cache_dir = tmp_path / "osv_cache"
        cache_dir.mkdir()
        monkeypatch.setattr(scanner, "CACHE_DIR", cache_dir)

        vuln_data = {
            "id": "PYSEC-2023-TEST",
            "summary": "Test vuln in requests",
            "details": "A test vulnerability",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "requests"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "2.0.0"},
                                {"fixed": "2.25.0"},
                            ],
                        }
                    ],
                }
            ],
            "database_specific": {"severity": "HIGH"},
        }
        (cache_dir / "PYSEC-2023-TEST.json").write_text(json.dumps(vuln_data))

        vulns = scanner._query_from_cache_only([("requests", "2.19.1")])
        assert len(vulns) == 1
        assert vulns[0].id == "PYSEC-2023-TEST"
        assert vulns[0].package_name == "requests"
        assert vulns[0].package_version == "2.19.1"
        assert vulns[0].severity == "high"

    def test_offline_skips_unrelated_packages(self, tmp_path, monkeypatch):
        from ca9 import scanner

        cache_dir = tmp_path / "osv_cache"
        cache_dir.mkdir()
        monkeypatch.setattr(scanner, "CACHE_DIR", cache_dir)

        vuln_data = {
            "id": "PYSEC-2023-TEST",
            "summary": "Test vuln",
            "affected": [
                {"package": {"ecosystem": "PyPI", "name": "requests"}},
            ],
        }
        (cache_dir / "PYSEC-2023-TEST.json").write_text(json.dumps(vuln_data))

        vulns = scanner._query_from_cache_only([("flask", "2.0.0")])
        assert len(vulns) == 0

    def test_offline_empty_cache(self, tmp_path, monkeypatch):
        from ca9 import scanner

        cache_dir = tmp_path / "osv_cache"
        cache_dir.mkdir()
        monkeypatch.setattr(scanner, "CACHE_DIR", cache_dir)

        vulns = scanner._query_from_cache_only([("requests", "2.19.1")])
        assert vulns == []

    def test_offline_no_cache_dir(self, tmp_path, monkeypatch):
        from ca9 import scanner

        monkeypatch.setattr(scanner, "CACHE_DIR", tmp_path / "nonexistent")

        vulns = scanner._query_from_cache_only([("requests", "2.19.1")])
        assert vulns == []

    def test_query_osv_batch_offline_delegates(self, tmp_path, monkeypatch):
        from ca9 import scanner

        cache_dir = tmp_path / "osv_cache"
        cache_dir.mkdir()
        monkeypatch.setattr(scanner, "CACHE_DIR", cache_dir)

        vuln_data = {
            "id": "PYSEC-2023-OFFLINE",
            "summary": "Offline test",
            "affected": [
                {"package": {"ecosystem": "PyPI", "name": "requests"}},
            ],
            "database_specific": {"severity": "MEDIUM"},
        }
        (cache_dir / "PYSEC-2023-OFFLINE.json").write_text(json.dumps(vuln_data))

        vulns = query_osv_batch([("requests", "2.19.1")], offline=True)
        assert len(vulns) == 1
        assert vulns[0].id == "PYSEC-2023-OFFLINE"


class TestResolveScanInventory:
    @patch("ca9.scanner.get_installed_packages")
    def test_prefers_repo_declared_packages(self, mock_get, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "requirements.txt").write_text("requests==2.31.0\n")
        (repo / "pyproject.toml").write_text('[tool.poetry.dependencies]\ndjango = "^5.0"\n')

        mock_get.return_value = [("Django", "5.0.2"), ("unused", "1.0.0")]

        inventory = resolve_scan_inventory(repo)

        assert isinstance(inventory, ScanInventory)
        assert inventory.source == "repo"
        assert inventory.packages == (("django", "5.0.2"), ("requests", "2.31.0"))
        assert inventory.pinned_dependencies == 1
        assert inventory.environment_fallbacks == 1
        assert any("used installed environment versions" in w for w in inventory.warnings)

    @patch("ca9.scanner.get_installed_packages")
    def test_falls_back_when_no_repo_inventory(self, mock_get, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        mock_get.return_value = [("requests", "2.31.0")]

        inventory = resolve_scan_inventory(repo)

        assert inventory.source == "environment"
        assert inventory.packages == (("requests", "2.31.0"),)
        assert any("fell back to installed environment packages" in w for w in inventory.warnings)

    @patch("ca9.scanner.get_installed_packages")
    def test_prefers_lockfile_versions_over_environment_fallback(self, mock_get, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "pyproject.toml").write_text(
            '[project]\nname = "demo-app"\ndependencies = ["requests>=2.0"]\n'
        )
        (repo / "uv.lock").write_text(
            """
version = 1

[[package]]
name = "requests"
version = "2.32.3"

[[package]]
name = "demo-app"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "requests" },
]
""".strip()
        )
        mock_get.return_value = [("requests", "2.19.1")]

        inventory = resolve_scan_inventory(repo)

        assert inventory.source == "repo"
        assert inventory.packages == (("requests", "2.32.3"),)
        assert inventory.pinned_dependencies == 1
        assert inventory.environment_fallbacks == 0

    @patch("ca9.scanner.get_installed_packages")
    def test_uses_pipfile_lock_versions(self, mock_get, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "Pipfile.lock").write_text(
            """
{
  "_meta": {"pipfile-spec": 6},
  "default": {
    "requests": {"version": "==2.32.3"}
  }
}
""".strip()
        )
        mock_get.return_value = [("requests", "2.19.1")]

        inventory = resolve_scan_inventory(repo)

        assert inventory.source == "repo"
        assert inventory.packages == (("requests", "2.32.3"),)
        assert inventory.pinned_dependencies == 1
        assert inventory.environment_fallbacks == 0


class TestScanRepository:
    @patch("ca9.scanner.query_osv_batch")
    @patch("ca9.scanner.get_installed_packages")
    def test_uses_repo_inventory_for_osv_query(self, mock_get, mock_query, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "requirements.txt").write_text("requests==2.31.0\n")
        mock_get.return_value = [("unused", "1.0.0")]
        mock_query.return_value = []

        vulns, inventory = scan_repository(repo)

        assert vulns == []
        assert inventory.source == "repo"
        mock_query.assert_called_once_with(
            [("requests", "2.31.0")],
            offline=False,
            refresh_cache=False,
            max_workers=8,
        )
