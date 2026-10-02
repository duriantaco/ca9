from __future__ import annotations

import json
import os
import time
from unittest.mock import MagicMock, patch

import pytest

from ca9.models import VersionRange
from ca9.scanner import (
    ScanInventory,
    _cvss_to_level,
    _extract_severity,
    _extract_version_ranges,
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
        "aliases": ["CVE-2023-0001"],
        "severity": [{"type": "CVSS_V3", "score": "9.8"}],
        "database_specific": {"severity": "CRITICAL", "cwe_ids": ["CWE-94"]},
        "published": "2023-01-01T00:00:00Z",
        "modified": "2023-01-02T00:00:00Z",
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
        assert vulns[0].aliases == ("CVE-2023-0001",)
        assert vulns[0].cwes == ("CWE-94",)
        assert vulns[0].advisory_source == "osv.dev"
        assert vulns[0].advisory_url == "https://osv.dev/vulnerability/PYSEC-2023-001"
        assert vulns[0].published_at == "2023-01-01T00:00:00Z"
        assert vulns[0].modified_at == "2023-01-02T00:00:00Z"
        assert vulns[0].fetched_at is not None
        assert vulns[0].cache_stale is False
        assert vulns[0].malicious is False

    @patch("ca9.scanner._fetch_vuln_details")
    @patch("ca9.scanner.urllib.request.urlopen")
    def test_npm_query_preserves_ecosystem_and_malware_classification(
        self, mock_urlopen_fn, mock_fetch
    ):
        mock_urlopen_fn.return_value = _mock_urlopen(
            {"results": [{"vulns": [{"id": "GHSA-g7cv-rxg3-hmpx"}]}]}
        )
        mock_fetch.return_value = {
            "id": "GHSA-g7cv-rxg3-hmpx",
            "aliases": ["MAL-2026-3345"],
            "summary": "Malware in npm packages exfiltrates cloud credentials",
            "affected": [
                {"package": {"ecosystem": "npm", "name": "@tanstack/history"}},
            ],
        }

        vulns = query_osv_batch([("@tanstack/history", "1.161.9")], ecosystem="npm")

        request = mock_urlopen_fn.call_args[0][0]
        payload = json.loads(request.data.decode())
        assert payload["queries"][0]["package"]["ecosystem"] == "npm"
        assert vulns[0].ecosystem == "npm"
        assert vulns[0].malicious is True
        assert vulns[0].package_name == "@tanstack/history"

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


class TestExtractVersionRanges:
    def test_preserves_multiple_intervals_in_one_osv_range(self):
        vulnerability = {
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "requests"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "1.0"},
                                {"introduced": "1.5"},
                                {"fixed": "1.9"},
                                {"introduced": "2.1"},
                            ],
                        }
                    ],
                }
            ]
        }

        assert _extract_version_ranges(vulnerability, "requests", "pypi") == (
            VersionRange(introduced="0", fixed="1.0"),
            VersionRange(introduced="1.5", fixed="1.9"),
            VersionRange(introduced="2.1"),
        )


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
            "aliases": ["CVE-2023-9999"],
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
        assert vulns[0].aliases == ("CVE-2023-9999",)
        assert vulns[0].fetched_at is not None
        assert vulns[0].cache_stale is False

    def test_offline_can_match_npm_cached_vulns(self, tmp_path, monkeypatch):
        from ca9 import scanner

        cache_dir = tmp_path / "osv_cache"
        cache_dir.mkdir()
        monkeypatch.setattr(scanner, "CACHE_DIR", cache_dir)

        vuln_data = {
            "id": "GHSA-g7cv-rxg3-hmpx",
            "aliases": ["MAL-2026-3345"],
            "summary": "Malware in npm packages exfiltrates cloud credentials",
            "affected": [
                {"package": {"ecosystem": "npm", "name": "@tanstack/history"}},
            ],
        }
        (cache_dir / "GHSA-g7cv-rxg3-hmpx.json").write_text(json.dumps(vuln_data))

        vulns = scanner._query_from_cache_only(
            [("@tanstack/history", "1.161.9")],
            ecosystem="npm",
        )

        assert len(vulns) == 1
        assert vulns[0].ecosystem == "npm"
        assert vulns[0].malicious is True

    def test_offline_returns_stale_cached_vulns_with_freshness_flag(self, tmp_path, monkeypatch):
        from ca9 import scanner

        cache_dir = tmp_path / "osv_cache"
        cache_dir.mkdir()
        monkeypatch.setattr(scanner, "CACHE_DIR", cache_dir)

        vuln_data = {
            "id": "PYSEC-2023-STALE",
            "summary": "Stale cached vuln in requests",
            "affected": [
                {"package": {"ecosystem": "PyPI", "name": "requests"}},
            ],
        }
        cache_file = cache_dir / "PYSEC-2023-STALE.json"
        cache_file.write_text(json.dumps(vuln_data))
        old_time = time.time() - scanner.CACHE_TTL_SECONDS - 60

        os.utime(cache_file, (old_time, old_time))

        vulns = scanner._query_from_cache_only([("requests", "2.19.1")])

        assert len(vulns) == 1
        assert vulns[0].id == "PYSEC-2023-STALE"
        assert vulns[0].cache_stale is True
        assert vulns[0].fetched_at is not None

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
        assert inventory.packages == (("requests", "2.31.0"),)
        assert inventory.pinned_dependencies == 1
        assert inventory.environment_fallbacks == 0
        assert any("skipped declared package" in w for w in inventory.warnings)

    @patch("ca9.scanner.get_installed_packages")
    def test_allows_environment_fallback_when_requested(self, mock_get, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "pyproject.toml").write_text('[tool.poetry.dependencies]\ndjango = "^5.0"\n')
        mock_get.return_value = [("Django", "5.0.2"), ("unused", "1.0.0")]

        inventory = resolve_scan_inventory(repo, allow_environment_fallback=True)

        assert inventory.source == "repo"
        assert inventory.packages == (("django", "5.0.2"),)
        assert inventory.environment_fallbacks == 1
        assert any("used installed environment versions" in w for w in inventory.warnings)

    @patch("ca9.scanner.get_installed_packages")
    def test_does_not_fall_back_when_no_repo_inventory_by_default(self, mock_get, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        mock_get.return_value = [("requests", "2.31.0")]

        inventory = resolve_scan_inventory(repo)

        assert inventory.source == "none"
        assert inventory.packages == ()
        assert any("no declared dependencies" in w for w in inventory.warnings)

    @patch("ca9.scanner.get_installed_packages")
    def test_falls_back_when_no_repo_inventory_if_allowed(self, mock_get, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        mock_get.return_value = [("requests", "2.31.0")]

        inventory = resolve_scan_inventory(repo, allow_environment_fallback=True)

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


# An ordinary GHSA whose prose uses words the old free-text classifier keyed on.
_AXIOS_SSRF = {
    "id": "GHSA-3p68-rc4w-qgx5",
    "aliases": ["CVE-2025-27152"],
    "summary": "axios Requests Vulnerable To Possible SSRF and Credential Leakage via Absolute URL",
    "details": (
        "A malicious package of requests can pass an absolute URL, letting an attacker "
        "exfiltrate credentials such as API keys to a third-party host."
    ),
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "axios"},
            "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.8.2"}]}
            ],
        }
    ],
    "references": [{"type": "WEB", "url": "https://github.com/axios/axios/issues/6463"}],
    "database_specific": {"github_reviewed": True, "severity": "HIGH", "cwe_ids": ["CWE-918"]},
}

_OPENSSF_MALWARE = {
    "id": "MAL-2025-3345",
    "summary": "Malicious code in evil-pkg (npm)",
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "evil-pkg"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
        }
    ],
    "database_specific": {
        "malicious-packages-origins": [{"source": "ghsa-malware", "id": "GHSA-aaaa-bbbb-cccc"}]
    },
}


class TestMaliciousClassification:
    def test_ordinary_advisory_prose_is_not_malware(self):
        from ca9.scanner import _is_malicious_osv

        assert _is_malicious_osv(_AXIOS_SSRF, _AXIOS_SSRF["id"]) is False

    def test_mal_ids_aliases_and_openssf_origins_are_malware(self):
        from ca9.scanner import _is_malicious_osv

        assert _is_malicious_osv(_OPENSSF_MALWARE, "MAL-2025-3345") is True
        assert _is_malicious_osv({"id": "GHSA-x", "aliases": ["MAL-2025-1"]}, "GHSA-x") is True
        origins_only = {
            "id": "GHSA-aaaa-bbbb-cccc",
            "database_specific": {"malicious-packages-origins": [{"source": "ghsa-malware"}]},
        }
        assert _is_malicious_osv(origins_only, "GHSA-aaaa-bbbb-cccc") is True

    @patch("ca9.scanner._fetch_vuln_details")
    @patch("ca9.scanner.urllib.request.urlopen")
    def test_query_does_not_flag_ordinary_cve_as_malicious(self, mock_urlopen_fn, mock_fetch):
        mock_urlopen_fn.return_value = _mock_urlopen(
            {"results": [{"vulns": [{"id": "GHSA-3p68-rc4w-qgx5"}]}]}
        )
        mock_fetch.return_value = _AXIOS_SSRF

        vulns = query_osv_batch([("axios", "1.7.0")], ecosystem="npm")

        assert [vuln.malicious for vuln in vulns] == [False]


def _write_cached_advisory(cache_dir, data):
    cache_dir.mkdir(exist_ok=True)
    (cache_dir / f"{data['id']}.json").write_text(json.dumps(data))


class TestOfflineVersionFiltering:
    def _cache(self, tmp_path, monkeypatch, *records):
        from ca9 import scanner

        cache_dir = tmp_path / "osv_cache"
        for record in records:
            _write_cached_advisory(cache_dir, record)
        monkeypatch.setattr(scanner, "CACHE_DIR", cache_dir)
        return scanner

    def test_fixed_version_is_not_reported_offline(self, tmp_path, monkeypatch):
        scanner = self._cache(
            tmp_path,
            monkeypatch,
            {
                "id": "PYSEC-2023-RANGE",
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "requests"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [{"introduced": "2.0.0"}, {"fixed": "2.25.0"}],
                            }
                        ],
                    }
                ],
            },
        )

        assert scanner._query_from_cache_only([("requests", "2.31.0")]) == []
        assert scanner._query_from_cache_only([("requests", "1.9.0")]) == []
        assert len(scanner._query_from_cache_only([("requests", "2.19.1")])) == 1
        assert len(query_osv_batch([("requests", "2.24.0")], offline=True)) == 1
        assert query_osv_batch([("requests", "2.25.0")], offline=True) == []

    def test_npm_semver_ranges_and_explicit_versions(self, tmp_path, monkeypatch):
        listed = {
            "id": "GHSA-listed",
            "affected": [
                {"package": {"ecosystem": "npm", "name": "listed"}, "versions": ["1.0.0"]}
            ],
        }
        last_affected = {
            "id": "GHSA-last",
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "lastpkg"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [{"introduced": "0"}, {"last_affected": "2.0.0"}],
                        }
                    ],
                }
            ],
        }
        scanner = self._cache(tmp_path, monkeypatch, _AXIOS_SSRF, listed, last_affected)

        def ids(name, version):
            return [v.id for v in scanner._query_from_cache_only([(name, version)], "npm")]

        assert ids("axios", "1.7.0") == ["GHSA-3p68-rc4w-qgx5"]
        assert ids("axios", "1.8.2") == []
        assert ids("listed", "1.0.0") == ["GHSA-listed"]
        assert ids("listed", "1.0.1") == []
        assert ids("lastpkg", "2.0.0") == ["GHSA-last"]
        assert ids("lastpkg", "2.0.1") == []

    def test_whole_package_and_uncomparable_versions_stay_reported(self, tmp_path, monkeypatch):
        scanner = self._cache(tmp_path, monkeypatch, _OPENSSF_MALWARE, _AXIOS_SSRF)

        malware = scanner._query_from_cache_only([("evil-pkg", "9.9.9")], "npm")
        assert [(v.id, v.malicious) for v in malware] == [("MAL-2025-3345", True)]
        # ca9 cannot order this version, so it errs toward reporting the advisory.
        assert len(scanner._query_from_cache_only([("axios", "not-a-version")], "npm")) == 1

    def test_pypi_names_are_normalized(self, tmp_path, monkeypatch):
        scanner = self._cache(
            tmp_path,
            monkeypatch,
            {
                "id": "PYSEC-NAME",
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "Requests_OAuthlib"},
                        "versions": ["1.0"],
                    }
                ],
            },
        )

        assert len(scanner._query_from_cache_only([("requests-oauthlib", "1.0")])) == 1


class _FakeOsvTransport:
    """Stands in for urlopen: records each querybatch payload and replies per call."""

    def __init__(self, responder):
        self.responder = responder
        self.payloads: list[dict] = []

    def __call__(self, request, timeout=None):
        payload = json.loads(request.data.decode())
        self.payloads.append(payload)
        reply = self.responder(payload, len(self.payloads))
        if isinstance(reply, Exception):
            raise reply
        return _mock_urlopen(reply)


def _http_error(code, headers=None):
    import urllib.error

    return urllib.error.HTTPError(
        "https://api.osv.dev/v1/querybatch", code, "err", headers or {}, None
    )


class TestOsvBatchTransport:
    @patch("ca9.scanner._fetch_vuln_details", return_value={})
    def test_large_inventories_are_chunked_at_osv_limit(self, _mock_fetch):
        def responder(payload, _call):
            return {
                "results": [
                    {"vulns": [{"id": "PYSEC-HIT"}]} if q["package"]["name"] == "pkg-1500" else {}
                    for q in payload["queries"]
                ]
            }

        transport = _FakeOsvTransport(responder)
        packages = [(f"pkg-{index}", "1.0.0") for index in range(2500)]
        with patch("ca9.scanner.urllib.request.urlopen", transport):
            vulns = query_osv_batch(packages)

        assert [len(p["queries"]) for p in transport.payloads] == [1000, 1000, 500]
        assert [(v.id, v.package_name) for v in vulns] == [("PYSEC-HIT", "pkg-1500")]

    @patch("ca9.scanner._fetch_vuln_details", return_value={})
    def test_rate_limits_and_server_errors_are_retried_with_backoff(self, _mock_fetch):
        replies = [
            _http_error(429, {"Retry-After": "2"}),
            _http_error(503),
            {"results": [{"vulns": [{"id": "PYSEC-OK"}]}]},
        ]
        transport = _FakeOsvTransport(lambda _payload, call: replies[call - 1])

        with (
            patch("ca9.scanner.urllib.request.urlopen", transport),
            patch("ca9.scanner.time.sleep") as mock_sleep,
        ):
            vulns = query_osv_batch([("pkg", "1.0.0")])

        assert [v.id for v in vulns] == ["PYSEC-OK"]
        assert [c.args[0] for c in mock_sleep.call_args_list] == [2.0, 1.0]

    def test_persistent_server_errors_give_up_after_bounded_retries(self):
        from ca9 import scanner

        transport = _FakeOsvTransport(lambda _payload, _call: _http_error(503))
        with (
            patch("ca9.scanner.urllib.request.urlopen", transport),
            patch("ca9.scanner.time.sleep") as mock_sleep,
            pytest.raises(ConnectionError, match="OSV.dev API request failed"),
        ):
            query_osv_batch([("pkg", "1.0.0")])

        assert len(transport.payloads) == scanner.OSV_BATCH_MAX_ATTEMPTS
        delays = [c.args[0] for c in mock_sleep.call_args_list]
        assert delays == sorted(delays)
        assert max(delays) <= scanner.OSV_BATCH_MAX_BACKOFF_SECONDS

    def test_client_errors_are_not_retried(self):
        transport = _FakeOsvTransport(lambda _payload, _call: _http_error(400))
        with (
            patch("ca9.scanner.urllib.request.urlopen", transport),
            patch("ca9.scanner.time.sleep") as mock_sleep,
            pytest.raises(ConnectionError),
        ):
            query_osv_batch([("pkg", "1.0.0")])

        assert len(transport.payloads) == 1
        mock_sleep.assert_not_called()

    @patch("ca9.scanner._fetch_vuln_details", return_value={})
    def test_next_page_token_is_followed_per_query(self, _mock_fetch):
        def responder(payload, call):
            if call == 1:
                return {
                    "results": [
                        {"vulns": [{"id": "PYSEC-A"}], "next_page_token": "tok-1"},
                        {"vulns": [{"id": "PYSEC-C"}]},
                    ]
                }
            assert payload["queries"] == [
                {
                    "package": {"name": "first", "ecosystem": "PyPI"},
                    "version": "1.0.0",
                    "page_token": "tok-1",
                }
            ]
            return {"results": [{"vulns": [{"id": "PYSEC-B"}]}]}

        transport = _FakeOsvTransport(responder)
        with patch("ca9.scanner.urllib.request.urlopen", transport):
            vulns = query_osv_batch([("first", "1.0.0"), ("second", "2.0.0")])

        assert len(transport.payloads) == 2
        assert sorted((v.package_name, v.id) for v in vulns) == [
            ("first", "PYSEC-A"),
            ("first", "PYSEC-B"),
            ("second", "PYSEC-C"),
        ]

    def test_endless_pagination_is_bounded(self, monkeypatch):
        from ca9 import scanner

        monkeypatch.setattr(scanner, "OSV_BATCH_MAX_PAGES", 3)
        transport = _FakeOsvTransport(
            lambda _payload, _call: {"results": [{"vulns": [], "next_page_token": "again"}]}
        )
        with (
            patch("ca9.scanner.urllib.request.urlopen", transport),
            pytest.raises(ValueError, match="result pages"),
        ):
            query_osv_batch([("pkg", "1.0.0")])

        assert len(transport.payloads) == 3
