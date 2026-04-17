from __future__ import annotations

import json
from unittest.mock import patch

from ca9.models import ThreatIntelData
from ca9.threat_intel import (
    _fetch_epss_batch,
    _fetch_kev_catalog,
    fetch_threat_intel_batch,
)


def _mock_epss_response(cve_ids):
    """Create a mock EPSS API response."""
    data = []
    for cve in cve_ids:
        data.append({"cve": cve, "epss": "0.87", "percentile": "0.97"})
    return json.dumps({"status": "OK", "data": data}).encode()


def _mock_kev_response():
    """Create a mock KEV catalog response."""
    return json.dumps(
        {
            "title": "CISA KEV",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-0001",
                    "vendorProject": "vendor",
                    "product": "product",
                    "dueDate": "2024-03-15",
                },
                {
                    "cveID": "CVE-2024-0002",
                    "vendorProject": "vendor2",
                    "product": "product2",
                    "dueDate": "2024-04-01",
                },
            ],
        }
    ).encode()


class TestFetchEpssBatch:
    def test_parses_response(self):
        with patch("ca9.threat_intel._http_get") as mock_get:
            mock_get.return_value = _mock_epss_response(["CVE-2024-0001"])
            result = _fetch_epss_batch(["CVE-2024-0001"])
            assert "CVE-2024-0001" in result
            score, pctl = result["CVE-2024-0001"]
            assert score == 0.87
            assert pctl == 0.97

    def test_handles_network_failure(self):
        with patch("ca9.threat_intel._http_get", return_value=None):
            result = _fetch_epss_batch(["CVE-2024-0001"])
            assert result == {}

    def test_handles_bad_json(self):
        with patch("ca9.threat_intel._http_get", return_value=b"not json"):
            result = _fetch_epss_batch(["CVE-2024-0001"])
            assert result == {}

    def test_empty_input(self):
        result = _fetch_epss_batch([])
        assert result == {}


class TestFetchKevCatalog:
    def test_parses_catalog(self, tmp_path):
        with (
            patch("ca9.threat_intel._http_get", return_value=_mock_kev_response()),
            patch("ca9.threat_intel._read_cache", return_value=None),
            patch("ca9.threat_intel._write_cache"),
        ):
            result = _fetch_kev_catalog()
            assert "CVE-2024-0001" in result
            assert result["CVE-2024-0001"] == "2024-03-15"
            assert "CVE-2024-0002" in result

    def test_uses_cache(self):
        cached = {"CVE-2024-0001": "2024-03-15"}
        with patch("ca9.threat_intel._read_cache", return_value=cached):
            result = _fetch_kev_catalog()
            assert result == cached

    def test_falls_back_to_stale_cache(self):
        stale = {"CVE-2024-0001": "2024-03-15"}
        with (
            patch("ca9.threat_intel._read_cache", return_value=None),
            patch("ca9.threat_intel._http_get", return_value=None),
            patch("ca9.threat_intel._read_stale_cache", return_value=stale),
        ):
            result = _fetch_kev_catalog()
            assert result == stale


class TestFetchThreatIntelBatch:
    def test_combines_epss_and_kev(self):
        with (
            patch("ca9.threat_intel._fetch_epss_batch") as mock_epss,
            patch("ca9.threat_intel._fetch_kev_catalog") as mock_kev,
            patch("ca9.threat_intel._read_cache", return_value=None),
            patch("ca9.threat_intel._write_cache"),
        ):
            mock_epss.return_value = {
                "CVE-2024-0001": (0.87, 0.97),
            }
            mock_kev.return_value = {
                "CVE-2024-0001": "2024-03-15",
            }

            result = fetch_threat_intel_batch(["CVE-2024-0001", "CVE-2024-9999"])

            assert "CVE-2024-0001" in result
            ti = result["CVE-2024-0001"]
            assert ti.epss_score == 0.87
            assert ti.epss_percentile == 0.97
            assert ti.in_kev is True
            assert ti.kev_due_date == "2024-03-15"

            assert "CVE-2024-9999" in result
            ti2 = result["CVE-2024-9999"]
            assert ti2.epss_score is None
            assert ti2.in_kev is False

    def test_empty_input(self):
        result = fetch_threat_intel_batch([])
        assert result == {}

    def test_uses_cached_epss(self):
        cached_epss = {"CVE-2024-0001": [0.5, 0.8]}
        with (
            patch("ca9.threat_intel._read_cache", return_value=cached_epss),
            patch("ca9.threat_intel._write_cache"),
            patch("ca9.threat_intel._fetch_kev_catalog", return_value={}),
        ):
            result = fetch_threat_intel_batch(["CVE-2024-0001"])
            assert result["CVE-2024-0001"].epss_score == 0.5


class TestThreatIntelData:
    def test_dataclass_creation(self):
        ti = ThreatIntelData(epss_score=0.5, in_kev=True, kev_due_date="2024-01-01")
        assert ti.epss_score == 0.5
        assert ti.in_kev is True

    def test_defaults(self):
        ti = ThreatIntelData()
        assert ti.epss_score is None
        assert ti.epss_percentile is None
        assert ti.in_kev is False
        assert ti.kev_due_date is None
