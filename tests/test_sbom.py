from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from ca9.models import Evidence, Report, Verdict, VerdictResult, Vulnerability
from ca9.sbom import (
    _extract_cyclonedx_components,
    _extract_spdx_packages,
    _parse_purl,
    _worst_verdict,
    detect_sbom_format,
    enrich_sbom,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestDetectFormat:
    def test_cyclonedx(self):
        assert detect_sbom_format({"bomFormat": "CycloneDX"}) == "cyclonedx"

    def test_spdx(self):
        assert detect_sbom_format({"spdxVersion": "SPDX-2.3"}) == "spdx"

    def test_unknown(self):
        import pytest

        with pytest.raises(ValueError, match="Unknown SBOM format"):
            detect_sbom_format({"random": "data"})


class TestParsePurl:
    def test_basic(self):
        assert _parse_purl("pkg:pypi/requests@2.31.0") == ("requests", "2.31.0")

    def test_no_version(self):
        assert _parse_purl("pkg:pypi/requests") == ("requests", "")

    def test_with_qualifiers(self):
        assert _parse_purl("pkg:pypi/requests@2.31.0?vcs_url=...") == ("requests", "2.31.0")

    def test_non_pypi(self):
        assert _parse_purl("pkg:npm/lodash@4.17.21") == ("", "")


class TestExtractComponents:
    def test_cyclonedx(self):
        data = json.loads((FIXTURES / "sample_cyclonedx.json").read_text())
        components = _extract_cyclonedx_components(data)
        names = [c.get("name") for c in components]
        assert "requests" in names
        assert "flask" in names
        assert "lodash" not in names

    def test_spdx(self):
        data = json.loads((FIXTURES / "sample_spdx.json").read_text())
        packages = _extract_spdx_packages(data)
        names = [p.get("name") for p in packages]
        assert "requests" in names
        assert "flask" in names


class TestWorstVerdict:
    def test_reachable_wins(self):
        assert _worst_verdict([Verdict.REACHABLE, Verdict.UNREACHABLE_STATIC]) == Verdict.REACHABLE

    def test_inconclusive_over_unreachable(self):
        assert (
            _worst_verdict([Verdict.INCONCLUSIVE, Verdict.UNREACHABLE_STATIC])
            == Verdict.INCONCLUSIVE
        )

    def test_empty(self):
        assert _worst_verdict([]) == Verdict.INCONCLUSIVE

    def test_single(self):
        assert _worst_verdict([Verdict.UNREACHABLE_STATIC]) == Verdict.UNREACHABLE_STATIC


class TestEnrichSbom:
    def test_cyclonedx_enrichment(self, tmp_path):
        data = json.loads((FIXTURES / "sample_cyclonedx.json").read_text())

        vuln = Vulnerability(
            id="CVE-2024-0001",
            package_name="requests",
            package_version="2.31.0",
            severity="high",
            title="Test vuln",
        )
        result = VerdictResult(
            vulnerability=vuln,
            verdict=Verdict.REACHABLE,
            reason="test",
            evidence=Evidence(),
            confidence_score=85,
        )
        report = Report(
            results=[result],
            repo_path=str(tmp_path),
        )

        (tmp_path / "app.py").write_text("import requests\n")

        with (
            patch("ca9.scanner.query_osv_batch", return_value=[vuln]),
            patch("ca9.engine.analyze", return_value=report),
        ):
            enriched = enrich_sbom(data, tmp_path)

        for comp in enriched["components"]:
            if comp.get("name") == "requests":
                props = {p["name"]: p["value"] for p in comp.get("properties", [])}
                assert "ca9:reachability_verdict" in props
                assert props["ca9:reachability_verdict"] == "reachable"
                assert "ca9:confidence_score" in props
                break
        else:
            raise AssertionError("requests component not found")

    def test_spdx_enrichment(self, tmp_path):
        data = json.loads((FIXTURES / "sample_spdx.json").read_text())

        vuln = Vulnerability(
            id="CVE-2024-0001",
            package_name="requests",
            package_version="2.31.0",
            severity="high",
            title="Test vuln",
        )
        result = VerdictResult(
            vulnerability=vuln,
            verdict=Verdict.UNREACHABLE_STATIC,
            reason="not imported",
            evidence=Evidence(),
            confidence_score=70,
        )
        report = Report(
            results=[result],
            repo_path=str(tmp_path),
        )

        (tmp_path / "app.py").write_text("")

        with (
            patch("ca9.scanner.query_osv_batch", return_value=[vuln]),
            patch("ca9.engine.analyze", return_value=report),
        ):
            enriched = enrich_sbom(data, tmp_path)

        for pkg in enriched["packages"]:
            if pkg.get("name") == "requests":
                annotations = pkg.get("annotations", [])
                assert len(annotations) >= 1
                assert "ca9:reachability_verdict=unreachable_static" in annotations[0]["comment"]
                break
        else:
            raise AssertionError("requests package not found")

    def test_no_vulns(self, tmp_path):
        data = json.loads((FIXTURES / "sample_cyclonedx.json").read_text())
        (tmp_path / "app.py").write_text("")

        with patch("ca9.scanner.query_osv_batch", return_value=[]):
            enriched = enrich_sbom(data, tmp_path)

        assert len(enriched["components"]) == len(data["components"])

    def test_osv_failure_is_annotated(self, tmp_path):
        data = json.loads((FIXTURES / "sample_cyclonedx.json").read_text())
        (tmp_path / "app.py").write_text("")

        with patch("ca9.scanner.query_osv_batch", side_effect=ConnectionError("offline")):
            enriched = enrich_sbom(data, tmp_path)

        metadata = enriched.get("metadata", {})
        properties = metadata.get("properties", [])
        assert any(
            p.get("name") == "ca9:warning" and "OSV enrichment failed" in p.get("value", "")
            for p in properties
        )

    def test_empty_components(self, tmp_path):
        data = {"bomFormat": "CycloneDX", "components": []}
        (tmp_path / "app.py").write_text("")

        enriched = enrich_sbom(data, tmp_path)
        assert enriched == data
