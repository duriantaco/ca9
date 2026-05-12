from __future__ import annotations

import json
import os
import time

from ca9.advisory import (
    attach_cache_freshness,
    extract_cpes,
    extract_cwes,
    metadata_from_osv,
    normalize_advisory_aliases,
    normalize_ecosystem,
    package_purl,
)
from ca9.models import Report, Verdict, VerdictResult, Vulnerability
from ca9.report import write_json, write_sarif
from ca9.vex import write_openvex


def test_normalizes_advisory_aliases():
    aliases = normalize_advisory_aliases(
        "GHSA-abcd-1234-wxyz",
        ["cve-2024-12345", "GHSA-ABCD-1234-WXYZ", "PYSEC-2024-1"],
    )

    assert aliases == ("CVE-2024-12345", "PYSEC-2024-1")


def test_extracts_cwes_and_cpes_from_nested_advisory_data():
    data = {
        "database_specific": {"cwe_ids": ["CWE-79", "cwe_352"]},
        "configurations": [
            {"criteria": "cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*"},
        ],
    }

    assert extract_cwes(data) == ("CWE-79", "CWE-352")
    assert extract_cpes(data) == ("cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*",)


def test_osv_metadata_includes_aliases_cwes_and_cache_freshness(tmp_path):
    cache_file = tmp_path / "GHSA-test.json"
    cache_file.write_text("{}")
    old_time = time.time() - 60
    cache_file.touch()

    os.utime(cache_file, (old_time, old_time))

    payload = attach_cache_freshness(
        {
            "id": "GHSA-abcd-1234-wxyz",
            "aliases": ["CVE-2024-12345"],
            "published": "2024-01-01T00:00:00Z",
            "modified": "2024-01-02T00:00:00Z",
            "database_specific": {"cwe_ids": ["CWE-79"]},
        },
        source="osv.dev",
        ttl_seconds=3600,
        path=cache_file,
    )

    metadata = metadata_from_osv(payload, "GHSA-abcd-1234-wxyz")

    assert metadata.aliases == ("CVE-2024-12345",)
    assert metadata.cwes == ("CWE-79",)
    assert metadata.source == "osv.dev"
    assert metadata.source_url == "https://osv.dev/vulnerability/GHSA-abcd-1234-wxyz"
    assert metadata.published_at == "2024-01-01T00:00:00Z"
    assert metadata.modified_at == "2024-01-02T00:00:00Z"
    assert metadata.fetched_at is not None
    assert metadata.cache_stale is False


def test_package_purl_uses_ecosystem_type():
    assert package_purl("PyYAML", "6.0.1", "pypi") == "pkg:pypi/pyyaml@6.0.1"
    assert package_purl("@scope/pkg", "1.2.3", "npm") == "pkg:npm/%40scope/pkg@1.2.3"
    assert (
        package_purl("org.apache.logging.log4j:log4j-core", "2.17.1", "maven")
        == "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"
    )
    assert package_purl("left-pad", "", "npm") == "pkg:npm/left-pad"
    assert package_purl("mystery-lib", "1.0", "") == "pkg:generic/mystery-lib@1.0"


def test_missing_ecosystem_does_not_default_to_pypi():
    assert normalize_ecosystem("") == ""
    assert normalize_ecosystem(None) == ""
    assert normalize_ecosystem("pip") == "pypi"


def test_advisory_metadata_appears_in_json_sarif_and_vex():
    vuln = Vulnerability(
        id="GHSA-abcd-1234-wxyz",
        package_name="requests",
        package_version="2.31.0",
        severity="high",
        title="test",
        aliases=("CVE-2024-12345",),
        cwes=("CWE-79",),
        advisory_source="osv.dev",
        advisory_url="https://osv.dev/vulnerability/GHSA-abcd-1234-wxyz",
        published_at="2024-01-01T00:00:00Z",
        fetched_at="2024-01-02T00:00:00Z",
        cache_stale=False,
    )
    report = Report(
        results=[VerdictResult(vulnerability=vuln, verdict=Verdict.REACHABLE, reason="test")],
        repo_path=".",
    )

    json_data = json.loads(write_json(report))
    assert json_data["results"][0]["advisory"]["aliases"] == ["CVE-2024-12345"]
    assert json_data["results"][0]["advisory"]["cwes"] == ["CWE-79"]
    assert json_data["results"][0]["advisory"]["cache_stale"] is False

    sarif_data = json.loads(write_sarif(report))
    assert sarif_data["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["aliases"] == [
        "CVE-2024-12345"
    ]
    assert sarif_data["runs"][0]["results"][0]["properties"]["advisory_source"] == "osv.dev"

    vex_data = json.loads(write_openvex(report))
    assert vex_data["statements"][0]["ca9"]["advisory"]["aliases"] == ["CVE-2024-12345"]
