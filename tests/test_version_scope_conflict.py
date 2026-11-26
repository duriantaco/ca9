import json
from dataclasses import replace

import pytest

from ca9 import scanner
from ca9.engine import analyze
from ca9.models import Verdict, VersionRange, Vulnerability
from ca9.report import write_json
from ca9.vex import write_openvex


@pytest.mark.parametrize("standard", ["strict", "balanced"])
def test_normalized_affected_version_prevents_suppression_from_release_ranges(
    tmp_path, monkeypatch, standard
):
    cache = tmp_path / "cache"
    cache.mkdir()
    monkeypatch.setattr(scanner, "CACHE_DIR", cache)
    (tmp_path / "requirements.txt").write_text("example==2020.6.20\n")
    (cache / "LOCAL-TEST.json").write_text(
        json.dumps(
            {
                "id": "LOCAL-TEST",
                "summary": "Example advisory",
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "example"},
                        "versions": ["2020.06.20"],
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [{"introduced": "2021.5.30"}, {"fixed": "2024.7.4"}],
                            }
                        ],
                    }
                ],
            }
        )
    )
    # A legacy offline cache has only advisory details, with no prior query for
    # the exact installed version. Membership must survive that lookup as well.
    findings, _ = scanner.scan_repository(tmp_path, offline=True)
    assert len(findings) == 1
    after_fix = replace(findings[0], package_version="2025.1")
    report = analyze([findings[0], after_fix], tmp_path, proof_standard=standard)
    actual, outside = report.results
    assert actual.verdict == Verdict.INCONCLUSIVE
    assert actual.evidence.version_in_range is None
    assert "explicitly lists 2020.06.20" in actual.reason
    assert "2020.6.20 is outside" in actual.reason
    assert outside.verdict == Verdict.UNREACHABLE_STATIC
    assert outside.evidence.version_in_range is False
    assert outside.evidence.version_scope_conflict is None
    assert json.loads(write_json(report))["results"][0]["evidence"]["version_scope_conflict"]
    assert [s["status"] for s in json.loads(write_openvex(report))["statements"]] == [
        "under_investigation",
        "not_affected",
    ]


def test_verified_affected_api_call_is_retained_despite_version_scope_conflict(tmp_path):
    (tmp_path / "app.py").write_text(
        "from requests.auth import HTTPBasicAuth\n"
        "def build():\n    return HTTPBasicAuth('example', 'example')\n"
    )
    coverage = tmp_path / "coverage.json"
    coverage.write_text(json.dumps({"files": {"app.py": {"executed_lines": [1, 2, 3]}}}))
    finding = Vulnerability(
        "LOCAL-AUTH",
        "requests",
        "1.0",
        "low",
        "Authentication advisory",
        affected_versions=("1.0",),
        affected_ranges=(VersionRange(introduced="2", fixed="3"),),
    )
    report = analyze([finding], tmp_path, coverage)
    result = report.results[0]
    assert result.evidence.api_call_sites_covered
    assert result.verdict == Verdict.REACHABLE
    assert result.evidence.version_scope_conflict in result.reason
    assert json.loads(write_openvex(report))["statements"][0]["status"] == "affected"
