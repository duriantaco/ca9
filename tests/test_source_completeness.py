from __future__ import annotations

import json
from dataclasses import replace

import pytest

from ca9.engine import analyze
from ca9.models import Verdict, VersionRange, Vulnerability
from ca9.report import write_json
from ca9.vex import write_openvex


def _transitive_finding():
    return Vulnerability(
        id="LOCAL-TEST-1",
        package_name="urllib3",
        package_version="1.0",
        severity="low",
        title="Example advisory",
        report_dependency_chain=("requests", "urllib3"),
    )


@pytest.mark.parametrize("standard", ["strict", "balanced"])
def test_incomplete_source_cannot_justify_absence_or_vex_suppression(tmp_path, standard):
    (tmp_path / "app.py").write_text("value = 1\n")
    finding = _transitive_finding()
    before = analyze([finding], tmp_path, proof_standard=standard)
    assert before.results[0].verdict == Verdict.UNREACHABLE_STATIC

    (tmp_path / "partial.py").write_text("import requests\nvalue =\n")
    (tmp_path / "unreadable.py").symlink_to(tmp_path / "missing")
    report = analyze([finding], tmp_path, proof_standard=standard)

    assert report.results[0].verdict == Verdict.INCONCLUSIVE
    assert report.exit_code == 2
    assert "could not check all runtime Python source" in report.results[0].reason
    assert len(report.warnings) == 1
    assert "partial.py" in report.warnings[0] and "unreadable.py" in report.warnings[0]
    evidence = json.loads(write_json(report))["results"][0]["evidence"]
    assert evidence["source_imports_complete"] is False
    assert json.loads(write_openvex(report))["statements"][0]["status"] == "under_investigation"


@pytest.mark.parametrize(
    "source",
    [
        "# coding: latin-1\né = 1\nimport requests\n".encode("latin-1"),
        "é = 1\nimport requests\n".encode("utf-8-sig"),
    ],
)
def test_valid_python_source_encodings_preserve_transitive_evidence(tmp_path, source):
    (tmp_path / "app.py").write_bytes(source)
    report = analyze([_transitive_finding()], tmp_path)

    assert report.warnings == []
    result = report.results[0]
    assert result.evidence.source_imports_complete is True
    assert result.dependency_of == "requests"
    assert result.verdict == Verdict.INCONCLUSIVE


def test_partial_source_preserves_independent_proof_and_bounds_the_warning(tmp_path):
    for i in range(5):
        (tmp_path / f"bad_{i}.py").write_bytes(b"# coding: unknown-codec\n")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "ignored.py").write_text("invalid (")
    finding = _transitive_finding()
    outside = replace(
        finding, id="LOCAL-TEST-2", affected_ranges=(VersionRange(introduced="0", fixed="0.9"),)
    )
    coverage_path = tmp_path / "coverage.json"
    coverage_path.write_text(
        json.dumps({"files": {"site-packages/urllib3/__init__.py": {"executed_lines": [1]}}})
    )
    report = analyze([finding, outside], tmp_path, coverage_path)

    assert len(report.warnings) == 1
    assert "5 path(s)" in report.warnings[0]
    assert "bad_3.py" not in report.warnings[0]
    assert [result.verdict for result in report.results] == [
        Verdict.REACHABLE,
        Verdict.UNREACHABLE_STATIC,
    ]
    assert json.loads(write_openvex(report))["statements"][1]["justification"] == (
        "vulnerable_code_not_present"
    )


def test_incomplete_source_preserves_a_covered_call_in_a_valid_file(tmp_path):
    (tmp_path / "partial.py").write_text("value =\n")
    (tmp_path / "app.py").write_text(
        "from requests.auth import HTTPBasicAuth\n"
        "def credentials():\n"
        "    return HTTPBasicAuth('example', 'example')\n"
    )
    finding = Vulnerability("LOCAL-AUTH", "requests", "2.0", "low", "Authentication advisory")
    coverage = tmp_path / "coverage.json"
    coverage.write_text(json.dumps({"files": {"app.py": {"executed_lines": [1, 2, 3]}}}))
    report = analyze([finding], tmp_path, coverage)

    result = report.results[0]
    assert result.evidence.source_imports_complete is False
    assert result.evidence.api_call_sites_covered is True
    assert result.verdict == Verdict.REACHABLE
