from __future__ import annotations

import json

import pytest

from ca9.analysis.coverage_reader import get_covered_files, get_measured_files
from ca9.engine import _apply_proof_standard, analyze, collect_evidence, derive_verdict
from ca9.models import AffectedComponent, Evidence, Report, Verdict, Vulnerability
from ca9.vex import write_openvex

ALPHA_FILE = "/env/site-packages/samplelib/alpha.py"
BETA_FILE = "/env/site-packages/samplelib/beta.py"
VULN = Vulnerability(
    "TEST-COVERAGE-REGRESSION",
    "samplelib",
    "1.0.0",
    "high",
    "Synthetic evidence precedence regression",
    report_dependency_kind="direct",
)


def _result(files, *, imports=("samplelib",), submodules=(), standard="strict", production=None):
    data = {"files": files}
    component = AffectedComponent(
        "samplelib", submodules, confidence="high" if submodules else "low"
    )
    evidence = collect_evidence(
        VULN,
        "samplelib",
        set(imports),
        {},
        False,
        {"samplelib"},
        get_covered_files(data),
        component=component,
        measured_files=get_measured_files(data),
        production_observed=production,
    )
    return _apply_proof_standard(
        derive_verdict(VULN, evidence, "samplelib", component, None, True), standard
    )


@pytest.mark.parametrize("imports", [(), ("samplelib.beta",)])
def test_measured_affected_execution_overrides_static_import_absence(imports):
    result = _result(
        {ALPHA_FILE: {"executed_lines": [1], "missing_lines": []}},
        imports=imports,
        submodules=("samplelib.alpha",),
    )
    assert result.evidence.coverage_seen is True
    assert result.verdict == Verdict.REACHABLE
    report = Report([result], ".")
    assert report.exit_code == 1
    assert json.loads(write_openvex(report))["statements"][0]["status"] == "affected"


def test_analyze_observed_submodule_overrides_sibling_only_source_import(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("import samplelib.beta\n")
    coverage = tmp_path / "coverage.json"
    coverage.write_text(
        json.dumps({"files": {ALPHA_FILE: {"executed_lines": [1], "missing_lines": []}}})
    )
    component = AffectedComponent("samplelib", ("samplelib.alpha",), confidence="high")
    monkeypatch.setattr("ca9.engine.extract_affected_component", lambda _: component)
    monkeypatch.setattr("ca9.engine.resolve_transitive_deps", lambda _: ({}, False))
    report = analyze([VULN], tmp_path, coverage)
    assert report.results[0].evidence.submodule_imported is False
    assert report.results[0].evidence.coverage_seen is True
    assert report.results[0].verdict == Verdict.REACHABLE
    assert report.exit_code == 1


def test_observed_api_execution_overrides_missing_static_package_import():
    evidence = Evidence(
        package_imported=False,
        declared_direct_dependency=True,
        api_usage_seen=True,
        api_call_sites_covered=True,
    )
    result = derive_verdict(VULN, evidence, "samplelib", AffectedComponent("samplelib"), None, True)
    assert result.verdict == Verdict.REACHABLE
    assert "API call sites executed" in result.reason


@pytest.mark.parametrize("imports", [(), ("samplelib.beta",)])
def test_package_production_observation_prevents_absence_suppression(imports):
    result = _result({}, imports=imports, submodules=("samplelib.alpha",), production=True)
    assert result.evidence.production_observed is True
    assert result.verdict == Verdict.INCONCLUSIVE
    statement = json.loads(write_openvex(Report([result], ".")))["statements"][0]
    assert statement["status"] == "under_investigation"
    assert "production" in result.reason


def test_execution_does_not_override_confirmed_unaffected_version():
    evidence = Evidence(
        version_in_range=False,
        declared_direct_dependency=True,
        coverage_seen=True,
        production_observed=True,
        api_usage_seen=True,
        api_call_sites_covered=True,
    )
    result = derive_verdict(VULN, evidence, "samplelib", AffectedComponent("samplelib"), None, True)
    assert result.verdict == Verdict.UNREACHABLE_STATIC
    assert "outside the affected version range" in result.reason


@pytest.mark.parametrize("package_imported", [False, True])
def test_package_execution_does_not_establish_unexecuted_affected_api(package_imported):
    evidence = Evidence(
        package_imported=package_imported,
        declared_direct_dependency=True,
        coverage_seen=True,
        api_usage_seen=True,
        api_call_sites_covered=False,
    )
    result = derive_verdict(VULN, evidence, "samplelib", AffectedComponent("samplelib"), None, True)
    assert result.verdict == Verdict.INCONCLUSIVE
    assert "call sites not executed" in result.reason


@pytest.mark.parametrize("field", ["missing_lines", "excluded_lines"])
def test_valid_executed_lines_survive_malformed_ancillary_fields(field):
    record = {"executed_lines": [1], "missing_lines": [], "excluded_lines": []}
    record[field] = "invalid metadata"
    result = _result(
        {
            ALPHA_FILE: {"executed_lines": [], "missing_lines": [1]},
            BETA_FILE: record,
        },
        standard="balanced",
    )
    assert result.evidence.coverage_seen is True
    assert result.verdict == Verdict.REACHABLE
    assert BETA_FILE in result.evidence.coverage_files


@pytest.mark.parametrize(
    "record",
    [
        None,
        [],
        {},
        {"executed_lines": "invalid", "missing_lines": [2]},
        {"executed_lines": [], "missing_lines": "invalid"},
        {"executed_lines": [], "missing_lines": [], "excluded_lines": "invalid"},
    ],
)
def test_malformed_sibling_cannot_be_covered_by_valid_missing_only_file(record):
    result = _result(
        {
            ALPHA_FILE: {"executed_lines": [], "missing_lines": [1]},
            BETA_FILE: record,
        },
        standard="balanced",
    )
    assert result.evidence.coverage_seen is None
    assert result.evidence.coverage_scope == "partial"
    assert result.evidence.coverage_unmeasured_targets == ("samplelib",)
    assert result.verdict == Verdict.INCONCLUSIVE


def test_unrelated_malformed_package_does_not_invalidate_reported_target():
    result = _result(
        {
            ALPHA_FILE: {"executed_lines": [], "missing_lines": [1]},
            "/env/site-packages/otherlib/beta.py": None,
        },
        submodules=("samplelib.alpha",),
        standard="balanced",
    )
    assert result.evidence.coverage_seen is False
    assert result.verdict == Verdict.UNREACHABLE_DYNAMIC
