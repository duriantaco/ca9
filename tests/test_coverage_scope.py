from __future__ import annotations

import json

import pytest

from ca9.engine import analyze
from ca9.models import AffectedComponent, Verdict, Vulnerability
from ca9.report import write_json, write_sarif
from ca9.vex import write_openvex

PACKAGE_FILE = "/env/site-packages/samplelib/__init__.py"
ALPHA_FILE = "/env/site-packages/samplelib/alpha.py"
BETA_FILE = "/env/site-packages/samplelib/beta.py"


@pytest.fixture
def analyze_scope(tmp_path, monkeypatch):
    """Analyze imports and supplied observations without running dependency code."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import samplelib\nimport samplelib.alpha\nimport samplelib.beta\n"
    )
    monkeypatch.setattr("ca9.engine.resolve_transitive_deps", lambda _imports: ({}, False))
    vuln = Vulnerability(
        id="TEST-COVERAGE-SCOPE",
        package_name="samplelib",
        package_version="1.0.0",
        severity="high",
        title="Synthetic coverage scope finding",
    )

    def run(files=None, *, submodules=(), percent=None, proof_standard="strict"):
        component = AffectedComponent(
            package_import_name="samplelib",
            submodule_paths=submodules,
            confidence="high" if submodules else "low",
            extraction_source="test",
        )
        monkeypatch.setattr("ca9.engine.extract_affected_component", lambda _vuln: component)
        coverage_path = None
        if files is not None:
            data = {"files": files}
            if percent is not None:
                data["totals"] = {"percent_covered": percent}
            coverage_path = tmp_path / "coverage.json"
            coverage_path.write_text(json.dumps(data))
        return analyze([vuln], repo, coverage_path, proof_standard=proof_standard)

    return run


@pytest.mark.parametrize("proof_standard", ["strict", "balanced"])
@pytest.mark.parametrize("percent", [None, 0.0, 79.0, 80.0, 95.0, 100.0])
@pytest.mark.parametrize("submodules", [(), ("samplelib.alpha",)])
def test_unreported_affected_scope_is_unknown_at_any_global_percentage(
    analyze_scope, proof_standard, percent, submodules
):
    # Sibling and application coverage cannot establish measurement of the target.
    unrelated_file = BETA_FILE if submodules else "/repo/app.py"
    report = analyze_scope(
        {unrelated_file: {"executed_lines": [1, 2], "missing_lines": []}},
        submodules=submodules,
        percent=percent,
        proof_standard=proof_standard,
    )

    result = report.results[0]
    assert result.verdict == Verdict.INCONCLUSIVE
    assert report.exit_code == 2
    evidence = result.evidence
    assert evidence is not None
    assert evidence.coverage_seen is None
    assert evidence.coverage_scope == "not_reported"
    assert evidence.coverage_measured_files == ()
    assert evidence.coverage_unmeasured_targets == (submodules or ("samplelib",))


def test_absent_report_is_distinguished_from_absent_target(analyze_scope):
    result = analyze_scope().results[0]

    assert result.verdict == Verdict.INCONCLUSIVE
    assert result.evidence is not None
    assert result.evidence.coverage_seen is None
    assert result.evidence.coverage_scope == "unavailable"


@pytest.mark.parametrize("proof_standard", ["strict", "balanced"])
@pytest.mark.parametrize(
    "file_record",
    [
        {},
        {"executed_lines": []},
        {"executed_lines": [], "missing_lines": [], "excluded_lines": []},
        {"executed_lines": [], "missing_lines": [], "excluded_lines": [1, 2]},
    ],
    ids=["missing-line-records", "empty-hits", "empty-statements", "excluded-only"],
)
def test_files_without_executable_statement_evidence_are_unknown(
    analyze_scope, proof_standard, file_record
):
    result = analyze_scope(
        {PACKAGE_FILE: file_record}, percent=100.0, proof_standard=proof_standard
    ).results[0]

    assert result.verdict == Verdict.INCONCLUSIVE
    assert result.evidence is not None
    assert result.evidence.coverage_seen is None
    assert result.evidence.coverage_scope == "no_statements"
    assert result.evidence.coverage_unmeasured_targets == ("samplelib",)


@pytest.mark.parametrize("percent", [None, 0.0, 80.0, 100.0])
@pytest.mark.parametrize("submodules", [(), ("samplelib.alpha",)])
def test_strict_retains_measured_nonexecution_without_suppressing(
    analyze_scope, percent, submodules
):
    affected_file = ALPHA_FILE if submodules else PACKAGE_FILE
    report = analyze_scope(
        {affected_file: {"executed_lines": [], "missing_lines": [1, 2]}},
        submodules=submodules,
        percent=percent,
    )

    result = report.results[0]
    assert result.verdict == Verdict.INCONCLUSIVE
    assert result.original_verdict == Verdict.UNREACHABLE_DYNAMIC
    assert result.policy_adjustment
    assert report.exit_code == 2
    assert result.evidence is not None
    assert result.evidence.coverage_seen is False
    assert result.evidence.coverage_scope == "reported"
    assert result.evidence.coverage_measured_files == (affected_file,)
    assert result.evidence.coverage_unmeasured_targets == ()
    assert result.executed_files == []


def test_balanced_retains_explicit_measured_nonexecution(analyze_scope):
    result = analyze_scope(
        {PACKAGE_FILE: {"executed_lines": [], "missing_lines": [1, 2]}},
        proof_standard="balanced",
    ).results[0]

    assert result.verdict == Verdict.UNREACHABLE_DYNAMIC
    assert result.evidence is not None
    assert result.evidence.coverage_seen is False
    assert result.evidence.coverage_scope == "reported"
    assert result.evidence.coverage_measured_files == (PACKAGE_FILE,)


@pytest.mark.parametrize("proof_standard", ["strict", "balanced"])
def test_one_measured_submodule_does_not_cover_a_second_affected_target(
    analyze_scope, proof_standard
):
    result = analyze_scope(
        {ALPHA_FILE: {"executed_lines": [], "missing_lines": [1, 2]}},
        submodules=("samplelib.alpha", "samplelib.beta"),
        percent=100.0,
        proof_standard=proof_standard,
    ).results[0]

    assert result.verdict == Verdict.INCONCLUSIVE
    assert result.evidence is not None
    assert result.evidence.coverage_seen is None
    assert result.evidence.coverage_scope == "partial"
    assert result.evidence.coverage_measured_files == (ALPHA_FILE,)
    assert result.evidence.coverage_unmeasured_targets == ("samplelib.beta",)


@pytest.mark.parametrize("submodules", [(), ("samplelib.alpha",)])
def test_positive_affected_execution_still_establishes_reachability(analyze_scope, submodules):
    affected_file = ALPHA_FILE if submodules else PACKAGE_FILE
    report = analyze_scope(
        {affected_file: {"executed_lines": [1], "missing_lines": [2]}},
        submodules=submodules,
        percent=0.0,
    )

    result = report.results[0]
    assert result.verdict == Verdict.REACHABLE
    assert report.exit_code == 1
    assert result.evidence is not None
    assert result.evidence.coverage_seen is True
    assert result.executed_files == [affected_file]


def test_positive_execution_survives_partial_affected_scope(analyze_scope):
    result = analyze_scope(
        {ALPHA_FILE: {"executed_lines": [1], "missing_lines": []}},
        submodules=("samplelib.alpha", "samplelib.beta"),
    ).results[0]

    assert result.verdict == Verdict.REACHABLE
    assert result.evidence is not None
    assert result.evidence.coverage_seen is True
    assert result.evidence.coverage_scope == "partial"
    assert result.evidence.coverage_unmeasured_targets == ("samplelib.beta",)


@pytest.mark.parametrize("measured", [False, True])
def test_evidence_scope_is_preserved_across_json_sarif_and_vex(analyze_scope, measured):
    files = {PACKAGE_FILE: {"executed_lines": [], "missing_lines": [1]}} if measured else {}
    report = analyze_scope(files, percent=100.0)

    json_result = json.loads(write_json(report))["results"][0]
    sarif_result = json.loads(write_sarif(report))["runs"][0]["results"][0]
    vex_statement = json.loads(write_openvex(report))["statements"][0]

    assert json_result["verdict"] == "inconclusive"
    assert sarif_result["level"] == "warning"
    assert sarif_result["properties"]["verdict"] == "inconclusive"
    assert vex_statement["status"] == "under_investigation"
    assert "justification" not in vex_statement
    for evidence in (
        json_result["evidence"],
        sarif_result["properties"]["evidence"],
        vex_statement["ca9"]["evidence_summary"],
    ):
        assert evidence["coverage_seen"] is (False if measured else None)
        assert evidence["coverage_scope"] == ("reported" if measured else "not_reported")
        assert evidence["coverage_measured_files"] == ([PACKAGE_FILE] if measured else [])
        assert evidence["coverage_unmeasured_targets"] == ([] if measured else ["samplelib"])


def test_balanced_nonexecution_does_not_export_a_not_affected_vex_claim(analyze_scope):
    report = analyze_scope(
        {PACKAGE_FILE: {"executed_lines": [], "missing_lines": [1]}},
        percent=100.0,
        proof_standard="balanced",
    )
    assert report.results[0].verdict == Verdict.UNREACHABLE_DYNAMIC

    statement = json.loads(write_openvex(report))["statements"][0]
    assert statement["status"] == "under_investigation"
    assert "justification" not in statement
    assert statement["ca9"]["verdict"] == "unreachable_dynamic"
    assert statement["ca9"]["evidence_summary"]["coverage_scope"] == "reported"
