from __future__ import annotations

import json
from datetime import date

import pytest
from click.testing import CliRunner

from ca9.cli import main
from ca9.models import Report, Verdict, VerdictResult, Vulnerability
from ca9.policy import apply_policy, load_accepted_risks
from ca9.report import write_json


def _result(
    vuln_id: str = "CVE-1",
    package: str = "requests",
    version: str = "2.31.0",
    verdict: Verdict = Verdict.REACHABLE,
) -> VerdictResult:
    return VerdictResult(
        vulnerability=Vulnerability(
            id=vuln_id,
            package_name=package,
            package_version=version,
            severity="high",
            title="Test",
        ),
        verdict=verdict,
        reason="test",
    )


def test_load_accepted_risks_from_toml(tmp_path):
    path = tmp_path / "accepted.toml"
    path.write_text(
        '[[risk]]\nid = "CVE-1"\npackage = "requests"\nversion = "2.31.0"\n'
        'reason = "temporary exception"\nexpires = "2099-01-01"\nowner = "sec"\n'
    )

    risks = load_accepted_risks(path)

    assert len(risks) == 1
    assert risks[0].vuln_id == "CVE-1"
    assert risks[0].package == "requests"
    assert risks[0].version == "2.31.0"


def test_load_accepted_risks_from_json(tmp_path):
    path = tmp_path / "accepted.json"
    path.write_text(json.dumps({"risks": [{"id": "CVE-1", "package": "requests"}]}))

    risks = load_accepted_risks(path)

    assert len(risks) == 1
    assert risks[0].vuln_id == "CVE-1"


def test_active_accepted_risk_filters_result(tmp_path):
    accepted = tmp_path / "accepted.toml"
    accepted.write_text(
        '[[risk]]\nid = "CVE-1"\npackage = "requests"\nexpires = "2099-01-01"\n'
        'reason = "tracked exception"\nowner = "security"\n'
    )
    report = Report(results=[_result()], repo_path=".")

    filtered = apply_policy(report, accepted_risks_path=accepted, today=date(2026, 1, 1))

    assert filtered.results == []
    assert len(filtered.ignored_results) == 1
    assert filtered.ignored_results[0].policy == "accepted_risk"
    assert filtered.ignored_results[0].reason == "tracked exception"
    assert filtered.ignored_results[0].owner == "security"
    assert filtered.exit_code == 0
    assert any("accepted-risk" in warning for warning in filtered.warnings)


def test_expired_accepted_risk_does_not_filter_result(tmp_path):
    accepted = tmp_path / "accepted.toml"
    accepted.write_text('[[risk]]\nid = "CVE-1"\npackage = "requests"\nexpires = "2020-01-01"\n')
    report = Report(results=[_result()], repo_path=".")

    filtered = apply_policy(report, accepted_risks_path=accepted, today=date(2026, 1, 1))

    assert len(filtered.results) == 1
    assert filtered.exit_code == 1
    assert any("expired" in warning for warning in filtered.warnings)


def test_new_only_filters_baselined_reachable_and_inconclusive(tmp_path):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {
                "results": [
                    {"id": "CVE-1", "package": "requests", "version": "2.31.0"},
                    {"id": "CVE-2", "package": "django", "version": "5.0"},
                ]
            }
        )
    )
    report = Report(
        results=[
            _result("CVE-1", "requests", "2.31.0", Verdict.REACHABLE),
            _result("CVE-2", "django", "5.0", Verdict.INCONCLUSIVE),
            _result("CVE-3", "flask", "3.0", Verdict.REACHABLE),
        ],
        repo_path=".",
    )

    filtered = apply_policy(report, baseline_path=baseline, new_only=True)

    assert [r.vulnerability.id for r in filtered.results] == ["CVE-3"]
    assert [r.result.vulnerability.id for r in filtered.ignored_results] == ["CVE-1", "CVE-2"]
    assert {r.policy for r in filtered.ignored_results} == {"baseline"}
    assert any("baseline" in warning for warning in filtered.warnings)


def test_new_only_keeps_baselined_unreachable_for_visibility(tmp_path):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps({"results": [{"id": "CVE-1", "package": "requests", "version": "2.31.0"}]})
    )
    report = Report(results=[_result(verdict=Verdict.UNREACHABLE_STATIC)], repo_path=".")

    filtered = apply_policy(report, baseline_path=baseline, new_only=True)

    assert len(filtered.results) == 1


@pytest.mark.parametrize("previous", list(Verdict))
def test_new_only_reopens_only_newly_reachable_findings(tmp_path, previous):
    baseline = tmp_path / "baseline.json"
    write_json(Report(results=[_result(verdict=previous)], repo_path="."), baseline)

    for current in (Verdict.REACHABLE, Verdict.INCONCLUSIVE):
        report = Report(results=[_result(verdict=current)], repo_path=".")
        filtered = apply_policy(report, baseline_path=baseline, new_only=True)
        if current == Verdict.REACHABLE and previous != Verdict.REACHABLE:
            assert filtered.results == report.results
            assert filtered.exit_code == 1
        else:
            assert filtered.results == []
            assert filtered.ignored_results[0].policy == "baseline"
            assert filtered.exit_code == 0


def test_new_only_does_not_carry_accepted_risks_forward_as_baseline(tmp_path):
    accepted = tmp_path / "accepted.json"
    accepted.write_text(
        json.dumps([{"id": "CVE-1", "package": "requests", "expires": "2026-02-01"}])
    )
    baseline = tmp_path / "baseline.json"
    write_json(Report(results=[_result(verdict=Verdict.INCONCLUSIVE)], repo_path="."), baseline)
    current = Report(results=[_result(verdict=Verdict.REACHABLE)], repo_path=".")

    filtered = apply_policy(current, accepted, baseline, new_only=True, today=date(2026, 2, 1))
    assert filtered.exit_code == 0
    assert filtered.ignored_results[0].policy == "accepted_risk"
    write_json(filtered, baseline)

    expired = apply_policy(current, accepted, baseline, new_only=True, today=date(2026, 2, 2))
    assert expired.exit_code == 1
    assert any("expired" in warning for warning in expired.warnings)


def test_new_only_cli_reopens_reachable_finding_from_filtered_report(
    tmp_path, snyk_path, coverage_path
):
    sca = json.loads(snyk_path.read_text())
    sca["vulnerabilities"] = [v for v in sca["vulnerabilities"] if v["packageName"] == "requests"]
    input_path = tmp_path / "sca.json"
    input_path.write_text(json.dumps(sca))
    (tmp_path / "app.py").write_text("import requests\n")
    args = ["check", str(input_path), "--repo", str(tmp_path), "-f", "json", "--no-auto-coverage"]
    runner = CliRunner()
    baseline = tmp_path / "baseline.json"
    assert runner.invoke(main, [*args, "-o", str(baseline)]).exit_code == 2

    filtered = tmp_path / "filtered.json"
    result = runner.invoke(
        main, [*args, "--new-only", "--baseline", str(baseline), "-o", str(filtered)]
    )
    assert result.exit_code == 0
    assert json.loads(filtered.read_text())["ignored_results"][0]["verdict"] == "inconclusive"
    gate = [*args, "--new-only", "--baseline", str(filtered)]
    assert runner.invoke(main, gate).exit_code == 0

    result = runner.invoke(main, [*gate, "--coverage", str(coverage_path)])
    assert result.exit_code == 1
    assert json.loads(result.output)["results"][0]["verdict"] == "reachable"


def test_new_only_without_baseline_warns_and_keeps_results():
    report = Report(results=[_result()], repo_path=".")

    filtered = apply_policy(report, new_only=True)

    assert len(filtered.results) == 1
    assert any("no baseline" in warning for warning in filtered.warnings)


def test_new_only_with_empty_baseline_warns_and_keeps_results(tmp_path):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"results": []}))
    report = Report(results=[_result()], repo_path=".")

    filtered = apply_policy(report, baseline_path=baseline, new_only=True)

    assert len(filtered.results) == 1
    assert any("no usable findings" in warning for warning in filtered.warnings)


def test_empty_accepted_risks_file_warns_and_keeps_results(tmp_path):
    accepted = tmp_path / "accepted.toml"
    accepted.write_text("")
    report = Report(results=[_result()], repo_path=".")

    filtered = apply_policy(report, accepted_risks_path=accepted)

    assert len(filtered.results) == 1
    assert any("no usable risk entries" in warning for warning in filtered.warnings)
