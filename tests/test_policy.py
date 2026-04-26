from __future__ import annotations

import json
from datetime import date

from ca9.models import Report, Verdict, VerdictResult, Vulnerability
from ca9.policy import apply_policy, load_accepted_risks


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
    accepted.write_text('[[risk]]\nid = "CVE-1"\npackage = "requests"\nexpires = "2099-01-01"\n')
    report = Report(results=[_result()], repo_path=".")

    filtered = apply_policy(report, accepted_risks_path=accepted, today=date(2026, 1, 1))

    assert filtered.results == []
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
    assert any("baseline" in warning for warning in filtered.warnings)


def test_new_only_keeps_baselined_unreachable_for_visibility(tmp_path):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps({"results": [{"id": "CVE-1", "package": "requests", "version": "2.31.0"}]})
    )
    report = Report(results=[_result(verdict=Verdict.UNREACHABLE_STATIC)], repo_path=".")

    filtered = apply_policy(report, baseline_path=baseline, new_only=True)

    assert len(filtered.results) == 1


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
