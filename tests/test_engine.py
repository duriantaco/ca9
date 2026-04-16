from __future__ import annotations

import json
from unittest.mock import patch

from ca9.engine import analyze, derive_verdict
from ca9.models import (
    AffectedComponent,
    ApiUsageHit,
    Evidence,
    Verdict,
    VersionRange,
    Vulnerability,
)


def _make_vuln(
    pkg: str,
    vuln_id: str = "V-1",
    title: str = "",
    desc: str = "",
) -> Vulnerability:
    return Vulnerability(
        id=vuln_id,
        package_name=pkg,
        package_version="1.0.0",
        severity="high",
        title=title or f"Vuln in {pkg}",
        description=desc,
    )


class TestAnalyze:
    def test_unreachable_static(self, sample_repo):
        vulns = [_make_vuln("some-unused-package")]
        report = analyze(vulns, sample_repo)
        assert report.results[0].verdict == Verdict.UNREACHABLE_STATIC

    def test_imported_no_coverage(self, sample_repo):
        vulns = [_make_vuln("requests")]
        report = analyze(vulns, sample_repo)
        assert report.results[0].verdict == Verdict.INCONCLUSIVE

    def test_imported_with_coverage_executed(self, sample_repo, coverage_path):
        vulns = [_make_vuln("requests")]
        report = analyze(vulns, sample_repo, coverage_path)
        assert report.results[0].verdict == Verdict.REACHABLE

    def test_imported_with_coverage_not_executed(self, sample_repo, coverage_path):
        vulns = [_make_vuln("PyYAML")]
        report = analyze(vulns, sample_repo, coverage_path)
        assert report.results[0].verdict == Verdict.INCONCLUSIVE
        assert report.results[0].original_verdict == Verdict.UNREACHABLE_DYNAMIC

    def test_full_snyk_report(self, sample_repo, snyk_path):
        from ca9.parsers.snyk import SnykParser

        data = json.loads(snyk_path.read_text())
        vulns = SnykParser().parse(data)
        report = analyze(vulns, sample_repo)

        verdicts = {r.vulnerability.package_name: r.verdict for r in report.results}
        assert verdicts["requests"] == Verdict.REACHABLE
        assert verdicts["PyYAML"] == Verdict.INCONCLUSIVE
        assert verdicts["Pillow"] == Verdict.INCONCLUSIVE
        assert verdicts["some-unused-package"] == Verdict.UNREACHABLE_STATIC

    def test_report_counts(self, sample_repo, coverage_path):
        vulns = [
            _make_vuln("requests", "V-1"),
            _make_vuln("PyYAML", "V-2"),
            _make_vuln("some-unused-package", "V-3"),
        ]
        report = analyze(vulns, sample_repo, coverage_path)
        assert report.total == 3
        assert report.reachable_count == 1
        assert report.unreachable_count == 1
        assert report.inconclusive_count == 1

    def test_threat_intel_failure_surfaces_warning(self, sample_repo):
        vulns = [_make_vuln("requests", vuln_id="CVE-2024-0001")]

        with patch(
            "ca9.threat_intel.fetch_threat_intel_batch", side_effect=RuntimeError("timeout")
        ):
            report = analyze(vulns, sample_repo, threat_intel=True)

        assert any("threat intelligence enrichment unavailable" in w for w in report.warnings)
        evidence = report.results[0].evidence
        assert evidence is not None
        assert any(
            "threat intelligence enrichment unavailable" in w
            for w in evidence.external_fetch_warnings
        )

    def test_otel_failure_surfaces_warning(self, sample_repo, tmp_path):
        vulns = [_make_vuln("requests")]
        otel_path = tmp_path / "traces.json"
        otel_path.write_text("{}")

        with patch(
            "ca9.analysis.otel_reader.load_otel_traces", side_effect=RuntimeError("bad traces")
        ):
            report = analyze(vulns, sample_repo, otel_traces_path=otel_path)

        assert any("production trace ingestion unavailable" in w for w in report.warnings)
        evidence = report.results[0].evidence
        assert evidence is not None
        assert any(
            "production trace ingestion unavailable" in w for w in evidence.external_fetch_warnings
        )

    def test_empty_repo(self, tmp_path):
        empty_repo = tmp_path / "empty_repo"
        empty_repo.mkdir()
        vulns = [_make_vuln("requests")]
        report = analyze(vulns, empty_repo)
        assert report.results[0].verdict == Verdict.INCONCLUSIVE

    def test_verdict_result_fields(self, sample_repo, coverage_path):
        vulns = [_make_vuln("requests")]
        report = analyze(vulns, sample_repo, coverage_path)
        r = report.results[0]
        assert r.imported_as == "requests"
        assert len(r.executed_files) > 0
        assert r.reason

    def test_direct_dependency_not_imported_stays_unreachable_static(self, sample_repo):
        vulns = [_make_vuln("some-unused-package")]
        report = analyze(vulns, sample_repo)
        assert report.results[0].verdict == Verdict.UNREACHABLE_STATIC
        assert "declared as a direct dependency" in report.results[0].reason

    def test_transitive_without_dependency_graph_is_inconclusive(self, sample_repo):
        vulns = [_make_vuln("urllib3")]
        with patch("ca9.analysis.ast_scanner.importlib.metadata.distributions", return_value=[]):
            report = analyze(vulns, sample_repo)
        assert report.results[0].verdict == Verdict.INCONCLUSIVE
        assert "dependency graph" in report.results[0].reason

    def test_report_dependency_chain_marks_transitive_without_local_metadata(self, sample_repo):
        vulns = [
            Vulnerability(
                id="V-urllib3",
                package_name="urllib3",
                package_version="1.26.18",
                severity="high",
                title="urllib3 issue",
                report_dependency_kind="transitive",
                report_dependency_chain=("requests", "urllib3"),
            )
        ]
        with patch("ca9.analysis.ast_scanner.importlib.metadata.distributions", return_value=[]):
            report = analyze(vulns, sample_repo)
        assert report.results[0].verdict == Verdict.INCONCLUSIVE
        assert "dependency of requests" in report.results[0].reason

    def test_report_dependency_chain_requires_imported_root(self, sample_repo):
        vulns = [
            Vulnerability(
                id="V-urllib3",
                package_name="urllib3",
                package_version="1.26.18",
                severity="high",
                title="urllib3 issue",
                report_dependency_kind="transitive",
                report_dependency_chain=("django", "urllib3"),
            )
        ]
        with patch("ca9.analysis.ast_scanner.importlib.metadata.distributions", return_value=[]):
            report = analyze(vulns, sample_repo)
        assert report.results[0].verdict == Verdict.UNREACHABLE_STATIC


class TestCoverageCompletenessPropagation:
    def test_coverage_completeness_propagated(self, sample_repo, coverage_path):
        vulns = [_make_vuln("requests")]
        report = analyze(vulns, sample_repo, coverage_path)
        ev = report.results[0].evidence
        assert ev is not None
        assert ev.coverage_completeness_pct == 75.0


class TestSubmoduleAnalysis:
    def test_submodule_not_imported_with_temp_repo(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("from django.db import models\n")

        vulns = [
            _make_vuln(
                "Django",
                title="Session fixation vulnerability",
            )
        ]
        report = analyze(vulns, repo)
        r = report.results[0]
        assert r.verdict == Verdict.UNREACHABLE_STATIC
        assert "django.contrib.sessions" in r.reason
        assert r.affected_component is not None
        assert r.affected_component.confidence == "high"

    def test_submodule_imported_no_coverage(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("from django.contrib.admin import site\n")

        vulns = [_make_vuln("Django", title="XSS in Django admin")]
        report = analyze(vulns, repo)
        r = report.results[0]
        assert r.verdict == Verdict.INCONCLUSIVE

    def test_submodule_executed_reachable(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("from django.contrib.admin import site\n")

        cov_file = tmp_path / "cov.json"
        cov_file.write_text(
            json.dumps(
                {
                    "files": {
                        "/site-packages/django/contrib/admin/sites.py": {
                            "executed_lines": [1, 2, 3],
                        },
                    }
                }
            )
        )

        vulns = [_make_vuln("Django", title="XSS in Django admin")]
        report = analyze(vulns, repo, cov_file)
        r = report.results[0]
        assert r.verdict == Verdict.REACHABLE
        assert r.affected_component is not None

    def test_submodule_not_executed_unreachable_dynamic(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("from django.contrib.admin import site\n")

        cov_file = tmp_path / "cov.json"
        cov_file.write_text(
            json.dumps(
                {
                    "files": {
                        "/site-packages/django/db/models/query.py": {
                            "executed_lines": [1, 2, 3],
                        },
                    },
                    "totals": {"percent_covered": 95.0},
                }
            )
        )

        vulns = [_make_vuln("Django", title="XSS in Django admin")]
        report = analyze(vulns, repo, cov_file)
        r = report.results[0]
        assert r.verdict == Verdict.UNREACHABLE_DYNAMIC
        assert "django.contrib.admin" in r.reason

    def test_balanced_mode_keeps_unreachable_dynamic(self, sample_repo, coverage_path):
        vulns = [_make_vuln("PyYAML")]
        report = analyze(vulns, sample_repo, coverage_path, proof_standard="balanced")
        assert report.results[0].verdict == Verdict.UNREACHABLE_DYNAMIC

    def test_low_confidence_falls_back_to_package_level(self, sample_repo, coverage_path):
        vulns = [_make_vuln("requests", title="An unspecified vulnerability")]
        report = analyze(vulns, sample_repo, coverage_path)
        r = report.results[0]
        assert r.verdict == Verdict.REACHABLE
        assert r.affected_component is not None
        assert r.affected_component.confidence == "low"

    def test_affected_component_always_set(self, sample_repo):
        vulns = [
            _make_vuln("requests"),
            _make_vuln("some-unused-package"),
        ]
        report = analyze(vulns, sample_repo)
        for r in report.results:
            assert r.affected_component is not None


class TestApiCallSiteCoverage:
    def _make_component(self, confidence="low"):
        return AffectedComponent(
            package_import_name="requests",
            confidence=confidence,
            extraction_source="test",
        )

    def test_api_found_call_sites_covered_reachable(self):
        evidence = Evidence(
            version_in_range=True,
            package_imported=True,
            dependency_kind="direct",
            api_usage_seen=True,
            api_usage_confidence=80,
            api_call_sites_covered=True,
            api_usage_hits=(
                ApiUsageHit(file_path="app.py", line=10, matched_target="requests.get"),
            ),
            api_targets=("requests.get",),
            coverage_seen=True,
            coverage_files=("site-packages/requests/api.py",),
        )
        result = derive_verdict(
            _make_vuln("requests"),
            evidence,
            "requests",
            self._make_component(),
            dep_of=None,
            has_coverage=True,
        )
        assert result.verdict == Verdict.REACHABLE
        assert "call sites executed" in result.reason

    def test_api_found_call_sites_not_covered_inconclusive(self):
        evidence = Evidence(
            version_in_range=True,
            package_imported=True,
            dependency_kind="direct",
            api_usage_seen=True,
            api_usage_confidence=80,
            api_call_sites_covered=False,
            api_usage_hits=(
                ApiUsageHit(file_path="app.py", line=10, matched_target="requests.get"),
            ),
            api_targets=("requests.get",),
        )
        result = derive_verdict(
            _make_vuln("requests"),
            evidence,
            "requests",
            self._make_component(),
            dep_of=None,
            has_coverage=True,
        )
        assert result.verdict == Verdict.INCONCLUSIVE
        assert "not executed" in result.reason

    def test_api_found_no_coverage_still_reachable(self):
        evidence = Evidence(
            version_in_range=True,
            package_imported=True,
            dependency_kind="direct",
            api_usage_seen=True,
            api_usage_confidence=80,
            api_call_sites_covered=None,
            api_usage_hits=(
                ApiUsageHit(file_path="app.py", line=10, matched_target="requests.get"),
            ),
            api_targets=("requests.get",),
        )
        result = derive_verdict(
            _make_vuln("requests"),
            evidence,
            "requests",
            self._make_component(),
            dep_of=None,
            has_coverage=False,
        )
        assert result.verdict == Verdict.REACHABLE

    def test_api_found_coverage_none_but_package_executed(self):
        evidence = Evidence(
            version_in_range=True,
            package_imported=True,
            dependency_kind="direct",
            api_usage_seen=True,
            api_usage_confidence=80,
            api_call_sites_covered=None,
            api_usage_hits=(
                ApiUsageHit(file_path="app.py", line=10, matched_target="requests.get"),
            ),
            api_targets=("requests.get",),
            coverage_seen=True,
            coverage_files=("site-packages/requests/api.py",),
        )
        result = derive_verdict(
            _make_vuln("requests"),
            evidence,
            "requests",
            self._make_component(),
            dep_of=None,
            has_coverage=True,
        )
        assert result.verdict == Verdict.REACHABLE


class TestVersionRangeFiltering:
    def test_version_outside_range_unreachable(self, sample_repo):
        vuln = Vulnerability(
            id="V-VR-1",
            package_name="requests",
            package_version="2.28.0",
            severity="high",
            title="Bug in requests",
            affected_ranges=(VersionRange(introduced="2.0", fixed="2.25.0"),),
        )
        report = analyze([vuln], sample_repo)
        r = report.results[0]
        assert r.verdict == Verdict.UNREACHABLE_STATIC
        assert "outside" in r.reason
        assert "version range" in r.reason

    def test_version_inside_range_continues(self, sample_repo, coverage_path):
        vuln = Vulnerability(
            id="V-VR-2",
            package_name="requests",
            package_version="2.20.0",
            severity="high",
            title="Bug in requests",
            affected_ranges=(VersionRange(introduced="2.0", fixed="2.25.0"),),
        )
        report = analyze([vuln], sample_repo, coverage_path)
        r = report.results[0]
        assert r.verdict == Verdict.REACHABLE

    def test_no_ranges_continues_normally(self, sample_repo):
        vuln = _make_vuln("requests")
        report = analyze([vuln], sample_repo)
        r = report.results[0]
        assert r.verdict == Verdict.INCONCLUSIVE
