from __future__ import annotations

import json

from ca9.engine import analyze
from ca9.models import Verdict, VersionRange, Vulnerability


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
        # requests is imported and executed → REACHABLE
        vulns = [_make_vuln("requests")]
        report = analyze(vulns, sample_repo, coverage_path)
        assert report.results[0].verdict == Verdict.REACHABLE

    def test_imported_with_coverage_not_executed(self, sample_repo, coverage_path):
        vulns = [_make_vuln("PyYAML")]
        report = analyze(vulns, sample_repo, coverage_path)
        assert report.results[0].verdict == Verdict.UNREACHABLE_DYNAMIC

    def test_full_snyk_report(self, sample_repo, snyk_path):
        from ca9.parsers.snyk import SnykParser

        data = json.loads(snyk_path.read_text())
        vulns = SnykParser().parse(data)
        report = analyze(vulns, sample_repo)

        verdicts = {r.vulnerability.package_name: r.verdict for r in report.results}
        # requests.get() found in sample_repo → REACHABLE via API scanner
        assert verdicts["requests"] == Verdict.REACHABLE
        # safe_load is not a vulnerable API target → still INCONCLUSIVE
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
        assert report.unreachable_count == 2
        assert report.inconclusive_count == 0

    def test_empty_repo(self, tmp_path):
        empty_repo = tmp_path / "empty_repo"
        empty_repo.mkdir()
        vulns = [_make_vuln("requests")]
        report = analyze(vulns, empty_repo)
        assert report.results[0].verdict == Verdict.UNREACHABLE_STATIC

    def test_verdict_result_fields(self, sample_repo, coverage_path):
        vulns = [_make_vuln("requests")]
        report = analyze(vulns, sample_repo, coverage_path)
        r = report.results[0]
        assert r.imported_as == "requests"
        assert len(r.executed_files) > 0
        assert r.reason


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
                    }
                }
            )
        )

        vulns = [_make_vuln("Django", title="XSS in Django admin")]
        report = analyze(vulns, repo, cov_file)
        r = report.results[0]
        assert r.verdict == Verdict.UNREACHABLE_DYNAMIC
        assert "django.contrib.admin" in r.reason

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
