from __future__ import annotations

import json

from ca9.models import Evidence, PolicyIgnoredResult, Report, Verdict, VerdictResult, Vulnerability
from ca9.report import write_html, write_json, write_markdown, write_sarif


def _vuln(vid: str = "CVE-2023-0001", pkg: str = "requests", sev: str = "high") -> Vulnerability:
    return Vulnerability(
        id=vid,
        package_name=pkg,
        package_version="1.0.0",
        severity=sev,
        title=f"Vulnerability in {pkg}",
        description=f"Description of {vid}",
    )


class TestSARIF:
    def test_sarif_structure(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.REACHABLE,
                    reason="imported and executed",
                    imported_as="requests",
                ),
            ],
            repo_path=".",
        )
        text = write_sarif(report)
        data = json.loads(text)

        assert data["version"] == "2.1.0"
        assert "$schema" in data
        assert len(data["runs"]) == 1

        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "ca9"
        assert len(run["tool"]["driver"]["rules"]) == 1
        assert len(run["results"]) == 1

    def test_markdown_report(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.REACHABLE,
                    reason="imported | executed",
                    imported_as="requests",
                    confidence_score=88,
                ),
            ],
            repo_path=".",
        )
        text = write_markdown(report)
        assert "# ca9 Reachability Report" in text
        assert "CVE-2023-0001" in text
        assert "imported \\| executed" in text

    def test_markdown_report_includes_ignored_findings(self):
        ignored_result = VerdictResult(
            vulnerability=_vuln(),
            verdict=Verdict.REACHABLE,
            reason="imported and executed",
            confidence_score=90,
        )
        report = Report(
            results=[],
            ignored_results=[
                PolicyIgnoredResult(
                    result=ignored_result,
                    policy="accepted_risk",
                    reason="tracked exception",
                    owner="security",
                    expires="2099-01-01",
                )
            ],
            repo_path=".",
        )

        text = write_markdown(report)

        assert "Ignored Findings" in text
        assert "accepted_risk" in text
        assert "tracked exception" in text

    def test_html_report_escapes_content(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(vid="CVE-2023-0001", pkg="<pkg>"),
                    verdict=Verdict.INCONCLUSIVE,
                    reason="<script>alert(1)</script>",
                    confidence_score=42,
                ),
            ],
            repo_path=".",
        )
        text = write_html(report)
        assert "<!doctype html>" in text
        assert "&lt;pkg&gt;" in text
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text

    def test_html_report_includes_ignored_findings(self):
        ignored_result = VerdictResult(
            vulnerability=_vuln(vid="CVE-2023-0001", pkg="<pkg>"),
            verdict=Verdict.REACHABLE,
            reason="test",
        )
        report = Report(
            results=[],
            ignored_results=[
                PolicyIgnoredResult(
                    result=ignored_result,
                    policy="accepted_risk",
                    reason="<approved>",
                    owner="security",
                )
            ],
            repo_path=".",
        )

        text = write_html(report)

        assert "Ignored Findings" in text
        assert "&lt;pkg&gt;" in text
        assert "&lt;approved&gt;" in text

    def test_sarif_reachable_is_error(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    imported_as="requests",
                ),
            ],
            repo_path=".",
        )
        data = json.loads(write_sarif(report))
        assert data["runs"][0]["results"][0]["level"] == "error"

    def test_sarif_inconclusive_is_warning(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.INCONCLUSIVE,
                    reason="test",
                    imported_as="requests",
                ),
            ],
            repo_path=".",
        )
        data = json.loads(write_sarif(report))
        assert data["runs"][0]["results"][0]["level"] == "warning"

    def test_sarif_unreachable_is_note(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.UNREACHABLE_STATIC,
                    reason="test",
                    imported_as="requests",
                ),
            ],
            repo_path=".",
        )
        data = json.loads(write_sarif(report))
        assert data["runs"][0]["results"][0]["level"] == "note"

    def test_sarif_severity_mapping(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(sev="critical"),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    imported_as="requests",
                ),
            ],
            repo_path=".",
        )
        data = json.loads(write_sarif(report))
        rule = data["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["security-severity"] == "9.0"

    def test_sarif_deduplicates_rules(self):
        vuln = _vuln()
        report = Report(
            results=[
                VerdictResult(vulnerability=vuln, verdict=Verdict.REACHABLE, reason="r1"),
                VerdictResult(vulnerability=vuln, verdict=Verdict.REACHABLE, reason="r2"),
            ],
            repo_path=".",
        )
        data = json.loads(write_sarif(report))
        assert len(data["runs"][0]["tool"]["driver"]["rules"]) == 1
        assert len(data["runs"][0]["results"]) == 2

    def test_sarif_dependency_of(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    dependency_of="flask",
                ),
            ],
            repo_path=".",
        )
        data = json.loads(write_sarif(report))
        assert data["runs"][0]["results"][0]["properties"]["dependency_of"] == "flask"

    def test_sarif_write_to_file(self, tmp_path):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                ),
            ],
            repo_path=".",
        )
        outfile = tmp_path / "report.sarif"
        write_sarif(report, outfile)
        data = json.loads(outfile.read_text())
        assert data["version"] == "2.1.0"

    def test_sarif_help_uri(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(vid="CVE-2023-9999"),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                ),
            ],
            repo_path=".",
        )
        data = json.loads(write_sarif(report))
        rule = data["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["helpUri"] == "https://osv.dev/vulnerability/CVE-2023-9999"

    def test_sarif_fingerprints(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    confidence_score=85,
                ),
            ],
            repo_path=".",
        )
        data = json.loads(write_sarif(report))
        result = data["runs"][0]["results"][0]
        assert "fingerprints" in result
        assert "ca9/v1" in result["fingerprints"]
        assert len(result["fingerprints"]["ca9/v1"]) == 32

    def test_sarif_confidence_in_properties(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    confidence_score=75,
                ),
            ],
            repo_path=".",
        )
        data = json.loads(write_sarif(report))
        props = data["runs"][0]["results"][0]["properties"]
        assert props["confidence_score"] == 75

    def test_sarif_evidence_in_properties(self):
        evidence = Evidence(
            version_in_range=True,
            package_imported=True,
            dependency_kind="direct",
            coverage_seen=True,
            coverage_files=("file1.py",),
        )
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    evidence=evidence,
                ),
            ],
            repo_path=".",
        )
        data = json.loads(write_sarif(report))
        ev = data["runs"][0]["results"][0]["properties"]["evidence"]
        assert ev["version_in_range"] is True
        assert ev["package_imported"] is True
        assert ev["dependency_kind"] == "direct"

    def test_json_includes_evidence(self):
        evidence = Evidence(
            version_in_range=True,
            package_imported=True,
            dependency_kind="direct",
            affected_component_source="curated:django",
            affected_component_confidence=85,
        )
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    evidence=evidence,
                    confidence_score=80,
                ),
            ],
            repo_path=".",
        )
        data = json.loads(write_json(report))
        r = data["results"][0]
        assert r["confidence_score"] == 80
        assert r["evidence"]["version_in_range"] is True
        assert r["evidence"]["affected_component_source"] == "curated:django"

    def test_json_includes_ignored_findings(self):
        ignored_result = VerdictResult(
            vulnerability=_vuln(),
            verdict=Verdict.REACHABLE,
            reason="imported and executed",
            confidence_score=90,
        )
        report = Report(
            results=[],
            ignored_results=[
                PolicyIgnoredResult(
                    result=ignored_result,
                    policy="accepted_risk",
                    reason="tracked exception",
                    owner="security",
                    expires="2099-01-01",
                )
            ],
            repo_path=".",
        )

        data = json.loads(write_json(report))

        assert data["summary"]["total"] == 0
        assert data["summary"]["ignored"] == 1
        ignored = data["ignored_results"][0]
        assert ignored["id"] == "CVE-2023-0001"
        assert ignored["policy"] == "accepted_risk"
        assert ignored["policy_reason"] == "tracked exception"
        assert ignored["owner"] == "security"

    def test_json_includes_proof_standard_and_policy_adjustment(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.INCONCLUSIVE,
                    original_verdict=Verdict.UNREACHABLE_DYNAMIC,
                    policy_adjustment="strict proof downgraded this suppression because coverage completeness is below 80%",
                    reason="test",
                ),
            ],
            repo_path=".",
            proof_standard="strict",
        )
        data = json.loads(write_json(report))
        assert data["proof_standard"] == "strict"
        assert data["results"][0]["original_verdict"] == "unreachable_dynamic"
        assert "coverage completeness" in data["results"][0]["policy_adjustment"]

    def test_json_includes_report_warnings(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.INCONCLUSIVE,
                    reason="test",
                ),
            ],
            repo_path=".",
            warnings=["threat intelligence enrichment unavailable: timeout"],
        )

        data = json.loads(write_json(report))
        assert data["warnings"] == ["threat intelligence enrichment unavailable: timeout"]

    def test_sarif_includes_policy_adjustment(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.INCONCLUSIVE,
                    original_verdict=Verdict.UNREACHABLE_STATIC,
                    policy_adjustment="strict proof downgraded this suppression because the dependency graph came from the ambient environment rather than the report",
                    reason="test",
                ),
            ],
            repo_path=".",
            proof_standard="strict",
        )
        data = json.loads(write_sarif(report))
        props = data["runs"][0]["results"][0]["properties"]
        assert props["proof_standard"] == "strict"
        assert props["original_verdict"] == "unreachable_static"
        assert "ambient environment" in props["policy_adjustment"]

    def test_sarif_includes_report_warnings(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.INCONCLUSIVE,
                    reason="test",
                ),
            ],
            repo_path=".",
            warnings=["production trace ingestion unavailable: bad traces"],
        )

        data = json.loads(write_sarif(report))
        assert data["runs"][0]["properties"]["warnings"] == [
            "production trace ingestion unavailable: bad traces"
        ]

    def test_sarif_includes_ignored_findings_as_suppressed_results(self):
        ignored_result = VerdictResult(
            vulnerability=_vuln(),
            verdict=Verdict.REACHABLE,
            reason="imported and executed",
            confidence_score=90,
        )
        report = Report(
            results=[],
            ignored_results=[
                PolicyIgnoredResult(
                    result=ignored_result,
                    policy="accepted_risk",
                    reason="tracked exception",
                    owner="security",
                    expires="2099-01-01",
                )
            ],
            repo_path=".",
        )

        data = json.loads(write_sarif(report))
        result = data["runs"][0]["results"][0]

        assert result["suppressions"] == [
            {"kind": "external", "justification": "tracked exception"}
        ]
        assert result["properties"]["policy_ignored"] is True
        assert result["properties"]["policy"] == "accepted_risk"
        assert result["properties"]["policy_owner"] == "security"

    def test_sarif_blast_radius_in_properties(self):
        from ca9.capabilities.models import BlastRadius, CapabilityHit

        br = BlastRadius(
            capabilities=("exec.shell", "network.egress"),
            details=(
                CapabilityHit(name="exec.shell", scope="*", source_file="t.py", asset_ref="a"),
            ),
            risk_level="high",
            risk_reasons=("Attacker gains shell execution",),
        )
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    blast_radius=br,
                ),
            ],
            repo_path=".",
        )
        data = json.loads(write_sarif(report))
        props = data["runs"][0]["results"][0]["properties"]
        assert "blast_radius" in props
        assert props["blast_radius"]["risk_level"] == "high"
        assert "exec.shell" in props["blast_radius"]["capabilities"]

    def test_sarif_fingerprint_stable(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.REACHABLE,
                    reason="test1",
                ),
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.REACHABLE,
                    reason="test2",
                ),
            ],
            repo_path=".",
        )
        data = json.loads(write_sarif(report))
        fp1 = data["runs"][0]["results"][0]["fingerprints"]["ca9/v1"]
        fp2 = data["runs"][0]["results"][1]["fingerprints"]["ca9/v1"]
        assert fp1 == fp2
