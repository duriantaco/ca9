from __future__ import annotations

import json

from ca9.capabilities.models import BlastRadius, CapabilityHit
from ca9.models import Evidence, PolicyIgnoredResult, Report, Verdict, VerdictResult, Vulnerability
from ca9.vex import write_openvex


def _vuln(pkg="requests", version="2.31.0", vuln_id="CVE-2024-1234"):
    return Vulnerability(
        id=vuln_id, package_name=pkg, package_version=version, severity="high", title="Test"
    )


def _blast_radius(caps=("exec.shell",), risk="high"):
    hits = tuple(
        CapabilityHit(name=c, scope="*", source_file="app.py", asset_ref="a") for c in caps
    )
    return BlastRadius(
        capabilities=caps, details=hits, risk_level=risk, risk_reasons=("Shell exec gained",)
    )


class TestVEXStatusMapping:
    def test_reachable_maps_to_affected(self):
        report = Report(
            results=[
                VerdictResult(vulnerability=_vuln(), verdict=Verdict.REACHABLE, reason="test")
            ],
            repo_path=".",
        )
        data = json.loads(write_openvex(report))
        assert data["statements"][0]["status"] == "affected"
        assert "justification" not in data["statements"][0]

    def test_unreachable_static_maps_to_not_affected(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.UNREACHABLE_STATIC,
                    reason="not imported",
                    evidence=Evidence(package_imported=False),
                )
            ],
            repo_path=".",
        )
        data = json.loads(write_openvex(report))
        stmt = data["statements"][0]
        assert stmt["status"] == "not_affected"
        assert stmt["justification"] == "component_not_present"

    def test_unreachable_dynamic_maps_to_not_affected_execute_path(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.UNREACHABLE_DYNAMIC,
                    reason="not executed",
                    evidence=Evidence(package_imported=True, coverage_seen=False),
                )
            ],
            repo_path=".",
        )
        data = json.loads(write_openvex(report))
        stmt = data["statements"][0]
        assert stmt["status"] == "not_affected"
        assert stmt["justification"] == "vulnerable_code_not_in_execute_path"

    def test_inconclusive_maps_to_under_investigation(self):
        report = Report(
            results=[
                VerdictResult(vulnerability=_vuln(), verdict=Verdict.INCONCLUSIVE, reason="no data")
            ],
            repo_path=".",
        )
        data = json.loads(write_openvex(report))
        assert data["statements"][0]["status"] == "under_investigation"


class TestVEXJustifications:
    def test_version_out_of_range(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.UNREACHABLE_STATIC,
                    reason="version not affected",
                    evidence=Evidence(version_in_range=False),
                )
            ],
            repo_path=".",
        )
        data = json.loads(write_openvex(report))
        assert data["statements"][0]["justification"] == "component_not_present"

    def test_submodule_not_imported(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.UNREACHABLE_STATIC,
                    reason="submodule not imported",
                    evidence=Evidence(package_imported=True, submodule_imported=False),
                )
            ],
            repo_path=".",
        )
        data = json.loads(write_openvex(report))
        assert data["statements"][0]["justification"] == "vulnerable_code_not_present"

    def test_unreachable_static_no_evidence(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.UNREACHABLE_STATIC,
                    reason="test",
                    evidence=None,
                )
            ],
            repo_path=".",
        )
        data = json.loads(write_openvex(report))
        assert data["statements"][0]["justification"] == "component_not_present"

    def test_unreachable_dynamic_no_evidence(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.UNREACHABLE_DYNAMIC,
                    reason="test",
                    evidence=None,
                )
            ],
            repo_path=".",
        )
        data = json.loads(write_openvex(report))
        assert data["statements"][0]["justification"] == "vulnerable_code_not_in_execute_path"


class TestVEXImpactStatement:
    def test_reachable_has_impact_statement(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(), verdict=Verdict.REACHABLE, reason="imported and executed"
                )
            ],
            repo_path=".",
        )
        data = json.loads(write_openvex(report))
        assert "impact_statement" in data["statements"][0]
        assert "reachable" in data["statements"][0]["impact_statement"].lower()

    def test_reachable_with_blast_radius_in_impact(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    blast_radius=_blast_radius(("exec.shell", "network.egress"), "critical"),
                )
            ],
            repo_path=".",
        )
        data = json.loads(write_openvex(report))
        impact = data["statements"][0]["impact_statement"]
        assert "exec.shell" in impact
        assert "critical" in impact.lower()

    def test_unreachable_has_no_impact_statement(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.UNREACHABLE_STATIC,
                    reason="test",
                    evidence=Evidence(package_imported=False),
                )
            ],
            repo_path=".",
        )
        data = json.loads(write_openvex(report))
        assert "impact_statement" not in data["statements"][0]


class TestVEXMetadata:
    def test_document_structure(self):
        report = Report(results=[], repo_path=".", proof_standard="strict")
        data = json.loads(write_openvex(report))
        assert data["@context"] == "https://openvex.dev/ns/v0.2.0"
        assert data["role"] == "tool"
        assert data["version"] == 1
        assert data["tooling"]["name"] == "ca9"
        assert data["tooling"]["proof_standard"] == "strict"
        assert data["statements"] == []

    def test_ca9_metadata_on_statement(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    confidence_score=85,
                )
            ],
            repo_path=".",
        )
        data = json.loads(write_openvex(report))
        ca9 = data["statements"][0]["ca9"]
        assert ca9["confidence_score"] == 85
        assert ca9["verdict"] == "reachable"

    def test_policy_adjustment_preserved(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.INCONCLUSIVE,
                    reason="downgraded",
                    original_verdict=Verdict.UNREACHABLE_DYNAMIC,
                    policy_adjustment="strict proof downgraded",
                )
            ],
            repo_path=".",
        )
        data = json.loads(write_openvex(report))
        ca9 = data["statements"][0]["ca9"]
        assert ca9["original_verdict"] == "unreachable_dynamic"
        assert "strict proof" in ca9["policy_adjustment"]

    def test_ignored_policy_findings_are_preserved(self):
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

        data = json.loads(write_openvex(report))
        stmt = data["statements"][0]

        assert stmt["status"] == "affected"
        assert stmt["ca9"]["policy_ignored"] is True
        assert stmt["ca9"]["policy"] == "accepted_risk"
        assert stmt["ca9"]["policy_reason"] == "tracked exception"
        assert stmt["ca9"]["policy_owner"] == "security"

    def test_evidence_summary_included(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    evidence=Evidence(
                        package_imported=True,
                        dependency_kind="direct",
                        coverage_seen=True,
                        coverage_completeness_pct=92.0,
                        dependency_graph_source="report",
                    ),
                )
            ],
            repo_path=".",
        )
        data = json.loads(write_openvex(report))
        ev = data["statements"][0]["ca9"]["evidence_summary"]
        assert ev["package_imported"] is True
        assert ev["dependency_kind"] == "direct"
        assert ev["coverage_seen"] is True
        assert ev["coverage_completeness_pct"] == 92.0
        assert ev["dependency_graph_source"] == "report"

    def test_purl_lowercased(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(pkg="PyYAML", version="6.0.1"),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                )
            ],
            repo_path=".",
        )
        data = json.loads(write_openvex(report))
        assert data["statements"][0]["products"][0]["@id"] == "pkg:pypi/pyyaml@6.0.1"
