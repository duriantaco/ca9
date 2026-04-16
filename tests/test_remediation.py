from __future__ import annotations

from ca9.capabilities.models import BlastRadius, CapabilityHit
from ca9.models import Evidence, Report, Verdict, VerdictResult, VersionRange, Vulnerability
from ca9.remediation import (
    generate_remediation,
    generate_remediation_plan,
    remediation_plan_to_dict,
)


def _vuln(pkg="requests", version="2.31.0", severity="high", fix="2.32.0"):
    ranges = (VersionRange(introduced="2.0.0", fixed=fix),) if fix else ()
    return Vulnerability(
        id="CVE-2024-1234",
        package_name=pkg,
        package_version=version,
        severity=severity,
        title="Test",
        affected_ranges=ranges,
    )


def _blast_radius(caps=("exec.shell",), risk="high"):
    hits = tuple(
        CapabilityHit(name=c, scope="*", source_file="app.py", asset_ref="a") for c in caps
    )
    return BlastRadius(capabilities=caps, details=hits, risk_level=risk, risk_reasons=())


class TestActionDetermination:
    def test_reachable_with_fix_suggests_upgrade(self):
        result = VerdictResult(
            vulnerability=_vuln(fix="2.32.0"),
            verdict=Verdict.REACHABLE,
            reason="test",
            evidence=Evidence(dependency_kind="direct"),
        )
        action = generate_remediation(result)
        assert action.action == "upgrade"
        assert action.fix_version == "2.32.0"
        assert "Upgrade" in action.summary

    def test_reachable_without_fix_suggests_mitigate(self):
        result = VerdictResult(
            vulnerability=_vuln(fix=None),
            verdict=Verdict.REACHABLE,
            reason="test",
            evidence=Evidence(dependency_kind="direct"),
        )
        action = generate_remediation(result)
        assert action.action == "mitigate"
        assert "No fix available" in action.summary

    def test_inconclusive_suggests_investigate(self):
        result = VerdictResult(
            vulnerability=_vuln(), verdict=Verdict.INCONCLUSIVE, reason="no coverage"
        )
        action = generate_remediation(result)
        assert action.action == "investigate"

    def test_unreachable_dynamic_suggests_monitor(self):
        result = VerdictResult(
            vulnerability=_vuln(), verdict=Verdict.UNREACHABLE_DYNAMIC, reason="not executed"
        )
        action = generate_remediation(result)
        assert action.action == "monitor"

    def test_unreachable_static_suggests_none(self):
        result = VerdictResult(
            vulnerability=_vuln(), verdict=Verdict.UNREACHABLE_STATIC, reason="not imported"
        )
        action = generate_remediation(result)
        assert action.action == "none"


class TestPriorityComputation:
    def test_critical_severity_reachable_high_blast_is_critical(self):
        result = VerdictResult(
            vulnerability=_vuln(severity="critical"),
            verdict=Verdict.REACHABLE,
            reason="test",
            evidence=Evidence(dependency_kind="direct"),
            blast_radius=_blast_radius(("exec.shell",), "high"),
        )
        assert generate_remediation(result).priority == "critical"

    def test_medium_severity_critical_blast_is_critical(self):
        result = VerdictResult(
            vulnerability=_vuln(severity="medium"),
            verdict=Verdict.REACHABLE,
            reason="test",
            evidence=Evidence(dependency_kind="direct"),
            blast_radius=_blast_radius(("exec.shell", "network.egress"), "critical"),
        )
        assert generate_remediation(result).priority == "critical"

    def test_low_severity_no_blast_is_low(self):
        result = VerdictResult(
            vulnerability=_vuln(severity="low"),
            verdict=Verdict.REACHABLE,
            reason="test",
            evidence=Evidence(dependency_kind="direct"),
        )
        assert generate_remediation(result).priority == "low"

    def test_inconclusive_critical_severity_is_high(self):
        result = VerdictResult(
            vulnerability=_vuln(severity="critical"), verdict=Verdict.INCONCLUSIVE, reason="test"
        )
        assert generate_remediation(result).priority == "high"

    def test_inconclusive_high_severity_is_medium(self):
        result = VerdictResult(
            vulnerability=_vuln(severity="high"), verdict=Verdict.INCONCLUSIVE, reason="test"
        )
        assert generate_remediation(result).priority == "medium"

    def test_unreachable_static_always_low(self):
        result = VerdictResult(
            vulnerability=_vuln(severity="critical"),
            verdict=Verdict.UNREACHABLE_STATIC,
            reason="test",
        )
        assert generate_remediation(result).priority == "low"

    def test_high_confidence_critical_reachable_is_critical(self):
        result = VerdictResult(
            vulnerability=_vuln(severity="critical"),
            verdict=Verdict.REACHABLE,
            reason="test",
            confidence_score=85,
            evidence=Evidence(dependency_kind="direct"),
        )
        assert generate_remediation(result).priority == "critical"


class TestCompensatingControls:
    def test_shell_exec_controls(self):
        result = VerdictResult(
            vulnerability=_vuln(fix=None),
            verdict=Verdict.REACHABLE,
            reason="test",
            evidence=Evidence(dependency_kind="direct"),
            blast_radius=_blast_radius(("exec.shell",), "high"),
        )
        action = generate_remediation(result)
        assert any("shell" in c.lower() for c in action.compensating_controls)
        assert any("allowlist" in c.lower() for c in action.compensating_controls)

    def test_exfiltration_risk_controls(self):
        result = VerdictResult(
            vulnerability=_vuln(fix=None),
            verdict=Verdict.REACHABLE,
            reason="test",
            evidence=Evidence(dependency_kind="direct"),
            blast_radius=_blast_radius(("filesystem.read", "network.egress"), "high"),
        )
        action = generate_remediation(result)
        assert any("exfiltration" in c.lower() for c in action.compensating_controls)

    def test_db_exfiltration_risk_controls(self):
        result = VerdictResult(
            vulnerability=_vuln(fix=None),
            verdict=Verdict.REACHABLE,
            reason="test",
            evidence=Evidence(dependency_kind="direct"),
            blast_radius=_blast_radius(("db.read", "network.egress"), "high"),
        )
        action = generate_remediation(result)
        assert any(
            "db.read" in c.lower() and "exfiltration" in c.lower()
            for c in action.compensating_controls
        )

    def test_shell_plus_fs_write_critical_control(self):
        result = VerdictResult(
            vulnerability=_vuln(fix=None),
            verdict=Verdict.REACHABLE,
            reason="test",
            evidence=Evidence(dependency_kind="direct"),
            blast_radius=_blast_radius(("exec.shell", "filesystem.write"), "critical"),
        )
        action = generate_remediation(result)
        assert any(
            "critical" in c.lower() or "sandbox" in c.lower() for c in action.compensating_controls
        )

    def test_no_blast_radius_gets_generic_control(self):
        result = VerdictResult(
            vulnerability=_vuln(fix=None),
            verdict=Verdict.REACHABLE,
            reason="test",
            evidence=Evidence(dependency_kind="direct"),
        )
        action = generate_remediation(result)
        assert len(action.compensating_controls) >= 1
        assert any("review" in c.lower() for c in action.compensating_controls)

    def test_investigate_gets_controls_when_has_blast_radius(self):
        result = VerdictResult(
            vulnerability=_vuln(),
            verdict=Verdict.INCONCLUSIVE,
            reason="test",
            blast_radius=_blast_radius(("exec.shell",), "high"),
        )
        action = generate_remediation(result)
        assert any("shell" in c.lower() for c in action.compensating_controls)


class TestDependencyInfo:
    def test_transitive_dep_info(self):
        result = VerdictResult(
            vulnerability=_vuln(pkg="urllib3"),
            verdict=Verdict.REACHABLE,
            reason="test",
            evidence=Evidence(
                dependency_kind="transitive",
                report_dependency_chain=("requests", "urllib3"),
            ),
        )
        action = generate_remediation(result)
        assert not action.is_direct_dependency
        assert action.dependency_chain == ["requests", "urllib3"]

    def test_transitive_dep_to_dict_has_upgrade_hint(self):
        result = VerdictResult(
            vulnerability=_vuln(pkg="urllib3"),
            verdict=Verdict.REACHABLE,
            reason="test",
            evidence=Evidence(
                dependency_kind="transitive",
                report_dependency_chain=("requests", "urllib3"),
            ),
        )
        d = generate_remediation(result).to_dict()
        assert "upgrade_hint" in d
        assert "requests" in d["upgrade_hint"]


class TestSummary:
    def test_summary_includes_blast_radius(self):
        result = VerdictResult(
            vulnerability=_vuln(),
            verdict=Verdict.REACHABLE,
            reason="test",
            evidence=Evidence(dependency_kind="direct"),
            blast_radius=_blast_radius(("exec.shell", "network.egress"), "critical"),
        )
        action = generate_remediation(result)
        assert "critical" in action.summary.lower()
        assert "exec.shell" in action.summary

    def test_inconclusive_critical_severity_mentions_severity(self):
        result = VerdictResult(
            vulnerability=_vuln(severity="critical"),
            verdict=Verdict.INCONCLUSIVE,
            reason="test",
        )
        action = generate_remediation(result)
        assert "critical" in action.summary.lower()

    def test_confidence_score_in_to_dict(self):
        result = VerdictResult(
            vulnerability=_vuln(),
            verdict=Verdict.REACHABLE,
            reason="test",
            confidence_score=75,
            evidence=Evidence(dependency_kind="direct"),
        )
        d = generate_remediation(result).to_dict()
        assert d["confidence_score"] == 75


class TestRemediationPlan:
    def test_plan_sorts_by_priority(self):
        results = [
            VerdictResult(
                vulnerability=_vuln(pkg="low-pkg", severity="low"),
                verdict=Verdict.UNREACHABLE_STATIC,
                reason="not imported",
            ),
            VerdictResult(
                vulnerability=_vuln(pkg="high-pkg", severity="critical"),
                verdict=Verdict.REACHABLE,
                reason="imported",
                evidence=Evidence(dependency_kind="direct"),
            ),
            VerdictResult(
                vulnerability=_vuln(pkg="med-pkg", severity="medium"),
                verdict=Verdict.INCONCLUSIVE,
                reason="no coverage",
            ),
        ]
        report = Report(results=results, repo_path=".")
        plan = generate_remediation_plan(report)

        assert plan[0].package_name == "high-pkg"
        assert plan[0].priority in ("critical", "high")
        assert plan[-1].priority == "low"

    def test_plan_to_dict_summary(self):
        results = [
            VerdictResult(
                vulnerability=_vuln(),
                verdict=Verdict.REACHABLE,
                reason="test",
                evidence=Evidence(dependency_kind="direct"),
            ),
            VerdictResult(
                vulnerability=_vuln(pkg="other", fix=None),
                verdict=Verdict.REACHABLE,
                reason="test",
                evidence=Evidence(dependency_kind="direct"),
            ),
        ]
        report = Report(results=results, repo_path=".")
        plan = generate_remediation_plan(report)
        data = remediation_plan_to_dict(plan)

        assert data["summary"]["total"] == 2
        assert data["summary"]["upgradable"] == 1
        assert data["summary"]["needs_mitigation"] == 1
        assert data["summary"]["actionable"] == 2

    def test_empty_report(self):
        report = Report(results=[], repo_path=".")
        plan = generate_remediation_plan(report)
        data = remediation_plan_to_dict(plan)
        assert data["summary"]["total"] == 0
        assert data["actions"] == []
