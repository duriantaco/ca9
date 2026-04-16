from __future__ import annotations

from ca9.action_plan import generate_action_plan
from ca9.capabilities.models import BlastRadius, CapabilityHit
from ca9.models import Evidence, Report, Verdict, VerdictResult, VersionRange, Vulnerability


def _vuln(pkg="requests", severity="high", fix="2.32.0"):
    ranges = (VersionRange(introduced="2.0.0", fixed=fix),) if fix else ()
    return Vulnerability(
        id="CVE-1",
        package_name=pkg,
        package_version="2.31.0",
        severity=severity,
        title="Test",
        affected_ranges=ranges,
    )


def _blast_radius(caps=("exec.shell",), risk="high"):
    hits = tuple(CapabilityHit(name=c, scope="*", source_file="a.py", asset_ref="a") for c in caps)
    return BlastRadius(capabilities=caps, details=hits, risk_level=risk, risk_reasons=())


class TestActionPlan:
    def test_critical_reachable_blocks_deploy(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(severity="critical"),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    evidence=Evidence(dependency_kind="direct"),
                )
            ],
            repo_path=".",
        )
        plan = generate_action_plan(report)

        assert plan.decision == "block"
        assert plan.exit_code == 1
        assert any(a.action_type == "block_deploy" for a in plan.actions)

    def test_critical_blast_radius_blocks_deploy(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(severity="medium"),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    evidence=Evidence(dependency_kind="direct"),
                    blast_radius=_blast_radius(("exec.shell", "network.egress"), "critical"),
                )
            ],
            repo_path=".",
        )
        plan = generate_action_plan(report)

        assert plan.decision == "block"

    def test_high_reachable_with_fix_opens_pr(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(severity="high", fix="2.32.0"),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    evidence=Evidence(dependency_kind="direct"),
                )
            ],
            repo_path=".",
        )
        plan = generate_action_plan(report)

        assert any(a.action_type == "open_pr" for a in plan.actions)
        pr_action = next(a for a in plan.actions if a.action_type == "open_pr")
        assert pr_action.details["fix_version"] == "2.32.0"

    def test_medium_reachable_notifies(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(severity="medium", fix="2.32.0"),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    evidence=Evidence(dependency_kind="direct"),
                )
            ],
            repo_path=".",
        )
        plan = generate_action_plan(report)

        assert any(a.action_type == "notify" for a in plan.actions)

    def test_no_fix_with_dangerous_cap_revokes(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(fix=None),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    evidence=Evidence(dependency_kind="direct"),
                    blast_radius=_blast_radius(("exec.shell",), "high"),
                )
            ],
            repo_path=".",
        )
        plan = generate_action_plan(report)

        assert any(a.action_type == "revoke_capability" for a in plan.actions)
        revoke = next(a for a in plan.actions if a.action_type == "revoke_capability")
        assert revoke.target == "exec.shell"

    def test_inconclusive_adds_monitor(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(), verdict=Verdict.INCONCLUSIVE, reason="no coverage"
                )
            ],
            repo_path=".",
        )
        plan = generate_action_plan(report)

        assert plan.decision == "warn"
        assert any(a.action_type == "add_monitor" for a in plan.actions)

    def test_all_unreachable_passes(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(),
                    verdict=Verdict.UNREACHABLE_STATIC,
                    reason="not imported",
                )
            ],
            repo_path=".",
        )
        plan = generate_action_plan(report)

        assert plan.decision == "pass"
        assert plan.exit_code == 0

    def test_action_plan_to_dict(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=_vuln(severity="critical", fix="2.32.0"),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    evidence=Evidence(dependency_kind="direct"),
                ),
                VerdictResult(
                    vulnerability=_vuln(pkg="flask", fix=None),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    evidence=Evidence(dependency_kind="direct"),
                    blast_radius=_blast_radius(("exec.shell",), "high"),
                ),
            ],
            repo_path=".",
        )
        plan = generate_action_plan(report)
        data = plan.to_dict()

        assert data["decision"] == "block"
        assert data["counts"]["block_deploy"] >= 1
        assert data["counts"]["open_pr"] >= 1
        assert data["counts"]["revoke_capability"] >= 1

    def test_deduplicates_actions(self):
        report = Report(
            results=[
                VerdictResult(
                    vulnerability=Vulnerability(
                        id="CVE-1",
                        package_name="requests",
                        package_version="2.31.0",
                        severity="high",
                        title="t",
                        affected_ranges=(VersionRange(fixed="2.32.0"),),
                    ),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    evidence=Evidence(dependency_kind="direct"),
                ),
                VerdictResult(
                    vulnerability=Vulnerability(
                        id="CVE-2",
                        package_name="requests",
                        package_version="2.31.0",
                        severity="high",
                        title="t2",
                        affected_ranges=(VersionRange(fixed="2.32.0"),),
                    ),
                    verdict=Verdict.REACHABLE,
                    reason="test",
                    evidence=Evidence(dependency_kind="direct"),
                ),
            ],
            repo_path=".",
        )
        plan = generate_action_plan(report)

        pr_actions = [a for a in plan.actions if a.action_type == "open_pr"]
        assert len(pr_actions) == 1
