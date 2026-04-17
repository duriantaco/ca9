from __future__ import annotations

from dataclasses import dataclass, field

from ca9.models import Report, Verdict, VerdictResult


@dataclass
class RemediationAction:
    vuln_id: str
    package_name: str
    package_version: str
    severity: str
    action: str  # upgrade, mitigate, investigate, monitor, none
    priority: str  # critical, high, medium, low
    summary: str
    fix_version: str | None = None
    is_direct_dependency: bool = True
    dependency_chain: list[str] = field(default_factory=list)
    compensating_controls: list[str] = field(default_factory=list)
    blast_radius_capabilities: list[str] = field(default_factory=list)
    blast_radius_risk: str = "low"
    confidence_score: int = 0

    def to_dict(self) -> dict:
        d: dict = {
            "vuln_id": self.vuln_id,
            "package": self.package_name,
            "version": self.package_version,
            "severity": self.severity,
            "action": self.action,
            "priority": self.priority,
            "summary": self.summary,
            "confidence_score": self.confidence_score,
        }
        if self.fix_version:
            d["fix_version"] = self.fix_version
        if not self.is_direct_dependency:
            d["is_direct_dependency"] = False
            if self.dependency_chain:
                d["dependency_chain"] = self.dependency_chain
            d["upgrade_hint"] = (
                f"Transitive dependency — upgrade {self.dependency_chain[0]} "
                f"to pull a fixed version of {self.package_name}"
                if self.dependency_chain
                else f"Transitive dependency — find which direct dep pulls {self.package_name}"
            )
        if self.compensating_controls:
            d["compensating_controls"] = self.compensating_controls
        if self.blast_radius_capabilities:
            d["blast_radius"] = {
                "capabilities": self.blast_radius_capabilities,
                "risk": self.blast_radius_risk,
            }
        return d


def _get_blast_radius(result: VerdictResult):
    br = result.blast_radius
    if br is None:
        return None
    if not hasattr(br, "capabilities"):
        return None
    return br


def _extract_fix_version(result: VerdictResult) -> str | None:
    for r in result.vulnerability.affected_ranges:
        if r.fixed:
            return r.fixed
    return None


def _compute_priority(result: VerdictResult) -> str:
    verdict = result.verdict
    severity = result.vulnerability.severity.lower()
    confidence = result.confidence_score

    ti = result.threat_intel
    has_high_epss = ti is not None and ti.epss_score is not None and ti.epss_score >= 0.5
    is_kev = ti is not None and ti.in_kev

    if verdict == Verdict.REACHABLE:
        br = _get_blast_radius(result)
        br_risk = br.risk_level if br else "low"

        if br_risk == "critical":
            return "critical"
        if severity == "critical" and br_risk in ("high", "critical"):
            return "critical"
        if severity == "critical" and confidence >= 70:
            return "critical"
        if has_high_epss and is_kev:
            return "critical"
        if severity in ("critical", "high") or br_risk in ("high", "critical"):
            return "high"
        if has_high_epss and severity == "medium":
            return "high"
        if severity == "medium" or br_risk == "medium":
            return "medium"
        if is_kev:
            return "medium"
        return "low"

    if verdict == Verdict.INCONCLUSIVE:
        if severity == "critical":
            return "high"
        if severity == "high":
            return "medium"
        if is_kev:
            return "medium"
        return "low"

    return "low"


def _determine_action(result: VerdictResult) -> str:
    if result.verdict == Verdict.REACHABLE:
        if _extract_fix_version(result):
            return "upgrade"
        return "mitigate"

    if result.verdict == Verdict.INCONCLUSIVE:
        return "investigate"

    if result.verdict == Verdict.UNREACHABLE_DYNAMIC:
        return "monitor"

    return "none"


def _generate_compensating_controls(result: VerdictResult) -> list[str]:
    controls: list[str] = []

    br = _get_blast_radius(result)
    if not br:
        if result.verdict == Verdict.REACHABLE:
            controls.append("Review vulnerable code path and assess exploitability manually")
        return controls

    caps = set(br.capabilities)

    if "exec.shell" in caps:
        controls.append(
            "Restrict or remove shell execution capability from MCP/agent configuration"
        )
        controls.append("Apply allowlist for permitted shell commands")

    if "network.egress" in caps:
        controls.append("Restrict network egress to known-safe domains via firewall or proxy rules")
        controls.append("Monitor outbound traffic for anomalous data exfiltration patterns")

    if any(c.startswith("filesystem.write") or c == "filesystem.write" for c in caps):
        controls.append("Restrict filesystem write paths to minimum necessary scope")
        controls.append("Enable filesystem integrity monitoring on sensitive paths")

    if any(c.startswith("filesystem.read") or c == "filesystem.read" for c in caps):
        if "network.egress" in caps:
            controls.append(
                "PRIORITY: filesystem.read + network.egress = exfiltration risk — "
                "isolate service or restrict read paths"
            )

    if "db.read" in caps and "network.egress" in caps:
        controls.append(
            "PRIORITY: db.read + network.egress = data exfiltration risk — "
            "restrict database read access and monitor egress"
        )

    if "db.write" in caps:
        controls.append("Restrict database write permissions to minimum necessary tables/schemas")

    if "db.read" in caps:
        controls.append("Restrict database read access to minimum necessary tables/views")

    for c in caps:
        if c.startswith("storage.") and c.endswith(".write"):
            controls.append(
                f"Restrict cloud storage write access ({c}) to specific buckets/prefixes"
            )
        if c.startswith("storage.") and c.endswith(".read") and "network.egress" in caps:
            controls.append(
                f"Cloud storage read ({c}) + network egress = exfiltration risk — "
                f"restrict storage access scope"
            )

    if "exec.shell" in caps and any(
        c.startswith("filesystem.write") or c == "filesystem.write" for c in caps
    ):
        controls.append(
            "CRITICAL: shell exec + filesystem write — "
            "consider isolating this service in a sandboxed environment"
        )

    return controls


def _build_summary(result: VerdictResult, action: str, fix_version: str | None) -> str:
    vuln = result.vulnerability
    pkg = f"{vuln.package_name}@{vuln.package_version}"

    if result.verdict == Verdict.REACHABLE:
        if fix_version:
            base = f"Upgrade {pkg} to {fix_version} — vulnerability is reachable"
        else:
            base = f"No fix available for {pkg} — apply compensating controls"

        br = _get_blast_radius(result)
        if br and br.risk_level in ("high", "critical"):
            base += f" with {br.risk_level} blast radius"
            if br.capabilities:
                base += f" ({', '.join(sorted(br.capabilities)[:3])})"
        return base

    if result.verdict == Verdict.INCONCLUSIVE:
        severity = vuln.severity.lower()
        if severity in ("critical", "high"):
            return (
                f"Investigate {pkg} (severity: {severity}) — reachability could not be "
                f"determined. Add coverage or review manually."
            )
        return (
            f"Investigate {pkg} — reachability could not be determined. "
            f"Add coverage or review manually."
        )

    if result.verdict == Verdict.UNREACHABLE_DYNAMIC:
        return f"Monitor {pkg} — not executed in tests but imported. Retest after code changes."

    return f"No action needed for {pkg} — not reachable."


def generate_remediation(result: VerdictResult) -> RemediationAction:
    fix_version = _extract_fix_version(result)
    action = _determine_action(result)
    priority = _compute_priority(result)
    if result.runtime_adjusted_priority:
        priority = result.runtime_adjusted_priority
    compensating = _generate_compensating_controls(result) if action != "none" else []
    summary = _build_summary(result, action, fix_version)

    ev = result.evidence
    is_direct = True
    chain: list[str] = []
    if ev:
        is_direct = ev.dependency_kind != "transitive"
        if ev.report_dependency_chain:
            chain = list(ev.report_dependency_chain)

    br = _get_blast_radius(result)
    br_caps = list(br.capabilities) if br else []
    br_risk = br.risk_level if br else "low"

    return RemediationAction(
        vuln_id=result.vulnerability.id,
        package_name=result.vulnerability.package_name,
        package_version=result.vulnerability.package_version,
        severity=result.vulnerability.severity,
        action=action,
        priority=priority,
        summary=summary,
        fix_version=fix_version,
        is_direct_dependency=is_direct,
        dependency_chain=chain,
        compensating_controls=compensating,
        blast_radius_capabilities=br_caps,
        blast_radius_risk=br_risk,
        confidence_score=result.confidence_score,
    )


def generate_remediation_plan(report: Report) -> list[RemediationAction]:
    actions = [generate_remediation(r) for r in report.results]

    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    actions.sort(key=lambda a: (priority_order.get(a.priority, 4), a.package_name))

    return actions


def remediation_plan_to_dict(actions: list[RemediationAction]) -> dict:
    critical = sum(1 for a in actions if a.priority == "critical")
    high = sum(1 for a in actions if a.priority == "high")
    actionable = [a for a in actions if a.action not in ("none", "monitor")]

    return {
        "summary": {
            "total": len(actions),
            "critical_priority": critical,
            "high_priority": high,
            "actionable": len(actionable),
            "upgradable": sum(1 for a in actions if a.action == "upgrade"),
            "needs_mitigation": sum(1 for a in actions if a.action == "mitigate"),
            "needs_investigation": sum(1 for a in actions if a.action == "investigate"),
        },
        "actions": [a.to_dict() for a in actions],
    }
