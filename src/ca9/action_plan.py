from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

from ca9.core.models import package_key
from ca9.models import Report, ScanCoverage, Verdict, VerdictResult
from ca9.remediation import RemediationAction, common_fix_version, generate_remediation


@dataclass
class ActionItem:
    action_type: str  # block_deploy, open_pr, revoke_capability, add_monitor, notify, no_action
    target: str  # package name, capability ref, or service name
    reason: str
    priority: str  # critical, high, medium, low
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d: dict = {
            "action_type": self.action_type,
            "target": self.target,
            "reason": self.reason,
            "priority": self.priority,
        }
        if self.details:
            d["details"] = self.details
        return d


@dataclass
class ActionPlan:
    decision: str  # block, warn, pass
    exit_code: int
    actions: list[ActionItem] = field(default_factory=list)
    summary: str = ""
    scan_coverage: ScanCoverage | None = None

    def to_dict(self) -> dict:
        return {
            **({"scan_coverage": self.scan_coverage.to_dict()} if self.scan_coverage else {}),
            "decision": self.decision,
            "exit_code": self.exit_code,
            "summary": self.summary,
            "actions": [a.to_dict() for a in self.actions],
            "counts": {
                "block_deploy": sum(1 for a in self.actions if a.action_type == "block_deploy"),
                "open_pr": sum(1 for a in self.actions if a.action_type == "open_pr"),
                "revoke_capability": sum(
                    1 for a in self.actions if a.action_type == "revoke_capability"
                ),
                "add_monitor": sum(1 for a in self.actions if a.action_type == "add_monitor"),
                "notify": sum(1 for a in self.actions if a.action_type == "notify"),
            },
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


def _get_blast_radius(result):
    br = result.blast_radius
    if br is None or not hasattr(br, "capabilities"):
        return None
    return br


def _package_upgrade(group: list[tuple[VerdictResult, RemediationAction]]) -> ActionItem:
    result, first = group[0]  # Ordered by priority.
    target = common_fix_version([item.vulnerability for item, _ in group])
    details = {
        "ecosystem": result.vulnerability.ecosystem,
        "current_version": first.package_version,
        "vuln_ids": sorted({rem.vuln_id for _, rem in group}),
    }
    if target is None:
        details["individual_fixes"] = {rem.vuln_id: rem.fix_version for _, rem in group}
        reported = {
            rem.vuln_id: list(rem.reported_fix_versions)
            for _, rem in group
            if rem.fix_version is None and rem.reported_fix_versions
        }
        if reported:
            details["reported_fix_versions"] = reported
        controls = sorted(
            {
                control
                for _, rem in group
                if rem.action == "mitigate"
                for control in rem.compensating_controls
            }
        )
        if controls:
            details["compensating_controls"] = controls
        return ActionItem(
            "notify",
            first.package_name,
            "Review upgrade options: the reported fixes do not establish one version "
            "that addresses all of these advisories.",
            first.priority,
            details,
        )
    details.update(
        {
            "fix_version": target,
            "is_direct": first.is_direct_dependency,
            "dependency_chain": first.dependency_chain,
        }
    )
    action_type = "open_pr" if first.priority in ("critical", "high") else "notify"
    return ActionItem(
        action_type,
        first.package_name,
        f"Upgrade {first.package_name} to {target}",
        first.priority,
        details,
    )


def generate_action_plan(report: Report) -> ActionPlan:
    actions: list[ActionItem] = []
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings = [(result, generate_remediation(result)) for result in report.results]
    findings.sort(
        key=lambda pair: (
            priority_order.get(pair[1].priority, 4),
            pair[1].package_name,
            pair[1].vuln_id,
        )
    )

    groups: dict[str, list[tuple[VerdictResult, RemediationAction]]] = {}
    for result, rem in findings:
        if result.verdict == Verdict.REACHABLE:
            key = package_key(result.vulnerability.ecosystem, rem.package_name, rem.package_version)
            groups.setdefault(key, []).append((result, rem))
    upgrades = {
        key: _package_upgrade(group)
        for key, group in groups.items()
        if any(
            rem.action == "upgrade"
            or rem.priority in ("critical", "high")
            or _get_blast_radius(result) is None
            for result, rem in group
        )
    }

    for result, rem in findings:
        if rem.action == "mitigate":
            br = _get_blast_radius(result) if result else None
            if br:
                for cap in br.capabilities:
                    if cap in ("exec.shell", "db.write") or (
                        cap == "filesystem.write" and rem.blast_radius_risk in ("high", "critical")
                    ):
                        actions.append(
                            ActionItem(
                                action_type="revoke_capability",
                                target=cap,
                                reason=(
                                    f"No fix for {rem.package_name} — "
                                    f"revoke {cap} to reduce blast radius"
                                ),
                                priority=rem.priority,
                                details={
                                    "package": rem.package_name,
                                    "capability": cap,
                                    "blast_radius_risk": rem.blast_radius_risk,
                                },
                            )
                        )

        if rem.action == "investigate":
            actions.append(
                ActionItem(
                    action_type="add_monitor",
                    target=rem.package_name,
                    reason=f"Reachability inconclusive for {rem.package_name} — monitor",
                    priority=rem.priority,
                    details={"severity": rem.severity},
                )
            )

        if rem.action == "monitor":
            actions.append(
                ActionItem(
                    action_type="add_monitor",
                    target=rem.package_name,
                    reason=f"{rem.package_name} not executed in tests but imported — watch for changes",
                    priority="low",
                )
            )

    for r in report.results:
        if r.verdict != Verdict.REACHABLE:
            continue
        ti = r.threat_intel
        if ti and ti.in_kev and ti.kev_due_date:
            actions.append(
                ActionItem(
                    action_type="block_deploy",
                    target=r.vulnerability.package_name,
                    reason=(
                        f"CISA KEV: {r.vulnerability.id} in {r.vulnerability.package_name} "
                        f"has remediation deadline {ti.kev_due_date}"
                    ),
                    priority="critical",
                    details={
                        "vuln_id": r.vulnerability.id,
                        "kev_due_date": ti.kev_due_date,
                    },
                )
            )

    has_critical = any(
        r.verdict == Verdict.REACHABLE and r.vulnerability.severity.lower() == "critical"
        for r in report.results
    )
    has_critical_blast = any(
        r.verdict == Verdict.REACHABLE
        and _get_blast_radius(r) is not None
        and _get_blast_radius(r).risk_level == "critical"
        for r in report.results
    )
    has_kev_reachable = any(
        r.verdict == Verdict.REACHABLE and r.threat_intel is not None and r.threat_intel.in_kev
        for r in report.results
    )

    if has_critical or has_critical_blast or has_kev_reachable:
        decision = "block"
        exit_code = 1
        summary = "Deployment blocked: critical reachable vulnerabilities detected"
    elif report.reachable_count > 0:
        decision = "warn"
        exit_code = 1
        summary = f"Deployment warning: {report.reachable_count} reachable vulnerabilities"
    elif report.scan_coverage and not report.scan_coverage.complete:
        decision = "warn"
        exit_code = 2
        summary = "Dependency scan incomplete"
    elif report.inconclusive_count > 0:
        decision = "warn"
        exit_code = 2
        summary = f"Review needed: {report.inconclusive_count} inconclusive verdicts"
    else:
        decision = "pass"
        exit_code = 0
        summary = "All vulnerabilities are unreachable — safe to deploy"

    seen: set[tuple[str, str]] = set()
    unique_actions: list[ActionItem] = []
    for a in actions:
        key = (a.action_type, a.target)
        if key not in seen:
            seen.add(key)
            unique_actions.append(a)

    unique_actions.extend(upgrades.values())
    unique_actions.sort(key=lambda a: priority_order.get(a.priority, 4))

    if has_critical or has_critical_blast or has_kev_reachable:
        unique_actions.insert(
            0,
            ActionItem(
                action_type="block_deploy",
                target="deployment",
                reason=summary,
                priority="critical",
            ),
        )

    return ActionPlan(
        decision=decision,
        exit_code=exit_code,
        summary=summary,
        actions=unique_actions,
        scan_coverage=report.scan_coverage,
    )


def write_action_plan(plan: ActionPlan, output: Path | TextIO | None = None) -> str:
    text = plan.to_json()
    if isinstance(output, Path):
        output.write_text(text)
    elif output is not None:
        output.write(text)
    return text
