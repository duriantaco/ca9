from __future__ import annotations

import json
from dataclasses import dataclass

from ca9.analyzers.supply_chain import (
    SupplyChainPolicy,
    analyze_supply_chain,
    evaluate_supply_chain_findings,
    findings_from_malware_advisories,
)
from ca9.core.models import Decision, Finding, Inventory
from ca9.models import Vulnerability


@dataclass(frozen=True)
class SupplyChainReport:
    inventory: Inventory
    findings: tuple[Finding, ...]
    decisions: tuple[Decision, ...]
    warnings: tuple[str, ...] = ()
    artifact_scans: int = 0
    skipped_artifacts: int = 0

    @property
    def blocking_count(self) -> int:
        return sum(1 for decision in self.decisions if decision.action == "block")

    @property
    def warning_count(self) -> int:
        return sum(1 for decision in self.decisions if decision.action == "warn")

    @property
    def exit_code(self) -> int:
        return 1 if self.blocking_count else 0

    def summary(self) -> dict[str, int]:
        return {
            "findings": len(self.findings),
            "blocking": self.blocking_count,
            "warnings": self.warning_count,
            "packages": len(self.inventory.packages),
            "dependency_edges": len(self.inventory.dependency_edges),
            "artifact_scans": self.artifact_scans,
            "skipped_artifacts": self.skipped_artifacts,
        }

    def to_dict(self) -> dict:
        return {
            "schema_version": "ca9.vet.v1",
            "repo_path": self.inventory.repo_path,
            "summary": self.summary(),
            "inventory": {
                "summary": self.inventory.summary(),
                "source_inputs": [
                    source_input.to_dict() for source_input in self.inventory.source_inputs
                ],
                "warnings": list(self.inventory.warnings),
            },
            "findings": [finding.to_dict() for finding in self.findings],
            "decisions": [decision.to_dict() for decision in self.decisions],
            "warnings": list(self.warnings),
        }


def build_supply_chain_report(
    inventory: Inventory,
    *,
    policy: SupplyChainPolicy | None = None,
    malware_advisories: list[Vulnerability] | None = None,
    extra_findings: list[Finding] | None = None,
    extra_warnings: list[str] | None = None,
    artifact_scans: int = 0,
    skipped_artifacts: int = 0,
) -> SupplyChainReport:
    local_findings = analyze_supply_chain(inventory, policy=policy)
    malware_findings = findings_from_malware_advisories(malware_advisories or [])
    findings = tuple(
        _dedupe_findings([*local_findings, *malware_findings, *(extra_findings or [])])
    )
    decisions = tuple(evaluate_supply_chain_findings(list(findings)))
    return SupplyChainReport(
        inventory=inventory,
        findings=findings,
        decisions=decisions,
        warnings=tuple([*inventory.warnings, *(extra_warnings or [])]),
        artifact_scans=artifact_scans,
        skipped_artifacts=skipped_artifacts,
    )


def supply_chain_report_to_json(report: SupplyChainReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def supply_chain_report_to_table(report: SupplyChainReport) -> str:
    summary = report.summary()
    lines = [
        f"ca9 supply-chain report for {report.inventory.repo_path}",
        (
            f"Packages: {summary['packages']} | Edges: {summary['dependency_edges']} | "
            f"Findings: {summary['findings']} | Block: {summary['blocking']} | Warn: {summary['warnings']}"
        ),
        f"Artifact scans: {summary['artifact_scans']} | Skipped artifacts: {summary['skipped_artifacts']}",
    ]

    if report.warnings:
        lines.append("")
        lines.append("Warnings:")
        lines.extend(f"  - {warning}" for warning in report.warnings)

    if report.findings:
        decisions_by_fingerprint = {
            decision.finding_fingerprint: decision for decision in report.decisions
        }
        lines.append("")
        lines.append("Findings:")
        for finding in report.findings:
            decision = decisions_by_fingerprint.get(finding.fingerprint)
            action = decision.action.upper() if decision else "WARN"
            package = finding.metadata.get("package") or finding.package_key
            version = finding.metadata.get("version") or "unknown"
            lines.append(
                f"  [{action}] {finding.signal_type} {finding.severity} {package}@{version}"
            )
            lines.append(f"    {finding.title}")
            if decision and decision.reason:
                lines.append(f"    Why: {decision.reason}")
            hint = _remediation_hint(finding)
            if hint:
                lines.append(f"    Next: {hint}")
    else:
        lines.append("")
        lines.append("No supply-chain findings.")

    return "\n".join(lines)


def _remediation_hint(finding: Finding) -> str:
    hints = {
        "malware": "remove the package version, rotate exposed credentials if it ran, and upgrade to a clean release",
        "untrusted_registry": "pin the dependency to a trusted index or add an explicit private-index policy",
        "dependency_confusion": "publish or pin the internal package only from the configured private index",
        "missing_artifact_hash": "use a lockfile entry with an artifact hash before enabling artifact download checks",
        "missing_artifact_metadata": "inspect package metadata manually before allowing this dependency in release builds",
        "sdist_only": "prefer a wheel or scan the source distribution before using it in release builds",
        "mutable_source": "pin the dependency source to an immutable version, tag, or commit",
        "github_actions_pull_request_target_checkout": "replace with pull_request or split untrusted tests from privileged reporting",
        "github_actions_pull_request_target": "review whether the workflow needs target-repo privileges and avoid checking out PR code",
        "github_actions_oidc_write": "limit OIDC to deploy jobs and enforce cloud trust claims for repo, ref, workflow, and environment",
        "github_actions_write_permissions": "grant write permissions only in the single job that needs them",
        "github_actions_source_clone": "remove broad source cloning or run it without write-capable token scope",
        "github_actions_cache_on_pull_request_target": "avoid cache restore/save across pull_request_target trust boundaries",
        "github_actions_mutable_action_ref": "pin the action to a full-length commit SHA from the trusted upstream repository",
        "github_actions_encoded_shell_payload": "block the change and inspect recent workflow runs for credential exposure",
        "github_actions_cloud_metadata_probe": "block the change and audit cloud role assumptions from affected workflow runs",
        "github_actions_credential_file_harvest": "block the change and rotate any credential type the workflow could read",
    }
    return hints.get(finding.signal_type, "")


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    deduped: dict[str, Finding] = {}
    for finding in findings:
        deduped[finding.fingerprint] = finding
    return sorted(
        deduped.values(),
        key=lambda finding: (finding.severity, finding.signal_type, finding.package_key),
    )
