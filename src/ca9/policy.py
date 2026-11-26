from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from ca9.config import _load_toml
from ca9.models import PolicyIgnoredResult, Report, Verdict, VerdictResult, finding_key


@dataclass(frozen=True)
class AcceptedRisk:
    vuln_id: str
    package: str
    version: str | None = None
    reason: str = ""
    expires: str | None = None
    owner: str = ""

    def matches(self, result: VerdictResult) -> bool:
        vuln = result.vulnerability
        if vuln.id != self.vuln_id:
            return False
        if vuln.package_name.lower() != self.package.lower():
            return False
        return not (self.version and vuln.package_version != self.version)

    def is_active(self, today: date | None = None) -> bool:
        if not self.expires:
            return True
        today = today or date.today()
        try:
            return date.fromisoformat(self.expires) >= today
        except ValueError:
            return False


def load_accepted_risks(path: Path) -> list[AcceptedRisk]:
    if path.suffix.lower() == ".json":
        try:
            raw = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return []
    else:
        raw = _load_toml(path)

    if isinstance(raw, dict):
        entries = raw.get("risks") or raw.get("risk") or []
    elif isinstance(raw, list):
        entries = raw
    else:
        entries = []

    risks: list[AcceptedRisk] = []
    for item in entries:
        if not isinstance(item, dict):
            continue
        vuln_id = item.get("id") or item.get("vuln_id") or item.get("vulnerability")
        package = item.get("package") or item.get("package_name")
        if not isinstance(vuln_id, str) or not isinstance(package, str):
            continue
        version = item.get("version")
        expires = item.get("expires")
        risks.append(
            AcceptedRisk(
                vuln_id=vuln_id,
                package=package,
                version=version if isinstance(version, str) and version else None,
                reason=str(item.get("reason") or ""),
                expires=str(expires) if expires else None,
                owner=str(item.get("owner") or ""),
            )
        )
    return risks


def _baseline_alerts(path: Path) -> set[tuple[str, str, str, Verdict]]:
    try:
        data = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return set()

    if not isinstance(data, dict):
        return set()

    results = data.get("results")
    results = list(results) if isinstance(results, list) else []
    ignored = data.get("ignored_results")
    if isinstance(ignored, list):
        # Carry a baseline suppression forward without extending an accepted risk.
        results.extend(
            row for row in ignored if isinstance(row, dict) and row.get("policy") == "baseline"
        )

    alerts: set[tuple[str, str, str, Verdict]] = set()
    for item in results:
        if not isinstance(item, dict):
            continue
        vuln_id = item.get("id")
        package = item.get("package")
        version = item.get("version")
        if not (isinstance(vuln_id, str) and isinstance(package, str) and isinstance(version, str)):
            continue
        # Legacy baselines contained only the identity and suppressed both alert types.
        try:
            previous = Verdict(item.get("verdict", Verdict.REACHABLE.value))
        except ValueError:
            continue
        key = finding_key(vuln_id, package, version)
        alerts.add((*key, Verdict.INCONCLUSIVE))
        if previous == Verdict.REACHABLE:
            alerts.add((*key, Verdict.REACHABLE))
    return alerts


def apply_policy(
    report: Report,
    accepted_risks_path: Path | None = None,
    baseline_path: Path | None = None,
    new_only: bool = False,
    today: date | None = None,
) -> Report:
    accepted_risks = load_accepted_risks(accepted_risks_path) if accepted_risks_path else []
    baseline = _baseline_alerts(baseline_path) if baseline_path and new_only else set()
    warnings = list(report.warnings)

    if accepted_risks_path is not None and not accepted_risks:
        warnings.append("policy: accepted-risk file has no usable risk entries")
    if new_only and baseline_path is None:
        warnings.append("policy: --new-only ignored because no baseline was provided")
    elif new_only and baseline_path is not None and not baseline:
        warnings.append("policy: --new-only requested but the baseline has no usable findings")

    kept: list[VerdictResult] = []
    ignored = list(report.ignored_results)
    accepted_count = 0
    baseline_count = 0
    expired_or_invalid: list[AcceptedRisk] = []

    for result in report.results:
        active_risk = None
        for risk in accepted_risks:
            if risk.matches(result):
                if risk.is_active(today):
                    active_risk = risk
                    break
                expired_or_invalid.append(risk)

        if active_risk is not None:
            accepted_count += 1
            reason = active_risk.reason or "accepted risk"
            ignored.append(
                PolicyIgnoredResult(
                    result=result,
                    policy="accepted_risk",
                    reason=reason,
                    owner=active_risk.owner,
                    expires=active_risk.expires,
                )
            )
            continue

        vuln = result.vulnerability
        key = finding_key(vuln.id, vuln.package_name, vuln.package_version)
        if (*key, result.verdict) in baseline:
            baseline_count += 1
            ignored.append(
                PolicyIgnoredResult(
                    result=result,
                    policy="baseline",
                    reason="already present in baseline",
                )
            )
            continue

        kept.append(result)

    if accepted_count:
        warnings.append(f"policy: ignored {accepted_count} accepted-risk finding(s)")
    if baseline_count:
        warnings.append(f"policy: ignored {baseline_count} finding(s) already present in baseline")
    if expired_or_invalid:
        seen: set[tuple[str, str, str | None]] = set()
        for risk in expired_or_invalid:
            key = (risk.vuln_id, risk.package, risk.version)
            if key in seen:
                continue
            seen.add(key)
            warnings.append(
                "policy: accepted risk is expired or has an invalid expiry and was not applied "
                f"({risk.vuln_id} {risk.package})"
            )

    return Report(
        results=kept,
        repo_path=report.repo_path,
        coverage_path=report.coverage_path,
        proof_standard=report.proof_standard,
        warnings=warnings,
        ignored_results=ignored,
        scan_coverage=report.scan_coverage,
    )
