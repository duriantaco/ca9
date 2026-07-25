from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ca9.analyzers.github_actions import analyze_github_actions_workflows
from ca9.analyzers.supply_chain import SupplyChainPolicy
from ca9.core.models import Decision, Finding
from ca9.inventory import build_inventory
from ca9.package_feed import (
    FeedStatus,
    feed_status,
    package_age_findings,
    package_malware_findings,
)
from ca9.package_policy import PackagePolicy, expired_policy_exceptions
from ca9.runtime.preflight import RuntimePreflightError, parse_install_command
from ca9.supply_chain import (
    SupplyChainReport,
    build_supply_chain_report,
    remediation_hint,
)

PROTECT_SCHEMA = "ca9.protect.v1"
_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)


@dataclass(frozen=True)
class ManagerPosture:
    manager: str
    coverage: str
    detected_files: tuple[str, ...]
    detail: str
    runtime_commands: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "manager": self.manager,
            "coverage": self.coverage,
            "detected_files": list(self.detected_files),
            "detail": self.detail,
            "runtime_commands": list(self.runtime_commands),
        }


@dataclass(frozen=True)
class ProtectCheck:
    check_id: str
    status: str
    title: str
    detail: str
    paths: tuple[str, ...] = ()
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.check_id,
            "status": self.status,
            "title": self.title,
            "detail": self.detail,
            "paths": list(self.paths),
        }
        if self.remediation:
            data["remediation"] = self.remediation
        return data


@dataclass(frozen=True)
class ProtectReport:
    repo_path: str
    policy: PackagePolicy
    managers: tuple[ManagerPosture, ...]
    checks: tuple[ProtectCheck, ...]
    feed: FeedStatus
    supply_chain: SupplyChainReport

    @property
    def blocking_checks(self) -> int:
        return sum(check.status == "block" for check in self.checks)

    @property
    def warning_checks(self) -> int:
        return sum(check.status == "warn" for check in self.checks)

    @property
    def status(self) -> str:
        if self.blocking_checks or self.supply_chain.blocking_count:
            return "block"
        if self.warning_checks or self.supply_chain.warning_count or self.supply_chain.warnings:
            return "warn"
        return "pass"

    @property
    def exit_code(self) -> int:
        return 1 if self.status == "block" else 0

    def summary(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "managers": len(self.managers),
            "packages": len(self.supply_chain.inventory.packages),
            "findings": len(self.supply_chain.findings),
            "blocking_checks": self.blocking_checks,
            "warning_checks": self.warning_checks,
            "blocking_decisions": self.supply_chain.blocking_count,
            "warning_decisions": self.supply_chain.warning_count,
            "expired_exceptions": len(expired_policy_exceptions(self.policy)),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PROTECT_SCHEMA,
            "repo_path": self.repo_path,
            "summary": self.summary(),
            "policy": {
                "sources": list(self.policy.sources),
                "mode": {
                    "default": self.policy.mode.default,
                    "offline": self.policy.mode.offline,
                },
                "configured_exceptions": len(self.policy.exceptions),
                "expired_exceptions": [
                    exception.to_dict() for exception in expired_policy_exceptions(self.policy)
                ],
            },
            "managers": [manager.to_dict() for manager in self.managers],
            "checks": [check.to_dict() for check in self.checks],
            "feed": self.feed.to_dict(),
            "supply_chain": self.supply_chain.to_dict(),
            "recommendations": _report_recommendations(self),
        }


def build_protect_report(
    repo_path: Path,
    policy: PackagePolicy,
    *,
    scan_workflows: bool = True,
    feed_cache_dir: Path | None = None,
) -> ProtectReport:
    repo = repo_path.resolve()
    if not repo.is_dir():
        raise ValueError(f"protect repository path is not a directory: {repo}")

    managers, manager_checks = _detect_manager_posture(repo)
    inventory = build_inventory(repo)
    status = feed_status(policy=policy, cache_dir=feed_cache_dir)

    policy_findings: list[Finding] = []
    feed_warnings: list[str] = []
    age_findings, age_warnings = package_age_findings(
        inventory.packages,
        policy,
        cache_dir=feed_cache_dir,
    )
    malware_findings, malware_warnings = package_malware_findings(
        inventory.packages,
        policy,
        cache_dir=feed_cache_dir,
    )
    policy_findings.extend(age_findings)
    policy_findings.extend(malware_findings)
    feed_warnings.extend(age_warnings)
    feed_warnings.extend(malware_warnings)

    workflow_findings = analyze_github_actions_workflows(repo) if scan_workflows else []
    supply_policy = SupplyChainPolicy(
        trusted_indexes=policy.registries.allow,
        denied_indexes=policy.registries.deny,
        mode=policy.mode.default,
        block_untrusted_direct=policy.registries.custom_requires_approval,
        exceptions=policy.exceptions,
    )
    supply_chain = build_supply_chain_report(
        inventory,
        policy=supply_policy,
        extra_findings=[*policy_findings, *workflow_findings],
        extra_warnings=feed_warnings,
    )

    checks = [
        *manager_checks,
        _feed_posture_check(status, policy),
        _inventory_posture_check(supply_chain),
        _exception_posture_check(policy),
    ]
    if scan_workflows:
        checks.append(_workflow_posture_check(repo, workflow_findings, supply_chain.decisions))

    return ProtectReport(
        repo_path=str(repo),
        policy=policy,
        managers=tuple(managers),
        checks=tuple(checks),
        feed=status,
        supply_chain=supply_chain,
    )


def protect_report_to_json(report: ProtectReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def protect_report_to_table(report: ProtectReport) -> str:
    summary = report.summary()
    lines = [
        f"ca9 protect: {report.status.upper()}",
        f"Repository: {report.repo_path}",
        (
            f"Managers: {summary['managers']} | Packages: {summary['packages']} | "
            f"Findings: {summary['findings']}"
        ),
        (
            f"Blocking checks: {summary['blocking_checks']} | "
            f"Blocking decisions: {summary['blocking_decisions']} | "
            f"Warnings: {summary['warning_checks'] + summary['warning_decisions']}"
        ),
        "",
        "Dependency workflows:",
    ]
    if report.managers:
        for manager in report.managers:
            files = ", ".join(manager.detected_files)
            lines.append(
                f"  [{manager.coverage.upper()}] {manager.manager}: {manager.detail} ({files})"
            )
            lines.extend(f"    Enforce: {command}" for command in manager.runtime_commands)
    else:
        lines.append("  [WARN] No supported package-manager workflow detected.")

    lines.extend(["", "Posture checks:"])
    for check in report.checks:
        lines.append(f"  [{check.status.upper()}] {check.title}: {check.detail}")

    actionable = _actionable_findings(report)
    if actionable:
        lines.extend(["", "Policy findings:"])
        for finding, decision in actionable:
            target = finding.metadata.get("package") or finding.package_key
            lines.append(
                f"  [{decision.action.upper()}] {decision.policy_id} {target}: {decision.reason}"
            )

    recommendations = _report_recommendations(report)
    if recommendations:
        lines.extend(["", "Next actions:"])
        lines.extend(f"  - {item}" for item in recommendations)
    return "\n".join(lines)


def protect_report_to_markdown(report: ProtectReport) -> str:
    summary = report.summary()
    lines = [
        "# ca9 protect report",
        "",
        f"**Status:** `{report.status}`  ",
        f"**Repository:** `{report.repo_path}`",
        "",
        (
            f"{summary['packages']} packages, {summary['findings']} findings, "
            f"{summary['blocking_checks']} blocking posture checks, and "
            f"{summary['blocking_decisions']} blocking policy decisions."
        ),
        "",
        "## Dependency workflows",
        "",
        "| Manager | Coverage | Files | Enforcement |",
        "|---|---|---|---|",
    ]
    if report.managers:
        for manager in report.managers:
            commands = "<br>".join(f"`{command}`" for command in manager.runtime_commands) or "—"
            files = "<br>".join(f"`{path}`" for path in manager.detected_files)
            lines.append(
                f"| {_md(manager.manager)} | {_md(manager.coverage)} | "
                f"{_md(files)} | {_md(commands)} |"
            )
    else:
        lines.append("| — | unsupported | No package workflow detected | — |")

    lines.extend(
        [
            "",
            "## Posture checks",
            "",
            "| Status | Check | Detail |",
            "|---|---|---|",
        ]
    )
    for check in report.checks:
        lines.append(f"| {_md(check.status)} | {_md(check.title)} | {_md(check.detail)} |")

    actionable = _actionable_findings(report)
    if actionable:
        lines.extend(
            [
                "",
                "## Policy findings",
                "",
                "| Action | Policy | Target | Reason |",
                "|---|---|---|---|",
            ]
        )
        for finding, decision in actionable:
            target = str(finding.metadata.get("package") or finding.package_key)
            lines.append(
                f"| {_md(decision.action)} | {_md(decision.policy_id or '')} | "
                f"{_md(target)} | {_md(decision.reason)} |"
            )

    recommendations = _report_recommendations(report)
    if recommendations:
        lines.extend(["", "## Next actions", ""])
        lines.extend(f"- {item}" for item in recommendations)
    return "\n".join(lines)


def protect_report_to_sarif(report: ProtectReport) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for check in report.checks:
        if check.status not in {"block", "warn"}:
            continue
        rule_id = check.check_id
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "shortDescription": {"text": check.title},
                "help": {"text": check.remediation or check.detail},
            },
        )
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": "error" if check.status == "block" else "warning",
            "message": {"text": check.detail},
            "properties": {"status": check.status},
        }
        if check.paths:
            result["locations"] = [_sarif_location(check.paths[0])]
        results.append(result)

    findings = {finding.fingerprint: finding for finding in report.supply_chain.findings}
    for decision in report.supply_chain.decisions:
        if decision.action not in {"block", "warn", "investigate"}:
            continue
        finding = findings.get(decision.finding_fingerprint)
        if finding is None:
            continue
        rule_id = decision.policy_id or f"ca9.{finding.signal_type}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "shortDescription": {"text": finding.title},
                "help": {"text": decision.reason},
            },
        )
        result = {
            "ruleId": rule_id,
            "level": "error" if decision.action == "block" else "warning",
            "message": {"text": decision.reason},
            "partialFingerprints": {
                "ca9FindingFingerprint": finding.fingerprint,
            },
            "properties": {
                "action": decision.action,
                "severity": finding.severity,
                "package_key": finding.package_key,
                "decision": decision.to_dict(),
            },
        }
        location = _finding_location(finding, Path(report.repo_path))
        if location is not None:
            result["locations"] = [location]
        results.append(result)

    payload = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ca9",
                        "informationUri": "https://github.com/duriantaco/ca9",
                        "rules": [rules[key] for key in sorted(rules)],
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2)


def _detect_manager_posture(
    repo: Path,
) -> tuple[list[ManagerPosture], list[ProtectCheck]]:
    managers: list[ManagerPosture] = []
    checks: list[ProtectCheck] = []

    package_json = repo / "package.json"
    package_lock = repo / "package-lock.json"
    pnpm_lock = repo / "pnpm-lock.yaml"
    yarn_lock = repo / "yarn.lock"
    if package_lock.is_file():
        try:
            parse_install_command(("npm", "ci"), cwd=repo)
        except RuntimePreflightError as exc:
            coverage = "partial"
            status = "block"
            detail = f"package-lock.json cannot be enforced safely: {exc}"
            commands: tuple[str, ...] = ()
            remediation = "Regenerate a valid npm v2/v3 package-lock.json and rerun ca9 protect."
        else:
            coverage = "supported"
            status = "pass"
            detail = "npm clean installs are covered by lockfile preflight and the registry gateway"
            commands = ("ca9 run -- npm ci",)
            remediation = None
        managers.append(
            ManagerPosture(
                manager="npm",
                coverage=coverage,
                detected_files=("package-lock.json",),
                detail=detail,
                runtime_commands=commands,
            )
        )
        checks.append(
            ProtectCheck(
                check_id="ca9.protect.npm",
                status=status,
                title="npm install enforcement",
                detail=detail,
                paths=("package-lock.json",),
                remediation=remediation,
            )
        )
    elif package_json.is_file() and not pnpm_lock.is_file() and not yarn_lock.is_file():
        detail = "package.json is present without a lockfile that ca9 can enforce"
        managers.append(
            ManagerPosture(
                manager="npm",
                coverage="unsupported",
                detected_files=("package.json",),
                detail=detail,
            )
        )
        checks.append(
            ProtectCheck(
                check_id="ca9.protect.npm",
                status="block",
                title="npm install enforcement",
                detail=detail,
                paths=("package.json",),
                remediation="Commit package-lock.json and use `ca9 run -- npm ci` in CI.",
            )
        )

    requirement_files = tuple(
        sorted(path for path in repo.glob("requirements*.txt") if path.is_file())
    )
    if requirement_files:
        commands: list[str] = []
        errors: list[str] = []
        relative_paths = tuple(_relative(path, repo) for path in requirement_files)
        for relative_path in relative_paths:
            try:
                parse_install_command(
                    ("pip", "install", "-r", relative_path),
                    cwd=repo,
                )
            except RuntimePreflightError as exc:
                errors.append(f"{relative_path}: {exc}")
            else:
                commands.append(f"ca9 run -- pip install -r {relative_path}")
        if errors:
            coverage = "partial"
            status = "block"
            detail = "one or more requirements entry points cannot be enforced: " + "; ".join(
                errors
            )
            remediation = (
                "Remove unsupported sources/options and keep all included requirement files "
                "inside the repository."
            )
        else:
            coverage = "supported"
            status = "pass"
            detail = "pip requirements installs are covered by file preflight and the PyPI gateway"
            remediation = None
        managers.append(
            ManagerPosture(
                manager="pip",
                coverage=coverage,
                detected_files=relative_paths,
                detail=detail,
                runtime_commands=tuple(commands),
            )
        )
        checks.append(
            ProtectCheck(
                check_id="ca9.protect.pip",
                status=status,
                title="pip install enforcement",
                detail=detail,
                paths=relative_paths,
                remediation=remediation,
            )
        )

    unsupported_managers = (
        ("pnpm", "pnpm-lock.yaml", "pnpm runtime mediation is not implemented yet"),
        ("yarn", "yarn.lock", "Yarn runtime mediation is not implemented yet"),
        ("uv", "uv.lock", "uv sync runtime mediation is not implemented yet"),
        ("poetry", "poetry.lock", "Poetry install runtime mediation is not implemented yet"),
        ("pipenv", "Pipfile.lock", "Pipenv runtime mediation is not implemented yet"),
        ("pdm", "pdm.lock", "PDM runtime mediation is not implemented yet"),
        ("fyn", "fyn.lock", "fyn runtime mediation is not implemented yet"),
        (
            "npm",
            "npm-shrinkwrap.json",
            "npm shrinkwrap runtime mediation is not implemented yet",
        ),
    )
    for manager_name, filename, detail in unsupported_managers:
        path = repo / filename
        if not path.is_file():
            continue
        managers.append(
            ManagerPosture(
                manager=manager_name,
                coverage="unsupported",
                detected_files=(filename,),
                detail=detail,
            )
        )
        checks.append(
            ProtectCheck(
                check_id=f"ca9.protect.{manager_name}",
                status="warn",
                title=f"{manager_name} install enforcement",
                detail=detail,
                paths=(filename,),
                remediation=(
                    "Keep the lockfile committed and use `ca9 vet` until a dedicated runtime "
                    "driver is available."
                ),
            )
        )

    pylock_files = tuple(sorted(repo.glob("pylock*.toml")))
    if pylock_files:
        paths = tuple(_relative(path, repo) for path in pylock_files)
        detail = "PEP 751 pylock runtime mediation is not implemented yet"
        managers.append(
            ManagerPosture(
                manager="pylock",
                coverage="unsupported",
                detected_files=paths,
                detail=detail,
            )
        )
        checks.append(
            ProtectCheck(
                check_id="ca9.protect.pylock",
                status="warn",
                title="pylock install enforcement",
                detail=detail,
                paths=paths,
                remediation="Continue static vetting; use a supported requirements entry point.",
            )
        )

    pyproject = repo / "pyproject.toml"
    python_locks = {
        "uv.lock",
        "poetry.lock",
        "Pipfile.lock",
        "pdm.lock",
        *(path.name for path in pylock_files),
    }
    if (
        pyproject.is_file()
        and not requirement_files
        and not any((repo / name).is_file() for name in python_locks)
    ):
        detail = "pyproject.toml dependencies have no enforceable install lock or requirements file"
        managers.append(
            ManagerPosture(
                manager="python-project",
                coverage="unsupported",
                detected_files=("pyproject.toml",),
                detail=detail,
            )
        )
        checks.append(
            ProtectCheck(
                check_id="ca9.protect.python_project",
                status="block",
                title="Python install enforcement",
                detail=detail,
                paths=("pyproject.toml",),
                remediation=(
                    "Generate and commit a pinned requirements entry point, then install it "
                    "through `ca9 run -- pip install -r ...`."
                ),
            )
        )

    if not managers:
        checks.append(
            ProtectCheck(
                check_id="ca9.protect.manager_detection",
                status="warn",
                title="Dependency workflow detection",
                detail="no recognized package-manager manifest or lockfile was found",
                remediation="Point `--repo` at the project root or add a supported lockfile.",
            )
        )
    managers.sort(key=lambda item: (item.manager, item.detected_files))
    checks.sort(key=lambda item: item.check_id)
    return managers, checks


def _feed_posture_check(status: FeedStatus, policy: PackagePolicy) -> ProtectCheck:
    protections_enabled = policy.malware.enabled or policy.package_age.enabled
    if not protections_enabled:
        return ProtectCheck(
            check_id="ca9.protect.feed",
            status="pass",
            title="Package intelligence feed",
            detail="feed-backed malware and package-age policy are disabled",
        )
    if status.state == "ready":
        return ProtectCheck(
            check_id="ca9.protect.feed",
            status="pass",
            title="Package intelligence feed",
            detail=status.reason,
        )
    blocking = (
        status.state == "tampered"
        or (policy.malware.enabled and policy.malware.fail_closed)
        or (policy.package_age.enabled and status.action == "block")
    )
    return ProtectCheck(
        check_id="ca9.protect.feed",
        status="block" if blocking else "warn",
        title="Package intelligence feed",
        detail=status.reason,
        remediation="Run `ca9 feed update`, then rerun `ca9 protect`.",
    )


def _inventory_posture_check(report: SupplyChainReport) -> ProtectCheck:
    package_count = len(report.inventory.packages)
    if package_count:
        return ProtectCheck(
            check_id="ca9.protect.inventory",
            status="warn" if report.inventory.warnings else "pass",
            title="Dependency inventory",
            detail=f"ca9 identified {package_count} package occurrences",
            remediation=(
                "Resolve inventory warnings before relying on the report."
                if report.inventory.warnings
                else None
            ),
        )
    return ProtectCheck(
        check_id="ca9.protect.inventory",
        status="warn",
        title="Dependency inventory",
        detail="ca9 did not identify any package dependencies",
        remediation="Check the repository path and commit a supported manifest or lockfile.",
    )


def _exception_posture_check(policy: PackagePolicy) -> ProtectCheck:
    expired = expired_policy_exceptions(policy)
    if expired:
        labels = ", ".join(
            f"{exception.policy_id} ({exception.owner}, {exception.expires})"
            for exception in expired
        )
        return ProtectCheck(
            check_id="ca9.protect.policy_exceptions",
            status="warn",
            title="Policy exception hygiene",
            detail=f"{len(expired)} expired policy exception(s): {labels}",
            remediation="Remove expired exceptions or renew them with a new review and reason.",
        )
    return ProtectCheck(
        check_id="ca9.protect.policy_exceptions",
        status="pass",
        title="Policy exception hygiene",
        detail=f"{len(policy.exceptions)} configured exception(s), none expired",
    )


def _workflow_posture_check(
    repo: Path,
    findings: list[Finding],
    decisions: tuple[Decision, ...],
) -> ProtectCheck:
    paths = tuple(
        sorted(
            _relative(path, repo)
            for path in (repo / ".github" / "workflows").glob("*")
            if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}
        )
    )
    finding_fingerprints = {finding.fingerprint for finding in findings}
    relevant = [
        decision for decision in decisions if decision.finding_fingerprint in finding_fingerprints
    ]
    blocking = sum(decision.action == "block" for decision in relevant)
    warning = sum(decision.action in {"warn", "investigate"} for decision in relevant)
    if blocking:
        status = "block"
    elif warning:
        status = "warn"
    else:
        status = "pass"
    detail = (
        f"scanned {len(paths)} workflow file(s); "
        f"{blocking} blocking and {warning} warning decision(s)"
    )
    return ProtectCheck(
        check_id="ca9.protect.github_actions",
        status=status,
        title="GitHub Actions trust boundaries",
        detail=detail,
        paths=paths,
        remediation=(
            "Apply the workflow remediations in the policy findings." if relevant else None
        ),
    )


def _actionable_findings(
    report: ProtectReport,
) -> list[tuple[Finding, Decision]]:
    findings = {finding.fingerprint: finding for finding in report.supply_chain.findings}
    return [
        (findings[decision.finding_fingerprint], decision)
        for decision in report.supply_chain.decisions
        if decision.action in {"block", "warn", "investigate"}
        and decision.finding_fingerprint in findings
    ]


def _report_recommendations(report: ProtectReport) -> list[str]:
    recommendations = [
        check.remediation
        for check in report.checks
        if check.remediation and check.status in {"block", "warn"}
    ]
    for finding, _decision in _actionable_findings(report):
        hint = remediation_hint(finding)
        if not hint:
            continue
        target = str(finding.metadata.get("package") or finding.package_key)
        recommendations.append(f"{target}: {hint}")
    return list(dict.fromkeys(recommendations))


def _relative(path: Path, repo: Path) -> str:
    try:
        return path.resolve().relative_to(repo).as_posix()
    except (OSError, ValueError):
        return str(path)


def _md(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _sarif_location(path: str, line: int | None = None) -> dict[str, Any]:
    region = {"startLine": max(line or 1, 1)}
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": path},
            "region": region,
        }
    }


def _finding_location(finding: Finding, repo: Path) -> dict[str, Any] | None:
    path: str | None = None
    line: int | None = None
    if finding.evidence:
        path = finding.evidence[0].source.path
        raw_line = finding.evidence[0].metadata.get("line")
        if isinstance(raw_line, int):
            line = raw_line
    if path is None:
        raw_path = finding.metadata.get("workflow_path")
        path = str(raw_path) if raw_path else None
    if line is None and isinstance(finding.metadata.get("line"), int):
        line = int(finding.metadata["line"])
    if not path:
        return None
    candidate = Path(path)
    if candidate.is_absolute():
        path = _relative(candidate, repo)
    return _sarif_location(path, line)
