from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ca9.core.models import Evidence, Finding, RiskSignal, SourceEvidence

_WORKFLOW_SUFFIXES = {".yml", ".yaml"}
_RISKY_WRITE_PERMISSIONS = {"actions", "checks", "contents", "deployments", "packages"}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


@dataclass(frozen=True)
class _WorkflowFindingSpec:
    signal_type: str
    title: str
    severity: str
    action: str
    reason: str
    evidence_kind: str
    line: int
    metadata: dict[str, object]


def analyze_github_actions_workflows(repo_path: Path) -> list[Finding]:
    workflow_dir = Path(repo_path) / ".github" / "workflows"
    if not workflow_dir.is_dir():
        return []

    findings: list[Finding] = []
    for workflow_path in sorted(workflow_dir.iterdir()):
        if workflow_path.suffix.lower() not in _WORKFLOW_SUFFIXES or not workflow_path.is_file():
            continue
        try:
            content = workflow_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        findings.extend(_analyze_workflow_file(workflow_path, repo_path, content))

    return _sort_findings(_dedupe_findings(findings))


def _analyze_workflow_file(workflow_path: Path, repo_path: Path, content: str) -> list[Finding]:
    specs: list[_WorkflowFindingSpec] = []
    pull_request_target = _find_line(content, r"(?m)^\s*pull_request_target\s*:")

    if pull_request_target:
        checks_out_pr_code = _checks_out_pull_request_code(content)
        if checks_out_pr_code:
            specs.append(
                _WorkflowFindingSpec(
                    signal_type="github_actions_pull_request_target_checkout",
                    title="pull_request_target workflow checks out pull request code",
                    severity="critical",
                    action="block",
                    reason=(
                        "pull_request_target runs with elevated token context and this workflow "
                        "checks out pull request-controlled code"
                    ),
                    evidence_kind="github_actions_workflow",
                    line=pull_request_target,
                    metadata={"pull_request_target": True, "checks_out_pr_code": True},
                )
            )
        else:
            specs.append(
                _WorkflowFindingSpec(
                    signal_type="github_actions_pull_request_target",
                    title="pull_request_target workflow requires trust-boundary review",
                    severity="high",
                    action="investigate",
                    reason="pull_request_target runs with elevated token context",
                    evidence_kind="github_actions_workflow",
                    line=pull_request_target,
                    metadata={"pull_request_target": True},
                )
            )

    oidc_line = _find_line(content, r"(?mi)^\s*id-token\s*:\s*write\s*(?:#.*)?$")
    if oidc_line:
        specs.append(
            _WorkflowFindingSpec(
                signal_type="github_actions_oidc_write",
                title="GitHub Actions workflow grants OIDC token write scope",
                severity="high",
                action="investigate",
                reason="id-token: write allows the workflow to mint cloud or package-publish tokens",
                evidence_kind="github_actions_workflow",
                line=oidc_line,
                metadata={"permission": "id-token: write"},
            )
        )

    write_permissions = _write_permissions(content)
    if write_permissions:
        specs.append(
            _WorkflowFindingSpec(
                signal_type="github_actions_write_permissions",
                title="GitHub Actions workflow grants broad write permissions",
                severity="high",
                action="block",
                reason=(
                    "workflow grants write-capable GITHUB_TOKEN permissions: "
                    + ", ".join(write_permissions)
                ),
                evidence_kind="github_actions_workflow",
                line=_first_write_permission_line(content),
                metadata={"permissions": write_permissions},
            )
        )

    source_clone_line = _find_line(content, r"(?mi)\b(?:gh\s+repo\s+clone|git\s+clone)\b")
    if source_clone_line:
        source_clone_with_write = bool(write_permissions)
        specs.append(
            _WorkflowFindingSpec(
                signal_type="github_actions_source_clone",
                title="GitHub Actions workflow clones repository source during a job",
                severity="critical" if source_clone_with_write else "high",
                action="block" if source_clone_with_write else "investigate",
                reason=(
                    "workflow command can copy repository contents with write-capable token scope"
                    if source_clone_with_write
                    else "workflow command can copy repository contents during job execution"
                ),
                evidence_kind="github_actions_workflow",
                line=source_clone_line,
                metadata={"source_clone": True, "write_permissions": write_permissions},
            )
        )

    if pull_request_target and re.search(r"(?mi)^\s*-\s*uses\s*:\s*actions/cache@", content):
        specs.append(
            _WorkflowFindingSpec(
                signal_type="github_actions_cache_on_pull_request_target",
                title="pull_request_target workflow uses cache restore/save behavior",
                severity="high",
                action="investigate",
                reason="cache use across pull_request_target trust boundaries can expose poisoned artifacts",
                evidence_kind="github_actions_workflow",
                line=_find_line(content, r"(?mi)^\s*-\s*uses\s*:\s*actions/cache@"),
                metadata={"pull_request_target": True, "cache": True},
            )
        )

    for action_ref, line in _mutable_action_refs(content):
        specs.append(
            _WorkflowFindingSpec(
                signal_type="github_actions_mutable_action_ref",
                title=f"GitHub Actions workflow uses mutable action reference {action_ref}",
                severity="medium",
                action="investigate",
                reason="actions should be pinned to an immutable version or reviewed trusted tag",
                evidence_kind="github_actions_workflow",
                line=line,
                metadata={"action_ref": action_ref},
            )
        )

    return [_finding_from_spec(workflow_path, repo_path, content, spec) for spec in specs]


def _finding_from_spec(
    workflow_path: Path,
    repo_path: Path,
    content: str,
    spec: _WorkflowFindingSpec,
) -> Finding:
    rel_path = _relative_path(workflow_path, repo_path)
    source = SourceEvidence(
        source="github_actions_workflow",
        path=rel_path,
        reader="ca9 github actions analyzer",
        detail=f"line {spec.line}",
    )
    evidence = Evidence(
        kind=spec.evidence_kind,
        description=_line_description(content, spec.line, spec.reason),
        source=source,
        metadata={"workflow_path": rel_path, "line": spec.line, **spec.metadata},
    )
    package_key = f"github-actions:{rel_path}"
    signal = RiskSignal(
        signal_type=spec.signal_type,
        package_key=package_key,
        severity=spec.severity,
        confidence="high",
        evidence=(evidence,),
        metadata={"workflow_path": rel_path, "line": spec.line, **spec.metadata},
    )
    return Finding(
        title=spec.title,
        signal_type=spec.signal_type,
        package_key=package_key,
        severity=spec.severity,
        signals=(signal,),
        evidence=(evidence,),
        metadata={
            "action": spec.action,
            "reason": spec.reason,
            "workflow_path": rel_path,
            "line": spec.line,
            "policy_id": f"ca9.{spec.signal_type}",
            **spec.metadata,
        },
    )


def _checks_out_pull_request_code(content: str) -> bool:
    return bool(
        re.search(r"(?mi)^\s*ref\s*:\s*.*github\.event\.pull_request", content)
        or re.search(r"refs/pull/\$\{\{\s*github\.event\.pull_request", content)
        or re.search(r"(?mi)github\.event\.pull_request\.head\.(?:sha|ref)", content)
    )


def _write_permissions(content: str) -> list[str]:
    permissions: set[str] = set()
    if re.search(r"(?mi)^\s*permissions\s*:\s*write-all\s*(?:#.*)?$", content):
        permissions.add("write-all")

    for match in re.finditer(r"(?mi)^\s*([a-z-]+)\s*:\s*write\s*(?:#.*)?$", content):
        permission = match.group(1).lower()
        if permission in _RISKY_WRITE_PERMISSIONS:
            permissions.add(f"{permission}: write")

    return sorted(permissions)


def _first_write_permission_line(content: str) -> int:
    for pattern in (
        r"(?mi)^\s*permissions\s*:\s*write-all\s*(?:#.*)?$",
        r"(?mi)^\s*(?:actions|checks|contents|deployments|packages)\s*:\s*write\s*(?:#.*)?$",
    ):
        line = _find_line(content, pattern)
        if line:
            return line
    return 1


def _mutable_action_refs(content: str) -> list[tuple[str, int]]:
    refs: list[tuple[str, int]] = []
    for match in re.finditer(r"(?mi)^\s*-\s*uses\s*:\s*([^@\s#]+)(?:@([^\s#]+))?", content):
        action_name = match.group(1)
        ref = match.group(2)
        if action_name.startswith(("./", "docker://")):
            continue
        if ref is None or ref.lower() in {"main", "master", "head"} or ref.startswith("refs/heads/"):
            refs.append((f"{action_name}@{ref or '<missing>'}", _line_number(content, match.start())))
    return refs


def _find_line(content: str, pattern: str) -> int:
    match = re.search(pattern, content)
    if not match:
        return 0
    return _line_number(content, match.start())


def _line_number(content: str, offset: int) -> int:
    return content[:offset].count("\n") + 1


def _line_description(content: str, line: int, reason: str) -> str:
    lines = content.splitlines()
    if 1 <= line <= len(lines):
        return f"{reason}: {lines[line - 1].strip()}"
    return reason


def _relative_path(path: Path, repo_path: Path) -> str:
    try:
        return str(path.relative_to(repo_path))
    except ValueError:
        return str(path)


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    deduped: dict[str, Finding] = {}
    for finding in findings:
        deduped[finding.fingerprint] = finding
    return list(deduped.values())


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            _SEVERITY_ORDER.get(finding.severity, 5),
            finding.signal_type,
            finding.package_key,
        ),
    )
