from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ca9.core.models import Evidence, Finding, RiskSignal, SourceEvidence

_WORKFLOW_SUFFIXES = {".yml", ".yaml"}
_ACTION_FILE_NAMES = {"action.yml", "action.yaml"}
_RISKY_WRITE_PERMISSIONS = {"actions", "checks", "contents", "deployments", "packages"}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
# Triggers that run with base-repository secrets or a write-capable token while
# processing data an outside contributor controls.
_UNTRUSTED_TRIGGERS = (
    "pull_request_target",
    "workflow_run",
    "issue_comment",
    "issues",
    "discussion",
    "discussion_comment",
)
_KNOWN_EVENTS = frozenset(
    {
        "branch_protection_rule",
        "check_run",
        "check_suite",
        "create",
        "delete",
        "deployment",
        "deployment_status",
        "discussion",
        "discussion_comment",
        "fork",
        "gollum",
        "issue_comment",
        "issues",
        "label",
        "merge_group",
        "milestone",
        "page_build",
        "public",
        "pull_request",
        "pull_request_review",
        "pull_request_review_comment",
        "pull_request_target",
        "push",
        "registry_package",
        "release",
        "repository_dispatch",
        "schedule",
        "status",
        "watch",
        "workflow_call",
        "workflow_dispatch",
        "workflow_run",
    }
)
# Keys whose values are prose rather than executed configuration.
_PROSE_KEYS = frozenset({"name", "description", "title"})
_SCRIPT_KEYS = frozenset({"run", "script"})
_GITHUB_OWNED_ACTION_OWNERS = frozenset({"actions", "github"})
_CLOUD_METADATA_PATTERNS = (
    r"169\.254\.169\.254",
    r"metadata\.google\.internal",
    r"\bmetadata\.azure\.com\b",
    r"\bAWS_CONTAINER_CREDENTIALS_(?:FULL_URI|RELATIVE_URI)\b",
    r"\bACTIONS_ID_TOKEN_REQUEST_(?:TOKEN|URL)\b",
)
_CREDENTIAL_FILE_PATTERNS = (
    r"~/.ssh/(?:id_rsa|id_ed25519)",
    r"\$HOME/.ssh/(?:id_rsa|id_ed25519)",
    r"\.docker/config\.json",
    r"\.kube/config",
    r"\.vault-token",
    r"\.terraform\.d/credentials\.tfrc\.json",
    r"\.aws/credentials",
    r"\.config/gcloud",
    r"\.azure/accessTokens\.json",
)
_KEY_RE = re.compile(r"""^(\s*)((?:-\s+)*)["']?([A-Za-z0-9_.-]+)["']?\s*:(?:\s+(.*))?$""")
_BLOCK_SCALAR_RE = re.compile(r"^[|>][-+0-9]*$")
_USES_RE = re.compile(r"""^\s*(?:-\s+)?uses\s*:\s*["']?([^"'\s]+)""")
_FULL_SHA_RE = re.compile(r"[0-9a-fA-F]{40}")
_ON_RE = re.compile(r"""^["']?on["']?\s*:(.*)$""")
_EVENT_ITEM_RE = re.compile(r"""^\s*(?:-\s+)?["']?([A-Za-z_]+)["']?\s*(?::|$)""")
# Shell echo/printf arguments are displayed, not executed. Double-quoted text
# stays visible when it contains command substitution.
_ECHO_ARGS_RE = re.compile(
    r"""\b(?:echo|printf)\b(?:\s+-[neE]+)*"""
    r"""((?:\s+(?:"(?:[^"\\$`]|\\.|\$(?!\())*"|'[^']*'|(?:[^\s|;&<>()`$'"]|\$(?!\())+))*)"""
)
_EXPRESSION_RE = re.compile(r"\$\{\{(.*?)\}\}")
_UNTRUSTED_CONTEXT_RE = re.compile(
    r"\bgithub\.head_ref\b|"
    r"\bgithub\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|"
    r"head_commit|commits|pages|workflow_run)\b[\w.*\[\]'\"-]*?\."
    r"(?:title|body|head\.ref|head\.label|head_branch|message|page_name|default_branch|"
    r"(?:author|committer)\.(?:name|email))\b"
)
_PR_CHECKOUT_PATTERNS = (
    re.compile(
        r"^\s*(?:-\s+)?ref\s*:.*(?:github\.event\.pull_request\.(?:head|merge_commit_sha|number)|"
        r"github\.head_ref|github\.event\.workflow_run\.head_(?:sha|branch)|refs/pull/)"
    ),
    re.compile(
        r"^\s*(?:-\s+)?repository\s*:.*"
        r"github\.event\.(?:pull_request\.head\.repo|workflow_run\.head_repository)"
    ),
    re.compile(r"\bgh\s+pr\s+checkout\b"),
    re.compile(
        r"\bgit\s+(?:fetch|checkout|switch|pull|worktree\s+add)\b.*(?:\bpull/|refs/pull/|"
        r"github\.head_ref|github\.event\.pull_request\.head|"
        r"github\.event\.workflow_run\.head_(?:sha|branch))"
    ),
)
_WORKFLOW_RUN_ARTIFACT_RE = re.compile(
    r"github\.event\.workflow_run\.id|\bgh\s+run\s+download\b|"
    r"\buses\s*:\s*dawidd6/action-download-artifact@"
)


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


@dataclass(frozen=True)
class _Line:
    number: int
    code: str
    indent: int
    key: str | None
    context: str | None


def analyze_github_actions_workflows(repo_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for workflow_path in _workflow_files(Path(repo_path)):
        try:
            content = workflow_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        findings.extend(_analyze_workflow_file(workflow_path, repo_path, content))

    return _sort_findings(_dedupe_findings(findings))


def _workflow_files(repo_path: Path) -> list[Path]:
    files: list[Path] = []
    workflow_dir = repo_path / ".github" / "workflows"
    if workflow_dir.is_dir():
        files.extend(
            path
            for path in sorted(workflow_dir.iterdir())
            if path.suffix.lower() in _WORKFLOW_SUFFIXES and path.is_file()
        )
    # Composite actions run their steps inside the calling workflow's job.
    actions_dir = repo_path / ".github" / "actions"
    if actions_dir.is_dir():
        files.extend(
            path
            for path in sorted(actions_dir.rglob("*"))
            if path.name.lower() in _ACTION_FILE_NAMES and path.is_file()
        )
    for name in sorted(_ACTION_FILE_NAMES):
        candidate = repo_path / name
        if candidate.is_file():
            files.append(candidate)
    return files


def _analyze_workflow_file(workflow_path: Path, repo_path: Path, content: str) -> list[Finding]:
    specs: list[_WorkflowFindingSpec] = []
    lines = _parse_lines(content)
    code = "\n".join(line.code for line in lines)
    command_text = "\n".join("" if line.context in _PROSE_KEYS else line.code for line in lines)
    neutral_text = "\n".join(_neutralize_echo_text(line) for line in command_text.split("\n"))
    triggers = _workflow_triggers(lines)
    untrusted_triggers = [trigger for trigger in _UNTRUSTED_TRIGGERS if trigger in triggers]
    pull_request_target = triggers.get("pull_request_target", 0)
    pr_checkout_line = _pull_request_checkout_line(lines)

    if pull_request_target:
        if pr_checkout_line:
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
    elif pr_checkout_line:
        privileged = [trigger for trigger in untrusted_triggers if trigger != "pull_request_target"]
        if privileged:
            specs.append(
                _WorkflowFindingSpec(
                    signal_type="github_actions_untrusted_checkout",
                    title=f"{privileged[0]} workflow checks out pull request code",
                    severity="critical",
                    action="block",
                    reason=(
                        f"{privileged[0]} runs with base-repository secrets and token scope "
                        "and this workflow checks out pull request-controlled code"
                    ),
                    evidence_kind="github_actions_workflow",
                    line=pr_checkout_line,
                    metadata={"triggers": privileged, "checks_out_pr_code": True},
                )
            )

    if "workflow_run" in triggers:
        artifact = _WORKFLOW_RUN_ARTIFACT_RE.search(command_text)
        if artifact:
            specs.append(
                _WorkflowFindingSpec(
                    signal_type="github_actions_workflow_run_artifact",
                    title="workflow_run workflow consumes artifacts from the triggering run",
                    severity="high",
                    action="investigate",
                    reason=(
                        "artifacts from a pull request run are attacker-controlled; using them in "
                        "a privileged workflow_run job can poison it"
                    ),
                    evidence_kind="github_actions_workflow",
                    line=_line_number(command_text, artifact.start()),
                    metadata={"workflow_run": True},
                )
            )

    oidc_line = _find_line(code, r"(?mi)^\s*id-token\s*:\s*write\s*$")
    if oidc_line:
        # Trusted publishing and cloud deploys need id-token: write; it is a
        # meaningful risk when untrusted input can steer the job.
        specs.append(
            _WorkflowFindingSpec(
                signal_type="github_actions_oidc_write",
                title="GitHub Actions workflow grants OIDC token write scope",
                severity="high" if untrusted_triggers else "low",
                action="investigate" if untrusted_triggers else "warn",
                reason=(
                    "id-token: write lets a workflow reachable from untrusted triggers mint "
                    "cloud or package-publish tokens"
                    if untrusted_triggers
                    else "id-token: write allows the workflow to mint cloud or package-publish tokens"
                ),
                evidence_kind="github_actions_workflow",
                line=oidc_line,
                metadata={
                    "permission": "id-token: write",
                    "untrusted_triggers": untrusted_triggers,
                },
            )
        )

    write_permissions = _write_permissions(code)
    if write_permissions:
        # Job-scoped grants are the least-privilege form the remediation asks
        # for; they block only when untrusted input can reach the workflow.
        workflow_wide = _has_workflow_level_write(lines)
        blocking = workflow_wide or bool(untrusted_triggers)
        specs.append(
            _WorkflowFindingSpec(
                signal_type="github_actions_write_permissions",
                title=(
                    "GitHub Actions workflow grants broad write permissions"
                    if workflow_wide
                    else "GitHub Actions job grants write permissions"
                ),
                severity="high" if blocking else "medium",
                action="block" if blocking else "warn",
                reason=(
                    ("workflow" if workflow_wide else "job")
                    + " grants write-capable GITHUB_TOKEN permissions: "
                    + ", ".join(write_permissions)
                ),
                evidence_kind="github_actions_workflow",
                line=_first_write_permission_line(code),
                metadata={"permissions": write_permissions, "workflow_level": workflow_wide},
            )
        )

    source_clone_line = _find_line(neutral_text, r"(?mi)\b(?:gh\s+repo\s+clone|git\s+clone)\b")
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

    action_refs = _action_refs(lines)
    cache_line = next(
        (line for name, _ref, line in action_refs if name.lower().startswith("actions/cache")),
        0,
    )
    if pull_request_target and cache_line:
        specs.append(
            _WorkflowFindingSpec(
                signal_type="github_actions_cache_on_pull_request_target",
                title="pull_request_target workflow uses cache restore/save behavior",
                severity="high",
                action="investigate",
                reason="cache use across pull_request_target trust boundaries can expose poisoned artifacts",
                evidence_kind="github_actions_workflow",
                line=cache_line,
                metadata={"pull_request_target": True, "cache": True},
            )
        )

    for name, ref, line in action_refs:
        owner = name.split("/", 1)[0].lower()
        if (
            ref is None
            or ref.lower() in {"main", "master", "head"}
            or ref.startswith("refs/heads/")
        ):
            action_ref = f"{name}@{ref or '<missing>'}"
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
        elif not _FULL_SHA_RE.fullmatch(ref) and owner not in _GITHUB_OWNED_ACTION_OWNERS:
            # Tags of third-party actions can be moved by whoever controls the
            # upstream repository (tj-actions/changed-files, 2025). GitHub-owned
            # actions are maintained by the platform itself, so their tags are
            # not reported; their branch refs still are, above.
            action_ref = f"{name}@{ref}"
            specs.append(
                _WorkflowFindingSpec(
                    signal_type="github_actions_unpinned_action",
                    title=f"GitHub Actions workflow uses third-party action tag {action_ref}",
                    severity="medium",
                    action="warn",
                    reason="third-party actions should be pinned to a full-length commit SHA",
                    evidence_kind="github_actions_workflow",
                    line=line,
                    metadata={"action_ref": action_ref},
                )
            )

    for line in _template_injection_lines(lines):
        specs.append(
            _WorkflowFindingSpec(
                signal_type="github_actions_template_injection",
                title="GitHub Actions script interpolates untrusted event data",
                severity="high",
                action="block" if untrusted_triggers else "warn",
                reason=(
                    "attacker-controlled event text is expanded into a script before it runs"
                    + (
                        f" in a {untrusted_triggers[0]} workflow with privileged token context"
                        if untrusted_triggers
                        else ""
                    )
                ),
                evidence_kind="github_actions_workflow",
                line=line,
                metadata={"template_injection": True, "untrusted_triggers": untrusted_triggers},
            )
        )

    for line in _encoded_shell_payload_lines(command_text):
        specs.append(
            _WorkflowFindingSpec(
                signal_type="github_actions_encoded_shell_payload",
                title="GitHub Actions workflow decodes and executes encoded shell payload",
                severity="critical",
                action="block",
                reason="base64-decoded shell payloads are a common CI credential-stealing technique",
                evidence_kind="github_actions_workflow",
                line=line,
                metadata={"encoded_shell_payload": True},
            )
        )

    for line in _cloud_metadata_probe_lines(neutral_text):
        specs.append(
            _WorkflowFindingSpec(
                signal_type="github_actions_cloud_metadata_probe",
                title="GitHub Actions workflow probes cloud metadata or OIDC token endpoints",
                severity="high",
                action="block",
                reason="workflow commands should not harvest runner cloud metadata or OIDC request tokens",
                evidence_kind="github_actions_workflow",
                line=line,
                metadata={"cloud_metadata_probe": True},
            )
        )

    for line in _credential_file_harvest_lines(neutral_text):
        specs.append(
            _WorkflowFindingSpec(
                signal_type="github_actions_credential_file_harvest",
                title="GitHub Actions workflow references local credential files",
                severity="high",
                action="block",
                reason="workflow commands should not read broad local credential stores",
                evidence_kind="github_actions_workflow",
                line=line,
                metadata={"credential_file_harvest": True},
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


def _parse_lines(content: str) -> list[_Line]:
    """Index each line with its comment-free text and the YAML key it belongs to.

    This is a line model, not a YAML parser: it tracks block scalars
    (``key: |``) so script text and prose are attributed to their key.
    """
    lines: list[_Line] = []
    block_key: str | None = None
    block_indent = -1
    for number, raw in enumerate(content.splitlines(), start=1):
        code = _strip_comment(raw)
        indent = len(raw) - len(raw.lstrip())
        if block_key is not None and (not raw.strip() or indent > block_indent):
            lines.append(_Line(number, code, indent, None, block_key))
            continue
        block_key = None
        match = _KEY_RE.match(code)
        if match is None:
            lines.append(_Line(number, code, indent, None, None))
            continue
        key = match.group(3)
        value = (match.group(4) or "").strip()
        if _BLOCK_SCALAR_RE.match(value):
            block_key = key
            block_indent = len(match.group(1)) + len(match.group(2))
        lines.append(_Line(number, code, indent, key, key))
    return lines


def _strip_comment(line: str) -> str:
    quote: str | None = None
    for index, char in enumerate(line):
        if quote:
            if char == quote:
                quote = None
        elif char in {'"', "'"}:
            quote = char
        elif char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index].rstrip()
    return line.rstrip()


def _neutralize_echo_text(line: str) -> str:
    return _ECHO_ARGS_RE.sub(
        lambda match: match.group(0)[: match.start(1) - match.start(0)] + " " * len(match.group(1)),
        line,
    )


def _workflow_triggers(lines: list[_Line]) -> dict[str, int]:
    """Return trigger events with their line, for scalar, list, and mapping forms."""
    events: dict[str, int] = {}
    for index, line in enumerate(lines):
        if line.indent:
            continue
        match = _ON_RE.match(line.code)
        if match is None:
            continue
        inline = match.group(1).strip()
        if inline:
            for name in re.findall(r"[A-Za-z_]+", inline):
                if name in _KNOWN_EVENTS:
                    events.setdefault(name, line.number)
            continue
        child_indent: int | None = None
        for child in lines[index + 1 :]:
            text = child.code.strip()
            if not text:
                continue
            if child.indent == 0 and not text.startswith("-"):
                break
            if child_indent is None:
                child_indent = child.indent
            if child.indent != child_indent:
                continue
            item = _EVENT_ITEM_RE.match(child.code)
            if item and item.group(1) in _KNOWN_EVENTS:
                events.setdefault(item.group(1), child.number)
    return events


def _pull_request_checkout_line(lines: list[_Line]) -> int:
    for line in lines:
        if line.context in _PROSE_KEYS:
            continue
        if any(pattern.search(line.code) for pattern in _PR_CHECKOUT_PATTERNS):
            return line.number
    return 0


def _action_refs(lines: list[_Line]) -> list[tuple[str, str | None, int]]:
    refs: list[tuple[str, str | None, int]] = []
    for line in lines:
        if line.key != "uses":
            continue
        match = _USES_RE.match(line.code)
        if match is None:
            continue
        target = match.group(1)
        if target.startswith(("./", "docker://")):
            continue
        name, separator, ref = target.partition("@")
        refs.append((name, ref if separator and ref else None, line.number))
    return refs


def _template_injection_lines(lines: list[_Line]) -> list[int]:
    found: list[int] = []
    for line in lines:
        if line.context not in _SCRIPT_KEYS:
            continue
        if any(
            _UNTRUSTED_CONTEXT_RE.search(expression)
            for expression in _EXPRESSION_RE.findall(line.code)
        ):
            found.append(line.number)
    return found


def _write_permissions(content: str) -> list[str]:
    permissions: set[str] = set()
    if re.search(r"(?mi)^\s*permissions\s*:\s*write-all\s*$", content):
        permissions.add("write-all")

    for match in re.finditer(r"(?mi)^\s*([a-z-]+)\s*:\s*write\s*$", content):
        permission = match.group(1).lower()
        if permission in _RISKY_WRITE_PERMISSIONS:
            permissions.add(f"{permission}: write")

    return sorted(permissions)


def _has_workflow_level_write(lines: list[_Line]) -> bool:
    block_indent: int | None = None
    for line in lines:
        if not line.code.strip():
            continue
        if block_indent is not None and line.indent <= block_indent:
            block_indent = None
        if line.key == "permissions":
            value = line.code.split(":", 1)[1].strip().lower()
            if value == "write-all" and line.indent == 0:
                return True
            block_indent = line.indent if not value else None
            continue
        if (
            block_indent == 0
            and (line.key or "").lower() in _RISKY_WRITE_PERMISSIONS
            and re.search(r":\s*write\s*$", line.code, re.IGNORECASE)
        ):
            return True
    return False


def _first_write_permission_line(content: str) -> int:
    for pattern in (
        r"(?mi)^\s*permissions\s*:\s*write-all\s*$",
        r"(?mi)^\s*(?:actions|checks|contents|deployments|packages)\s*:\s*write\s*$",
    ):
        line = _find_line(content, pattern)
        if line:
            return line
    return 1


def _encoded_shell_payload_lines(content: str) -> list[int]:
    lines: list[int] = []
    for match in re.finditer(
        r"(?mi)\bbase64\s+(?:-[A-Za-z]*d[A-Za-z]*|--decode)\b[^\n|;&]*[|;&]\s*(?:/bin/)?(?:ba)?sh\b",
        content,
    ):
        lines.append(_line_number(content, match.start()))
    for match in re.finditer(
        r"(?mi)\b(?:ba)?sh\b[^\n]*\$\([^)]*\bbase64\s+(?:-[A-Za-z]*d[A-Za-z]*|--decode)\b",
        content,
    ):
        lines.append(_line_number(content, match.start()))
    return sorted(set(lines))


def _cloud_metadata_probe_lines(content: str) -> list[int]:
    return _matching_lines(content, _CLOUD_METADATA_PATTERNS)


def _credential_file_harvest_lines(content: str) -> list[int]:
    return _matching_lines(content, _CREDENTIAL_FILE_PATTERNS)


def _matching_lines(content: str, patterns: tuple[str, ...]) -> list[int]:
    lines: set[int] = set()
    for pattern in patterns:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            lines.add(_line_number(content, match.start()))
    return sorted(lines)


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
