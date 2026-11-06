"""Publish-job rules over the CI job reach model.

Each rule covers a gap that zizmor 1.32.0, poutine 1.1.6 and OpenSSF Scorecard
5.6.0 left open on the @subql, Nx, LiteLLM, TanStack and SAP release workflows
(gap check run 2026-11-05): none of them scopes these checks to the job that
holds publish credentials or ``id-token: write``.
"""

from __future__ import annotations

from pathlib import PurePath
from typing import Any

from ca9.ci.inventory import DEFAULT_MAX_JOBS, build_inventory
from ca9.ci.model import Job, Workflow

UNPINNED_TOOL = "unpinned_tool_in_credentialed_job"
UNVERIFIED_DOWNLOAD = "unverified_download_into_publish"
OIDC_WITHOUT_ENVIRONMENT = "oidc_publish_without_environment"
PUBLISH_TRIGGER = "publish_on_dispatch_or_any_branch"
RULES = (UNPINNED_TOOL, UNVERIFIED_DOWNLOAD, OIDC_WITHOUT_ENVIRONMENT, PUBLISH_TRIGGER)
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_ECOSYSTEMS = {"github": "github-actions", "gitlab": "gitlab-ci"}
_WILDCARD_CHARS = frozenset("*?[!+")

_REMEDIATION = {
    UNPINNED_TOOL: (
        "Pin every tool this job installs to an exact version with a checksum (or a "
        "SHA-pinned setup action with a fixed version), or install and run the tool in a "
        "separate job that holds no publish credentials and no id-token."
    ),
    UNVERIFIED_DOWNLOAD: (
        "Do not publish downloaded files. If the step is needed, pin the URL to an immutable "
        "release and verify a checksum or signature (sha256sum -c, cosign verify-blob, "
        "gh attestation verify) before the publish step."
    ),
    OIDC_WITHOUT_ENVIRONMENT: (
        "Run the publish job in a GitHub environment (for example environment: release) with "
        "deployment-branch rules and required reviewers, and set that environment name in the "
        "npm or PyPI trusted publisher so tokens minted outside it are refused."
    ),
    PUBLISH_TRIGGER: (
        "Publish only from protected refs: remove workflow_dispatch from the publish workflow "
        "or guard the publish job with if: github.ref == 'refs/heads/main', restrict push "
        "branches to protected ones, and require an environment with deployment-branch rules."
    ),
}


def audit_repository(
    repo_root: str | PurePath, *, max_jobs: int = DEFAULT_MAX_JOBS
) -> dict[str, Any]:
    inventory, workflows = build_inventory(repo_root, max_jobs=max_jobs)
    findings: list[dict[str, Any]] = []
    publish_secrets = sorted(
        {
            name
            for workflow in workflows
            if workflow.provider == "github"
            for job in workflow.jobs
            for name in job.publish_credentials
            if name in job.secret_names
        }
    )
    for workflow in workflows:
        for job in workflow.jobs:
            findings.extend(_unpinned_tools(workflow, job, publish_secrets))
            findings.extend(_unverified_downloads(workflow, job))
            findings.extend(_oidc_without_environment(workflow, job))
        if workflow.provider == "github":
            findings.extend(_publish_trigger(workflow))
    findings.sort(
        key=lambda item: (
            _SEVERITY_RANK.get(item["severity"], 4),
            item["signal_type"],
            item["file"],
            item["line"],
        )
    )
    receipt = {
        "status": inventory["status"],
        "truncated": inventory["truncated"],
        "workflows": len(workflows),
        "jobs": sum(len(workflow.jobs) for workflow in workflows),
        "rules": list(RULES),
        "dropped_rules": [],
        "not_applied": [
            {
                "rule": PUBLISH_TRIGGER,
                "provider": "gitlab",
                "reason": "GitLab protects variables per branch on the server; YAML cannot show it",
            }
        ],
        "skipped": list(inventory.get("skipped", [])),
        "complete": inventory["status"] == "complete" and not inventory["truncated"],
    }
    return {"findings": findings, "receipt": receipt}


def _credentialed(workflow: Workflow, job: Job) -> bool:
    if job.id_token or job.publish_credentials or job.publishes:
        return True
    return workflow.provider == "github" and (job.inherit or job.all_via_tojson)


def _credential_labels(workflow: Workflow, job: Job, publish_secrets: list[str]) -> list[str]:
    labels = sorted(job.publish_credentials)
    if job.id_token:
        labels.append("id-token: write")
    everything = workflow.provider == "github" and (job.inherit or job.all_via_tojson)
    if workflow.provider == "github" and job.inherit:
        labels.append("all secrets (secrets: inherit)")
    if job.all_via_tojson:
        labels.append("all secrets (toJSON(secrets))")
    if everything:
        labels.extend(
            f"{name} (reachable as one of all secrets)"
            for name in publish_secrets
            if name not in job.publish_credentials
        )
    return labels


def _holds_publish_credentials(workflow: Workflow, job: Job, publish_secrets: list[str]) -> bool:
    if job.publish_credentials or job.publishes:
        return True
    everything = workflow.provider == "github" and (job.inherit or job.all_via_tojson)
    return everything and bool(publish_secrets)


def _publish_labels(job: Job) -> list[dict[str, Any]]:
    return [
        {"registry": item.registry, "method": item.method, "via": item.via, "line": item.line}
        for item in job.publishes
    ]


def _finding(
    signal: str,
    severity: str,
    action: str,
    workflow: Workflow,
    job: Job | None,
    title: str,
    reason: str,
    line: int,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    name = workflow.file
    job_id = None
    if job is not None:
        name = job.id
        job_id = job.id
    return {
        "signal_type": signal,
        "severity": severity,
        "action": action,
        "ecosystem": _ECOSYSTEMS.get(workflow.provider, workflow.provider),
        "name": name,
        "version": None,
        "title": title,
        "reason": reason,
        "remediation": _REMEDIATION[signal],
        "evidence": {
            "provider": workflow.provider,
            "workflow": workflow.file,
            "job": job_id,
            "line": line,
            **evidence,
        },
        "file": workflow.file,
        "line": line,
    }


def _unpinned_tools(
    workflow: Workflow, job: Job, publish_secrets: list[str]
) -> list[dict[str, Any]]:
    if not _credentialed(workflow, job):
        return []
    tools = [
        tool for tool in [*job.tools, *job.other_tools] if not tool.pinned and not tool.self_update
    ]
    if not tools:
        return []
    tools.sort(key=lambda tool: tool.line)
    names = ", ".join(dict.fromkeys(f"{tool.name} ({tool.route})" for tool in tools))
    credentials = _credential_labels(workflow, job, publish_secrets)
    severity = "MEDIUM"
    holder = "can mint OIDC tokens"
    if not job.id_token:
        holder = "can read all repository secrets"
    if _holds_publish_credentials(workflow, job, publish_secrets):
        severity = "HIGH"
        holder = "holds publish credentials"
    return [
        _finding(
            UNPINNED_TOOL,
            severity,
            "warn",
            workflow,
            job,
            f"Unpinned tools run in job '{job.id}', which {holder}",
            (
                f"{names} install without an exact version or checksum in a job that can reach "
                f"{', '.join(credentials)}; a hijacked tool release runs with those credentials "
                "(LiteLLM's PyPI token leaked from CI that pulled Trivy unpinned)"
            ),
            tools[0].line,
            {
                "tools": [
                    {"name": tool.name, "route": tool.route, "line": tool.line, **_origin(tool)}
                    for tool in tools
                ],
                "credentials": credentials,
                "publishes": _publish_labels(job),
            },
        )
    ]


def _origin(item: Any) -> dict[str, Any]:
    if item.origin is None:
        return {}
    return {"via_action": item.origin.to_dict()}


def _unverified_downloads(workflow: Workflow, job: Job) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for download in job.downloads:
        if not download.reaches_publish or download.verified:
            continue
        blocking = download.replaces or download.used_by_publish
        action = "warn"
        if blocking:
            action = "block"
        landing = download.lands_in or "the job workspace"
        detail = "is downloaded"
        if download.archive:
            detail = f"is downloaded and unpacked into {landing}"
        if download.replaces:
            detail = f"replaces {landing} after it was deleted"
        findings.append(
            _finding(
                UNVERIFIED_DOWNLOAD,
                "HIGH",
                action,
                workflow,
                job,
                f"Unverified download from {download.host} reaches the publish step in job '{job.id}'",
                (
                    f"a file from {download.host} {detail} with no checksum or signature check, "
                    "and the job publishes afterwards; the @subql 5.8.3 release swapped "
                    "packages/common for such an archive"
                ),
                download.line,
                {
                    "host": download.host,
                    "archive": download.archive,
                    "lands_in": download.lands_in,
                    "replaces_source": download.replaces,
                    "used_by_publish_step": download.used_by_publish,
                    "publishes": _publish_labels(job),
                    **_origin(download),
                },
            )
        )
    return findings


def _oidc_without_environment(workflow: Workflow, job: Job) -> list[dict[str, Any]]:
    if not job.id_token or not job.publishes:
        return []
    if job.environment is not None and not job.environment_dynamic:
        return []
    registries = ", ".join(sorted({item.registry for item in job.publishes}))
    if job.environment_dynamic:
        detail = (
            f"its environment comes from an expression ({job.environment}), so whoever starts "
            "the run chooses it"
        )
    else:
        detail = "it has no environment:"
    token_source = "workflow-level permissions"
    if job.permissions_source == "job":
        token_source = "job permissions"
    if workflow.provider == "gitlab":
        token_source = "id_tokens"
    return [
        _finding(
            OIDC_WITHOUT_ENVIRONMENT,
            "HIGH",
            "warn",
            workflow,
            job,
            f"Publish job '{job.id}' can mint OIDC tokens without an environment",
            (
                f"job '{job.id}' gets id-token: write from {token_source} and publishes to "
                f"{registries}, but {detail}; a trusted publisher cannot be bound to a protected "
                "environment, so any ref that runs this job can publish (Red Hat npm 2026-06-01, "
                "TanStack 2026-05-11)"
            ),
            job.line,
            {
                "environment": job.environment,
                "environment_dynamic": job.environment_dynamic,
                "id_token_source": job.permissions_source,
                "publishes": _publish_labels(job),
            },
        )
    ]


def _publish_trigger(workflow: Workflow) -> list[dict[str, Any]]:
    publish_jobs = [job for job in workflow.jobs if job.publishes]
    exposed = [job for job in publish_jobs if not job.ref_guarded]
    if not exposed:
        return []
    wildcards = [
        pattern for pattern in workflow.branch_filters or [] if _WILDCARD_CHARS & set(pattern)
    ]
    if not (workflow.dispatch or workflow.any_branch or wildcards):
        return []
    unprotected = [job for job in exposed if job.environment is None or job.environment_dynamic]
    routes: list[str] = []
    if workflow.dispatch:
        routes.append("workflow_dispatch")
    if workflow.any_branch:
        routes.append("a push to any branch")
    if wildcards and not workflow.any_branch:
        routes.append("pushes to branch patterns " + ", ".join(f"'{item}'" for item in wildcards))
    strong = workflow.dispatch or workflow.any_branch
    severity, action = "LOW", "investigate"
    if unprotected and strong:
        severity, action = "HIGH", "warn"
    elif unprotected:
        severity, action = "MEDIUM", "warn"
    line = workflow.trigger_lines.get("push", workflow.on_line)
    if workflow.dispatch:
        line = workflow.trigger_lines.get("workflow_dispatch", line)
    job_names = ", ".join(f"'{job.id}'" for job in exposed)
    if unprotected:
        protection = "no environment protects " + ", ".join(f"'{job.id}'" for job in unprotected)
    else:
        environments = ", ".join(sorted({str(job.environment) for job in exposed}))
        protection = (
            f"environment {environments} protects it only if its deployment-branch rule "
            "restricts branches, which YAML does not show"
        )
    callers = ""
    own_route = "workflow_dispatch" in workflow.triggers or "push" in workflow.triggers
    if workflow.called_by and not own_route:
        callers = " through " + ", ".join(sorted(workflow.called_by))
    return [
        _finding(
            PUBLISH_TRIGGER,
            severity,
            action,
            workflow,
            None,
            f"Publish workflow can be started by {' or '.join(routes)}",
            (
                f"{' or '.join(routes)}{callers} can run publish job(s) {job_names} from a branch "
                f"other than the release branch, and {protection} (Nx 2025, @subql 2026-10-05)"
            ),
            line,
            {
                "routes": routes,
                "branch_filters": workflow.branch_filters,
                "jobs": [
                    {
                        "job": job.id,
                        "environment": job.environment,
                        "environment_dynamic": job.environment_dynamic,
                        "publishes": _publish_labels(job),
                    }
                    for job in exposed
                ],
                "called_by": sorted(workflow.called_by),
            },
        )
    ]
