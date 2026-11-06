"""GitLab CI job reach model for ``.gitlab-ci.yml`` and its local includes.

GitLab injects project and group CI/CD variables into every job unless a
variable is protected or scoped to an environment (server-side settings), so
each job is modelled with ``secrets.inherit`` set.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ca9.ci import jobs as jobtools
from ca9.ci.model import ActionRef, Job, Workflow
from ca9.ci.shell import ScriptFacts, ShellContext, scan_script
from ca9.ci.yamlload import LineList, LineMap, YamlError, as_strings, load_file

MAX_INCLUDES = 50
MAX_EXTENDS_DEPTH = 10

_RESERVED = frozenset(
    {
        "stages",
        "variables",
        "default",
        "include",
        "workflow",
        "image",
        "services",
        "before_script",
        "after_script",
        "cache",
        "spec",
    }
)
_INHERITED_DEFAULTS = ("before_script", "after_script", "tags", "cache", "id_tokens")
_VAR_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")
_PREDEFINED_RE = re.compile(
    r"^(?:CI|CI_\w+|GITLAB_\w+|HOME|PATH|PWD|USER|SHELL|HOSTNAME|TMPDIR|RUNNER_\w+|FF_\w+|"
    r"DOCKER_\w+|LANG|LC_\w+|TERM|OLDPWD|UID|GID|IFS|RANDOM|SECONDS|BASH_\w+|\d+)$"
)
_SOURCE_RE = re.compile(r"\$CI_PIPELINE_SOURCE\s*==\s*[\"']?([A-Za-z_]+)")
_BRANCH_RE = re.compile(
    r"\$(?:CI_COMMIT_BRANCH|CI_COMMIT_REF_NAME|CI_DEFAULT_BRANCH)\s*==\s*[\"']?([A-Za-z0-9_./-]+)"
)
_SHA_RE = re.compile(r"[0-9a-fA-F]{40}")
_DEFAULT_TRIGGERS = ["api", "push", "schedule", "trigger", "web"]


def load_gitlab(
    repo_root: Path,
    project: dict[str, Any],
    remaining_jobs: int,
) -> tuple[Workflow | None, bool, list[dict[str, str]]]:
    path = repo_root / ".gitlab-ci.yml"
    if not path.is_file():
        return None, False, []
    skipped: list[dict[str, str]] = []
    document = load_file(path, repo_root)
    if not isinstance(document, LineMap):
        raise YamlError("pipeline is not a mapping")
    workflow = Workflow(file=".gitlab-ci.yml", provider="gitlab")
    merged: dict[str, Any] = {}
    _includes(repo_root, document, workflow, merged, skipped)
    merged.update(document)
    variables = _variables(merged.get("variables"))
    default = merged.get("default")
    if not isinstance(default, dict):
        default = {}
    names = [
        key
        for key, value in merged.items()
        if key not in _RESERVED and not key.startswith(".") and isinstance(value, dict)
    ]
    truncated = False
    texts: list[str] = [_rules_text(merged.get("workflow"))]
    for name in names:
        if len(workflow.jobs) >= remaining_jobs:
            truncated = True
            break
        node = _extended(merged, name, 0)
        line = document.key_lines.get(name, 1)
        texts.append(_rules_text(node.get("rules")) + _rules_text(node.get("only")))
        workflow.jobs.append(_job(name, node, line, default, variables, project))
    _triggers(workflow, merged, texts)
    return workflow, truncated, skipped


def _includes(
    repo_root: Path,
    document: LineMap,
    workflow: Workflow,
    merged: dict[str, Any],
    skipped: list[dict[str, str]],
) -> None:
    raw = document.get("include")
    items: list[Any] = []
    if isinstance(raw, list):
        items = list(raw)
    elif raw is not None:
        items = [raw]
    for index, item in enumerate(items[:MAX_INCLUDES]):
        line = document.key_line("include")
        if isinstance(raw, LineList):
            line = raw.item_line(index)
        local = None
        if isinstance(item, str):
            if "://" in item:
                workflow.includes.append(
                    ActionRef(_host_only(item), "", False, line, True, kind="remote")
                )
                continue
            local = item
        elif isinstance(item, dict):
            if isinstance(item.get("local"), str):
                local = item["local"]
            elif isinstance(item.get("component"), str):
                name, _, ref = item["component"].partition("@")
                workflow.includes.append(
                    ActionRef(name, ref, bool(_SHA_RE.fullmatch(ref)), line, True, kind="component")
                )
                continue
            elif isinstance(item.get("project"), str):
                ref = str(item.get("ref") or "")
                workflow.includes.append(
                    ActionRef(
                        item["project"],
                        ref,
                        bool(_SHA_RE.fullmatch(ref)),
                        line,
                        True,
                        kind="project",
                    )
                )
                continue
            elif isinstance(item.get("remote"), str):
                workflow.includes.append(
                    ActionRef(_host_only(item["remote"]), "", False, line, True, kind="remote")
                )
                continue
            elif isinstance(item.get("template"), str):
                workflow.includes.append(
                    ActionRef(item["template"], "", False, line, False, kind="template")
                )
                continue
        if not local or any(char in local for char in "*$"):
            continue
        try:
            included = load_file(repo_root / local.lstrip("/"), repo_root)
        except (OSError, ValueError, YamlError):
            skipped.append({"file": local.lstrip("/"), "reason": "include_unreadable"})
            continue
        if isinstance(included, dict):
            merged.update(included)


def _host_only(url: str) -> str:
    match = re.match(r"^[a-z]+://(?:[^/@]*@)?([^/:?#]+)", url, re.I)
    if match is None:
        return "unknown"
    return match.group(1).lower()


def _variables(node: Any) -> dict[str, str]:
    if not isinstance(node, dict):
        return {}
    values: dict[str, str] = {}
    for key, value in node.items():
        if isinstance(value, dict):
            value = value.get("value")
        if isinstance(value, (str, int, float, bool)):
            values[key] = str(value)
    return values


def _extended(merged: dict[str, Any], name: str, depth: int) -> dict[str, Any]:
    node = merged.get(name)
    if not isinstance(node, dict) or depth > MAX_EXTENDS_DEPTH:
        return {}
    parents = node.get("extends")
    parent_names = as_strings(parents)
    result: dict[str, Any] = {}
    for parent in parent_names:
        if parent != name:
            result = _merge(result, _extended(merged, parent, depth + 1))
    return _merge(result, node)


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if key in {"variables"} and isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = {**result[key], **value}
        else:
            result[key] = value
    return result


def _rules_text(node: Any) -> str:
    parts: list[str] = []
    stack = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
        elif isinstance(current, str):
            parts.append(current)
    return " ".join(parts)


def _triggers(workflow: Workflow, merged: dict[str, Any], texts: list[str]) -> None:
    joined = " ".join(texts)
    sources = set(_SOURCE_RE.findall(joined))
    if "$CI_COMMIT_TAG" in joined:
        sources.add("tag")
    for word in ("web", "api", "schedules", "triggers", "tags", "branches", "merge_requests"):
        if re.search(rf"(?<![\w$]){word}(?![\w])", joined):
            sources.add(
                {
                    "schedules": "schedule",
                    "triggers": "trigger",
                    "tags": "tag",
                    "branches": "push",
                    "merge_requests": "merge_request_event",
                }.get(word, word)
            )
    restricted = bool(_rules_text(merged.get("workflow")).strip())
    if not sources and not restricted:
        workflow.triggers = list(_DEFAULT_TRIGGERS)
    else:
        workflow.triggers = sorted(sources) or list(_DEFAULT_TRIGGERS)
    workflow.dispatch = bool({"web", "api", "trigger"} & set(workflow.triggers))
    branches = sorted(set(_BRANCH_RE.findall(joined)))
    if branches:
        workflow.branch_filters = branches
    elif set(workflow.triggers) <= {"tag", "schedule", "web", "api", "trigger"}:
        workflow.branch_filters = []
    else:
        workflow.any_branch = True


def _script_items(node: Any) -> list[tuple[str, int]]:
    items: list[tuple[str, int]] = []
    if isinstance(node, str):
        return [(node, 0)]
    if not isinstance(node, LineList):
        return items
    for index, item in enumerate(node):
        if isinstance(item, str):
            line = node.item_line(index)
            if "\n" in item:
                line += 1
            items.append((item, line))
        elif isinstance(item, LineList):
            items.extend(_script_items(item))
    return items


def _job(
    name: str,
    node: dict[str, Any],
    line: int,
    default: dict[str, Any],
    global_variables: dict[str, str],
    project: dict[str, Any],
) -> Job:
    for key in _INHERITED_DEFAULTS:
        if key not in node and key in default:
            node = {**node, key: default[key]}
    job = Job(id=name, line=line, permissions_source="gitlab", inherit=True)
    job.labels = as_strings(node.get("tags"))
    job.self_hosted = any(not label.lower().startswith("saas-") for label in job.labels)
    job.runner_inferred = job.self_hosted
    environment = node.get("environment")
    if isinstance(environment, dict):
        environment = environment.get("name")
    if isinstance(environment, (str, int)) and str(environment).strip():
        job.environment = str(environment).strip()
        job.environment_dynamic = "$" in job.environment
    id_tokens = node.get("id_tokens")
    job.id_token = isinstance(id_tokens, dict) and bool(id_tokens)
    token_names: set[str] = set()
    if isinstance(id_tokens, dict):
        token_names = set(id_tokens)
    job.uses_cache = bool(node.get("cache"))
    variables = {**global_variables, **_variables(node.get("variables"))}
    scripts = [
        *_script_items(node.get("before_script")),
        *_script_items(node.get("script")),
        *_script_items(node.get("after_script")),
    ]
    context = ShellContext(
        env=variables,
        scripts=project.get("scripts", {}),
        local_packages=project.get("packages", frozenset()),
        yarn_berry=project.get("yarn_berry", False),
    )
    facts = ScriptFacts()
    contexts: dict[tuple[int, ...], str] = {}
    for index, (text, script_line) in enumerate(scripts):
        start = script_line or line
        contexts[(index,)] = text
        facts.extend(scan_script(text, start, context, (index,)))
        for match in _VAR_RE.finditer(text):
            var = match.group(1)
            if var in variables or var in token_names or _PREDEFINED_RE.match(var):
                continue
            job.secret_names.add(var)
            registry = jobtools.env_registry(var) or jobtools.secret_registry(var)
            if registry:
                jobtools.add_credential(job, var, registry, start)
    secrets = node.get("secrets")
    if isinstance(secrets, dict):
        job.secret_names.update(str(key) for key in secrets)
    jobtools.finalize(job, facts, contexts)
    return job
