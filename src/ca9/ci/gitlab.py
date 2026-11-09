"""GitLab CI job reach model for ``.gitlab-ci.yml`` and its local includes.

GitLab injects project and group CI/CD variables into every job unless a
variable is protected or scoped to an environment (server-side settings), so
each job is modelled with ``secrets.inherit`` set.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from ca9.ci import jobs as jobtools
from ca9.ci.images import image_pinned, image_reference
from ca9.ci.model import ActionRef, Job, Tool, Workflow
from ca9.ci.shell import ScriptFacts, ShellContext, scan_script
from ca9.ci.yamlload import LineList, LineMap, YamlError, as_strings, load_file

MAX_INCLUDES = 150
MAX_INCLUDE_DEPTH = 10
MAX_GLOB_ENTRIES = 20_000
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
_INHERITED_DEFAULTS = ("before_script", "after_script", "tags", "cache", "id_tokens", "image")
_GLOBAL_DEFAULTS = ("before_script", "after_script", "cache", "image")
_SKIP_GLOB_DIRS = frozenset({".git", "node_modules"})
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
    state = _IncludeState(repo_root, workflow, skipped)
    merged = _deep_merge(
        _includes(state, document, 0, frozenset({".gitlab-ci.yml"}), None), document
    )
    variables = _variables(merged.get("variables"))
    default = merged.get("default")
    if not isinstance(default, dict):
        default = {}
    for key in _GLOBAL_DEFAULTS:
        if key in merged and key not in default:
            default = {**default, key: merged[key]}
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


class _IncludeState:
    """Budget and records shared by every level of a pipeline's includes."""

    def __init__(self, repo_root: Path, workflow: Workflow, skipped: list[dict[str, str]]) -> None:
        self.repo_root = repo_root
        self.workflow = workflow
        self.skipped = skipped
        self.files = 0

    def skip(self, file: str, reason: str) -> None:
        entry = {"file": file, "reason": reason}
        if entry not in self.skipped:
            self.skipped.append(entry)


def _includes(
    state: _IncludeState,
    document: dict[str, Any],
    depth: int,
    chain: frozenset[str],
    anchor: int | None,
) -> dict[str, Any]:
    """Included configuration merged in GitLab's order: every include (with its own
    includes) in turn, before the including file. Includes that cannot be resolved
    inside the repository are recorded in ``skipped`` so the result is partial."""
    merged: dict[str, Any] = {}
    raw = document.get("include")
    items: list[Any] = []
    if isinstance(raw, list):
        items = list(raw)
    elif raw is not None:
        items = [raw]
    for index, item in enumerate(items):
        line = anchor
        if line is None and isinstance(document, LineMap):
            line = document.key_line("include")
            if isinstance(raw, LineList):
                line = raw.item_line(index)
        local = _local_include(state, item, line or 1)
        if local is None:
            continue
        pattern = local.strip().lstrip("/")
        if "$" in pattern:
            state.skip(pattern, "include_variable")
            continue
        for rel in _local_matches(state, pattern):
            if rel in chain:
                continue
            if state.files >= MAX_INCLUDES:
                state.skip(rel, "include_limit")
                return merged
            state.files += 1
            try:
                included = load_file(state.repo_root / rel, state.repo_root)
            except (OSError, ValueError, YamlError):
                state.skip(rel, "include_unreadable")
                continue
            if not isinstance(included, dict):
                continue
            nested: dict[str, Any] = {}
            if included.get("include") is not None:
                if depth + 1 >= MAX_INCLUDE_DEPTH:
                    state.skip(rel, "include_depth")
                else:
                    nested = _includes(state, included, depth + 1, chain | {rel}, line)
            merged = _deep_merge(merged, _deep_merge(nested, included))
    return merged


def _local_include(state: _IncludeState, item: Any, line: int) -> str | None:
    """The local path or pattern of an include; other kinds are listed as unknowns."""
    includes = state.workflow.includes
    if isinstance(item, str):
        if "://" in item:
            host = _host_only(item)
            includes.append(ActionRef(host, "", False, line, True, kind="remote"))
            state.skip(host, "include_remote")
            return None
        return item
    if not isinstance(item, dict):
        return None
    if isinstance(item.get("local"), str):
        return item["local"]
    if isinstance(item.get("component"), str):
        name, _, ref = item["component"].partition("@")
        includes.append(
            ActionRef(name, ref, bool(_SHA_RE.fullmatch(ref)), line, True, kind="component")
        )
        state.skip(name, "include_component")
    elif isinstance(item.get("project"), str):
        ref = str(item.get("ref") or "")
        includes.append(
            ActionRef(
                item["project"], ref, bool(_SHA_RE.fullmatch(ref)), line, True, kind="project"
            )
        )
        state.skip(item["project"], "include_project")
    elif isinstance(item.get("remote"), str):
        host = _host_only(item["remote"])
        includes.append(ActionRef(host, "", False, line, True, kind="remote"))
        state.skip(host, "include_remote")
    elif isinstance(item.get("template"), str):
        includes.append(ActionRef(item["template"], "", False, line, False, kind="template"))
        state.skip(item["template"], "include_template")
    else:
        state.skip(str(sorted(item))[:120], "include_unknown")
    return None


def _local_matches(state: _IncludeState, pattern: str) -> list[str]:
    """Repository files a local include names: the path itself, or every file a ``*``
    or ``**`` pattern matches, as GitLab expands wildcard local includes."""
    if not any(char in pattern for char in "*?["):
        return [pattern]
    parts = pattern.split("/")
    fixed: list[str] = []
    for part in parts:
        if any(char in part for char in "*?["):
            break
        fixed.append(part)
    base = "/".join(fixed)
    expression = re.compile(_glob_expression(pattern))
    recursive = "**" in pattern or len(fixed) < len(parts) - 1
    start = state.repo_root / base
    found: list[str] = []
    entries = 0
    try:
        root = state.repo_root.resolve()
        start.resolve().relative_to(root)
    except (OSError, ValueError):
        state.skip(pattern, "include_unreadable")
        return []
    for directory, dirnames, filenames in os.walk(start):
        dirnames[:] = sorted(name for name in dirnames if name not in _SKIP_GLOB_DIRS)
        if not recursive:
            dirnames[:] = []
        entries += len(dirnames) + len(filenames)
        if entries > MAX_GLOB_ENTRIES:
            state.skip(pattern, "include_limit")
            break
        for filename in sorted(filenames):
            rel = Path(directory, filename).relative_to(state.repo_root).as_posix()
            if expression.fullmatch(rel):
                found.append(rel)
    return sorted(found)


def _glob_expression(pattern: str) -> str:
    pieces: list[str] = []
    index = 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            pieces.append("(?:.*/)?")
            index += 3
        elif pattern.startswith("**", index):
            pieces.append(".*")
            index += 2
        elif pattern[index] == "*":
            pieces.append("[^/]*")
            index += 1
        elif pattern[index] == "?":
            pieces.append("[^/]")
            index += 1
        else:
            pieces.append(re.escape(pattern[index]))
            index += 1
    return "".join(pieces)


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """GitLab's include merge: mappings merge key by key, anything else is replaced."""
    result = dict(base)
    for key, value in override.items():
        current = result.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            result[key] = _deep_merge(current, value)
        else:
            result[key] = value
    return result


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


def _inherited_keys(node: dict[str, Any]) -> tuple[str, ...]:
    """Default keys a job takes: all of them unless ``inherit:default`` is false or a list."""
    inherit = node.get("inherit")
    if not isinstance(inherit, dict):
        return _INHERITED_DEFAULTS
    value = inherit.get("default")
    if value is False:
        return ()
    if isinstance(value, list):
        return tuple(key for key in _INHERITED_DEFAULTS if key in value)
    return _INHERITED_DEFAULTS


def _job(
    name: str,
    node: dict[str, Any],
    line: int,
    default: dict[str, Any],
    global_variables: dict[str, str],
    project: dict[str, Any],
) -> Job:
    for key in _inherited_keys(node):
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
    image = image_reference(node.get("image"))
    if image is not None:
        facts.other_tools.append(
            Tool(image, "container", image_pinned(image), line, manager="container")
        )
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
