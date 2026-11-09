"""GitHub Actions job reach model: one :class:`Job` per workflow job."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ca9.ci import jobs as jobtools
from ca9.ci.conditions import NOTHING, condition_facts
from ca9.ci.images import image_pinned, image_reference
from ca9.ci.model import ActionRef, Indirect, Job, Origin, Publish, Tool, Workflow
from ca9.ci.shell import ScriptFacts, ShellContext, scan_script
from ca9.ci.yamlload import (
    LineList,
    LineMap,
    YamlError,
    as_strings,
    empty_map,
    load_file,
    script_start_line,
)

MAX_WORKFLOW_FILES = 300
MAX_COMPOSITE_DEPTH = 4
MAX_NODE_VISITS = 200_000

_SHA_RE = re.compile(r"[0-9a-fA-F]{40}")
_EXPR_RE = re.compile(r"\$\{\{(.*?)\}\}", re.S)
_MATRIX_PATH_RE = re.compile(r"^\$\{\{\s*matrix\.([A-Za-z0-9_.-]+)\s*\}\}$")
_HOSTED_LABEL_RE = re.compile(r"^(?:ubuntu|windows|macos)-[\w.-]+$", re.I)
_VERSION_INPUT_RE = re.compile(r"^(?:[\w-]+-)?version(?:-file)?$", re.I)
_FLOATING_VERSIONS = frozenset(
    {"", "latest", "*", "x", "stable", "current", "head", "nightly", "node"}
)
_GITHUB_OWNERS = frozenset({"actions", "github"})
_CONTAINER_BUILD_ACTIONS = frozenset({"docker/build-push-action", "docker/bake-action"})
_RUNTIME_SETUP = frozenset(
    {"setup-node", "setup-python", "setup-java", "setup-go", "setup-dotnet", "setup-ruby"}
)


class TooComplex(RuntimeError):
    """A workflow needed more traversal than the per-file budget allows."""


class _Visits:
    def __init__(self) -> None:
        self.count = 0

    def tick(self) -> None:
        self.count += 1
        if self.count > MAX_NODE_VISITS:
            raise TooComplex("node budget exhausted")


def workflow_files(repo_root: Path) -> list[Path]:
    directory = repo_root / ".github" / "workflows"
    if not directory.is_dir():
        return []
    files = [
        path
        for path in sorted(directory.iterdir())
        if path.suffix.lower() in {".yml", ".yaml"} and path.is_file()
    ]
    return files[:MAX_WORKFLOW_FILES]


def load_workflow(
    repo_root: Path,
    path: Path,
    project: dict[str, Any],
    remaining_jobs: int,
) -> tuple[Workflow, bool]:
    """Parse one workflow; returns the model and whether jobs were cut at the limit."""
    document = load_file(path, repo_root)
    if not isinstance(document, LineMap):
        raise YamlError("workflow is not a mapping")
    rel = _relative(path, repo_root)
    workflow = Workflow(file=rel, provider="github")
    _triggers(workflow, document)
    jobs = document.get("jobs")
    truncated = False
    if not isinstance(jobs, LineMap):
        return workflow, truncated
    workflow_env = document.get("env")
    visits = _Visits()
    for job_id, node in jobs.items():
        if not isinstance(node, LineMap):
            continue
        if len(workflow.jobs) >= remaining_jobs:
            truncated = True
            break
        workflow.jobs.append(
            _job(
                repo_root,
                job_id,
                node,
                jobs.key_line(job_id),
                document,
                workflow_env,
                project,
                visits,
            )
        )
    return workflow, truncated


def link_reusable(workflows: list[Workflow]) -> None:
    """Give local reusable workflows the triggers and secret inheritance of their callers."""
    by_file = {workflow.file: workflow for workflow in workflows if workflow.provider == "github"}
    for _ in range(MAX_COMPOSITE_DEPTH):
        changed = False
        for caller in by_file.values():
            for job in caller.jobs:
                callee = by_file.get(job.calls or "")
                if callee is None or callee is caller:
                    continue
                label = f"{caller.file}#{job.id}"
                if label not in callee.called_by:
                    callee.called_by.append(label)
                    changed = True
                effective = caller.caller_triggers or caller.triggers
                for trigger in [*caller.triggers, *caller.caller_triggers]:
                    if trigger != "workflow_call" and trigger not in callee.caller_triggers:
                        callee.caller_triggers.append(trigger)
                        changed = True
                if (caller.dispatch or "workflow_dispatch" in effective) and not callee.dispatch:
                    callee.dispatch = True
                    changed = True
                if caller.any_branch and not callee.any_branch:
                    callee.any_branch = True
                    changed = True
                if (
                    caller.branch_filters
                    and callee.branch_filters is None
                    and not callee.any_branch
                ):
                    callee.branch_filters = list(caller.branch_filters)
                    changed = True
                if job.inherit or job.all_via_tojson:
                    for callee_job in callee.jobs:
                        if not callee_job.inherit:
                            callee_job.inherit = True
                            changed = True
        if not changed:
            break


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def _triggers(workflow: Workflow, document: LineMap) -> None:
    on = document.get("on")
    workflow.on_line = document.key_lines.get("on", 1)
    if isinstance(on, str):
        workflow.triggers = [on]
        workflow.trigger_lines[on] = document.value_line("on")
    elif isinstance(on, LineList):
        for index, item in enumerate(on):
            if isinstance(item, str):
                workflow.triggers.append(item)
                workflow.trigger_lines.setdefault(item, on.item_line(index))
    elif isinstance(on, LineMap):
        for key in on:
            workflow.triggers.append(key)
            workflow.trigger_lines[key] = on.key_line(key)
    workflow.dispatch = "workflow_dispatch" in workflow.triggers
    if "push" not in workflow.triggers:
        return
    push = None
    if isinstance(on, LineMap):
        push = on.get("push")
    if not isinstance(push, LineMap):
        workflow.any_branch = True
        return
    branches = push.get("branches")
    if branches is not None:
        patterns = as_strings(branches)
        workflow.branch_filters = patterns
        workflow.any_branch = any(
            pattern in {"*", "**"} or pattern.startswith("**") for pattern in patterns
        )
    elif push.get("branches-ignore") is not None:
        workflow.any_branch = True
    elif push.get("tags") is not None or push.get("tags-ignore") is not None:
        workflow.branch_filters = []
    else:
        workflow.any_branch = True


def _strings(
    node: Any, visits: _Visits, key: str | None = None
) -> Iterator[tuple[str | None, str]]:
    stack: list[tuple[Any, str | None]] = [(node, key)]
    while stack:
        visits.tick()
        current, current_key = stack.pop()
        if isinstance(current, dict):
            stack.extend((value, child_key) for child_key, value in current.items())
        elif isinstance(current, list):
            stack.extend((value, current_key) for value in current)
        elif isinstance(current, str):
            yield current_key, current


def _expressions(node: Any, visits: _Visits) -> list[str]:
    texts: list[str] = []
    for key, text in _strings(node, visits):
        if key == "if":
            texts.append(text)
        texts.extend(match.group(1) for match in _EXPR_RE.finditer(text))
    return texts


def _literal_env(node: Any) -> dict[str, str]:
    if not isinstance(node, LineMap):
        return {}
    return {
        key: str(value)
        for key, value in node.items()
        if isinstance(value, (str, int, float, bool)) and "${{" not in str(value)
    }


def _env_credentials(job: Job, node: Any, visits: _Visits) -> None:
    if not isinstance(node, LineMap):
        return
    for key, value in node.items():
        if not isinstance(value, str):
            continue
        names, _ = jobtools.secret_names(_EXPR_RE.findall(value))
        registry = jobtools.env_registry(key)
        line = node.key_line(key)
        if registry and "${{" in value:
            for name in sorted(names) or [key]:
                jobtools.add_credential(job, name, registry, line)
            continue
        for name in names:
            secret_registry = jobtools.secret_registry(name)
            if secret_registry:
                jobtools.add_credential(job, name, secret_registry, line)


def _with_credentials(job: Job, with_map: Any, line: int) -> None:
    if not isinstance(with_map, LineMap):
        return
    for value in with_map.values():
        if not isinstance(value, str):
            continue
        names, _ = jobtools.secret_names(_EXPR_RE.findall(value))
        for name in names:
            registry = jobtools.secret_registry(name)
            if registry:
                jobtools.add_credential(job, name, registry, line)


def _permissions(job: Job, node: LineMap, document: LineMap) -> None:
    if "permissions" in node:
        value, job.permissions_source = node.get("permissions"), "job"
    elif "permissions" in document:
        value, job.permissions_source = document.get("permissions"), "workflow"
    else:
        job.permissions_source = "default"
        return
    if isinstance(value, str):
        if value.strip().lower() == "write-all":
            job.write = ["write-all"]
            job.id_token = True
        return
    if not isinstance(value, LineMap):
        return
    for scope, level in value.items():
        if str(level).strip().lower() != "write":
            continue
        if scope == "id-token":
            job.id_token = True
        else:
            job.write.append(scope)


def _matrix_values(matrix: Any, path: list[str]) -> list[str]:
    if not isinstance(matrix, LineMap) or not path:
        return []
    found: list[str] = []
    sources: list[Any] = [matrix.get(path[0])]
    include = matrix.get("include")
    if isinstance(include, list):
        sources.extend(item.get(path[0]) for item in include if isinstance(item, dict))
    for source in sources:
        found.extend(_descend(source, path[1:]))
    return found


def _descend(node: Any, path: list[str]) -> list[str]:
    if isinstance(node, list):
        values: list[str] = []
        for item in node:
            values.extend(_descend(item, path))
        return values
    if not path:
        return as_strings(node)
    if isinstance(node, dict):
        return _descend(node.get(path[0]), path[1:])
    return []


def _runner(job: Job, node: LineMap) -> None:
    value = node.get("runs-on")
    group = False
    labels = as_strings(value)
    if isinstance(value, LineMap):
        group = bool(value.get("group"))
        labels = as_strings(value.get("labels"))
    resolved: list[str] = []
    matrix = _matrix(node)
    for label in labels:
        match = _MATRIX_PATH_RE.match(label.strip())
        if match:
            resolved.extend(_matrix_values(matrix, match.group(1).split(".")))
        else:
            resolved.append(label)
    job.labels = list(dict.fromkeys(resolved))
    explicit = any(label.lower() == "self-hosted" for label in job.labels)
    unknown = [
        label
        for label in job.labels
        if "${{" not in label
        and not _HOSTED_LABEL_RE.match(label)
        and label.lower() != "self-hosted"
    ]
    job.self_hosted = explicit or group or bool(unknown)
    job.runner_inferred = not explicit and job.self_hosted


def _environment(job: Job, node: LineMap) -> None:
    value = node.get("environment")
    if isinstance(value, LineMap):
        value = value.get("name")
    if isinstance(value, (str, int)) and str(value).strip():
        job.environment = str(value).strip()
        job.environment_dynamic = "${{" in job.environment


def _matrix(node: LineMap) -> Any:
    strategy = node.get("strategy")
    if isinstance(strategy, LineMap):
        return strategy.get("matrix")
    return None


def _matrix_scripts(node: LineMap) -> list[tuple[str, int]]:
    found: list[tuple[str, int]] = []
    stack: list[Any] = [_matrix(node)]
    while stack:
        current = stack.pop()
        if isinstance(current, LineMap):
            for key, value in current.items():
                if isinstance(value, str) and (" " in value.strip() or "\n" in value):
                    found.append((value, script_start_line(current, key)))
                else:
                    stack.append(value)
        elif isinstance(current, LineList):
            for index, value in enumerate(current):
                if isinstance(value, str) and " " in value.strip():
                    found.append((value, current.item_line(index)))
                else:
                    stack.append(value)
    return found


class _JobBuilder:
    def __init__(
        self,
        repo_root: Path,
        job: Job,
        node: LineMap,
        document: LineMap,
        workflow_env: Any,
        project: dict[str, Any],
    ) -> None:
        self.repo_root = repo_root
        self.job = job
        self.node = node
        self.document = document
        self.project = project
        self.facts = ScriptFacts()
        self.contexts: dict[tuple[int, ...], str] = {}
        self.base_env = {**_literal_env(workflow_env), **_literal_env(node.get("env"))}
        self.step_facts: dict[tuple[int, ...], frozenset[tuple[str, ...]]] = {}

    def context(self, step_env: dict[str, str], inputs: dict[str, str]) -> ShellContext:
        return ShellContext(
            env={**self.base_env, **step_env},
            scripts=self.project.get("scripts", {}),
            local_packages=self.project.get("packages", frozenset()),
            yarn_berry=self.project.get("yarn_berry", False),
            inputs=inputs,
        )

    def steps(
        self,
        steps: Any,
        base: tuple[int, ...],
        visits: _Visits,
        *,
        origin_file: str | None = None,
        call_line: int | None = None,
        call_context: str = "",
        inputs: dict[str, str] | None = None,
        depth: int = 0,
        seen: frozenset[str] = frozenset(),
    ) -> None:
        if not isinstance(steps, LineList):
            return
        for index, step in enumerate(steps):
            if not isinstance(step, LineMap):
                continue
            visits.tick()
            order = (*base, index)
            real_line = steps.item_line(index)
            line = real_line
            if call_line is not None:
                line = call_line
            step_env = _literal_env(step.get("env"))
            _env_credentials(self.job, step.get("env"), visits)
            with_map = step.get("with")
            _with_credentials(self.job, with_map, line)
            uses = step.get("uses")
            step_inputs = inputs or {}
            if isinstance(uses, str):
                self.uses(
                    uses.strip(),
                    step,
                    order,
                    line,
                    real_line,
                    origin_file,
                    visits,
                    depth,
                    seen,
                    step_inputs,
                    step_env,
                )
            run = step.get("run")
            if isinstance(run, str):
                text = run
                start = script_start_line(step, "run")
                context = self.context(step_env, step_inputs)
                workdir = step.get("working-directory")
                workdir_text = ""
                if workdir:
                    workdir_text = _resolve_inputs(str(workdir), step_inputs)
                self.contexts[order] = " ".join(
                    part
                    for part in (call_context, workdir_text, _resolve_inputs(text, step_inputs))
                    if part
                )
                self.scan(text, start, context, order, origin_file, line)
                if "matrix." in text:
                    for script, script_line in _matrix_scripts(self.node):
                        self.scan(script, script_line, context, order, origin_file, line)
            if not base:
                self.step_facts[order] = condition_facts(step.get("if"))

    def scan(
        self,
        text: str,
        start: int,
        context: ShellContext,
        order: tuple[int, ...],
        origin_file: str | None,
        line: int,
    ) -> None:
        facts = scan_script(text, start, context, order)
        if origin_file is not None:
            _relocate(facts, origin_file, line)
        self.facts.extend(facts)

    def uses(
        self,
        uses: str,
        step: LineMap,
        order: tuple[int, ...],
        line: int,
        real_line: int,
        origin_file: str | None,
        visits: _Visits,
        depth: int,
        seen: frozenset[str],
        inputs: dict[str, str],
        step_env: dict[str, str],
    ) -> None:
        origin = None
        if origin_file:
            origin = Origin(origin_file, real_line)
        with_map = step.get("with")
        if not isinstance(with_map, LineMap):
            with_map = empty_map()
        if uses.startswith("./"):
            self.local_action(uses, with_map, order, line, visits, depth, seen, inputs)
            return
        if uses.startswith("docker://"):
            image = image_reference(uses.removeprefix("docker://"))
            if image is not None:
                self.job.other_tools.append(
                    Tool(
                        image,
                        "docker_action",
                        image_pinned(image),
                        line,
                        manager="docker_action",
                        origin=origin,
                    )
                )
            return
        name, _, ref = uses.partition("@")
        parts = name.split("/")
        owner = parts[0].lower()
        repo = ""
        if len(parts) > 1:
            repo = parts[1].lower()
        third_party = owner not in _GITHUB_OWNERS
        pinned = bool(_SHA_RE.fullmatch(ref))
        self.job.actions.append(
            ActionRef(name, ref, pinned, line, third_party, kind="action", origin=origin)
        )
        lowered = name.lower()
        if (
            lowered.startswith("actions/cache")
            or _truthy(with_map.get("cache"))
            or _truthy(with_map.get("enable-cache"))
        ):
            self.job.uses_cache = True
        if lowered == "actions/setup-go" and str(with_map.get("cache", "true")).lower() != "false":
            self.job.uses_cache = True
        self.setup_tool(owner, repo, with_map, line, origin)
        if lowered in _CONTAINER_BUILD_ACTIONS:
            self.facts.indirect.append(Indirect("docker", line, origin=origin, order=order))
        if lowered == "pypa/gh-action-pypi-publish":
            password = with_map.get("password")
            method = "unknown"
            if isinstance(password, str) and password.strip():
                method = "token"
            self.facts.publishes.append(
                Publish(
                    "pypi",
                    line,
                    method=method,
                    command=name,
                    via="action",
                    origin=origin,
                    order=(*order, 0),
                )
            )
        elif lowered == "js-devtools/npm-publish":
            token = with_map.get("token")
            method = "unknown"
            if isinstance(token, str) and "secrets." in token:
                method = "token"
            self.facts.publishes.append(
                Publish(
                    "npm",
                    line,
                    method=method,
                    command=name,
                    via="action",
                    origin=origin,
                    order=(*order, 0),
                )
            )
        context = self.context(step_env, inputs)
        keys = ["run"]
        if lowered == "changesets/action":
            keys.append("publish")
        for key in keys:
            value = with_map.get(key)
            if isinstance(value, str):
                self.contexts[order] = value
                self.scan(
                    value, script_start_line(with_map, key), context, order, origin_file, line
                )

    def setup_tool(
        self,
        owner: str,
        repo: str,
        with_map: LineMap,
        line: int,
        origin: Origin | None,
    ) -> None:
        if not (repo.startswith("setup-") or repo.endswith("-setup") or repo == "action-setup"):
            return
        tool_name = repo.removeprefix("setup-").removesuffix("-setup")
        if repo == "action-setup":
            tool_name = owner
        versions = [
            str(value).strip()
            for key, value in with_map.items()
            if _VERSION_INPUT_RE.match(key) and value is not None
        ]
        github_owned = owner in _GITHUB_OWNERS
        if not versions:
            if github_owned and repo in _RUNTIME_SETUP:
                return
            if repo == "action-setup" and owner == "pnpm" and self.project.get("pnpm_pinned"):
                versions = ["packageManager"]
            if repo == "setup-uv" and owner == "astral-sh" and self.project.get("uv_pinned"):
                versions = ["required-version"]
        pinned = any(value.lower() not in _FLOATING_VERSIONS for value in versions)
        self.job.tools.append(Tool(tool_name, "setup_action", pinned, line, origin=origin))

    def local_action(
        self,
        uses: str,
        with_map: LineMap,
        order: tuple[int, ...],
        line: int,
        visits: _Visits,
        depth: int,
        seen: frozenset[str],
        inputs: dict[str, str],
    ) -> None:
        loaded = _composite(self.repo_root, uses)
        if loaded is None:
            return
        document, rel = loaded
        self.job.local_actions.append(rel)
        if depth >= MAX_COMPOSITE_DEPTH or rel in seen:
            return
        runs = document.get("runs")
        if not isinstance(runs, LineMap) or str(runs.get("using", "")).lower() != "composite":
            return
        action_inputs: dict[str, str] = {}
        declared = document.get("inputs")
        if isinstance(declared, LineMap):
            for key, spec in declared.items():
                if isinstance(spec, LineMap) and isinstance(spec.get("default"), str):
                    action_inputs[key] = spec["default"]
        for key, value in with_map.items():
            if isinstance(value, (str, int, float)):
                text = _resolve_inputs(str(value), inputs)
                if "${{" not in text:
                    action_inputs[key] = text
        call_context = " ".join(
            _resolve_inputs(str(value), inputs)
            for value in with_map.values()
            if isinstance(value, str)
        )
        self.steps(
            runs.get("steps"),
            order,
            visits,
            origin_file=rel,
            call_line=line,
            call_context=call_context,
            inputs=action_inputs,
            depth=depth + 1,
            seen=seen | {rel},
        )


def _truthy(value: Any) -> bool:
    if value is None:
        return False
    text = str(value).strip().lower()
    return bool(text) and text not in {"false", "0", "no", "off", "''", '""'}


def _resolve_inputs(text: str, inputs: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        inner = match.group(1).strip()
        found = re.fullmatch(r"inputs\.([A-Za-z0-9_-]+)", inner)
        if found and found.group(1) in inputs:
            return inputs[found.group(1)]
        return match.group(0)

    return _EXPR_RE.sub(replace, text)


def _composite(repo_root: Path, uses: str) -> tuple[LineMap, str] | None:
    relative = uses[2:].split("@", 1)[0].strip().rstrip("/")
    try:
        root = repo_root.resolve()
        target = (repo_root / relative).resolve()
        target.relative_to(root)
    except (OSError, ValueError):
        return None
    candidates = [target / "action.yml", target / "action.yaml"]
    if target.is_file():
        candidates = [target]
    for candidate in candidates:
        if not candidate.is_file() or candidate.name.lower() not in {"action.yml", "action.yaml"}:
            continue
        try:
            document = load_file(candidate, repo_root)
        except (OSError, YamlError):
            return None
        if isinstance(document, LineMap):
            return document, candidate.relative_to(root).as_posix()
    return None


def _relocate(facts: ScriptFacts, origin_file: str, line: int) -> None:
    for group in (
        facts.installs,
        facts.tools,
        facts.other_tools,
        facts.downloads,
        facts.publishes,
        facts.indirect,
    ):
        for item in group:
            if item.origin is None:
                item.origin = Origin(origin_file, item.line)
            item.line = line


def _job(
    repo_root: Path,
    job_id: str,
    node: LineMap,
    line: int,
    document: LineMap,
    workflow_env: Any,
    project: dict[str, Any],
    visits: _Visits,
) -> Job:
    job = Job(id=str(job_id), line=line)
    _runner(job, node)
    _environment(job, node)
    _permissions(job, node, document)
    names, whole = jobtools.secret_names(_expressions(node, visits))
    workflow_names, workflow_whole = jobtools.secret_names(_expressions(workflow_env, visits))
    job.secret_names = names | workflow_names
    job.all_via_tojson = whole or workflow_whole
    secrets_value = node.get("secrets")
    job.inherit = isinstance(secrets_value, str) and secrets_value.strip().lower() == "inherit"
    _env_credentials(job, workflow_env, visits)
    _env_credentials(job, node.get("env"), visits)
    if isinstance(secrets_value, LineMap):
        for key, value in secrets_value.items():
            if isinstance(value, str):
                for name in jobtools.secret_names(_EXPR_RE.findall(value))[0]:
                    registry = jobtools.secret_registry(name) or jobtools.env_registry(key)
                    if registry:
                        jobtools.add_credential(job, name, registry, secrets_value.key_line(key))
    calls = node.get("uses")
    if isinstance(calls, str):
        target = calls.strip()
        if target.startswith("./"):
            job.calls = target[2:].split("@", 1)[0]
        else:
            name, _, ref = target.partition("@")
            owner = name.split("/", 1)[0].lower()
            job.remote_reusable = True
            job.actions.append(
                ActionRef(
                    name,
                    ref,
                    bool(_SHA_RE.fullmatch(ref)),
                    node.key_line("uses"),
                    owner not in _GITHUB_OWNERS,
                    kind="workflow",
                )
            )
    image = image_reference(node.get("container"))
    if image is not None:
        job.other_tools.append(
            Tool(
                image,
                "container",
                image_pinned(image),
                node.key_line("container"),
                manager="container",
            )
        )
    builder = _JobBuilder(repo_root, job, node, document, workflow_env, project)
    builder.steps(node.get("steps"), (), visits)
    jobtools.finalize(job, builder.facts, builder.contexts)
    job_facts = condition_facts(node.get("if"))
    for publish in job.publishes:
        facts = job_facts
        if publish.via not in {"credential", "manual_oidc"}:
            facts = job_facts | builder.step_facts.get(publish.order[:1], NOTHING)
        job.publish_guards.append(facts)
    return job
