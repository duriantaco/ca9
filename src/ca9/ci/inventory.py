"""Build ``ca9.ci_inventory.v1``: what each CI job can install, run, reach and publish."""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePath
from typing import Any

from ca9.ci import github, gitlab
from ca9.ci.model import SCHEMA, Workflow
from ca9.ci.yamlload import YamlError, YamlUnavailable, yaml_available

DEFAULT_MAX_JOBS = 500
MAX_PACKAGE_JSON_BYTES = 2_000_000
_DEPENDENCY_KEYS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def build_inventory(
    repo_root: str | PurePath,
    *,
    max_jobs: int = DEFAULT_MAX_JOBS,
) -> tuple[dict[str, Any], list[Workflow]]:
    """Return the serialized inventory and the internal workflow models."""
    if not yaml_available():
        return _empty("yaml_unavailable"), []
    limit = max_jobs
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
        limit = DEFAULT_MAX_JOBS
    root = Path(repo_root)
    skipped: list[dict[str, str]] = []
    if not root.is_dir():
        result = _empty("partial")
        result["skipped"] = [{"file": ".", "reason": "not_a_directory"}]
        return result, []
    project = _project(root)
    workflows: list[Workflow] = []
    truncated = False
    remaining = limit
    files = github.workflow_files(root)
    directory = root / ".github" / "workflows"
    if directory.is_dir() and len(files) >= github.MAX_WORKFLOW_FILES:
        truncated = True
    for path in files:
        rel = path.relative_to(root).as_posix()
        if remaining <= 0:
            truncated = True
            break
        try:
            workflow, cut = github.load_workflow(root, path, project, remaining)
        except YamlUnavailable:
            return _empty("yaml_unavailable"), []
        except (OSError, UnicodeError) as exc:
            skipped.append({"file": rel, "reason": f"unreadable:{type(exc).__name__}"})
            continue
        except YamlError:
            skipped.append({"file": rel, "reason": "invalid_yaml"})
            continue
        except github.TooComplex:
            skipped.append({"file": rel, "reason": "too_complex"})
            continue
        except RecursionError:
            skipped.append({"file": rel, "reason": "too_deep"})
            continue
        workflows.append(workflow)
        remaining -= len(workflow.jobs)
        truncated = truncated or cut
    github.link_reusable(workflows)
    if remaining > 0:
        try:
            pipeline, cut, gitlab_skipped = gitlab.load_gitlab(root, project, remaining)
        except YamlUnavailable:
            return _empty("yaml_unavailable"), []
        except (OSError, UnicodeError, YamlError, RecursionError):
            pipeline, cut, gitlab_skipped = (
                None,
                False,
                [{"file": ".gitlab-ci.yml", "reason": "invalid_yaml"}],
            )
        if pipeline is not None:
            workflows.append(pipeline)
        truncated = truncated or cut
        skipped.extend(gitlab_skipped)
    elif (root / ".gitlab-ci.yml").is_file():
        truncated = True
    serialized = [workflow.to_dict() for workflow in workflows]
    truncated = truncated or any(job.truncated for workflow in workflows for job in workflow.jobs)
    status = "complete"
    if skipped:
        status = "partial"
    result: dict[str, Any] = {
        "schema": SCHEMA,
        "status": status,
        "truncated": truncated,
        "workflows": serialized,
    }
    if skipped:
        result["skipped"] = skipped
    return result, workflows


def _empty(status: str) -> dict[str, Any]:
    return {"schema": SCHEMA, "status": status, "truncated": False, "workflows": []}


def _project(root: Path) -> dict[str, Any]:
    """Root package.json facts: scripts, declared packages, package manager."""
    project: dict[str, Any] = {"scripts": {}, "packages": frozenset(), "yarn_berry": False}
    path = root / "package.json"
    data: Any = None
    try:
        if path.is_file() and path.stat().st_size <= MAX_PACKAGE_JSON_BYTES:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        data = None
    if isinstance(data, dict):
        scripts = data.get("scripts")
        if isinstance(scripts, dict):
            project["scripts"] = {
                str(key): value for key, value in scripts.items() if isinstance(value, str)
            }
        packages: set[str] = set()
        for key in _DEPENDENCY_KEYS:
            section = data.get(key)
            if isinstance(section, dict):
                packages.update(str(name) for name in section)
        project["packages"] = frozenset(packages)
        manager = data.get("packageManager")
        if isinstance(manager, str):
            match = re.match(r"^(yarn|pnpm)@(\d+)", manager)
            if match and match.group(1) == "yarn":
                project["yarn_berry"] = int(match.group(2)) >= 2
            if match and match.group(1) == "pnpm":
                project["pnpm_pinned"] = True
    if (root / ".yarnrc.yml").is_file():
        project["yarn_berry"] = True
    project["uv_pinned"] = _uv_pinned(root)
    return project


def _uv_pinned(root: Path) -> bool:
    """True when pyproject.toml or uv.toml pins uv's required-version exactly."""
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            return False
    for name, path in (("pyproject.toml", ("tool", "uv")), ("uv.toml", ())):
        candidate = root / name
        try:
            if not candidate.is_file() or candidate.stat().st_size > MAX_PACKAGE_JSON_BYTES:
                continue
            data: Any = tomllib.loads(candidate.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        for key in path:
            if not isinstance(data, dict):
                break
            data = data.get(key)
        if not isinstance(data, dict):
            continue
        value = data.get("required-version")
        if isinstance(value, str) and re.fullmatch(r"\s*(?:==\s*)?\d+(?:\.\d+){1,2}\s*", value):
            return True
    return False
