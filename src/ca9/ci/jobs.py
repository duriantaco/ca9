"""Shared job assembly: credentials, publish methods and download data flow."""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable

from ca9.ci.model import Job, Publish, Tool
from ca9.ci.shell import PLACEHOLDER, ScriptFacts, in_bin_dir, is_archive

LAST = (10**9,)

_ENV_REGISTRIES = (
    (
        re.compile(
            r"^(?:NODE_AUTH_TOKEN|NPM_TOKEN|NPM_AUTH_TOKEN|NPM_CONFIG__AUTH|NPM_CONFIG_TOKEN|"
            r"NPM_CONFIG__AUTHTOKEN|YARN_NPM_AUTH_TOKEN)$",
            re.I,
        ),
        "npm",
    ),
    (
        re.compile(
            r"^(?:TWINE_PASSWORD|TWINE_API_KEY|UV_PUBLISH_TOKEN|UV_PUBLISH_PASSWORD|"
            r"POETRY_PYPI_TOKEN_\w+|POETRY_HTTP_BASIC_\w+_PASSWORD|FLIT_PASSWORD|HATCH_INDEX_AUTH|"
            r"PDM_PUBLISH_PASSWORD|MATURIN_PYPI_TOKEN|MATURIN_PASSWORD|PYPI_TOKEN|PYPI_API_TOKEN|"
            r"PYPI_PASSWORD)$",
            re.I,
        ),
        "pypi",
    ),
    (
        re.compile(
            r"^(?:CARGO_REGISTRY_TOKEN|GEM_HOST_API_KEY|NUGET_API_KEY|NUGET_AUTH_TOKEN)$", re.I
        ),
        "other",
    ),
)
_SECRET_REGISTRIES = (
    (re.compile(r"NPM|NODE_AUTH", re.I), "npm"),
    (re.compile(r"PYPI|TWINE", re.I), "pypi"),
    (re.compile(r"CARGO_REGISTRY|CRATES_IO|RUBYGEMS|GEM_HOST|NUGET", re.I), "other"),
)
_WORKSPACE_PREFIXES = (
    "$GITHUB_WORKSPACE",
    "${GITHUB_WORKSPACE}",
    "$CI_PROJECT_DIR",
    "${CI_PROJECT_DIR}",
)
_OUTSIDE_PREFIXES = (
    "/",
    "~",
    "$HOME",
    "${HOME}",
    "$RUNNER_TEMP",
    "${RUNNER_TEMP}",
    "$RUNNER_TOOL_CACHE",
    "$TMPDIR",
    "${TMPDIR}",
    "$GITHUB_ACTION_PATH",
    "%",
)


def env_registry(name: str) -> str | None:
    for pattern, registry in _ENV_REGISTRIES:
        if pattern.match(name):
            return registry
    return None


def secret_registry(name: str) -> str | None:
    for pattern, registry in _SECRET_REGISTRIES:
        if pattern.search(name):
            return registry
    return None


def add_credential(job: Job, name: str, registry: str, line: int) -> None:
    job.publish_credentials.setdefault(name, registry)
    job.credential_lines.setdefault(name, line)


def finalize(job: Job, facts: ScriptFacts, contexts: dict[tuple[int, ...], str]) -> None:
    """Link downloads to what consumed them and decide each publish's method."""
    for credential in facts.credentials:
        add_credential(job, credential.name, credential.registry, credential.line)
    job.installs.extend(facts.installs)
    job.indirect.extend(facts.indirect)
    job.tools.extend(facts.tools)
    job.other_tools.extend(facts.other_tools)
    for publish in facts.publishes:
        if not publish.context:
            publish.context = contexts.get(publish.order[:-1], "")
        job.publishes.append(publish)
    credential_registries = set(job.publish_credentials.values())
    for publish in job.publishes:
        if publish.method != "unknown":
            continue
        if publish.registry in credential_registries:
            publish.method = "token"
        elif job.id_token:
            publish.method = "oidc"
    published = {publish.registry for publish in job.publishes}
    if facts.oidc_requests and job.id_token:
        for registry in sorted(facts.registry_hosts - published):
            job.publishes.append(
                Publish(
                    registry=registry,
                    line=facts.oidc_requests[0],
                    method="oidc",
                    command="OIDC token request",
                    via="manual_oidc",
                    order=LAST,
                )
            )
            published.add(registry)
    for name, registry in sorted(job.publish_credentials.items()):
        if registry in published:
            continue
        job.publishes.append(
            Publish(
                registry=registry,
                line=job.credential_lines.get(name, job.line),
                method="token",
                command="",
                via="credential",
                order=LAST,
            )
        )
        published.add(registry)
    _link_downloads(job, facts)


def _base(path: str | None) -> str | None:
    if not path:
        return None
    return posixpath.basename(path.rstrip("/")) or None


def _normal(path: str) -> str:
    text = path.strip().rstrip("/")
    for prefix in _WORKSPACE_PREFIXES:
        if text.startswith(prefix):
            text = text[len(prefix) :].lstrip("/")
    while text.startswith("./"):
        text = text[2:]
    return text or "."


def in_workspace(path: str | None) -> bool:
    if not path:
        return True
    text = path.strip()
    if text.startswith(_WORKSPACE_PREFIXES):
        return True
    if text.startswith(PLACEHOLDER):
        return False
    return not text.startswith(_OUTSIDE_PREFIXES) and not re.match(r"^[A-Za-z]:[\\/]", text)


def _link_downloads(job: Job, facts: ScriptFacts) -> None:
    publishes = job.publishes
    for download in facts.downloads:
        base = _base(download.target)
        extract_order = None
        if download.lands_in is not None:
            download.archive = True
            extract_order = download.order
        for extract in facts.extracts:
            if base and extract.order > download.order and _base(extract.file) == base:
                download.archive = True
                download.lands_in = extract.directory
                extract_order = extract.order
                break
        if not download.archive and is_archive(download.target):
            download.archive = True
        for move in facts.moves:
            if base and move.order > download.order and _base(move.source) == base:
                download.lands_in = move.destination
                break
        if in_bin_dir(download.lands_in) or in_bin_dir(download.target):
            download.executed = True
        for execution in facts.executions:
            if base and execution.order > download.order and _base(execution.file) == base:
                download.executed = True
        download.verified = any(
            verification.order > download.order
            and (
                (base is not None and base in verification.text)
                or verification.order[:-1] == download.order[:-1]
            )
            for verification in facts.verifications
        )
        location = download.lands_in or download.target
        tool_only = download.executed and not (
            download.lands_in
            and in_workspace(download.lands_in)
            and not in_bin_dir(download.lands_in)
        )
        later = [publish for publish in publishes if publish.order > download.order]
        download.reaches_publish = bool(later) and in_workspace(location) and not tool_only
        if download.lands_in and extract_order is not None:
            landing = _normal(download.lands_in)
            download.replaces = landing != "." and any(
                removal.order < extract_order
                and landing in {_normal(path) for path in removal.paths}
                for removal in facts.removals
            )
            download.used_by_publish = landing != "." and any(
                landing in publish.context for publish in later
            )
        if download.executed:
            job.tools.append(
                Tool(
                    name=base or download.host,
                    route="download",
                    pinned=download.verified,
                    line=download.line,
                    origin=download.origin,
                    order=download.order,
                )
            )
        job.downloads.append(download)


def secret_names(texts: Iterable[str]) -> tuple[set[str], bool]:
    """Secret names referenced in expression text, and whether the whole object is used."""
    names: set[str] = set()
    whole = False
    for text in texts:
        for match in _SECRET_DOT_RE.finditer(text):
            names.add(match.group(1))
        for match in _SECRET_INDEX_RE.finditer(text):
            names.add(match.group(1))
        if _SECRET_WHOLE_RE.search(text):
            whole = True
    names.discard("GITHUB_TOKEN")
    names.discard("github_token")
    return names, whole


_SECRET_DOT_RE = re.compile(r"(?<![\w.])secrets\s*\.\s*([A-Za-z_][A-Za-z0-9_-]*)", re.I)
_SECRET_INDEX_RE = re.compile(r"(?<![\w.])secrets\s*\[\s*['\"]([^'\"]+)['\"]\s*\]", re.I)
_SECRET_WHOLE_RE = re.compile(r"(?<![\w.])secrets(?!\s*[.\[\w-])", re.I)
