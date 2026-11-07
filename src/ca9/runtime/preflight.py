from __future__ import annotations

import json
import os
import re
import shlex
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlparse

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name

from ca9.package_feed import (
    FeedError,
    FeedSnapshot,
    FeedStatus,
    default_cache_root,
    feed_status,
    lookup_malware,
    lookup_release_time,
    release_window_covers,
)
from ca9.package_policy import (
    IgnoredPolicySetting,
    PackagePolicy,
    _load_policy_root,
    action_for_mode,
    find_policy_exception,
    load_effective_package_policy,
    tighten_package_policy,
)
from ca9.readers.package_lock import read_package_lock
from ca9.release_age import DEFAULT_NPM_REGISTRY, check_release_age

RUN_SCHEMA = "ca9.run.v1"
LEDGER_SCHEMA = "ca9.run.ledger.v1"
# Matched case-insensitively (fnmatch) against upper-cased variable names.
SECRET_ENV_PATTERNS = (
    "*_TOKEN",
    "*_SECRET",
    "*_KEY",
    "*_APIKEY",
    "*_PASSWORD",
    "*_PASSWD",
    "*_PASS",
    "*_PAT",
    "*_AUTH",
    "*_CREDENTIAL",
    "*_CREDENTIALS",
    "*_DSN",
    "*_JWT",
    "*_ACCESSTOKEN",
    "*_AUTHTOKEN",
    "*:_AUTH*",
    "*:_PASSWORD",
    "AWS_*",
    "GCP_*",
    "GOOGLE_*",
    "AZURE_*",
    "TWINE_*",
    "NPM_TOKEN",
    "PYPI_TOKEN",
    "GITHUB_TOKEN",
    "NODE_AUTH_TOKEN",
    "NPM_CONFIG__AUTH*",
    "NPM_CONFIG_//*",
    "PGPASSWORD",
    "MYSQL_PWD",
    "SYSTEM_ACCESSTOKEN",
    "CI_JOB_TOKEN",
    "CI_JOB_JWT*",
    "ACTIONS_ID_TOKEN_REQUEST_*",
    "ACTIONS_RUNTIME_TOKEN",
    "DOCKER_AUTH_CONFIG",
    "SSH_AUTH_SOCK",
)
# JWTs such as CI OIDC ID tokens: base64url header.payload.signature
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
_KNOWN_TOKEN_RE = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|npm_[A-Za-z0-9]{30,}"
    r"|glpat-[A-Za-z0-9_-]{20,}|pypi-[A-Za-z0-9_-]{40,}|xox[abposr]-[A-Za-z0-9-]{10,}"
    r"|AKIA[0-9A-Z]{16})\b"
)
# Values that are secrets whatever the variable is called. Detection reports names only.
_SECRET_VALUE_RES = (
    # URL userinfo carrying a password, e.g. postgres://user:pass@db/app
    re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s/@:]*:[^\s/@]+@"),
    _JWT_RE,
    _KNOWN_TOKEN_RE,
)
# GitHub Actions file commands: an install script writing to these persists into later steps.
GITHUB_FILE_COMMAND_ENV_NAMES = (
    "GITHUB_ENV",
    "GITHUB_PATH",
    "GITHUB_OUTPUT",
    "GITHUB_STATE",
    "GITHUB_STEP_SUMMARY",
)
_URL_CREDENTIALS_RE = re.compile(r"(?P<prefix>\b[A-Za-z][A-Za-z0-9+.-]*://)(?P<creds>[^/@\s]+)@")
_URL_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>]+")
_URL_SECRET_QUERY_RE = re.compile(
    r"(?i)(?P<key>[?&;][\w.-]*(?:token|auth|pass|secret|key|sig|credential)[\w.-]*=)"
    r"(?P<value>[^&#\s\"']+)"
)
_NPM_AUTH_SETTING_RE = re.compile(
    r"(?i)(?P<key>(?:^|(?<=[\s/:\"'_-]))_(?:authtoken|auth|password)\s*=\s*)"
    r"(?P<value>[^\s\"']+)"
)
_SECRET_OPTION_RE = re.compile(
    r"(?i)(?P<key>(?:^|(?<=\s))--?[\w.-]*(?:token|password|passwd|secret|otp|api[-_]?key)"
    r"[\w.-]*=)(?P<value>\S+)"
)
_SECRET_OPTION_NAME_RE = re.compile(
    r"(?i)^--?[\w.-]*(?:token|password|passwd|secret|otp|api[-_]?key|_auth)[\w.-]*$"
)
_AUTHORIZATION_RE = re.compile(
    r"(?i)\b(?P<name>authorization|proxy-authorization)"
    r"(?P<sep>\s*[:=]\s*)"
    r"(?P<scheme>bearer|basic|token)?"
    r"(?P<space>\s*)"
    r"(?P<value>[^,\s;]+)"
)
_NPM_SCOPED_REGISTRY_KEY_RE = re.compile(
    r"^@[^\s:=]+:registry$",
    re.IGNORECASE,
)
SUPPORTED_PIP_FLAGS_WITH_VALUE = {
    "--index-url",
    "-i",
    "--trusted-host",
}
UNSUPPORTED_PIP_SOURCE_FLAGS = {
    "--extra-index-url",
    "--find-links",
    "-f",
}
SUPPORTED_PIP_BOOL_FLAGS = {
    "--no-deps",
    "--upgrade",
    "-U",
    "--pre",
    "--require-hashes",
    "--no-cache-dir",
    "--disable-pip-version-check",
}
# pip general options are accepted before or after the subcommand on the command
# line, but not inside requirement files.
PIP_GENERAL_BOOL_FLAGS = {
    "-q",
    "-qq",
    "-qqq",
    "--quiet",
    "-v",
    "-vv",
    "-vvv",
    "--verbose",
    "--isolated",
    "--disable-pip-version-check",
    "--no-input",
    "--no-color",
    "--no-cache-dir",
    "--require-virtualenv",
}
PIP_GENERAL_FLAGS_WITH_VALUE = {"--cache-dir"}
PIP_UNSUPPORTED_GENERAL_FLAGS = {"--python"}
PIP_REQUIREMENT_FLAGS = {"-r", "--requirement"}
PIP_CONSTRAINT_FLAGS = {"-c", "--constraint"}
MAX_PIP_REQUIREMENT_DEPTH = 16
_PIP_HASH_RE = re.compile(
    r"(?:^|\s)--hash(?:=|\s+)"
    r"(?P<hash>(?:sha256:[0-9a-fA-F]{64}|sha384:[0-9a-fA-F]{96}|sha512:[0-9a-fA-F]{128}))"
    r"(?=\s|$)"
)
# pip's req_file.COMMENT_RE; comment lines are never joined with a following line.
_PIP_COMMENT_RE = re.compile(r"(^|\s+)#.*$")
# pip's ARCHIVE_EXTENSIONS: requirement strings ending in one of these are local files.
_PIP_ARCHIVE_SUFFIXES = (
    ".zip",
    ".whl",
    ".tar.bz2",
    ".tbz",
    ".tar.xz",
    ".txz",
    ".tlz",
    ".tar.lz",
    ".tar.lzma",
    ".tar.gz",
    ".tgz",
    ".tar",
)
_PIP_DIRECT_SCHEME_PREFIXES = ("file:", "git+", "hg+", "svn+", "bzr+")
_PIP_PROGRAM_RE = re.compile(r"^pip(?:3(?:\.\d+)?)?$")
_PYTHON_PROGRAM_RE = re.compile(r"^python(?:3(?:\.\d+)?)?$")
# CPython interpreter flags accepted before `-m pip`; X and W take a value.
_PYTHON_FLAG_CHARS = frozenset("IEsSuBbOq")
_PYTHON_FLAGS_WITH_VALUE = frozenset("XW")
SUPPORTED_NPM_FLAGS_WITH_VALUE = {
    "--registry",
    "--tag",
    "--cache",
    "--prefix",
    "--omit",
    "--include",
    "--install-strategy",
    "--workspace",
    "-w",
    "--loglevel",
}
# npm shorthands that expand to `--loglevel <level>`. They never consume a value,
# so a following `true`/`false` stays a package spec.
NPM_LOGLEVEL_SHORTHANDS = frozenset(
    {"-s", "--silent", "-q", "--quiet", "-d", "-dd", "-ddd", "--verbose"}
)
NPM_PREFIX_FLAGS = frozenset({"--prefix", "-C"})
NPM_CONFIG_FILE_FLAGS = frozenset({"--userconfig", "--globalconfig"})
NPM_BOOL_FLAG_ALIASES = {
    "-g": "--global",
    "-D": "--save-dev",
    "-O": "--save-optional",
    "-E": "--save-exact",
}
SUPPORTED_NPM_BOOL_FLAGS = {
    "--save",
    "--save-dev",
    "-D",
    "--save-optional",
    "-O",
    "--save-exact",
    "-E",
    "--ignore-scripts",
    "--global",
    "-g",
    "--legacy-bundling",
    "--global-style",
    "--strict-peer-deps",
    "--foreground-scripts",
    "--audit",
    "--no-audit",
    "--bin-links",
    "--no-bin-links",
    "--fund",
    "--no-fund",
    "--dry-run",
    "--workspaces",
    "--include-workspace-root",
    "--install-links",
    "--legacy-peer-deps",
}
NPM_INSTALL_SUBCOMMANDS = frozenset(
    {
        "install",
        "i",
        "add",
        "in",
        "ins",
        "inst",
        "insta",
        "instal",
        "isnt",
        "isnta",
        "isntal",
        "isntall",
    }
)
NPM_CLEAN_INSTALL_SUBCOMMANDS = frozenset(
    {"ci", "clean-install", "ic", "install-clean", "isntall-clean"}
)
# npm commands that can fetch, install, or execute packages through resolution
# paths ca9 run cannot preflight. They fail closed instead of running unchecked.
NPM_UNSUPPORTED_INSTALL_SUBCOMMANDS = frozenset(
    {
        "update",
        "up",
        "upgrade",
        "udpate",
        "exec",
        "x",
        "init",
        "create",
        "innit",
        "rebuild",
        "rb",
        "dedupe",
        "ddp",
        "install-test",
        "it",
        "install-ci-test",
        "cit",
        "clean-install-test",
        "sit",
    }
)
UNSUPPORTED_COMMAND_FAMILY_MESSAGE = (
    "unsupported command family; ca9 run supports npm install, npm i, npm ci, "
    "python -m pip install, and pip install"
)
# npm-package-arg classification patterns (see npa() and resolve()).
_NPM_URL_SPEC_RE = re.compile(r"^(?:git\+)?[a-z]+:", re.IGNORECASE)
_NPM_GIT_SCP_SPEC_RE = re.compile(r"^[^@]+@[^:.]+\.[^:]+:.+$", re.IGNORECASE)
_NPM_FILENAME_SPEC_RE = re.compile(r"\.(?:tgz|tar\.gz|tar)$", re.IGNORECASE)
_NPM_NAME_PART_RE = re.compile(r"^[A-Za-z0-9\-_.!~*'()]+$")
# Registry versions, ranges, and tags use only these characters. Anything else
# (`:`, `/`, `#`, `@`, ...) makes npm resolve a URL, git, or local source.
_NPM_REGISTRY_SPEC_RE = re.compile(r"^[A-Za-z0-9\-_.!~*'()<>=^|+ ]*$")
_NPM_SEMVER_RE = re.compile(
    r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$",
)
MALWARE_FEED_UNAVAILABLE_POLICY_ID = "ca9.malware_feed_unavailable"
RUNTIME_RELEASE_AGE_HOURS = 24
RELEASE_LOOKUP_WORKERS = 8
NPM_REGISTRY_ENV_NAMES = ("NPM_CONFIG_REGISTRY", "npm_config_registry")
NPM_GATEWAY_UPSTREAM_ENV_NAMES = ("CA9_NPM_UPSTREAM_REGISTRY",)
NPM_CONFIG_FILE_ENV_NAMES = (
    "NPM_CONFIG_USERCONFIG",
    "npm_config_userconfig",
    "NPM_CONFIG_GLOBALCONFIG",
    "npm_config_globalconfig",
)
PIP_INDEX_ENV_NAMES = ("PIP_INDEX_URL", "PIP_PYPI_URL")
PIP_GATEWAY_UPSTREAM_ENV_NAMES = ("CA9_PYPI_UPSTREAM_INDEX",)
PIP_UNSUPPORTED_SOURCE_ENV_NAMES = ("PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS")
PIP_CONFIG_FILE_ENV_NAMES = ("PIP_CONFIG_FILE",)
PIP_REQUIREMENT_ENV_NAMES = (
    "PIP_REQUIREMENT",
    "PIP_CONSTRAINT",
    "PIP_BUILD_CONSTRAINT",
    "PIP_REQUIREMENTS_FROM_SCRIPT",
    "PIP_EDITABLE",
    "PIP_GROUP",
)


@dataclass(frozen=True)
class PackageRequest:
    ecosystem: str
    name: str
    raw_spec: str
    version_spec: str | None = None
    exact_version: str | None = None
    source_path: str | None = None
    hashes: tuple[str, ...] = ()
    from_lockfile: bool = False

    @property
    def key(self) -> str:
        if self.exact_version:
            return f"{self.ecosystem}:{self.name}@{self.exact_version}"
        return f"{self.ecosystem}:{self.name}"

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "raw_spec": redact_sensitive_text(self.raw_spec),
        }
        if self.version_spec:
            data["version_spec"] = self.version_spec
        if self.exact_version:
            data["exact_version"] = self.exact_version
        if self.source_path:
            data["source_path"] = self.source_path
        if self.hashes:
            data["hashes"] = list(self.hashes)
        return data


@dataclass(frozen=True)
class RegistrySource:
    ecosystem: str
    kind: str
    url: str
    option: str

    def to_dict(self) -> dict[str, str]:
        return {
            "ecosystem": self.ecosystem,
            "kind": self.kind,
            "url": redact_sensitive_text(self.url),
            "option": self.option,
        }


@dataclass(frozen=True)
class RuntimeCommand:
    family: str
    command: tuple[str, ...]
    package_requests: tuple[PackageRequest, ...]
    registry_sources: tuple[RegistrySource, ...] = ()
    install_scripts_possible: bool = True

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "family": self.family,
            "command": redact_command_args(self.command),
            "package_requests": [request.to_dict() for request in self.package_requests],
            "install_scripts_possible": self.install_scripts_possible,
        }
        if self.registry_sources:
            data["registry_sources"] = [source.to_dict() for source in self.registry_sources]
        return data


@dataclass(frozen=True)
class RuntimeDecision:
    action: str
    policy_id: str
    reason: str
    package: str | None = None
    version: str | None = None
    evidence: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        data = {
            "action": self.action,
            "policy_id": self.policy_id,
            "reason": redact_sensitive_text(self.reason),
        }
        if self.package:
            data["package"] = self.package
        if self.version:
            data["version"] = self.version
        if self.evidence:
            data["evidence"] = _redact_value(self.evidence)
        return data


@dataclass(frozen=True)
class RuntimePreflight:
    command: RuntimeCommand
    decisions: tuple[RuntimeDecision, ...]
    secret_names: tuple[str, ...] = ()
    stripped_secret_names: tuple[str, ...] = ()
    feed: FeedStatus | None = None
    warnings: tuple[str, ...] = ()
    stripped_env_names: tuple[str, ...] = ()

    @property
    def action(self) -> str:
        actions = {decision.action for decision in self.decisions}
        if "block" in actions:
            return "block"
        if "strip" in actions:
            return "warn"
        if "warn" in actions:
            return "warn"
        return "pass"

    @property
    def blocked(self) -> bool:
        return self.action == "block"

    def to_dict(
        self,
        *,
        executed: bool = False,
        child_exit_code: int | None = None,
        ledger_path: Path | None = None,
    ) -> dict[str, Any]:
        data = {
            "schema_version": RUN_SCHEMA,
            "action": self.action,
            "command": self.command.to_dict(),
            "decisions": [decision.to_dict() for decision in self.decisions],
            "secret_names": list(self.secret_names),
            "stripped_secret_names": list(self.stripped_secret_names),
            "stripped_env_names": list(self.stripped_env_names),
            "executed": executed,
            "child_exit_code": child_exit_code,
            "warnings": [redact_sensitive_text(warning) for warning in self.warnings],
        }
        if self.feed:
            data["feed"] = {
                "state": self.feed.state,
                "action": self.feed.action,
                "reason": self.feed.reason,
                "snapshot_id": self.feed.snapshot.snapshot_id if self.feed.snapshot else None,
            }
        if ledger_path:
            data["ledger_path"] = str(ledger_path)
        return data


@dataclass(frozen=True)
class LedgerEvent:
    event_kind: str
    payload: dict[str, Any]
    session_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": LEDGER_SCHEMA,
            "event_kind": self.event_kind,
            "session_id": self.session_id,
            "timestamp": _utc_now_iso(),
            "payload": _redact_value(self.payload),
        }


class RuntimePreflightError(ValueError):
    def __init__(
        self,
        message: str,
        *,
        policy_id: str = "ca9.runtime.unsupported_command",
    ) -> None:
        super().__init__(message)
        self.policy_id = policy_id


@dataclass(frozen=True)
class _ParsedPipRequirement:
    request: PackageRequest
    requirement: Requirement


def parse_install_command(
    command: tuple[str, ...] | list[str],
    *,
    cwd: Path | None = None,
) -> RuntimeCommand:
    args = tuple(command)
    if not args:
        raise RuntimePreflightError("ca9 run needs a package-manager command after --")

    if args[0] == "npm":
        invocation = _parse_npm_invocation(args)
        requests, registry_sources = _parse_npm_install(invocation, cwd=cwd or Path.cwd())
        return RuntimeCommand(
            family="npm",
            command=args,
            package_requests=tuple(requests),
            registry_sources=tuple(registry_sources),
            install_scripts_possible=not invocation.flag_enabled("--ignore-scripts"),
        )

    if args[0] == "npx":
        raise RuntimePreflightError(
            "npx can download and execute packages but is not supported by ca9 run; "
            "install the package with npm install first"
        )

    pip_args = _pip_command_arguments(args)
    if pip_args is not None:
        requests, registry_sources = _parse_pip_install(pip_args, cwd=cwd or Path.cwd())
        return RuntimeCommand(
            family="pip",
            command=args,
            package_requests=tuple(requests),
            registry_sources=tuple(registry_sources),
        )

    raise RuntimePreflightError(UNSUPPORTED_COMMAND_FAMILY_MESSAGE)


def runtime_release_age_policy(policy: PackagePolicy) -> tuple[PackagePolicy, bool]:
    """Apply the ``ca9 run`` release-age cooldown to ``policy``.

    ``ca9 run`` holds versions published less than ``RUNTIME_RELEASE_AGE_HOURS``
    ago unless a trusted policy (user policy, ``CA9_POLICY`` or ``--policy``)
    sets ``package_age.enabled = false`` or ``package_age.minimum_hours = 0``.
    A trusted policy may also lower the hold with ``minimum_hours`` or add
    ``exclusions``. A tighten-only repository ``ca9.toml`` is merged against the
    hold itself, so it can raise ``minimum_hours`` but cannot disable the hold,
    lower it, or add exclusions; those settings are ignored with a warning.
    Returns the effective policy and whether the age check comes from this
    default rather than from policy; defaulted checks never block a version just
    because its release time is unknown.
    """
    trusted_paths = tuple(
        Path(source) for source in policy.sources if source not in policy.tighten_only_sources
    )
    trusted_table = _package_age_table(trusted_paths)
    if not policy.tighten_only_sources:
        return _trusted_release_age(policy, trusted_table)
    try:
        trusted_policy = load_effective_package_policy(paths=trusted_paths)
    except ValueError:
        trusted_policy = PackagePolicy()
    base, defaulted = _trusted_release_age(trusted_policy, trusted_table)
    if not base.package_age.enabled:
        return _trusted_release_age(policy, trusted_table)
    tightened = base
    ignored: list[IgnoredPolicySetting] = []
    repo_enables = False
    for source in policy.tighten_only_sources:
        try:
            root = _load_policy_root(Path(source))
        except ValueError:
            continue
        table = root.get("package_age")
        if isinstance(table, dict) and table.get("enabled") is True:
            repo_enables = True
        tightened, repo_ignored = tighten_package_policy(tightened, root, source=source)
        ignored.extend(item for item in repo_ignored if item.key.startswith("package_age."))
    known = {(item.key, item.source) for item in policy.ignored_settings}
    added = tuple(item for item in ignored if (item.key, item.source) not in known)
    effective = replace(
        policy,
        package_age=tightened.package_age,
        ignored_settings=(*policy.ignored_settings, *added),
    )
    return effective, defaulted and not repo_enables


def _trusted_release_age(
    policy: PackagePolicy, trusted: dict[str, Any]
) -> tuple[PackagePolicy, bool]:
    age = policy.package_age
    if age.enabled:
        if age.minimum_hours <= 0:
            return replace(policy, package_age=replace(age, enabled=False)), False
        return policy, False
    if trusted.get("enabled") is False or trusted.get("minimum_hours") == 0:
        return policy, False
    hours = RUNTIME_RELEASE_AGE_HOURS
    requested = trusted.get("minimum_hours")
    if isinstance(requested, int) and not isinstance(requested, bool) and requested > 0:
        hours = requested
    defaulted = replace(age, enabled=True, minimum_hours=hours)
    return replace(policy, package_age=defaulted), True


def _package_age_table(paths: tuple[Path, ...]) -> dict[str, Any]:
    settings: dict[str, Any] = {}
    for path in paths:
        try:
            root = _load_policy_root(path)
        except ValueError:
            continue
        table = root.get("package_age")
        if isinstance(table, dict):
            settings.update(table)
    return settings


def evaluate_runtime_preflight(
    command: tuple[str, ...] | list[str],
    policy: PackagePolicy,
    *,
    env: dict[str, str] | None = None,
    feed_cache_dir: Path | None = None,
    now: datetime | None = None,
    cwd: Path | None = None,
    release_age_defaulted: bool = False,
    release_fetch: Any = None,
) -> RuntimePreflight:
    """Evaluate a package-manager command against ``policy`` before it runs.

    ``release_age_defaulted`` marks the package-age check as the ``ca9 run``
    default (see ``runtime_release_age_policy``): an unknown release time then
    becomes a warning instead of a decision. ``release_fetch`` replaces the
    registry client used for release times, mainly for tests.
    """
    active_env = env if env is not None else dict(os.environ)
    try:
        parsed = parse_install_command(command, cwd=cwd)
    except RuntimePreflightError as exc:
        parsed = RuntimeCommand(
            family="unsupported",
            command=tuple(command),
            package_requests=(),
            install_scripts_possible=False,
        )
        return RuntimePreflight(
            command=parsed,
            decisions=(
                RuntimeDecision(
                    action="block",
                    policy_id=exc.policy_id,
                    reason=str(exc),
                ),
            ),
        )

    parsed = _with_env_registry_sources(parsed, active_env)
    decisions: list[RuntimeDecision] = []
    age_warnings: list[str] = []
    feed = _load_feed_status_if_needed(parsed, policy, feed_cache_dir=feed_cache_dir, now=now)
    decisions.extend(_registry_source_decisions(parsed, policy))
    decisions.extend(_gateway_requirement_source_decisions(parsed, policy, feed))
    decisions.extend(
        _feed_availability_decisions(feed, policy, release_age_defaulted=release_age_defaulted)
    )
    snapshot = None
    if feed and feed.snapshot:
        snapshot = feed.snapshot
        decisions.extend(_malware_decisions(parsed, policy, feed.snapshot, feed_cache_dir))
    if feed is None or feed.state != "tampered":
        decisions.extend(
            _package_age_decisions(
                parsed,
                policy,
                snapshot,
                now=now,
                defaulted=release_age_defaulted,
                cache_root=_release_cache_root(feed_cache_dir),
                fetch=release_fetch,
                env=active_env,
                warnings=age_warnings,
            )
        )
    decisions = _apply_runtime_policy_exceptions(decisions, parsed, policy, now=now)

    secrets = detect_secret_env(active_env)
    stripped: tuple[str, ...] = ()
    secret_decision, stripped = _secret_decision(parsed, policy, secrets)
    if secret_decision:
        decisions.append(secret_decision)

    return RuntimePreflight(
        command=parsed,
        decisions=tuple(decisions),
        secret_names=secrets,
        stripped_secret_names=stripped,
        feed=feed,
        warnings=(*_feed_warnings(feed, policy), *age_warnings),
        stripped_env_names=_ci_file_command_env_names(parsed, policy, active_env),
    )


def _apply_runtime_policy_exceptions(
    decisions: list[RuntimeDecision],
    command: RuntimeCommand,
    policy: PackagePolicy,
    *,
    now: datetime | None,
) -> list[RuntimeDecision]:
    ecosystem = "pypi" if command.family == "pip" else command.family
    applied: list[RuntimeDecision] = []
    for decision in decisions:
        if decision.action == "pass" or not decision.package:
            applied.append(decision)
            continue
        exception = find_policy_exception(
            policy.exceptions,
            policy_id=decision.policy_id,
            ecosystem=ecosystem,
            package=decision.package,
            version=decision.version,
            now=now,
        )
        if exception is None:
            applied.append(decision)
            continue
        evidence = dict(decision.evidence or {})
        evidence["policy_exception"] = {
            **exception.to_dict(),
            "original_action": decision.action,
        }
        applied.append(
            replace(
                decision,
                action=exception.action,
                reason=(
                    f"{decision.reason}; exception owned by {exception.owner} applies "
                    f"until {exception.expires}: {exception.reason}"
                ),
                evidence=evidence,
            )
        )
    return applied


_INDEX_URL_ENV_NAMES = frozenset(
    name.upper()
    for name in (*NPM_REGISTRY_ENV_NAMES, *PIP_INDEX_ENV_NAMES, *PIP_UNSUPPORTED_SOURCE_ENV_NAMES)
)
_CA9_OWNED_ENV_NAMES = frozenset(
    name.upper() for name in (*NPM_GATEWAY_UPSTREAM_ENV_NAMES, *PIP_GATEWAY_UPSTREAM_ENV_NAMES)
)


def child_environment(env: dict[str, str], preflight: RuntimePreflight) -> dict[str, str]:
    child_env = dict(env)
    for name in preflight.stripped_secret_names:
        value = child_env.get(name)
        if value is not None and name.upper() in _INDEX_URL_ENV_NAMES:
            # Keep the configured index so pip/npm cannot fall back to a public registry;
            # only the embedded credentials are removed.
            child_env[name] = _URL_CREDENTIALS_RE.sub(r"\g<prefix>", value)
        else:
            child_env.pop(name, None)
    for name in preflight.stripped_env_names:
        child_env.pop(name, None)
    # The gateway upstreams are ca9's own settings (and may carry credentials).
    for name in (*NPM_GATEWAY_UPSTREAM_ENV_NAMES, *PIP_GATEWAY_UPSTREAM_ENV_NAMES):
        child_env.pop(name, None)
    return child_env


def primary_registry_url(command: RuntimeCommand) -> str | None:
    for source in command.registry_sources:
        if source.kind in {"npm-registry", "pypi-index"} and not source.option.startswith(
            "package-lock.json:"
        ):
            return source.url
    for source in command.registry_sources:
        if source.kind in {"npm-registry", "pypi-index"}:
            return source.url
    return None


def gateway_child_command(
    command: RuntimeCommand,
    *,
    registry_url: str | None = None,
) -> tuple[str, ...]:
    if command.family == "npm":
        return _strip_option_values(command.command, {"--registry"})
    if command.family == "pip":
        stripped = _strip_option_values(command.command, {"--index-url", "-i"})
        if registry_url:
            return (*stripped, "--index-url", registry_url)
        return stripped
    return command.command


def default_ledger_path() -> Path:
    return Path(os.environ.get("CA9_AUDIT_LOG", default_cache_root() / "audit.jsonl")).expanduser()


def new_ledger_session_id() -> str:
    return uuid.uuid4().hex


def preflight_ledger_events(
    preflight: RuntimePreflight,
    *,
    session_id: str,
    dry_run: bool = False,
) -> tuple[LedgerEvent, ...]:
    events = [
        LedgerEvent(
            "session_started",
            {
                "action": preflight.action,
                "blocked": preflight.blocked,
                "dry_run": dry_run,
            },
            session_id,
        ),
        LedgerEvent("command_observed", preflight.command.to_dict(), session_id),
    ]
    for request in preflight.command.package_requests:
        events.append(LedgerEvent("package_requested", request.to_dict(), session_id))
    if preflight.feed:
        feed_payload = {
            "state": preflight.feed.state,
            "action": preflight.feed.action,
            "reason": preflight.feed.reason,
            "snapshot_id": preflight.feed.snapshot.snapshot_id if preflight.feed.snapshot else None,
        }
        events.append(LedgerEvent("feed_used", feed_payload, session_id))
        if preflight.feed.state in {"missing", "stale"}:
            events.append(LedgerEvent("offline_fallback", feed_payload, session_id))
    if preflight.secret_names:
        events.append(
            LedgerEvent(
                "secrets_detected", {"secret_names": list(preflight.secret_names)}, session_id
            )
        )
    if preflight.stripped_secret_names:
        events.append(
            LedgerEvent(
                "secrets_stripped",
                {"secret_names": list(preflight.stripped_secret_names)},
                session_id,
            )
        )
    if preflight.stripped_env_names:
        events.append(
            LedgerEvent(
                "env_stripped",
                {"env_names": list(preflight.stripped_env_names)},
                session_id,
            )
        )
    for decision in preflight.decisions:
        events.append(LedgerEvent("decision_emitted", decision.to_dict(), session_id))
    return tuple(events)


def child_process_started_event(
    preflight: RuntimePreflight,
    *,
    session_id: str,
) -> LedgerEvent:
    return LedgerEvent("child_process_started", preflight.command.to_dict(), session_id)


def child_process_exited_event(
    *,
    session_id: str,
    child_exit_code: int,
    signal_number: int | None = None,
    forwarded_signals: tuple[str, ...] = (),
) -> LedgerEvent:
    payload: dict[str, Any] = {"exit_code": child_exit_code}
    if signal_number is not None:
        payload["signal"] = signal_number
    if forwarded_signals:
        payload["forwarded_signals"] = list(forwarded_signals)
    return LedgerEvent("child_process_exited", payload, session_id)


def session_ended_event(
    preflight: RuntimePreflight,
    *,
    session_id: str,
    executed: bool,
    child_exit_code: int | None,
) -> LedgerEvent:
    return LedgerEvent(
        "session_ended",
        {
            "action": preflight.action,
            "blocked": preflight.blocked,
            "executed": executed,
            "child_exit_code": child_exit_code,
        },
        session_id,
    )


def append_ledger_events(
    events: tuple[LedgerEvent, ...] | list[LedgerEvent],
    *,
    ledger_path: Path | None = None,
) -> Path:
    path = ledger_path or default_ledger_path()
    lines = "".join(
        json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":")) + "\n"
        for event in events
    )
    _make_private_dirs(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a") as f:
        info = os.fstat(fd)
        # Tighten ledgers created world-readable by older ca9 versions.
        if info.st_mode & 0o077 and hasattr(os, "fchmod") and info.st_uid == os.getuid():
            os.fchmod(fd, 0o600)
        f.write(lines)
    return path


def _make_private_dirs(directory: Path) -> None:
    missing: list[Path] = []
    current = directory
    while not current.exists() and current.parent != current:
        missing.append(current)
        current = current.parent
    for item in reversed(missing):
        item.mkdir(mode=0o700, exist_ok=True)


def format_preflight(preflight: RuntimePreflight) -> str:
    lines = [
        f"ca9 runtime preflight: {preflight.action}",
        f"Command: {' '.join(redact_command_args(preflight.command.command))}",
    ]
    if preflight.command.package_requests:
        lines.append("Packages:")
        for request in preflight.command.package_requests:
            version = f" {request.exact_version}" if request.exact_version else ""
            lines.append(f"  - {request.ecosystem}:{request.name}{version}")
    if preflight.secret_names:
        lines.append("Secrets detected: " + ", ".join(preflight.secret_names))
    if preflight.stripped_secret_names:
        lines.append("Secrets stripped: " + ", ".join(preflight.stripped_secret_names))
    if preflight.stripped_env_names:
        lines.append("CI file-command env removed: " + ", ".join(preflight.stripped_env_names))
    if preflight.feed:
        lines.append(f"Feed: {preflight.feed.state} ({preflight.feed.reason})")
    if preflight.decisions:
        lines.append("Decisions:")
        for decision in preflight.decisions:
            target = f" {decision.package}" if decision.package else ""
            lines.append(
                f"  - [{decision.action.upper()}] {decision.policy_id}{target}: "
                f"{redact_sensitive_text(decision.reason)}"
            )
    else:
        lines.append("No blocking runtime policy decisions.")
    return "\n".join(lines)


def detect_secret_env(env: dict[str, str]) -> tuple[str, ...]:
    names: list[str] = []
    for name, value in env.items():
        if not value:
            continue
        upper = name.upper()
        if upper in _CA9_OWNED_ENV_NAMES:
            # Consumed by ca9's gateway and never passed to the child (see child_environment).
            continue
        if any(_match_secret_pattern(upper, pattern) for pattern in SECRET_ENV_PATTERNS) or any(
            pattern.search(value) for pattern in _SECRET_VALUE_RES
        ):
            names.append(name)
    return tuple(sorted(names))


def redact_sensitive_text(value: str) -> str:
    redacted = _URL_CREDENTIALS_RE.sub(r"\g<prefix>[redacted]@", value)
    redacted = _URL_RE.sub(_redact_url_path_tokens, redacted)
    redacted = _URL_SECRET_QUERY_RE.sub(r"\g<key>[redacted]", redacted)
    redacted = _NPM_AUTH_SETTING_RE.sub(r"\g<key>[redacted]", redacted)
    redacted = _SECRET_OPTION_RE.sub(r"\g<key>[redacted]", redacted)
    redacted = _JWT_RE.sub("[redacted-jwt]", redacted)
    redacted = _KNOWN_TOKEN_RE.sub("[redacted]", redacted)
    return _AUTHORIZATION_RE.sub(_redact_authorization_match, redacted)


def redact_command_args(args: tuple[str, ...] | list[str]) -> list[str]:
    redacted: list[str] = []
    secret_value_next = False
    for arg in args:
        if secret_value_next:
            redacted.append("[redacted]")
            secret_value_next = False
            continue
        redacted.append(redact_sensitive_text(arg))
        secret_value_next = bool(_SECRET_OPTION_NAME_RE.match(arg))
    return redacted


def _redact_url_path_tokens(match: re.Match[str]) -> str:
    url = match.group(0)
    authority_end = url.find("/", url.index("://") + 3)
    if authority_end < 0:
        return url
    path_end = len(url)
    for marker in ("?", "#"):
        index = url.find(marker, authority_end)
        if index >= 0:
            path_end = min(path_end, index)
    segments = url[authority_end:path_end].split("/")
    cleaned = ["[redacted]" if _looks_like_path_token(item) else item for item in segments]
    return url[:authority_end] + "/".join(cleaned) + url[path_end:]


def _looks_like_path_token(segment: str) -> bool:
    if _KNOWN_TOKEN_RE.fullmatch(segment):
        return True
    # Registry tokens embedded in URL paths (e.g. https://host/<token>/org/simple/) are long,
    # random, and mixed-case; package names, versions, and digests are not.
    return (
        len(segment) >= 16
        and re.fullmatch(r"[A-Za-z0-9_-]+", segment) is not None
        and re.search(r"[0-9]", segment) is not None
        and re.search(r"[a-z]", segment) is not None
        and re.search(r"[A-Z]", segment) is not None
    )


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, dict):
        return {key: _redact_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_value(item) for item in value)
    return value


def _redact_authorization_match(match: re.Match[str]) -> str:
    scheme = match.group("scheme") or ""
    space = " " if scheme else ""
    return f"{match.group('name')}{match.group('sep')}{scheme}{space}[redacted]"


@dataclass(frozen=True)
class _NpmInvocation:
    subcommand: str
    specs: tuple[str, ...]
    bool_flags: tuple[tuple[str, bool], ...]
    registry_sources: tuple[RegistrySource, ...]

    def flag_enabled(self, flag_name: str) -> bool:
        enabled = False
        for name, value in self.bool_flags:
            if name == flag_name:
                enabled = value
        return enabled


def _parse_npm_invocation(args: tuple[str, ...]) -> _NpmInvocation:
    # npm (nopt) accepts options anywhere, including before the subcommand, so
    # parse the whole argv once and take the first positional as the subcommand.
    subcommand = _npm_subcommand(args)
    if subcommand is None:
        raise RuntimePreflightError("npm command did not include a subcommand")
    if subcommand in NPM_UNSUPPORTED_INSTALL_SUBCOMMANDS:
        raise RuntimePreflightError(
            f"npm {subcommand} can install or execute packages but is not supported by "
            "ca9 run; use npm install <package> or npm ci"
        )
    if subcommand not in NPM_INSTALL_SUBCOMMANDS | NPM_CLEAN_INSTALL_SUBCOMMANDS:
        raise RuntimePreflightError(UNSUPPORTED_COMMAND_FAMILY_MESSAGE)
    if any(arg.split("=", 1)[0] in NPM_PREFIX_FLAGS for arg in args[1:]):
        raise RuntimePreflightError(
            "npm --prefix is unsupported because it can select a different project config "
            "or lockfile"
        )

    positionals: list[str] = []
    bool_flags: list[tuple[str, bool]] = []
    registry_sources: list[RegistrySource] = []
    terminated = False
    index = 1
    while index < len(args):
        arg = args[index]
        index += 1
        if terminated or arg == "-" or not arg.startswith("-"):
            positionals.append(arg)
            continue
        if arg == "--":
            terminated = True
            continue
        flag_name, separator, inline_value = arg.partition("=")
        if flag_name in NPM_CONFIG_FILE_FLAGS:
            raise RuntimePreflightError(
                f"npm {flag_name} is unsupported because it can load a different npm config"
            )
        if flag_name in SUPPORTED_NPM_FLAGS_WITH_VALUE:
            if separator:
                value = inline_value
            elif index < len(args):
                value = args[index]
                index += 1
            else:
                raise RuntimePreflightError(f"npm install option needs a value: {flag_name}")
            if flag_name == "--registry":
                registry_sources.append(
                    RegistrySource(
                        ecosystem="npm",
                        kind="npm-registry",
                        url=value,
                        option=flag_name,
                    )
                )
            continue
        if flag_name in NPM_LOGLEVEL_SHORTHANDS:
            if separator:
                # nopt splits `--silent=x` into `--loglevel silent x`, turning x
                # into a positional argument.
                raise RuntimePreflightError(f"npm shorthand option does not take a value: {arg}")
            continue
        if flag_name in SUPPORTED_NPM_BOOL_FLAGS:
            if separator:
                if inline_value not in {"true", "false"}:
                    raise RuntimePreflightError(
                        f"npm boolean option only accepts true or false: {arg}"
                    )
                value = inline_value
            elif index < len(args) and args[index] in {"true", "false"}:
                # nopt consumes a literal true/false after a boolean flag as its value.
                value = args[index]
                index += 1
            else:
                value = "true"
            bool_flags.append((NPM_BOOL_FLAG_ALIASES.get(flag_name, flag_name), value == "true"))
            continue
        raise RuntimePreflightError(f"unsupported npm install option: {arg}")

    return _NpmInvocation(
        subcommand=positionals[0],
        specs=tuple(positionals[1:]),
        bool_flags=tuple(bool_flags),
        registry_sources=tuple(registry_sources),
    )


def _npm_subcommand(args: tuple[str, ...]) -> str | None:
    flags_with_value = SUPPORTED_NPM_FLAGS_WITH_VALUE | NPM_CONFIG_FILE_FLAGS | NPM_PREFIX_FLAGS
    index = 1
    while index < len(args):
        arg = args[index]
        if arg == "--":
            return args[index + 1] if index + 1 < len(args) else None
        if arg == "-" or not arg.startswith("-"):
            return arg
        flag_name, separator, _ = arg.partition("=")
        takes_value = flag_name in flags_with_value
        consumes_bool = (
            flag_name in SUPPORTED_NPM_BOOL_FLAGS
            and index + 1 < len(args)
            and args[index + 1] in {"true", "false"}
        )
        index += 2 if not separator and (takes_value or consumes_bool) else 1
    return None


def _parse_npm_install(
    invocation: _NpmInvocation,
    *,
    cwd: Path,
) -> tuple[list[PackageRequest], list[RegistrySource]]:
    clean_install = invocation.subcommand in NPM_CLEAN_INSTALL_SUBCOMMANDS
    global_mode = invocation.flag_enabled("--global")
    if not clean_install and not invocation.specs and (global_mode or not _has_npm_lock(cwd)):
        raise RuntimePreflightError(
            "npm install without a package spec needs a project package-lock.json "
            "(v2 or v3) so ca9 can check the dependency tree it installs"
        )
    registry_sources = list(invocation.registry_sources)
    if not global_mode:
        registry_sources.extend(_npm_project_config_sources(cwd))
    if clean_install and invocation.specs:
        raise RuntimePreflightError("npm ci does not accept direct package specs")
    if clean_install:
        locked_requests, locked_sources = _npm_lock_requests(cwd)
        return locked_requests, [*registry_sources, *locked_sources]

    requests = [_parse_npm_spec(spec) for spec in invocation.specs]
    if not global_mode:
        # npm install reifies the whole project tree, so locked transitive versions
        # are fetched too and need the same lockfile preflight as npm ci.
        seen = {request.key for request in requests}
        for lock_root in _npm_project_lock_roots(cwd):
            locked_requests, locked_sources = _npm_lock_requests(lock_root)
            for request in locked_requests:
                if request.key not in seen:
                    seen.add(request.key)
                    requests.append(request)
            registry_sources.extend(locked_sources)
    return requests, registry_sources


def _npm_project_config_sources(cwd: Path) -> list[RegistrySource]:
    sources: list[RegistrySource] = []
    resolved_cwd = cwd.resolve()
    for config_path in _npm_project_config_paths(resolved_cwd):
        display_path = os.path.relpath(config_path, resolved_cwd)
        try:
            content = config_path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeError) as exc:
            raise RuntimePreflightError(
                f"cannot inspect npm project config {display_path}: {exc}",
                policy_id="ca9.runtime.unsupported_source",
            ) from exc

        for line_number, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            parsed = _npmrc_scoped_registry(line)
            if parsed is None:
                continue
            key, value = parsed
            sources.append(
                RegistrySource(
                    ecosystem="npm",
                    kind="npm-config-file",
                    url=value,
                    option=f"{display_path}:{line_number}:{key}",
                )
            )
    return sources


def _npmrc_scoped_registry(line: str) -> tuple[str, str] | None:
    if "=" not in line:
        return None
    raw_key, value = line.split("=", 1)
    key = _npmrc_unsafe_key(raw_key)
    if "${" in key:
        # @npmcli/config performs environment expansion on parsed keys. Without
        # duplicating the child's full config loader, an interpolated key cannot
        # be proven not to become a scoped registry selector.
        return "interpolated-key", value.strip()
    key = key.removesuffix("[]")
    if _NPM_SCOPED_REGISTRY_KEY_RE.fullmatch(key) is None:
        return None
    return key, value.strip()


def _npmrc_unsafe_key(raw_key: str) -> str:
    # JavaScript String.trim(), used by npm's INI parser, treats U+FEFF as
    # whitespace. Remove it conservatively anywhere in the raw key so repeated
    # or non-file-leading BOMs cannot hide a scoped registry selector.
    key = raw_key.replace("\ufeff", "").strip()
    quoted = len(key) >= 2 and key[0] == key[-1] and key[0] in {"'", '"'}
    if quoted:
        candidate = key[1:-1] if key[0] == "'" else key
        try:
            decoded = json.loads(candidate)
        except (json.JSONDecodeError, TypeError):
            decoded = candidate
        return str(decoded).strip()

    decoded: list[str] = []
    escaped = False
    for character in key:
        if escaped:
            if character in {"\\", ";", "#"}:
                decoded.append(character)
            else:
                decoded.extend(("\\", character))
            escaped = False
        elif character in {";", "#"}:
            break
        elif character == "\\":
            escaped = True
        else:
            decoded.append(character)
    if escaped:
        decoded.append("\\")
    return "".join(decoded).strip()


def _npm_project_config_paths(cwd: Path) -> tuple[Path, ...]:
    return tuple(root / ".npmrc" for root in _npm_project_roots(cwd) if (root / ".npmrc").is_file())


def _npm_project_lock_roots(cwd: Path) -> tuple[Path, ...]:
    return tuple(
        root
        for root in _npm_project_roots(cwd.resolve())
        if (root / "package-lock.json").is_file() or (root / "npm-shrinkwrap.json").is_file()
    )


def _has_npm_lock(cwd: Path) -> bool:
    return bool(_npm_project_lock_roots(cwd))


def _npm_project_roots(cwd: Path) -> tuple[Path, ...]:
    project_root: Path | None = None
    workspace_roots: list[Path] = []
    for candidate in (cwd, *cwd.parents):
        package_path = candidate / "package.json"
        if project_root is None and (
            package_path.is_file() or (candidate / "node_modules").is_dir()
        ):
            project_root = candidate
            continue
        if project_root is not None and _npm_declares_workspaces(package_path):
            # npm may promote localPrefix to a matching workspace root. Treat every
            # ancestor workspace declaration as a candidate instead of trying to
            # reproduce npm's evolving glob semantics and risking a missed config.
            workspace_roots.append(candidate)

    return (project_root or cwd, *workspace_roots)


def _npm_declares_workspaces(package_path: Path) -> bool:
    if not package_path.is_file():
        return False
    try:
        package = json.loads(package_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        # npm also skips malformed ancestor package files while looking for a
        # workspace root. The nearest package directory is still inspected above.
        return False
    if not isinstance(package, dict):
        return False
    workspaces = package.get("workspaces")
    if isinstance(workspaces, dict):
        workspaces = workspaces.get("packages")
    return isinstance(workspaces, list) and any(
        isinstance(pattern, str) and pattern.strip() for pattern in workspaces
    )


def _pip_command_arguments(args: tuple[str, ...]) -> tuple[str, ...] | None:
    """Return the arguments after `pip` or `python -m pip`, or None for other programs."""
    if _PIP_PROGRAM_RE.fullmatch(args[0]):
        return args[1:]
    if not _PYTHON_PROGRAM_RE.fullmatch(args[0]):
        return None

    index = 1
    while index < len(args):
        arg = args[index]
        if arg == "-" or not arg.startswith("-") or arg.startswith("--"):
            raise RuntimePreflightError(UNSUPPORTED_COMMAND_FAMILY_MESSAGE)
        # CPython accepts combined short flags (`-IS`) and attached values
        # (`-Wignore`, `-mpip`), so walk the flag characters one at a time.
        position = 1
        while position < len(arg):
            flag = arg[position]
            if flag in _PYTHON_FLAG_CHARS:
                position += 1
                continue
            if flag not in _PYTHON_FLAGS_WITH_VALUE and flag != "m":
                raise RuntimePreflightError(f"unsupported python option before -m pip: -{flag}")
            value = arg[position + 1 :]
            if not value:
                index += 1
                if index >= len(args):
                    raise RuntimePreflightError(f"python option needs a value: -{flag}")
                value = args[index]
            if flag == "m":
                if value != "pip":
                    raise RuntimePreflightError(UNSUPPORTED_COMMAND_FAMILY_MESSAGE)
                return args[index + 1 :]
            break
        index += 1
    raise RuntimePreflightError(UNSUPPORTED_COMMAND_FAMILY_MESSAGE)


def _pip_subcommand_index(args: tuple[str, ...]) -> int:
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "-" or not arg.startswith("-"):
            return index
        flag_name, separator, _ = arg.partition("=")
        if flag_name in PIP_UNSUPPORTED_GENERAL_FLAGS:
            raise RuntimePreflightError(
                f"pip {flag_name} is unsupported because it runs pip for a different interpreter"
            )
        if flag_name in PIP_GENERAL_FLAGS_WITH_VALUE:
            index += 1 if separator else 2
            continue
        if flag_name in PIP_GENERAL_BOOL_FLAGS and not separator:
            index += 1
            continue
        raise RuntimePreflightError(f"unsupported pip option before the subcommand: {arg}")
    raise RuntimePreflightError("pip command did not include a subcommand")


def _parse_pip_install(
    pip_args: tuple[str, ...],
    *,
    cwd: Path,
) -> tuple[list[PackageRequest], list[RegistrySource]]:
    subcommand_index = _pip_subcommand_index(pip_args)
    if pip_args[subcommand_index] != "install":
        raise RuntimePreflightError(UNSUPPORTED_COMMAND_FAMILY_MESSAGE)
    # pip re-parses general options given before the subcommand together with the
    # subcommand's own options.
    args = (*pip_args[:subcommand_index], *pip_args[subcommand_index + 1 :])
    repo_path = cwd.resolve()
    requirements: list[_ParsedPipRequirement] = []
    constraints: dict[str, list[Requirement]] = {}
    registry_sources: list[RegistrySource] = []
    visited_files: set[tuple[Path, bool]] = set()
    active_files: set[Path] = set()

    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            raise RuntimePreflightError(
                "pip install argument terminator is unsupported because it can bypass "
                "gateway option enforcement"
            )

        file_option = _pip_file_option(arg)
        if file_option is not None:
            flag_name, inline_value = file_option
            value, index = _pip_option_value(args, index, flag_name, inline_value)
            _read_pip_requirement_file(
                value,
                is_constraint=flag_name in PIP_CONSTRAINT_FLAGS,
                base_dir=repo_path,
                repo_path=repo_path,
                requirements=requirements,
                constraints=constraints,
                registry_sources=registry_sources,
                visited_files=visited_files,
                active_files=active_files,
                depth=0,
            )
            index += 1
            continue

        if arg.startswith("-"):
            flag_name = arg.split("=", 1)[0]
            if flag_name in UNSUPPORTED_PIP_SOURCE_FLAGS:
                raise RuntimePreflightError(
                    f"pip source option is not supported by ca9 run yet: {flag_name}"
                )
            if flag_name in PIP_UNSUPPORTED_GENERAL_FLAGS:
                raise RuntimePreflightError(
                    f"pip {flag_name} is unsupported because it runs pip for a different "
                    "interpreter"
                )
            if flag_name in SUPPORTED_PIP_FLAGS_WITH_VALUE | PIP_GENERAL_FLAGS_WITH_VALUE:
                inline_value = arg.split("=", 1)[1] if "=" in arg else None
                value, index = _pip_option_value(args, index, flag_name, inline_value)
                if flag_name in {"--index-url", "-i"}:
                    registry_sources.append(
                        RegistrySource(
                            ecosystem="pypi",
                            kind="pypi-index",
                            url=value,
                            option=flag_name,
                        )
                    )
            elif flag_name not in SUPPORTED_PIP_BOOL_FLAGS | PIP_GENERAL_BOOL_FLAGS:
                raise RuntimePreflightError(f"unsupported pip install option: {arg}")
            index += 1
            continue

        requirements.append(_parse_pip_requirement(arg))
        index += 1

    # Environment markers are not evaluated here: ca9's interpreter is not
    # necessarily the one pip installs for, so every requirement is checked.
    if not requirements:
        raise RuntimePreflightError("pip install command did not include a direct package spec")
    return _apply_pip_constraints(requirements, constraints), registry_sources


def _pip_file_option(arg: str) -> tuple[str, str | None] | None:
    for flag_name in ("--requirement", "--constraint"):
        if arg == flag_name:
            return flag_name, None
        if arg.startswith(f"{flag_name}="):
            return flag_name, arg.split("=", 1)[1]
    for flag_name in ("-r", "-c"):
        if arg == flag_name:
            return flag_name, None
        if arg.startswith(flag_name) and len(arg) > len(flag_name):
            value = arg[len(flag_name) :]
            return flag_name, value.removeprefix("=")
    return None


def _pip_option_value(
    args: tuple[str, ...],
    index: int,
    flag_name: str,
    inline_value: str | None,
) -> tuple[str, int]:
    if inline_value is not None:
        value = inline_value
    else:
        index += 1
        if index >= len(args):
            raise RuntimePreflightError(f"pip install option needs a value: {flag_name}")
        value = args[index]
    if not value.strip():
        raise RuntimePreflightError(f"pip install option needs a value: {flag_name}")
    return value, index


def _read_pip_requirement_file(
    raw_path: str,
    *,
    is_constraint: bool,
    base_dir: Path,
    repo_path: Path,
    requirements: list[_ParsedPipRequirement],
    constraints: dict[str, list[Requirement]],
    registry_sources: list[RegistrySource],
    visited_files: set[tuple[Path, bool]],
    active_files: set[Path],
    depth: int,
) -> None:
    if depth > MAX_PIP_REQUIREMENT_DEPTH:
        raise RuntimePreflightError(
            f"pip requirement include depth exceeds {MAX_PIP_REQUIREMENT_DEPTH}",
            policy_id="ca9.runtime.requirements_unavailable",
        )
    path = _resolve_pip_requirement_path(raw_path, base_dir=base_dir, repo_path=repo_path)
    if path in active_files:
        raise RuntimePreflightError(
            f"pip requirement include cycle detected at {_relative_path(path, repo_path)}",
            policy_id="ca9.runtime.requirements_unavailable",
        )
    visit_key = (path, is_constraint)
    if visit_key in visited_files:
        return
    visited_files.add(visit_key)
    active_files.add(path)

    try:
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise RuntimePreflightError(
                f"cannot read pip requirement file {_relative_path(path, repo_path)}: {exc}",
                policy_id="ca9.runtime.requirements_unavailable",
            ) from exc

        source_path = _relative_path(path, repo_path)
        for line_number, raw_line in _logical_pip_requirement_lines(content):
            line = _strip_pip_requirement_comment(raw_line)
            if not line:
                continue

            try:
                tokens = tuple(shlex.split(line, comments=False, posix=True))
            except ValueError as exc:
                raise RuntimePreflightError(
                    f"invalid quoting in {source_path}:{line_number}: {exc}",
                    policy_id="ca9.runtime.requirements_unavailable",
                ) from exc
            if not tokens:
                continue

            include_option = _pip_file_option(tokens[0])
            if include_option is not None:
                flag_name, inline_value = include_option
                value = _requirement_line_option_value(
                    tokens,
                    flag_name=flag_name,
                    inline_value=inline_value,
                    source_path=source_path,
                    line_number=line_number,
                )
                _read_pip_requirement_file(
                    value,
                    is_constraint=flag_name in PIP_CONSTRAINT_FLAGS,
                    base_dir=path.parent,
                    repo_path=repo_path,
                    requirements=requirements,
                    constraints=constraints,
                    registry_sources=registry_sources,
                    visited_files=visited_files,
                    active_files=active_files,
                    depth=depth + 1,
                )
                continue

            flag_name = tokens[0].split("=", 1)[0]
            if flag_name in UNSUPPORTED_PIP_SOURCE_FLAGS:
                raise RuntimePreflightError(
                    f"pip source option is not supported in "
                    f"{source_path}:{line_number}: {flag_name}",
                    policy_id="ca9.runtime.requirements_unavailable",
                )
            if flag_name in SUPPORTED_PIP_FLAGS_WITH_VALUE:
                inline_value = tokens[0].split("=", 1)[1] if "=" in tokens[0] else None
                value = _requirement_line_option_value(
                    tokens,
                    flag_name=flag_name,
                    inline_value=inline_value,
                    source_path=source_path,
                    line_number=line_number,
                )
                if flag_name in {"--index-url", "-i"}:
                    registry_sources.append(
                        RegistrySource(
                            ecosystem="pypi",
                            kind="pypi-requirement-index",
                            url=value,
                            option=f"{source_path}:{line_number}:{flag_name}",
                        )
                    )
                continue
            if flag_name in SUPPORTED_PIP_BOOL_FLAGS:
                if len(tokens) != 1:
                    raise RuntimePreflightError(
                        f"unexpected value after {flag_name} in {source_path}:{line_number}",
                        policy_id="ca9.runtime.requirements_unavailable",
                    )
                continue
            if tokens[0].startswith("-"):
                raise RuntimePreflightError(
                    f"unsupported pip requirement option in "
                    f"{source_path}:{line_number}: {tokens[0]}",
                    policy_id="ca9.runtime.requirements_unavailable",
                )

            requirement_text, hashes = _extract_pip_hashes(
                line,
                source_path=source_path,
                line_number=line_number,
            )
            parsed = _parse_pip_requirement(
                requirement_text,
                source_path=source_path,
                hashes=hashes,
            )
            if is_constraint:
                if hashes:
                    raise RuntimePreflightError(
                        f"constraint entries cannot contain hashes in {source_path}:{line_number}",
                        policy_id="ca9.runtime.requirements_unavailable",
                    )
                constraints.setdefault(parsed.request.name, []).append(parsed.requirement)
            else:
                requirements.append(parsed)
    finally:
        active_files.remove(path)


def _resolve_pip_requirement_path(
    raw_path: str,
    *,
    base_dir: Path,
    repo_path: Path,
) -> Path:
    candidate_text = raw_path.strip()
    if (
        not candidate_text
        or "\x00" in candidate_text
        or candidate_text.startswith("~")
        or "$" in candidate_text
        or urlparse(candidate_text).scheme
    ):
        raise RuntimePreflightError(
            f"pip requirement file must be a local repository path: {raw_path!r}",
            policy_id="ca9.runtime.requirements_unavailable",
        )
    try:
        candidate = Path(candidate_text)
        path = (candidate if candidate.is_absolute() else base_dir / candidate).resolve()
    except OSError as exc:
        raise RuntimePreflightError(
            f"cannot resolve pip requirement file {raw_path!r}: {exc}",
            policy_id="ca9.runtime.requirements_unavailable",
        ) from exc
    if not path.is_relative_to(repo_path):
        raise RuntimePreflightError(
            f"pip requirement file escapes the repository: {raw_path!r}",
            policy_id="ca9.runtime.requirements_unavailable",
        )
    if not path.is_file():
        raise RuntimePreflightError(
            f"pip requirement file does not exist: {_relative_path(path, repo_path)}",
            policy_id="ca9.runtime.requirements_unavailable",
        )
    return path


def _relative_path(path: Path, repo_path: Path) -> str:
    try:
        return path.relative_to(repo_path).as_posix()
    except ValueError:
        return str(path)


def _logical_pip_requirement_lines(content: str) -> tuple[tuple[int, str], ...]:
    # Mirrors pip's req_file.join_lines(): a line ending in a backslash continues
    # onto the next line, except comment lines, which pip never joins.
    logical_lines: list[tuple[int, str]] = []
    buffer: list[str] = []
    start_line = 1
    for line_number, line in enumerate(content.splitlines(), start=1):
        is_comment = _PIP_COMMENT_RE.match(line) is not None
        if not line.endswith("\\") or is_comment:
            if is_comment:
                line = " " + line
            if buffer:
                buffer.append(line)
                logical_lines.append((start_line, "".join(buffer)))
                buffer = []
            else:
                logical_lines.append((line_number, line))
            continue
        if not buffer:
            start_line = line_number
        buffer.append(line.strip("\\"))
    if buffer:
        logical_lines.append((start_line, "".join(buffer)))
    return tuple(logical_lines)


def _strip_pip_requirement_comment(line: str) -> str:
    return _PIP_COMMENT_RE.sub("", line).strip()


def _requirement_line_option_value(
    tokens: tuple[str, ...],
    *,
    flag_name: str,
    inline_value: str | None,
    source_path: str,
    line_number: int,
) -> str:
    expected_length = 1 if inline_value is not None else 2
    if len(tokens) != expected_length:
        raise RuntimePreflightError(
            f"{flag_name} needs exactly one value in {source_path}:{line_number}",
            policy_id="ca9.runtime.requirements_unavailable",
        )
    value = inline_value if inline_value is not None else tokens[1]
    if not value:
        raise RuntimePreflightError(
            f"{flag_name} needs a value in {source_path}:{line_number}",
            policy_id="ca9.runtime.requirements_unavailable",
        )
    return value


def _extract_pip_hashes(
    line: str,
    *,
    source_path: str,
    line_number: int,
) -> tuple[str, tuple[str, ...]]:
    hashes = tuple(match.group("hash").lower() for match in _PIP_HASH_RE.finditer(line))
    requirement_text = _PIP_HASH_RE.sub("", line).strip()
    if "--hash" in requirement_text:
        raise RuntimePreflightError(
            f"invalid or unsupported pip hash in {source_path}:{line_number}",
            policy_id="ca9.runtime.requirements_unavailable",
        )
    return requirement_text, hashes


def _apply_pip_constraints(
    requirements: list[_ParsedPipRequirement],
    constraints: dict[str, list[Requirement]],
) -> list[PackageRequest]:
    requests: list[PackageRequest] = []
    for parsed in requirements:
        name_constraints = constraints.get(parsed.request.name, ())
        applicable_constraints = [
            constraint for constraint in name_constraints if _requirement_marker_applies(constraint)
        ]
        # Markers are evaluated with ca9's interpreter, which may not be the one pip
        # installs for. Exact pins that only apply elsewhere are checked as well.
        for constraint in name_constraints:
            if any(constraint is applied for applied in applicable_constraints):
                continue
            for pinned in _exact_pip_versions(constraint):
                requests.append(
                    replace(parsed.request, version_spec=f"=={pinned}", exact_version=pinned)
                )
        if not applicable_constraints:
            requests.append(parsed.request)
            continue

        combined = [parsed.requirement, *applicable_constraints]
        specifier_parts = [str(item.specifier) for item in combined if str(item.specifier)]
        combined_specifier = SpecifierSet(",".join(specifier_parts))
        exact_versions = {
            specifier.version
            for item in combined
            for specifier in item.specifier
            if specifier.operator in {"==", "==="} and "*" not in specifier.version
        }
        if len(exact_versions) > 1:
            raise RuntimePreflightError(
                f"conflicting exact constraints for pip package {parsed.request.name}",
                policy_id="ca9.runtime.requirements_unavailable",
            )
        exact_version = next(iter(exact_versions), None)
        if exact_version is not None:
            try:
                exact_allowed = combined_specifier.contains(exact_version, prereleases=True)
            except (TypeError, ValueError):
                exact_allowed = False
            if not exact_allowed:
                raise RuntimePreflightError(
                    f"pip constraints exclude exact version {parsed.request.name}=={exact_version}",
                    policy_id="ca9.runtime.requirements_unavailable",
                )
        requests.append(
            replace(
                parsed.request,
                version_spec=str(combined_specifier) or None,
                exact_version=exact_version,
            )
        )
    return requests


def _exact_pip_versions(requirement: Requirement) -> tuple[str, ...]:
    return tuple(
        item.version
        for item in requirement.specifier
        if item.operator in {"==", "==="} and "*" not in item.version
    )


def _requirement_marker_applies(requirement: Requirement) -> bool:
    if requirement.marker is None:
        return True
    try:
        return requirement.marker.evaluate()
    except (KeyError, TypeError, ValueError):
        # Unknown marker environments should stay visible to policy rather than bypass it.
        return True


def _npm_lock_requests(cwd: Path) -> tuple[list[PackageRequest], list[RegistrySource]]:
    repo_path = cwd.resolve()
    lock_path = repo_path / "package-lock.json"
    if (repo_path / "npm-shrinkwrap.json").is_file():
        # npm prefers npm-shrinkwrap.json over package-lock.json, so preflighting
        # package-lock.json would check a different tree than npm installs.
        raise RuntimePreflightError(
            "npm-shrinkwrap.json is not supported by ca9 run yet",
            policy_id="ca9.runtime.lockfile_unavailable",
        )
    if not lock_path.is_file():
        raise RuntimePreflightError(
            f"npm lock-backed install requires package-lock.json at {lock_path}",
            policy_id="ca9.runtime.lockfile_unavailable",
        )

    expected_keys = _validated_external_npm_lock_keys(lock_path, repo_path)
    inventory = read_package_lock(repo_path)
    if inventory.warnings:
        raise RuntimePreflightError(
            "cannot safely preflight package-lock.json: " + "; ".join(inventory.warnings),
            policy_id="ca9.runtime.lockfile_unavailable",
        )

    requests: list[PackageRequest] = []
    registry_sources: list[RegistrySource] = []
    seen_requests: set[str] = set()
    seen_registries: set[str] = set()
    for package in inventory.packages:
        if package.ecosystem.lower() != "npm" or package.dependency_kind == "project":
            continue
        if not package.version:
            raise RuntimePreflightError(
                f"package-lock.json entry for {package.name} does not have an exact version",
                policy_id="ca9.runtime.lockfile_unavailable",
            )
        request = PackageRequest(
            ecosystem="npm",
            name=package.normalized_name,
            raw_spec=f"{package.name}@{package.version}",
            version_spec=package.version,
            exact_version=package.version,
            from_lockfile=True,
        )
        if request.key not in expected_keys:
            continue
        if request.key not in seen_requests:
            seen_requests.add(request.key)
            requests.append(request)
        if package.source_registry and package.source_registry not in seen_registries:
            seen_registries.add(package.source_registry)
            registry_sources.append(
                RegistrySource(
                    ecosystem="npm",
                    kind="npm-registry",
                    url=package.source_registry,
                    option=f"package-lock.json:{package.name}@{package.version}",
                )
            )
    missing_keys = expected_keys - seen_requests
    if missing_keys:
        raise RuntimePreflightError(
            "package-lock.json entries were not represented in the package inventory: "
            + ", ".join(sorted(missing_keys)),
            policy_id="ca9.runtime.lockfile_unavailable",
        )
    return requests, registry_sources


def _validated_external_npm_lock_keys(lock_path: Path, repo_path: Path) -> set[str]:
    data = _load_npm_lock_data(lock_path)
    lockfile_version = data.get("lockfileVersion")
    if type(lockfile_version) is not int or lockfile_version not in {2, 3}:
        rendered = repr(lockfile_version) if lockfile_version is not None else "missing"
        raise RuntimePreflightError(
            f"unsupported package-lock.json lockfileVersion: {rendered}; expected 2 or 3",
            policy_id="ca9.runtime.lockfile_unavailable",
        )
    if "packages" not in data:
        raise RuntimePreflightError(
            "package-lock.json is missing the packages table",
            policy_id="ca9.runtime.lockfile_unavailable",
        )
    raw_packages = data["packages"]
    if not isinstance(raw_packages, dict):
        raise RuntimePreflightError(
            "package-lock.json packages table is not an object",
            policy_id="ca9.runtime.lockfile_unavailable",
        )

    expected_keys: set[str] = set()
    for path, entry in raw_packages.items():
        if not isinstance(entry, dict):
            raise RuntimePreflightError(
                f"package-lock.json entry {path!r} is not an object",
                policy_id="ca9.runtime.lockfile_unavailable",
            )
        if path == "":
            _validate_root_lock_dependencies(entry, raw_packages)
            continue
        if not _safe_relative_lock_path(path):
            raise RuntimePreflightError(
                f"package-lock.json entry has an unsafe path: {path!r}",
                policy_id="ca9.runtime.lockfile_unavailable",
            )
        if entry.get("link") is True:
            _validate_workspace_link(path, entry, raw_packages, repo_path)
            continue
        if not _is_node_modules_lock_path(path):
            # npm records workspace source packages alongside their node_modules links.
            # These are local project code, not registry packages.
            continue

        name = _npm_lock_entry_name(path, entry)
        version = entry.get("version")
        if (
            not _valid_npm_lock_name(name)
            or not isinstance(version, str)
            or not _is_exact_npm_version(version.strip())
        ):
            raise RuntimePreflightError(
                f"package-lock.json dependency entry {path!r} is missing a name or exact version",
                policy_id="ca9.runtime.lockfile_unavailable",
            )
        _validate_external_lock_source(path, entry.get("resolved"), name=name, version=version)
        expected_keys.add(
            PackageRequest(
                ecosystem="npm",
                name=name.lower(),
                raw_spec="",
                version_spec=version,
                exact_version=version,
            ).key
        )
    return expected_keys


def _load_npm_lock_data(lock_path: Path) -> dict[str, Any]:
    try:
        with lock_path.open() as handle:
            data = json.load(handle)
    except OSError as exc:
        raise RuntimePreflightError(
            f"cannot read package-lock.json: {exc}",
            policy_id="ca9.runtime.lockfile_unavailable",
        ) from exc
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise RuntimePreflightError(
            f"cannot parse package-lock.json: {exc}",
            policy_id="ca9.runtime.lockfile_unavailable",
        ) from exc
    if not isinstance(data, dict):
        raise RuntimePreflightError(
            "package-lock.json did not parse to an object",
            policy_id="ca9.runtime.lockfile_unavailable",
        )
    return data


def _validate_root_lock_dependencies(
    root: dict[str, Any],
    raw_packages: dict[str, Any],
) -> None:
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        dependencies = root.get(field, {})
        if not isinstance(dependencies, dict):
            raise RuntimePreflightError(
                f"package-lock.json root {field} is not an object",
                policy_id="ca9.runtime.lockfile_unavailable",
            )
        for name in dependencies:
            if not isinstance(name, str) or not name.strip():
                raise RuntimePreflightError(
                    f"package-lock.json root {field} contains an invalid package name",
                    policy_id="ca9.runtime.lockfile_unavailable",
                )
            if f"node_modules/{name}" not in raw_packages:
                raise RuntimePreflightError(
                    f"package-lock.json root dependency {name!r} has no locked package entry",
                    policy_id="ca9.runtime.lockfile_unavailable",
                )


def _validate_workspace_link(
    path: str,
    entry: dict[str, Any],
    raw_packages: dict[str, Any],
    repo_path: Path,
) -> None:
    resolved = entry.get("resolved")
    if not isinstance(resolved, str) or not resolved.strip():
        raise RuntimePreflightError(
            f"package-lock.json workspace link {path!r} has no local target",
            policy_id="ca9.runtime.lockfile_unavailable",
        )
    target_key = resolved.removeprefix("file:").rstrip("/")
    if not _safe_relative_lock_path(target_key):
        raise RuntimePreflightError(
            f"package-lock.json workspace link {path!r} has an unsafe target",
            policy_id="ca9.runtime.lockfile_unavailable",
        )
    target_path = (repo_path / target_key).resolve()
    if not target_path.is_relative_to(repo_path) or target_key not in raw_packages:
        raise RuntimePreflightError(
            f"package-lock.json workspace link {path!r} has no in-repository target entry",
            policy_id="ca9.runtime.lockfile_unavailable",
        )


def _validate_external_lock_source(
    path: str,
    resolved: object,
    *,
    name: str,
    version: str,
) -> None:
    if resolved is None:
        return
    if not isinstance(resolved, str) or not resolved.strip():
        raise RuntimePreflightError(
            f"package-lock.json dependency entry {path!r} has an invalid resolved source",
            policy_id="ca9.runtime.lockfile_unavailable",
        )
    parsed = urlparse(resolved)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise RuntimePreflightError(
            f"package-lock.json dependency entry {path!r} uses an unsupported source",
            policy_id="ca9.runtime.lockfile_unavailable",
        )
    if not _registry_tarball_path_matches(parsed.path, name=name, version=version.strip()):
        # Policy checks use the entry's name and version, so the tarball npm
        # actually fetches must be that same registry artifact.
        raise RuntimePreflightError(
            f"package-lock.json dependency entry {path!r} resolves to a tarball that does "
            f"not match {name}@{version}",
            policy_id="ca9.runtime.lockfile_unavailable",
        )


def _registry_tarball_path_matches(url_path: str, *, name: str, version: str) -> bool:
    path = unquote(url_path)
    segments = path.split("/")
    if "\\" in path or any(segment in {".", ".."} for segment in segments):
        return False
    basename = name.rsplit("/", 1)[-1]
    # Registries may serve from a base path (`/api/npm/repo/...`), so match the
    # suffix. GitLab names scoped tarballs `/-/@scope/name-<version>.tgz`.
    expected = [f"/{name}/-/{basename}-{version}.tgz"]
    if name.startswith("@"):
        expected.append(f"/{name}/-/{name}-{version}.tgz")
    lowered = path.lower()
    if any(lowered.endswith(suffix.lower()) for suffix in expected):
        return True
    # GitHub Packages serves `/download/@scope/name/<version>/<sha>`.
    prefix, _, digest = lowered.rpartition("/")
    return (
        name.startswith("@")
        and prefix.endswith(f"/download/{name}/{version}".lower())
        and bool(re.fullmatch(r"[0-9a-f]{40,128}", digest))
    )


def _safe_relative_lock_path(path: str) -> bool:
    if not path or "\\" in path or "\x00" in path:
        return False
    parsed = PurePosixPath(path)
    return not parsed.is_absolute() and ".." not in parsed.parts


def _is_node_modules_lock_path(path: str) -> bool:
    return path.startswith("node_modules/") or "/node_modules/" in path


def _npm_lock_entry_name(path: str, entry: dict[str, Any]) -> str | None:
    raw_name = entry.get("name")
    if isinstance(raw_name, str) and raw_name.strip():
        return raw_name.strip()
    segment = path.rsplit("node_modules/", 1)[-1]
    parts = segment.split("/")
    if parts[0].startswith("@") and len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0] or None


def _valid_npm_lock_name(name: str | None) -> bool:
    if not name or name != name.strip():
        return False
    if name.startswith("@"):
        parts = name.split("/")
        return len(parts) == 2 and all(part for part in parts) and parts[0] != "@"
    return "/" not in name


def _parse_npm_spec(spec: str) -> PackageRequest:
    return _parse_npm_registry_spec(spec, raw_spec=spec, allow_alias=True)


def _parse_npm_registry_spec(spec: str, *, raw_spec: str, allow_alias: bool) -> PackageRequest:
    # Classify the spec the way npm-package-arg does. Only registry versions,
    # ranges, tags, and `npm:` aliases resolve through the registry (and so the
    # gateway); URL, git, hosted-git, file, directory, and tarball specs are
    # fetched directly by npm and are unsupported.
    if spec[:4].lower() == "npm:":
        return _parse_npm_alias(spec, raw_spec=raw_spec, allow_alias=allow_alias)
    if _NPM_URL_SPEC_RE.match(spec) or _NPM_GIT_SCP_SPEC_RE.match(spec):
        raise _unsupported_npm_source(raw_spec)
    name_end = spec.find("@", 1) if spec.startswith("@") else spec.find("@")
    name = spec[:name_end] if name_end > 0 else spec
    if not name.startswith("@") and (
        "/" in name or "\\" in name or _NPM_FILENAME_SPEC_RE.search(name)
    ):
        raise _unsupported_npm_source(raw_spec)
    if not _valid_npm_package_name(name):
        if name.startswith("."):
            raise _unsupported_npm_source(raw_spec)
        raise RuntimePreflightError(f"invalid npm package spec: {raw_spec}")

    version_spec: str | None = None
    if name_end > 0:
        version_spec = spec[name_end + 1 :].strip() or None
    if version_spec is not None:
        if version_spec[:4].lower() == "npm:":
            return _parse_npm_alias(version_spec, raw_spec=raw_spec, allow_alias=allow_alias)
        if (
            not _NPM_REGISTRY_SPEC_RE.fullmatch(version_spec)
            or version_spec.startswith(".")
            or _NPM_FILENAME_SPEC_RE.search(version_spec)
        ):
            raise _unsupported_npm_source(raw_spec)
    return PackageRequest(
        ecosystem="npm",
        name=name.lower(),
        raw_spec=raw_spec,
        version_spec=version_spec,
        exact_version=_exact_npm_spec_version(version_spec),
    )


def _parse_npm_alias(spec: str, *, raw_spec: str, allow_alias: bool) -> PackageRequest:
    # `alias@npm:real@range` installs `real` from the registry, so policy applies
    # to the real package. npm-package-arg rejects nested aliases.
    target = spec[4:]
    if not allow_alias or target[:4].lower() == "npm:":
        raise RuntimePreflightError(f"nested npm aliases are not supported: {raw_spec}")
    return _parse_npm_registry_spec(target, raw_spec=raw_spec, allow_alias=False)


def _unsupported_npm_source(spec: str) -> RuntimePreflightError:
    return RuntimePreflightError(
        f"unsupported npm direct, git, or local package spec: {spec}; ca9 run only "
        "installs registry packages it can check"
    )


def _valid_npm_package_name(name: str) -> bool:
    # validate-npm-package-name rules that still allow legacy (old) packages.
    if not name or name != name.strip() or name.startswith((".", "_")):
        return False
    if name.lower() in {"node_modules", "favicon.ico"}:
        return False
    if name.startswith("@"):
        scope, slash, package = name[1:].partition("/")
        return bool(
            slash and _NPM_NAME_PART_RE.fullmatch(scope) and _NPM_NAME_PART_RE.fullmatch(package)
        )
    return _NPM_NAME_PART_RE.fullmatch(name) is not None


def _exact_npm_spec_version(version_spec: str | None) -> str | None:
    if not version_spec:
        return None
    # semver's loose parsing accepts a leading `v` or `=` on an exact version.
    candidate = re.sub(r"^[=v\s]+", "", version_spec).strip()
    return candidate if _NPM_SEMVER_RE.fullmatch(candidate) else None


def _parse_pip_spec(spec: str) -> PackageRequest:
    return _parse_pip_requirement(spec).request


def _parse_pip_requirement(
    spec: str,
    *,
    source_path: str | None = None,
    hashes: tuple[str, ...] = (),
) -> _ParsedPipRequirement:
    if _is_pip_direct_or_local_spec(spec):
        raise _unsupported_pip_source(spec)
    try:
        requirement = Requirement(spec)
    except InvalidRequirement as exc:
        raise RuntimePreflightError(f"invalid pip package spec {spec!r}: {exc}") from exc
    if requirement.url is not None:
        # PEP 508 direct references (`name @ url`) bypass the package index.
        raise _unsupported_pip_source(spec)
    exact_version = None
    version_spec = str(requirement.specifier) or None
    exact_specs = [
        item.version
        for item in requirement.specifier
        if item.operator in {"==", "==="} and "*" not in item.version
    ]
    if len(exact_specs) == 1 and len(list(requirement.specifier)) == 1:
        exact_version = exact_specs[0]
    return _ParsedPipRequirement(
        request=PackageRequest(
            ecosystem="pypi",
            name=canonicalize_name(requirement.name),
            raw_spec=spec,
            version_spec=version_spec,
            exact_version=exact_version,
            source_path=source_path,
            hashes=hashes,
        ),
        requirement=requirement,
    )


def _is_pip_direct_or_local_spec(spec: str) -> bool:
    # Mirrors pip's install_req_from_line(): URLs, anything that looks like a
    # path, and archive filenames are installed from that location, not the index.
    text = spec.strip()
    head = text.split(";", 1)[0].strip()
    if "://" in text or head.lower().startswith(_PIP_DIRECT_SCHEME_PREFIXES):
        return True
    if "/" in head or "\\" in head or head.startswith("."):
        return True
    without_extras = re.sub(r"\[[^\]]*\]$", "", head)
    return without_extras.lower().endswith(_PIP_ARCHIVE_SUFFIXES)


def _unsupported_pip_source(spec: str) -> RuntimePreflightError:
    return RuntimePreflightError(
        f"unsupported pip direct or local package spec: {spec}; ca9 run only installs "
        "index packages it can check"
    )


def _with_env_registry_sources(command: RuntimeCommand, env: dict[str, str]) -> RuntimeCommand:
    sources = list(command.registry_sources)
    if command.family == "npm":
        sources.extend(_npm_env_registry_sources(env))
    elif command.family == "pip":
        sources.extend(_pip_env_registry_sources(env))
    if tuple(sources) == command.registry_sources:
        return command
    return replace(command, registry_sources=tuple(sources))


def _npm_env_registry_sources(env: dict[str, str]) -> list[RegistrySource]:
    sources: list[RegistrySource] = []
    seen: set[str] = set()
    for name in NPM_REGISTRY_ENV_NAMES:
        value = env.get(name)
        if value:
            seen.add(name)
            sources.append(
                RegistrySource(
                    ecosystem="npm",
                    kind="npm-registry",
                    url=value,
                    option=f"env:{name}",
                )
            )
    for name, value in env.items():
        lowered = name.lower()
        if (
            name not in seen
            and lowered.startswith("npm_config_")
            and lowered.endswith(":registry")
            and value
        ):
            sources.append(
                RegistrySource(
                    ecosystem="npm",
                    kind="npm-registry",
                    url=value,
                    option=f"env:{name}",
                )
            )
    for name in NPM_GATEWAY_UPSTREAM_ENV_NAMES:
        value = env.get(name)
        if value:
            sources.append(
                RegistrySource(
                    ecosystem="npm",
                    kind="npm-gateway-upstream",
                    url=value,
                    option=f"env:{name}",
                )
            )
    for name in NPM_CONFIG_FILE_ENV_NAMES:
        value = env.get(name)
        if value:
            sources.append(
                RegistrySource(
                    ecosystem="npm",
                    kind="npm-config-file",
                    url=value,
                    option=f"env:{name}",
                )
            )
    return sources


def _pip_env_registry_sources(env: dict[str, str]) -> list[RegistrySource]:
    sources: list[RegistrySource] = []
    for name in PIP_INDEX_ENV_NAMES:
        value = env.get(name)
        if value:
            sources.append(
                RegistrySource(
                    ecosystem="pypi",
                    kind="pypi-index",
                    url=value,
                    option=f"env:{name}",
                )
            )
    for name in PIP_GATEWAY_UPSTREAM_ENV_NAMES:
        value = env.get(name)
        if value:
            sources.append(
                RegistrySource(
                    ecosystem="pypi",
                    kind="pypi-gateway-upstream",
                    url=value,
                    option=f"env:{name}",
                )
            )
    for name in PIP_UNSUPPORTED_SOURCE_ENV_NAMES:
        value = env.get(name)
        if value:
            sources.append(
                RegistrySource(
                    ecosystem="pypi",
                    kind="pypi-unsupported-source",
                    url=value,
                    option=f"env:{name}",
                )
            )
    for name in PIP_CONFIG_FILE_ENV_NAMES:
        value = env.get(name)
        if value and value != os.devnull:
            sources.append(
                RegistrySource(
                    ecosystem="pypi",
                    kind="pypi-config-file",
                    url=value,
                    option=f"env:{name}",
                )
            )
    for name in PIP_REQUIREMENT_ENV_NAMES:
        value = env.get(name)
        if value:
            sources.append(
                RegistrySource(
                    ecosystem="pypi",
                    kind="pypi-requirement-env",
                    url=value,
                    option=f"env:{name}",
                )
            )
    return sources


def _load_feed_status_if_needed(
    command: RuntimeCommand,
    policy: PackagePolicy,
    *,
    feed_cache_dir: Path | None,
    now: datetime | None,
) -> FeedStatus | None:
    if not command.package_requests:
        return None
    if not policy.malware.enabled and not policy.package_age.enabled:
        return None
    return feed_status(policy=policy, cache_dir=feed_cache_dir, now=now)


def _feed_availability_decisions(
    status: FeedStatus | None,
    policy: PackagePolicy,
    *,
    release_age_defaulted: bool = False,
) -> list[RuntimeDecision]:
    if status is None:
        return []
    if status.state == "tampered":
        return [
            RuntimeDecision(
                action="block",
                policy_id="ca9.feed_unavailable",
                reason=status.reason,
                evidence={"state": status.state},
            )
        ]
    decisions: list[RuntimeDecision] = []
    if (
        policy.package_age.enabled
        and not release_age_defaulted
        and status.state in {"missing", "stale"}
    ):
        decisions.append(
            RuntimeDecision(
                action=status.action,
                policy_id="ca9.feed_unavailable",
                reason=status.reason,
                evidence={"state": status.state},
            )
        )
    if policy.malware.enabled and status.state in {"missing", "stale"}:
        if policy.malware.fail_closed:
            decisions.append(
                RuntimeDecision(
                    action="block",
                    policy_id=MALWARE_FEED_UNAVAILABLE_POLICY_ID,
                    reason=(
                        f"malware policy is fail-closed and feed state is {status.state}; "
                        "run `ca9 feed update`"
                    ),
                    evidence={"state": status.state},
                )
            )
        else:
            # Never let a missing or expired feed look like a clean pass.
            decisions.append(
                RuntimeDecision(
                    action=action_for_mode("warn", policy.mode.default),
                    policy_id=MALWARE_FEED_UNAVAILABLE_POLICY_ID,
                    reason=_malware_feed_warning(status),
                    evidence={"state": status.state},
                )
            )
    return decisions


def _feed_warnings(status: FeedStatus | None, policy: PackagePolicy) -> tuple[str, ...]:
    if status is None or not policy.malware.enabled or status.state not in {"missing", "stale"}:
        return ()
    return (_malware_feed_warning(status),)


def _malware_feed_warning(status: FeedStatus) -> str:
    if status.snapshot is None:
        return (
            "malware checks are inactive because no local malware feed is installed; "
            "run `ca9 feed update` to enable them"
        )
    return (
        f"the local malware feed is stale ({status.reason}); checks use the stale snapshot "
        "and may miss new malware; run `ca9 feed update` to refresh it"
    )


def _registry_source_decisions(
    command: RuntimeCommand,
    policy: PackagePolicy,
) -> list[RuntimeDecision]:
    decisions: list[RuntimeDecision] = []
    for source in command.registry_sources:
        if source.kind in {
            "pypi-unsupported-source",
            "pypi-config-file",
            "pypi-requirement-env",
            "npm-config-file",
        }:
            decisions.append(
                RuntimeDecision(
                    action="block",
                    policy_id="ca9.runtime.unsupported_source",
                    reason=f"{source.option} is not supported by ca9 run yet",
                    evidence=source.to_dict(),
                )
            )
            continue
        if _registry_denied(source.url, policy.registries.deny):
            decisions.append(
                RuntimeDecision(
                    action=action_for_mode("block", policy.mode.default),
                    policy_id="ca9.denied_registry",
                    reason=f"{source.option} points to denied registry {source.url}",
                    evidence=source.to_dict(),
                )
            )
            continue
        if policy.registries.custom_requires_approval and not _registry_allowed(
            source.url,
            policy.registries.allow,
        ):
            decisions.append(
                RuntimeDecision(
                    action=action_for_mode("block", policy.mode.default),
                    policy_id="ca9.untrusted_registry",
                    reason=f"{source.option} points to untrusted registry {source.url}",
                    evidence=source.to_dict(),
                )
            )
    return decisions


def _gateway_requirement_source_decisions(
    command: RuntimeCommand,
    policy: PackagePolicy,
    feed: FeedStatus | None,
) -> list[RuntimeDecision]:
    gateway_active = (
        command.family == "pip"
        and (policy.malware.enabled or policy.package_age.enabled)
        and feed is not None
        and feed.snapshot is not None
    )
    if not gateway_active:
        return []
    return [
        RuntimeDecision(
            action="block",
            policy_id="ca9.runtime.requirements_unavailable",
            reason=(
                f"pip source option is not supported while the PyPI gateway is active: "
                f"{source.option}"
            ),
            evidence=source.to_dict(),
        )
        for source in command.registry_sources
        if source.kind == "pypi-requirement-index"
    ]


def _malware_decisions(
    command: RuntimeCommand,
    policy: PackagePolicy,
    snapshot: FeedSnapshot,
    feed_cache_dir: Path | None,
) -> list[RuntimeDecision]:
    if not policy.malware.enabled:
        return []
    decisions: list[RuntimeDecision] = []
    for request in command.package_requests:
        matches = lookup_malware(
            request.ecosystem,
            request.name,
            request.exact_version,
            cache_dir=feed_cache_dir,
            snapshot=snapshot,
        )
        if request.exact_version is None:
            matches = tuple(entry for entry in matches if not entry.get("version"))
        for entry in matches:
            action = action_for_mode("block", policy.mode.default)
            decisions.append(
                RuntimeDecision(
                    action=action,
                    policy_id="ca9.malware",
                    reason=str(
                        entry.get("summary")
                        or entry.get("id")
                        or "local feed marks this package as malicious"
                    ),
                    package=request.name,
                    version=request.exact_version,
                    evidence={
                        "feed_snapshot": snapshot.snapshot_id,
                        "malware_id": entry.get("id"),
                        "feed_version": entry.get("version"),
                    },
                )
            )
    return decisions


def _package_age_decisions(
    command: RuntimeCommand,
    policy: PackagePolicy,
    snapshot: FeedSnapshot | None,
    *,
    now: datetime | None,
    defaulted: bool = False,
    cache_root: Path | None = None,
    fetch: Any = None,
    env: dict[str, str] | None = None,
    warnings: list[str] | None = None,
) -> list[RuntimeDecision]:
    """Package-age decisions for exact requests, in request order.

    Release times come from the feed, then registry metadata. npm lockfile
    entries the feed cannot date are left to the npm gateway, which reads the
    same release-time cache, so ``npm ci`` does not fetch every packument twice.
    """
    if not policy.package_age.enabled:
        return []
    active_now = now or datetime.now(timezone.utc)
    minimum_hours = policy.package_age.minimum_hours
    notes: list[str] = []
    if warnings is not None:
        notes = warnings
    planned: list[tuple[PackageRequest, str | None]] = []
    decisions: list[RuntimeDecision] = []
    for request in command.package_requests:
        if _is_age_excluded(request, policy.package_age.exclusions):
            continue
        if request.exact_version is None:
            if request.ecosystem == "npm" or defaulted:
                continue
            planned.append((request, "unknown"))
            continue
        released_at = None
        if snapshot is not None:
            released_at = lookup_release_time(
                request.ecosystem,
                request.name,
                request.exact_version,
                snapshot=snapshot,
            )
        if released_at:
            planned.append((request, released_at))
            continue
        if snapshot is not None and release_window_covers(
            snapshot,
            request.ecosystem,
            now=active_now,
            minimum_hours=minimum_hours,
        ):
            continue
        if request.ecosystem == "npm" and request.from_lockfile:
            continue
        planned.append((request, None))

    registry = _release_registry(command, policy, env or {})

    def lookup(request: PackageRequest) -> dict[str, Any]:
        return check_release_age(
            request.ecosystem,
            request.name,
            str(request.exact_version),
            min_hours=minimum_hours,
            cache_dir=cache_root,
            fetch=fetch,
            registry=registry,
            now=active_now,
        )

    to_lookup = [request for request, released_at in planned if released_at is None]
    lookups: dict[str, dict[str, Any]] = {}
    if to_lookup:
        with ThreadPoolExecutor(max_workers=min(RELEASE_LOOKUP_WORKERS, len(to_lookup))) as pool:
            for request, result in zip(to_lookup, pool.map(lookup, to_lookup), strict=True):
                lookups[request.key] = result

    for request, released_at in planned:
        if released_at == "unknown":
            decisions.append(_unknown_release_time_decision(request, policy, snapshot))
            continue
        suggested_version = None
        release_source = "feed"
        if released_at is None:
            result = lookups[request.key]
            if result["status"] == "old_enough":
                continue
            if result["status"] == "too_new" and result.get("published_at"):
                released_at = str(result["published_at"])
                suggested_version = result.get("suggested_version")
                release_source = str(result.get("source") or "registry")
            elif request.ecosystem == "npm":
                continue
            elif defaulted:
                notes.append(
                    f"release time for {request.name}=={request.exact_version} is unknown; "
                    f"the default {minimum_hours}h release-age hold was not applied"
                )
                continue
            else:
                decisions.append(_unknown_release_time_decision(request, policy, snapshot))
                continue
        released = _parse_feed_time(released_at)
        age_hours = (active_now - released).total_seconds() / 3600
        if age_hours >= minimum_hours:
            continue
        action = action_for_mode("block", policy.mode.default)
        reason = (
            f"package version age is {age_hours:.1f}h, below policy minimum of {minimum_hours}h"
        )
        evidence: dict[str, Any] = {
            "released_at": released_at,
            "age_hours": round(age_hours, 2),
            "minimum_hours": minimum_hours,
            "feed_snapshot": _snapshot_id(snapshot),
            "release_source": release_source,
        }
        if defaulted:
            evidence["default_policy"] = True
        if suggested_version:
            evidence["suggested_version"] = suggested_version
            reason = f"{reason}; use {suggested_version}, which is older than the window"
        decisions.append(
            RuntimeDecision(
                action=action,
                policy_id="ca9.package_age",
                reason=reason,
                package=request.name,
                version=request.exact_version,
                evidence=evidence,
            )
        )
    return decisions


def _snapshot_id(snapshot: FeedSnapshot | None) -> str | None:
    if snapshot is None:
        return None
    return snapshot.snapshot_id


def _release_cache_root(feed_cache_dir: Path | None) -> Path | None:
    if feed_cache_dir is None:
        return None
    return Path(feed_cache_dir).parent


def _release_registry(
    command: RuntimeCommand,
    policy: PackagePolicy,
    env: dict[str, str],
) -> str | None:
    """Registry to read npm publish times from: the trusted one npm will use."""
    if command.family != "npm":
        return None
    candidate = env.get("CA9_NPM_UPSTREAM_REGISTRY") or primary_registry_url(command)
    if not candidate:
        return DEFAULT_NPM_REGISTRY
    if not candidate.startswith("https://") or not _registry_allowed(
        candidate, policy.registries.allow
    ):
        return DEFAULT_NPM_REGISTRY
    return candidate


def _unknown_release_time_decision(
    request: PackageRequest,
    policy: PackagePolicy,
    snapshot: FeedSnapshot | None,
) -> RuntimeDecision:
    action = action_for_mode("block", policy.mode.offline)
    target = f"{request.name}@{request.exact_version}" if request.exact_version else request.name
    return RuntimeDecision(
        action=action,
        policy_id="ca9.package_age_unknown",
        reason=(
            f"release time for {target} is not available in the local feed or registry "
            "metadata; ca9 cannot verify the minimum package age"
        ),
        package=request.name,
        version=request.exact_version,
        evidence={
            "feed_snapshot": _snapshot_id(snapshot),
            "minimum_hours": policy.package_age.minimum_hours,
            "offline_mode": policy.mode.offline,
        },
    )


def _secret_decision(
    command: RuntimeCommand,
    policy: PackagePolicy,
    secrets: tuple[str, ...],
) -> tuple[RuntimeDecision | None, tuple[str, ...]]:
    if not secrets or not command.install_scripts_possible:
        return None, ()
    if policy.install_scripts.block_when_secrets_present:
        action = action_for_mode("block", policy.mode.default)
        stripped = secrets if action == "warn" and policy.ci.strip_secret_env_for_installs else ()
        if action == "pass":
            stripped = ()
        if stripped:
            action = "strip"
        return (
            RuntimeDecision(
                action=action,
                policy_id="ca9.install_scripts.secrets",
                reason="package install may run scripts while secret-bearing environment variables are present",
                evidence={"secret_names": list(secrets)},
            ),
            stripped,
        )
    if policy.ci.strip_secret_env_for_installs:
        return (
            RuntimeDecision(
                action="strip",
                policy_id="ca9.ci.strip_secret_env",
                reason="secret-bearing environment variables will be stripped before package install",
                evidence={"secret_names": list(secrets)},
            ),
            secrets,
        )
    action = action_for_mode("warn", policy.mode.default)
    return (
        RuntimeDecision(
            action=action,
            policy_id="ca9.install_scripts.secrets",
            reason="package install may run scripts while secret-bearing environment variables are present",
            evidence={"secret_names": list(secrets)},
        ),
        (),
    )


def _is_exact_npm_version(version: str) -> bool:
    if not version:
        return False
    if version in {"latest", "next"}:
        return False
    if re.search(r"[\^~<>=*xX| ]", version):
        return False
    return bool(re.match(r"^[0-9][0-9A-Za-z.+-]*$", version))


def _is_age_excluded(request: PackageRequest, exclusions: tuple[str, ...]) -> bool:
    target = request.name.lower()
    versioned = f"{request.ecosystem}:{target}@{request.exact_version}".lower()
    for pattern in exclusions:
        normalized = pattern.strip().lower()
        if not normalized:
            continue
        if _glob_match(target, normalized) or _glob_match(versioned, normalized):
            return True
    return False


def _glob_match(value: str, pattern: str) -> bool:
    from fnmatch import fnmatch

    return fnmatch(value, pattern)


def _strip_option_values(command: tuple[str, ...], flags: set[str]) -> tuple[str, ...]:
    stripped: list[str] = []
    index = 0
    while index < len(command):
        arg = command[index]
        flag_name = arg.split("=", 1)[0]
        if flag_name in flags:
            if "=" not in arg and index + 1 < len(command):
                index += 2
            else:
                index += 1
            continue
        stripped.append(arg)
        index += 1
    return tuple(stripped)


def _registry_allowed(registry: str, candidates: tuple[str, ...]) -> bool:
    return _registry_matches(registry, candidates)


def _registry_denied(registry: str, candidates: tuple[str, ...]) -> bool:
    return _registry_matches(registry, candidates)


def _registry_matches(registry: str, candidates: tuple[str, ...]) -> bool:
    normalized_registry = _normalize_index_url(registry)
    registry_host = _index_host(registry)
    for candidate in candidates:
        normalized_candidate = _normalize_index_url(candidate)
        if normalized_registry == normalized_candidate:
            return True
        candidate_host = _index_host(candidate)
        candidate_path = _index_path(candidate)
        if (
            candidate_host
            and registry_host
            and candidate_host == registry_host
            and not candidate_path
        ):
            return True
    return False


def _normalize_index_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme and parsed.netloc:
        path = parsed.path.rstrip("/")
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}"
    return value.strip().rstrip("/").lower()


def _index_host(value: str) -> str:
    raw = value.strip()
    parsed = urlparse(raw)
    if parsed.hostname:
        return parsed.hostname.lower()
    if "://" not in raw and "/" not in raw:
        return raw.rsplit(":", 1)[0].lower()
    return ""


def _index_path(value: str) -> str:
    raw = value.strip()
    if "://" not in raw and "/" not in raw:
        return ""
    return urlparse(raw).path.rstrip("/")


def _match_secret_pattern(name: str, pattern: str) -> bool:
    return fnmatchcase(name, pattern)


def _ci_file_command_env_names(
    command: RuntimeCommand,
    policy: PackagePolicy,
    env: dict[str, str],
) -> tuple[str, ...]:
    if not policy.ci.strip_secret_env_for_installs or not command.install_scripts_possible:
        return ()
    return tuple(name for name in GITHUB_FILE_COMMAND_ENV_NAMES if name in env)


def _parse_feed_time(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise FeedError(f"invalid feed release timestamp {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
