from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from packaging.requirements import InvalidRequirement, Requirement

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
from ca9.package_policy import PackagePolicy, action_for_mode

RUN_SCHEMA = "ca9.run.v1"
LEDGER_SCHEMA = "ca9.run.ledger.v1"
SECRET_ENV_PATTERNS = (
    "*_TOKEN",
    "*_SECRET",
    "*_KEY",
    "AWS_*",
    "GCP_*",
    "GOOGLE_*",
    "AZURE_*",
    "NPM_TOKEN",
    "PYPI_TOKEN",
    "GITHUB_TOKEN",
)
_URL_CREDENTIALS_RE = re.compile(r"(?P<prefix>(?:https?|git\+https)://)(?P<creds>[^/@\s]+)@")
_AUTHORIZATION_RE = re.compile(
    r"(?i)\b(?P<name>authorization|proxy-authorization)"
    r"(?P<sep>\s*[:=]\s*)"
    r"(?P<scheme>bearer|basic|token)?"
    r"(?P<space>\s*)"
    r"(?P<value>[^,\s;]+)"
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
    "--no-cache-dir",
    "--disable-pip-version-check",
}
SUPPORTED_NPM_FLAGS_WITH_VALUE = {
    "--registry",
    "--tag",
    "--cache",
    "--prefix",
    "--omit",
    "--include",
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
}
NPM_REGISTRY_ENV_NAMES = ("NPM_CONFIG_REGISTRY", "npm_config_registry")
NPM_CONFIG_FILE_ENV_NAMES = (
    "NPM_CONFIG_USERCONFIG",
    "npm_config_userconfig",
    "NPM_CONFIG_GLOBALCONFIG",
    "npm_config_globalconfig",
)
PIP_INDEX_ENV_NAMES = ("PIP_INDEX_URL",)
PIP_UNSUPPORTED_SOURCE_ENV_NAMES = ("PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS")
PIP_CONFIG_FILE_ENV_NAMES = ("PIP_CONFIG_FILE",)


@dataclass(frozen=True)
class PackageRequest:
    ecosystem: str
    name: str
    raw_spec: str
    version_spec: str | None = None
    exact_version: str | None = None

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
            "command": [redact_sensitive_text(item) for item in self.command],
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
            "executed": executed,
            "child_exit_code": child_exit_code,
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
    pass


def parse_install_command(command: tuple[str, ...] | list[str]) -> RuntimeCommand:
    args = tuple(command)
    if not args:
        raise RuntimePreflightError("ca9 run needs a package-manager command after --")

    if _is_npm_install(args):
        requests, registry_sources = _parse_npm_install(args)
        return RuntimeCommand(
            family="npm",
            command=args,
            package_requests=tuple(requests),
            registry_sources=tuple(registry_sources),
            install_scripts_possible="--ignore-scripts" not in args,
        )

    if _is_pip_install(args):
        requests, registry_sources = _parse_pip_install(args)
        return RuntimeCommand(
            family="pip",
            command=args,
            package_requests=tuple(requests),
            registry_sources=tuple(registry_sources),
        )

    raise RuntimePreflightError(
        "unsupported command family; phase 4 supports only npm install, npm i, "
        "python -m pip install, and pip install"
    )


def evaluate_runtime_preflight(
    command: tuple[str, ...] | list[str],
    policy: PackagePolicy,
    *,
    env: dict[str, str] | None = None,
    feed_cache_dir: Path | None = None,
    now: datetime | None = None,
) -> RuntimePreflight:
    active_env = env if env is not None else dict(os.environ)
    try:
        parsed = parse_install_command(command)
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
                    policy_id="ca9.runtime.unsupported_command",
                    reason=str(exc),
                ),
            ),
        )

    parsed = _with_env_registry_sources(parsed, active_env)
    decisions: list[RuntimeDecision] = []
    feed = _load_feed_status_if_needed(parsed, policy, feed_cache_dir=feed_cache_dir, now=now)
    decisions.extend(_registry_source_decisions(parsed, policy))
    decisions.extend(_feed_availability_decisions(feed, policy))
    if feed and feed.snapshot:
        decisions.extend(_malware_decisions(parsed, policy, feed.snapshot, feed_cache_dir))
        decisions.extend(_package_age_decisions(parsed, policy, feed.snapshot, now=now))

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
    )


def child_environment(env: dict[str, str], preflight: RuntimePreflight) -> dict[str, str]:
    child_env = dict(env)
    for name in preflight.stripped_secret_names:
        child_env.pop(name, None)
    return child_env


def primary_registry_url(command: RuntimeCommand) -> str | None:
    for source in command.registry_sources:
        if source.kind in {"npm-registry", "pypi-index"}:
            return source.url
    return None


def gateway_child_command(command: RuntimeCommand) -> tuple[str, ...]:
    if command.family == "npm":
        return _strip_option_values(command.command, {"--registry"})
    if command.family == "pip":
        return _strip_option_values(command.command, {"--index-url", "-i"})
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
) -> LedgerEvent:
    return LedgerEvent("child_process_exited", {"exit_code": child_exit_code}, session_id)


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
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        for event in events:
            f.write(json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":")))
            f.write("\n")
    return path


def format_preflight(preflight: RuntimePreflight) -> str:
    lines = [
        f"ca9 runtime preflight: {preflight.action}",
        f"Command: {' '.join(redact_sensitive_text(item) for item in preflight.command.command)}",
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
        if any(_match_secret_pattern(upper, pattern) for pattern in SECRET_ENV_PATTERNS):
            names.append(name)
    return tuple(sorted(names))


def redact_sensitive_text(value: str) -> str:
    redacted = _URL_CREDENTIALS_RE.sub(r"\g<prefix>[redacted]@", value)
    return _AUTHORIZATION_RE.sub(_redact_authorization_match, redacted)


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


def _is_npm_install(args: tuple[str, ...]) -> bool:
    return len(args) >= 3 and args[0] == "npm" and args[1] in {"install", "i"}


def _is_pip_install(args: tuple[str, ...]) -> bool:
    if len(args) >= 3 and args[0] == "pip" and args[1] == "install":
        return True
    return len(args) >= 5 and args[0] == "python" and args[1:4] == ("-m", "pip", "install")


def _parse_npm_install(args: tuple[str, ...]) -> tuple[list[PackageRequest], list[RegistrySource]]:
    specs, registry_sources = _collect_specs(
        args[2:],
        bool_flags=SUPPORTED_NPM_BOOL_FLAGS,
        flags_with_value=SUPPORTED_NPM_FLAGS_WITH_VALUE,
        registry_flags={"--registry"},
        manager="npm",
        ecosystem="npm",
    )
    return [_parse_npm_spec(spec) for spec in specs], registry_sources


def _parse_pip_install(args: tuple[str, ...]) -> tuple[list[PackageRequest], list[RegistrySource]]:
    start = 2 if args[0] == "pip" else 4
    specs, registry_sources = _collect_specs(
        args[start:],
        bool_flags=SUPPORTED_PIP_BOOL_FLAGS,
        flags_with_value=SUPPORTED_PIP_FLAGS_WITH_VALUE,
        registry_flags={"--index-url", "-i"},
        unsupported_source_flags=UNSUPPORTED_PIP_SOURCE_FLAGS,
        manager="pip",
        ecosystem="pypi",
    )
    return [_parse_pip_spec(spec) for spec in specs], registry_sources


def _collect_specs(
    args: tuple[str, ...],
    *,
    bool_flags: set[str],
    flags_with_value: set[str],
    registry_flags: set[str],
    manager: str,
    ecosystem: str,
    unsupported_source_flags: set[str] | None = None,
) -> tuple[list[str], list[RegistrySource]]:
    specs: list[str] = []
    registry_sources: list[RegistrySource] = []
    blocked_source_flags = unsupported_source_flags or set()
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            index += 1
            continue
        if arg in {"-r", "--requirement", "-c", "--constraint"}:
            raise RuntimePreflightError(
                f"{manager} requirements or constraint files are not supported by ca9 run yet"
            )
        if arg.startswith("-"):
            flag_name = arg.split("=", 1)[0]
            if flag_name in blocked_source_flags:
                raise RuntimePreflightError(
                    f"{manager} source option is not supported by ca9 run yet: {flag_name}"
                )
            if flag_name in flags_with_value:
                value = None
                if "=" not in arg:
                    index += 1
                    if index >= len(args):
                        raise RuntimePreflightError(
                            f"{manager} install option needs a value: {flag_name}"
                        )
                    value = args[index]
                else:
                    value = arg.split("=", 1)[1]
                if flag_name in registry_flags:
                    registry_sources.append(
                        RegistrySource(
                            ecosystem=ecosystem,
                            kind=_registry_source_kind(manager, flag_name),
                            url=value,
                            option=flag_name,
                        )
                    )
            elif flag_name not in bool_flags:
                raise RuntimePreflightError(f"unsupported {manager} install option: {arg}")
            index += 1
            continue
        specs.append(arg)
        index += 1
    if not specs:
        raise RuntimePreflightError(
            f"{manager} install command did not include a direct package spec"
        )
    return specs, registry_sources


def _registry_source_kind(manager: str, flag_name: str) -> str:
    if manager == "npm" and flag_name == "--registry":
        return "npm-registry"
    if manager == "pip" and flag_name in {"--index-url", "-i"}:
        return "pypi-index"
    return "registry"


def _parse_npm_spec(spec: str) -> PackageRequest:
    if _is_direct_or_local_spec(spec):
        raise RuntimePreflightError(f"unsupported npm direct or local package spec: {spec}")

    name = spec
    version_spec: str | None = None
    exact_version: str | None = None
    if spec.startswith("@"):
        slash = spec.find("/")
        if slash < 0:
            raise RuntimePreflightError(f"invalid npm scoped package spec: {spec}")
        remainder = spec[slash + 1 :]
        at = remainder.rfind("@")
        if at > 0:
            name = spec[: slash + 1 + at]
            version_spec = remainder[at + 1 :]
    elif "@" in spec:
        name, version_spec = spec.rsplit("@", 1)
    if not name or "/" in name.strip("/"):
        if not name.startswith("@"):
            raise RuntimePreflightError(f"invalid npm package spec: {spec}")
    if version_spec and _is_exact_npm_version(version_spec):
        exact_version = version_spec
    return PackageRequest(
        ecosystem="npm",
        name=name.lower(),
        raw_spec=spec,
        version_spec=version_spec,
        exact_version=exact_version,
    )


def _parse_pip_spec(spec: str) -> PackageRequest:
    if _is_direct_or_local_spec(spec) or "://" in spec:
        raise RuntimePreflightError(f"unsupported pip direct or local package spec: {spec}")
    try:
        requirement = Requirement(spec)
    except InvalidRequirement as exc:
        raise RuntimePreflightError(f"invalid pip package spec {spec!r}: {exc}") from exc
    exact_version = None
    version_spec = str(requirement.specifier) or None
    exact_specs = [item.version for item in requirement.specifier if item.operator == "=="]
    if len(exact_specs) == 1 and len(list(requirement.specifier)) == 1:
        exact_version = exact_specs[0]
    return PackageRequest(
        ecosystem="pypi",
        name=requirement.name.lower().replace("_", "-"),
        raw_spec=spec,
        version_spec=version_spec,
        exact_version=exact_version,
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
    if policy.package_age.enabled and status.state in {"missing", "stale"}:
        decisions.append(
            RuntimeDecision(
                action=status.action,
                policy_id="ca9.feed_unavailable",
                reason=status.reason,
                evidence={"state": status.state},
            )
        )
    if (
        policy.malware.enabled
        and policy.malware.fail_closed
        and status.state in {"missing", "stale"}
    ):
        decisions.append(
            RuntimeDecision(
                action="block",
                policy_id="ca9.malware_feed_unavailable",
                reason=f"malware policy is fail-closed and feed state is {status.state}",
                evidence={"state": status.state},
            )
        )
    return decisions


def _registry_source_decisions(
    command: RuntimeCommand,
    policy: PackagePolicy,
) -> list[RuntimeDecision]:
    decisions: list[RuntimeDecision] = []
    for source in command.registry_sources:
        if source.kind in {"pypi-unsupported-source", "pypi-config-file", "npm-config-file"}:
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
    snapshot: FeedSnapshot,
    *,
    now: datetime | None,
) -> list[RuntimeDecision]:
    if not policy.package_age.enabled:
        return []
    active_now = now or datetime.now(timezone.utc)
    decisions: list[RuntimeDecision] = []
    for request in command.package_requests:
        if _is_age_excluded(request, policy.package_age.exclusions):
            continue
        if request.exact_version is None:
            if request.ecosystem == "npm":
                continue
            decisions.append(_unknown_release_time_decision(request, policy, snapshot))
            continue
        released_at = lookup_release_time(
            request.ecosystem,
            request.name,
            request.exact_version,
            snapshot=snapshot,
        )
        if not released_at:
            if request.ecosystem == "npm":
                continue
            if release_window_covers(
                snapshot,
                request.ecosystem,
                now=active_now,
                minimum_hours=policy.package_age.minimum_hours,
            ):
                continue
            decisions.append(_unknown_release_time_decision(request, policy, snapshot))
            continue
        released = _parse_feed_time(released_at)
        age_hours = (active_now - released).total_seconds() / 3600
        if age_hours >= policy.package_age.minimum_hours:
            continue
        action = action_for_mode("block", policy.mode.default)
        decisions.append(
            RuntimeDecision(
                action=action,
                policy_id="ca9.package_age",
                reason=(
                    f"package version age is {age_hours:.1f}h, below policy minimum "
                    f"of {policy.package_age.minimum_hours}h"
                ),
                package=request.name,
                version=request.exact_version,
                evidence={
                    "released_at": released_at,
                    "age_hours": round(age_hours, 2),
                    "minimum_hours": policy.package_age.minimum_hours,
                    "feed_snapshot": snapshot.snapshot_id,
                },
            )
        )
    return decisions


def _unknown_release_time_decision(
    request: PackageRequest,
    policy: PackagePolicy,
    snapshot: FeedSnapshot,
) -> RuntimeDecision:
    action = action_for_mode("block", policy.mode.offline)
    target = f"{request.name}@{request.exact_version}" if request.exact_version else request.name
    return RuntimeDecision(
        action=action,
        policy_id="ca9.package_age_unknown",
        reason=(
            f"release time for {target} is not available in the local feed; "
            "ca9 cannot verify the minimum package age"
        ),
        package=request.name,
        version=request.exact_version,
        evidence={
            "feed_snapshot": snapshot.snapshot_id,
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


def _is_direct_or_local_spec(spec: str) -> bool:
    lowered = spec.lower()
    return (
        lowered.startswith((".", "/", "file:", "git+", "git:", "github:", "http:", "https:"))
        or lowered.endswith(".tgz")
        or lowered.endswith(".whl")
        or lowered.endswith(".zip")
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
    if pattern.startswith("*"):
        return name.endswith(pattern[1:])
    if pattern.endswith("*"):
        return name.startswith(pattern[:-1])
    return name == pattern


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
