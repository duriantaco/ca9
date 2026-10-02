from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, replace
from datetime import date, datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from packaging.utils import canonicalize_name

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python < 3.11
    import tomli as tomllib


MODE_VALUES = {"off", "warn", "block", "strict"}
OFFLINE_MODE_VALUES = {"warn", "block", "strict"}
# Enforcement strength used when an implicitly discovered repo policy may only tighten.
MODE_RANK = {"off": 0, "warn": 1, "block": 2, "strict": 3}
OFFLINE_MODE_RANK = {"warn": 0, "block": 1, "strict": 2}
REPO_POLICY_FILENAME = "ca9.toml"
EXCEPTION_ACTIONS = {"pass", "warn"}
NON_OVERRIDABLE_POLICY_IDS = {"ca9.malware"}
POLICY_SECTIONS = {
    "mode",
    "registries",
    "package_age",
    "malware",
    "install_scripts",
    "ci",
    "exceptions",
}


@dataclass(frozen=True)
class ModePolicy:
    default: str = "block"
    offline: str = "warn"


@dataclass(frozen=True)
class RegistriesPolicy:
    allow: tuple[str, ...] = ("registry.npmjs.org", "pypi.org", "files.pythonhosted.org")
    deny: tuple[str, ...] = ()
    custom_requires_approval: bool = True


@dataclass(frozen=True)
class PackageAgePolicy:
    enabled: bool = False
    minimum_hours: int = 48
    exclusions: tuple[str, ...] = ()


@dataclass(frozen=True)
class MalwarePolicy:
    enabled: bool = True
    fail_closed: bool = False


@dataclass(frozen=True)
class InstallScriptsPolicy:
    block_when_secrets_present: bool = True


@dataclass(frozen=True)
class CIPolicy:
    strip_secret_env_for_installs: bool = True
    block_unpinned_exec_tools: bool = True


@dataclass(frozen=True)
class PolicyException:
    policy_id: str
    owner: str
    reason: str
    expires: str
    action: str = "warn"
    ecosystem: str | None = None
    package: str | None = None
    version: str | None = None
    source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value is not None}


@dataclass(frozen=True)
class IgnoredPolicySetting:
    key: str
    requested: str
    effective: str
    source: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

    def warning(self) -> str:
        return (
            f"policy: ignored relaxing setting {self.key} = {self.requested} from "
            f"{self.source} (kept {self.effective}); an implicitly discovered repo policy "
            f"can only tighten enforcement. To trust it, pass --policy {self.source} "
            f"or set CA9_POLICY={self.source}"
        )


@dataclass(frozen=True)
class PackagePolicy:
    mode: ModePolicy = ModePolicy()
    registries: RegistriesPolicy = RegistriesPolicy()
    package_age: PackageAgePolicy = PackageAgePolicy()
    malware: MalwarePolicy = MalwarePolicy()
    install_scripts: InstallScriptsPolicy = InstallScriptsPolicy()
    ci: CIPolicy = CIPolicy()
    exceptions: tuple[PolicyException, ...] = ()
    sources: tuple[str, ...] = ()
    tighten_only_sources: tuple[str, ...] = ()
    ignored_settings: tuple[IgnoredPolicySetting, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def discover_policy_paths(
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    home: Path | None = None,
) -> tuple[Path, ...]:
    trusted, repo_policy = discover_policy_sources(cwd=cwd, env=env, home=home)
    return trusted if repo_policy is None else (*trusted, repo_policy)


def discover_policy_sources(
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    home: Path | None = None,
) -> tuple[tuple[Path, ...], Path | None]:
    """Return (trusted policy paths, tighten-only repo policy path).

    The user policy and an explicit CA9_POLICY are trusted. A ca9.toml found in
    the working directory comes from the checked-out repository, so it may only
    tighten the trusted policy unless CA9_POLICY names the same file.
    """
    active_env = os.environ if env is None else env
    current = (cwd or Path.cwd()).resolve()
    user_home = home or Path.home()
    trusted: list[Path] = []
    user_policy = user_home / ".config" / "ca9" / "policy.toml"
    if user_policy.is_file():
        trusted.append(user_policy)
    env_path = active_env.get("CA9_POLICY")
    if env_path and Path(env_path).expanduser().is_file():
        trusted.append(Path(env_path).expanduser())
    repo_policy = current / REPO_POLICY_FILENAME
    if not repo_policy.is_file() or any(_same_file(repo_policy, path) for path in trusted):
        return tuple(trusted), None
    return tuple(trusted), repo_policy


def load_package_policy(path: Path | None = None) -> PackagePolicy:
    if path is not None:
        return load_effective_package_policy(paths=(path,))
    return load_effective_package_policy()


def load_effective_package_policy(
    *,
    paths: tuple[Path, ...] | None = None,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    home: Path | None = None,
) -> PackagePolicy:
    if paths is not None:
        trusted_paths, repo_policy = tuple(paths), None
    else:
        trusted_paths, repo_policy = discover_policy_sources(cwd=cwd, env=env, home=home)
    raw: dict[str, Any] = {}
    sources: list[str] = []
    for path in trusted_paths:
        raw = _deep_merge(raw, _load_policy_root(path))
        sources.append(str(path))

    policy = _policy_from_raw(raw)
    ignored: tuple[IgnoredPolicySetting, ...] = ()
    tighten_only: tuple[str, ...] = ()
    if repo_policy is not None:
        policy, ignored = tighten_package_policy(
            policy, _load_policy_root(repo_policy), source=str(repo_policy)
        )
        sources.append(str(repo_policy))
        tighten_only = (str(repo_policy),)
    return replace(
        policy,
        sources=tuple(sources),
        tighten_only_sources=tighten_only,
        ignored_settings=ignored,
    )


def tighten_package_policy(
    base: PackagePolicy,
    root: dict[str, Any],
    *,
    source: str,
) -> tuple[PackagePolicy, tuple[IgnoredPolicySetting, ...]]:
    """Overlay an untrusted policy table on base, keeping only tightening values.

    Ordering per field, weakest to strongest:
      mode.default: off < warn < block < strict
      mode.offline: warn < block < strict
      every boolean toggle (checks, fail_closed, approvals, CI shielding): false < true
      registries.allow: only entries already allowed (narrowing); deny: additions only
      package_age.minimum_hours: higher only, unless trusted policy has age checks off
      package_age.exclusions: removals only; exceptions: never added
    """
    requested = _policy_from_raw(root)
    ignored: list[IgnoredPolicySetting] = []

    def ignore(key: str, requested_value: Any, effective_value: Any) -> None:
        ignored.append(
            IgnoredPolicySetting(
                key=key,
                requested=_format_policy_value(requested_value),
                effective=_format_policy_value(effective_value),
                source=source,
            )
        )

    def present(section: str, key: str) -> bool:
        table = root.get(section)
        return isinstance(table, dict) and key in table

    def ranked(key: str, want: str, have: str, ranks: dict[str, int]) -> str:
        if ranks[want] >= ranks[have]:
            return want
        ignore(key, want, have)
        return have

    def stricter_bool(section: str, key: str, have: bool) -> bool:
        want = getattr(getattr(requested, section), key)
        if want or not have:
            return want or have
        ignore(f"{section}.{key}", want, have)
        return have

    def tighten_bools(section: str, current: Any) -> Any:
        updates = {
            key: stricter_bool(section, key, getattr(current, key))
            for key, value in asdict(current).items()
            if isinstance(value, bool) and present(section, key)
        }
        return replace(current, **updates)

    mode = base.mode
    if present("mode", "default"):
        mode = replace(
            mode,
            default=ranked("mode.default", requested.mode.default, mode.default, MODE_RANK),
        )
    if present("mode", "offline"):
        mode = replace(
            mode,
            offline=ranked("mode.offline", requested.mode.offline, mode.offline, OFFLINE_MODE_RANK),
        )

    registries = tighten_bools("registries", base.registries)
    if present("registries", "allow"):
        covered = tuple(
            entry
            for entry in requested.registries.allow
            if _registry_entry_covered(entry, base.registries.allow)
        )
        widened = [entry for entry in requested.registries.allow if entry not in covered]
        if widened:
            ignore("registries.allow", widened, list(base.registries.allow))
        if covered:
            registries = replace(registries, allow=covered)
    if present("registries", "deny"):
        if any(entry not in requested.registries.deny for entry in base.registries.deny):
            ignore("registries.deny", list(requested.registries.deny), list(base.registries.deny))
        added = tuple(
            entry for entry in requested.registries.deny if entry not in base.registries.deny
        )
        registries = replace(registries, deny=(*base.registries.deny, *added))

    package_age = base.package_age
    if not package_age.enabled:
        # Any package-age configuration is at least as strict as age checks being off.
        package_age = replace(
            package_age,
            **{
                key: getattr(requested.package_age, key)
                for key in ("enabled", "minimum_hours", "exclusions")
                if present("package_age", key)
            },
        )
    else:
        package_age = tighten_bools("package_age", package_age)
        if present("package_age", "minimum_hours"):
            want_hours = requested.package_age.minimum_hours
            if want_hours >= package_age.minimum_hours:
                package_age = replace(package_age, minimum_hours=want_hours)
            else:
                ignore("package_age.minimum_hours", want_hours, package_age.minimum_hours)
        if present("package_age", "exclusions"):
            kept = tuple(
                item for item in requested.package_age.exclusions if item in package_age.exclusions
            )
            added = [item for item in requested.package_age.exclusions if item not in kept]
            if added:
                ignore("package_age.exclusions", added, list(package_age.exclusions))
            package_age = replace(package_age, exclusions=kept)

    for exception in requested.exceptions:
        if not any(_same_exception(exception, existing) for existing in base.exceptions):
            ignore(
                "exceptions",
                _exception_summary(exception),
                [_exception_summary(item) for item in base.exceptions],
            )

    tightened = replace(
        base,
        mode=mode,
        registries=registries,
        package_age=package_age,
        malware=tighten_bools("malware", base.malware),
        install_scripts=tighten_bools("install_scripts", base.install_scripts),
        ci=tighten_bools("ci", base.ci),
    )
    validate_effective_policy(tightened)
    return tightened, tuple(ignored)


def policy_trust_warnings(policy: PackagePolicy) -> tuple[str, ...]:
    return tuple(setting.warning() for setting in policy.ignored_settings)


def validate_package_policy(path: Path | None = None) -> PackagePolicy:
    policy = load_package_policy(path)
    validate_effective_policy(policy)
    return policy


def validate_effective_policy(policy: PackagePolicy) -> None:
    errors = _effective_policy_errors(policy)
    if errors:
        raise ValueError("; ".join(errors))


def package_policy_explain(policy: PackagePolicy) -> str:
    sources = ", ".join(policy.sources) if policy.sources else "built-in defaults"
    lines = [
        "ca9 package policy",
        f"Sources: {sources}",
    ]
    if policy.tighten_only_sources:
        lines.append("Tighten-only repo policy: " + ", ".join(policy.tighten_only_sources))
    lines += [
        f"Mode: default={policy.mode.default}, offline={policy.mode.offline}",
        (
            "Registries: allow="
            f"{', '.join(policy.registries.allow) or '(none)'}; "
            f"deny={', '.join(policy.registries.deny) or '(none)'}; "
            f"custom_requires_approval={str(policy.registries.custom_requires_approval).lower()}"
        ),
        (
            "Package age: "
            f"enabled={str(policy.package_age.enabled).lower()}, "
            f"minimum_hours={policy.package_age.minimum_hours}"
        ),
        (
            "Malware: "
            f"enabled={str(policy.malware.enabled).lower()}, "
            f"fail_closed={str(policy.malware.fail_closed).lower()}"
        ),
        (
            "Install scripts: "
            "block_when_secrets_present="
            f"{str(policy.install_scripts.block_when_secrets_present).lower()}"
        ),
        (
            "CI: "
            f"strip_secret_env_for_installs={str(policy.ci.strip_secret_env_for_installs).lower()}, "
            f"block_unpinned_exec_tools={str(policy.ci.block_unpinned_exec_tools).lower()}"
        ),
        f"Exceptions: {len(policy.exceptions)} configured",
    ]
    for exception in policy.exceptions:
        selectors = [
            value
            for value in (
                exception.ecosystem,
                exception.package,
                exception.version,
            )
            if value
        ]
        scope = "/".join(selectors) if selectors else "all matching decisions"
        lines.append(
            f"  - {exception.policy_id} -> {exception.action} for {scope}; "
            f"owner={exception.owner}; expires={exception.expires}"
        )
    if policy.ignored_settings:
        lines.append(f"Ignored relaxations: {len(policy.ignored_settings)}")
        for setting in policy.ignored_settings:
            lines.append(
                f"  - {setting.key} = {setting.requested} from {setting.source} "
                f"(kept {setting.effective})"
            )
        source = policy.ignored_settings[0].source
        lines.append(
            f"  Repo policy can only tighten; to trust it pass --policy {source} "
            f"or set CA9_POLICY={source}"
        )
    return "\n".join(lines)


def action_for_mode(action: str, mode: str) -> str:
    if mode == "off":
        return "pass"
    if mode == "warn" and action in {"block", "investigate"}:
        return "warn"
    return action


def find_policy_exception(
    exceptions: tuple[PolicyException, ...],
    *,
    policy_id: str,
    ecosystem: str | None = None,
    package: str | None = None,
    version: str | None = None,
    now: datetime | date | None = None,
) -> PolicyException | None:
    if policy_id in NON_OVERRIDABLE_POLICY_IDS:
        return None
    for exception in exceptions:
        if exception.policy_id != policy_id or policy_exception_expired(exception, now=now):
            continue
        if exception.ecosystem:
            if not ecosystem or exception.ecosystem.lower() != ecosystem.lower():
                continue
        if exception.package:
            if not package:
                continue
            normalized_package = _normalize_exception_package(package, ecosystem)
            normalized_pattern = _normalize_exception_package(exception.package, ecosystem)
            if not fnmatch(normalized_package, normalized_pattern):
                continue
        if exception.version and (not version or not fnmatch(version, exception.version)):
            continue
        return exception
    return None


def policy_exception_expired(
    exception: PolicyException,
    *,
    now: datetime | date | None = None,
) -> bool:
    current_date = _current_date(now)
    try:
        expires_on = date.fromisoformat(exception.expires)
    except (TypeError, ValueError):
        return True
    return current_date > expires_on


def expired_policy_exceptions(
    policy: PackagePolicy,
    *,
    now: datetime | date | None = None,
) -> tuple[PolicyException, ...]:
    return tuple(
        exception for exception in policy.exceptions if policy_exception_expired(exception, now=now)
    )


def _load_policy_root(path: Path) -> dict[str, Any]:
    data = _read_policy_toml(path)
    _validate_raw_policy(data, path)
    root = dict(_policy_root(data))
    if isinstance(root.get("exceptions"), list):
        root["exceptions"] = [
            {**item, "_source": str(path)} if isinstance(item, dict) else item
            for item in root["exceptions"]
        ]
    return root


def _same_file(left: Path, right: Path) -> bool:
    try:
        return os.path.samefile(left, right)
    except OSError:
        return False


def _same_exception(left: PolicyException, right: PolicyException) -> bool:
    return replace(left, source=None) == replace(right, source=None)


def _registry_entry_covered(entry: str, allowed: tuple[str, ...]) -> bool:
    # Mirrors runtime registry matching: exact URL, or a path-less entry covering its host.
    normalized = _normalize_registry_entry(entry)
    host, _ = _registry_entry_parts(entry)
    for candidate in allowed:
        if normalized == _normalize_registry_entry(candidate):
            return True
        candidate_host, candidate_path = _registry_entry_parts(candidate)
        if candidate_host and not candidate_path and candidate_host == host:
            return True
    return False


def _normalize_registry_entry(value: str) -> str:
    return value.strip().rstrip("/").lower()


def _registry_entry_parts(value: str) -> tuple[str, str]:
    raw = value.strip()
    if "://" in raw:
        parsed = urlparse(raw)
        return (parsed.hostname or "").lower(), parsed.path.rstrip("/")
    host, _, path = raw.partition("/")
    return host.rsplit(":", 1)[0].lower(), path.rstrip("/")


def _format_policy_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_format_policy_value(item) for item in value) + "]"
    if isinstance(value, str):
        return json.dumps(value)
    return str(value)


def _exception_summary(exception: PolicyException) -> str:
    selectors = "/".join(
        value for value in (exception.ecosystem, exception.package, exception.version) if value
    )
    return f"{exception.policy_id} for {selectors}" if selectors else exception.policy_id


def _read_policy_toml(path: Path) -> dict[str, Any]:
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"{path}: invalid TOML: {exc}") from exc
    except OSError as exc:
        raise ValueError(f"{path}: cannot read policy: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path}: policy must be a TOML table")
    return data


def _policy_root(data: dict[str, Any]) -> dict[str, Any]:
    tool = data.get("tool")
    if isinstance(tool, dict):
        ca9 = tool.get("ca9")
        if isinstance(ca9, dict) and any(key in ca9 for key in POLICY_SECTIONS):
            return ca9
    ca9 = data.get("ca9")
    if isinstance(ca9, dict) and any(key in ca9 for key in POLICY_SECTIONS):
        return ca9
    return data


def _validate_raw_policy(data: dict[str, Any], path: Path) -> None:
    root = _policy_root(data)
    errors: list[str] = []
    for section, value in root.items():
        if section not in POLICY_SECTIONS:
            errors.append(f"{path}: unknown policy section or key {section!r}")
            continue
        if section == "exceptions":
            errors.extend(_raw_exception_errors(path, value))
            continue
        if not isinstance(value, dict):
            errors.append(f"{path}: [{section}] must be a table")
            continue
        errors.extend(_section_type_errors(path, section, value))
    if errors:
        raise ValueError("; ".join(errors))


def _policy_from_raw(raw: dict[str, Any]) -> PackagePolicy:
    mode = raw.get("mode") if isinstance(raw.get("mode"), dict) else {}
    registries = raw.get("registries") if isinstance(raw.get("registries"), dict) else {}
    package_age = raw.get("package_age") if isinstance(raw.get("package_age"), dict) else {}
    malware = raw.get("malware") if isinstance(raw.get("malware"), dict) else {}
    install_scripts = (
        raw.get("install_scripts") if isinstance(raw.get("install_scripts"), dict) else {}
    )
    ci = raw.get("ci") if isinstance(raw.get("ci"), dict) else {}
    exceptions = raw.get("exceptions") if isinstance(raw.get("exceptions"), list) else []

    policy = PackagePolicy(
        mode=ModePolicy(
            default=_string_value(mode, "default", "block"),
            offline=_string_value(mode, "offline", "warn"),
        ),
        registries=RegistriesPolicy(
            allow=_string_tuple(registries, "allow", RegistriesPolicy().allow),
            deny=_string_tuple(registries, "deny", ()),
            custom_requires_approval=_bool_value(registries, "custom_requires_approval", True),
        ),
        package_age=PackageAgePolicy(
            enabled=_bool_value(package_age, "enabled", False),
            minimum_hours=_int_value(package_age, "minimum_hours", 48),
            exclusions=_string_tuple(package_age, "exclusions", ()),
        ),
        malware=MalwarePolicy(
            enabled=_bool_value(malware, "enabled", True),
            fail_closed=_bool_value(malware, "fail_closed", False),
        ),
        install_scripts=InstallScriptsPolicy(
            block_when_secrets_present=_bool_value(
                install_scripts, "block_when_secrets_present", True
            ),
        ),
        ci=CIPolicy(
            strip_secret_env_for_installs=_bool_value(ci, "strip_secret_env_for_installs", True),
            block_unpinned_exec_tools=_bool_value(ci, "block_unpinned_exec_tools", True),
        ),
        exceptions=tuple(_policy_exception_from_raw(item) for item in exceptions),
    )
    validate_effective_policy(policy)
    return policy


def _effective_policy_errors(policy: PackagePolicy) -> list[str]:
    errors: list[str] = []
    if policy.mode.default not in MODE_VALUES:
        errors.append("mode.default must be one of: " + ", ".join(sorted(MODE_VALUES)))
    if policy.mode.offline not in OFFLINE_MODE_VALUES:
        errors.append("mode.offline must be one of: " + ", ".join(sorted(OFFLINE_MODE_VALUES)))
    if policy.package_age.minimum_hours < 0:
        errors.append("package_age.minimum_hours must be >= 0")
    if not policy.registries.allow:
        errors.append("registries.allow must include at least one trusted registry")
    for index, exception in enumerate(policy.exceptions):
        prefix = f"exceptions[{index}]"
        for field_name in ("policy_id", "owner", "reason", "expires"):
            if not str(getattr(exception, field_name, "")).strip():
                errors.append(f"{prefix}.{field_name} must be a non-empty string")
        if exception.action not in EXCEPTION_ACTIONS:
            errors.append(
                f"{prefix}.action must be one of: " + ", ".join(sorted(EXCEPTION_ACTIONS))
            )
        if exception.policy_id in NON_OVERRIDABLE_POLICY_IDS:
            errors.append(f"{prefix}.policy_id cannot override {exception.policy_id}")
        try:
            date.fromisoformat(exception.expires)
        except (TypeError, ValueError):
            errors.append(f"{prefix}.expires must be an ISO date (YYYY-MM-DD)")
    return errors


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _string_value(section: dict[str, Any], key: str, default: str) -> str:
    value = section.get(key, default)
    return value if isinstance(value, str) else str(value)


def _bool_value(section: dict[str, Any], key: str, default: bool) -> bool:
    value = section.get(key, default)
    return value if isinstance(value, bool) else default


def _int_value(section: dict[str, Any], key: str, default: int) -> int:
    value = section.get(key, default)
    if isinstance(value, int):
        return value
    return default


def _string_tuple(section: dict[str, Any], key: str, default: tuple[str, ...]) -> tuple[str, ...]:
    value = section.get(key, default)
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(str(item) for item in value if isinstance(item, str))
    if isinstance(value, tuple):
        return tuple(str(item) for item in value if isinstance(item, str))
    return default


def _raw_exception_errors(path: Path, value: Any) -> list[str]:
    if not isinstance(value, list):
        return [f"{path}: [[exceptions]] must be an array of tables"]
    allowed_keys = {
        "policy_id",
        "owner",
        "reason",
        "expires",
        "action",
        "ecosystem",
        "package",
        "version",
    }
    required_keys = {"policy_id", "owner", "reason", "expires"}
    errors: list[str] = []
    for index, item in enumerate(value):
        prefix = f"{path}: exceptions[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be a table")
            continue
        for key in item:
            if key not in allowed_keys:
                errors.append(f"{prefix} has unknown key {key!r}")
        for key in sorted(required_keys):
            if key not in item:
                errors.append(f"{prefix}.{key} is required")
        for key in allowed_keys - {"expires"}:
            field_value = item.get(key)
            if field_value is not None and not isinstance(field_value, str):
                errors.append(f"{prefix}.{key} has invalid type")
            elif key in required_keys and isinstance(field_value, str) and not field_value.strip():
                errors.append(f"{prefix}.{key} must be a non-empty string")
        expires = item.get("expires")
        if expires is not None:
            try:
                _normalize_exception_expiry(expires)
            except ValueError:
                errors.append(f"{prefix}.expires must be an ISO date (YYYY-MM-DD)")
        action = item.get("action", "warn")
        if isinstance(action, str) and action not in EXCEPTION_ACTIONS:
            errors.append(
                f"{prefix}.action must be one of: " + ", ".join(sorted(EXCEPTION_ACTIONS))
            )
        policy_id = item.get("policy_id")
        if policy_id in NON_OVERRIDABLE_POLICY_IDS:
            errors.append(f"{prefix}.policy_id cannot override {policy_id}")
    return errors


def _policy_exception_from_raw(raw: Any) -> PolicyException:
    item = raw if isinstance(raw, dict) else {}
    return PolicyException(
        policy_id=str(item.get("policy_id") or ""),
        owner=str(item.get("owner") or ""),
        reason=str(item.get("reason") or ""),
        expires=_normalize_exception_expiry(item.get("expires")),
        action=str(item.get("action") or "warn"),
        ecosystem=_optional_string(item.get("ecosystem")),
        package=_optional_string(item.get("package")),
        version=_optional_string(item.get("version")),
        source=_optional_string(item.get("_source")),
    )


def _normalize_exception_expiry(value: Any) -> str:
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, str):
        return date.fromisoformat(value.strip()).isoformat()
    raise ValueError("invalid exception expiry")


def _optional_string(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _normalize_exception_package(value: str, ecosystem: str | None) -> str:
    if (ecosystem or "").lower() == "npm":
        return value.strip().lower()
    if "*" in value or "?" in value or "[" in value:
        return re.sub(r"[-_.]+", "-", value.strip()).lower()
    return str(canonicalize_name(value))


def _current_date(now: datetime | date | None) -> date:
    if isinstance(now, datetime):
        current = now
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        return current.astimezone(timezone.utc).date()
    if isinstance(now, date):
        return now
    return datetime.now(timezone.utc).date()


def _section_type_errors(path: Path, section: str, values: dict[str, Any]) -> list[str]:
    expected: dict[str, type | tuple[type, ...]] = {
        "mode.default": str,
        "mode.offline": str,
        "registries.allow": list,
        "registries.deny": list,
        "registries.custom_requires_approval": bool,
        "package_age.enabled": bool,
        "package_age.minimum_hours": int,
        "package_age.exclusions": list,
        "malware.enabled": bool,
        "malware.fail_closed": bool,
        "install_scripts.block_when_secrets_present": bool,
        "ci.strip_secret_env_for_installs": bool,
        "ci.block_unpinned_exec_tools": bool,
    }
    errors: list[str] = []
    for key, value in values.items():
        dotted = f"{section}.{key}"
        expected_type = expected.get(dotted)
        if expected_type is None:
            errors.append(f"{path}: unknown policy key {dotted}")
            continue
        if not isinstance(value, expected_type):
            errors.append(f"{path}: {dotted} has invalid type")
            continue
        if isinstance(value, list) and not all(isinstance(item, str) for item in value):
            errors.append(f"{path}: {dotted} must contain only strings")
    return errors
