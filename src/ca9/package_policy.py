from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python < 3.11
    import tomli as tomllib


MODE_VALUES = {"off", "warn", "block", "strict"}
OFFLINE_MODE_VALUES = {"warn", "block", "strict"}
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
class PackagePolicy:
    mode: ModePolicy = ModePolicy()
    registries: RegistriesPolicy = RegistriesPolicy()
    package_age: PackageAgePolicy = PackageAgePolicy()
    malware: MalwarePolicy = MalwarePolicy()
    install_scripts: InstallScriptsPolicy = InstallScriptsPolicy()
    ci: CIPolicy = CIPolicy()
    exceptions: tuple[PolicyException, ...] = ()
    sources: tuple[str, ...] = ()

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
    active_env = env or os.environ
    current = (cwd or Path.cwd()).resolve()
    user_home = home or Path.home()
    candidates: list[Path] = [
        user_home / ".config" / "ca9" / "policy.toml",
        current / "ca9.toml",
    ]
    env_path = active_env.get("CA9_POLICY")
    if env_path:
        candidates.append(Path(env_path).expanduser())
    return tuple(path for path in candidates if path.is_file())


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
    selected_paths = (
        paths if paths is not None else discover_policy_paths(cwd=cwd, env=env, home=home)
    )
    raw: dict[str, Any] = {}
    sources: list[str] = []
    for path in selected_paths:
        data = _read_policy_toml(path)
        _validate_raw_policy(data, path)
        root = dict(_policy_root(data))
        if isinstance(root.get("exceptions"), list):
            root["exceptions"] = [
                {**item, "_source": str(path)} if isinstance(item, dict) else item
                for item in root["exceptions"]
            ]
        raw = _deep_merge(raw, root)
        sources.append(str(path))

    policy = _policy_from_raw(raw)
    return PackagePolicy(
        mode=policy.mode,
        registries=policy.registries,
        package_age=policy.package_age,
        malware=policy.malware,
        install_scripts=policy.install_scripts,
        ci=policy.ci,
        exceptions=policy.exceptions,
        sources=tuple(sources),
    )


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
