from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python < 3.11
    import tomli as tomllib


MODE_VALUES = {"off", "warn", "block", "strict"}
OFFLINE_MODE_VALUES = {"warn", "block", "strict"}
POLICY_SECTIONS = {
    "mode",
    "registries",
    "package_age",
    "malware",
    "install_scripts",
    "ci",
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
class PackagePolicy:
    mode: ModePolicy = ModePolicy()
    registries: RegistriesPolicy = RegistriesPolicy()
    package_age: PackageAgePolicy = PackageAgePolicy()
    malware: MalwarePolicy = MalwarePolicy()
    install_scripts: InstallScriptsPolicy = InstallScriptsPolicy()
    ci: CIPolicy = CIPolicy()
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
        raw = _deep_merge(raw, _policy_root(data))
        sources.append(str(path))

    policy = _policy_from_raw(raw)
    return PackagePolicy(
        mode=policy.mode,
        registries=policy.registries,
        package_age=policy.package_age,
        malware=policy.malware,
        install_scripts=policy.install_scripts,
        ci=policy.ci,
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
    ]
    return "\n".join(lines)


def action_for_mode(action: str, mode: str) -> str:
    if mode == "off":
        return "pass"
    if mode == "warn" and action in {"block", "investigate"}:
        return "warn"
    return action


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
