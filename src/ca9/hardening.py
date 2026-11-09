"""Install-hardening settings a repository commits, and PRs that weaken them.

Units follow each tool's 2026 semantics: npm ``min-release-age`` is days (.npmrc,
npm >= 11.10); pnpm ``minimumReleaseAge`` is minutes (pnpm-workspace.yaml in pnpm
11, which defaults to 1440 and ignores pnpm keys in .npmrc; .npmrc
``minimum-release-age`` in pnpm 10); Yarn ``npmMinimalAgeGate`` is a duration
(.yarnrc.yml, bare numbers are minutes, default 1d since 4.15); Bun
``install.minimumReleaseAge`` is seconds (bunfig.toml); uv ``exclude-newer`` and pip
``uploaded-prior-to`` take relative durations or absolute dates; Dependabot
``cooldown.default-days`` is days (3 by default since 2026-07-14); Renovate
``minimumReleaseAge`` is a duration. pnpm 11 replaced ``onlyBuiltDependencies`` with
``allowBuilds`` and defaults ``strictDepBuilds`` to true; npm 12 turns dependency
install scripts off unless allowed (``allowScripts``).
"""

from __future__ import annotations

import configparser
import fnmatch
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ca9.agent_config import jsonc

try:
    import tomllib
except ImportError:
    import tomli as tomllib

try:
    import yaml
except ImportError:
    yaml = None

SCHEMA = "ca9.hardening.v1"
MAX_ACTION_REFS = 2000
MAX_ACTION_FILES = 500
MAX_CHECK_FAILED = 20
PNPM_SETTINGS_IN_WORKSPACE_ONLY = 11
MAX_BYTES = 4 * 1024 * 1024
DEPENDABOT_DEFAULT_DAYS = 3
COOLDOWN_KEYS = (
    "npm_days",
    "pnpm_minutes",
    "yarn",
    "bun_seconds",
    "uv",
    "pip",
    "dependabot_days",
    "renovate",
)
_COOLDOWN_LABELS = {
    "npm_days": "npm min-release-age",
    "pnpm_minutes": "pnpm minimumReleaseAge",
    "yarn": "Yarn npmMinimalAgeGate",
    "bun_seconds": "Bun install.minimumReleaseAge",
    "uv": "uv exclude-newer",
    "pip": "pip uploaded-prior-to",
    "dependabot_days": "Dependabot cooldown",
    "renovate": "Renovate minimumReleaseAge",
}
_UNIT_MINUTES = {
    "s": 1 / 60,
    "sec": 1 / 60,
    "secs": 1 / 60,
    "second": 1 / 60,
    "seconds": 1 / 60,
    "m": 1,
    "min": 1,
    "mins": 1,
    "minute": 1,
    "minutes": 1,
    "h": 60,
    "hr": 60,
    "hrs": 60,
    "hour": 60,
    "hours": 60,
    "d": 1440,
    "day": 1440,
    "days": 1440,
    "w": 10080,
    "wk": 10080,
    "wks": 10080,
    "week": 10080,
    "weeks": 10080,
    "mo": 43200,
    "month": 43200,
    "months": 43200,
    "y": 525600,
    "yr": 525600,
    "year": 525600,
    "years": 525600,
}
_ISO_DURATION = re.compile(
    r"^P(?:(?P<w>\d+(?:\.\d+)?)W)?(?:(?P<d>\d+(?:\.\d+)?)D)?"
    r"(?:T(?:(?P<h>\d+(?:\.\d+)?)H)?(?:(?P<m>\d+(?:\.\d+)?)M)?(?:(?P<s>\d+(?:\.\d+)?)S)?)?$",
    re.IGNORECASE,
)
_FRIENDLY_PART = re.compile(r"(\d+(?:\.\d+)?)\s*([a-z]+)", re.IGNORECASE)
_USES = re.compile(r"^\s*(?:-\s*)?uses\s*:\s*(['\"]?)([^'\"\s#]+)\1", re.MULTILINE)
_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
_SCRIPT_OVERRIDES = re.compile(
    r"\b(?P<npm>npm_config_ignore_scripts)\s*[:=]\s*['\"]?(?P<npm_value>false|0|no|off)\b"
    r"|(?<![\w-])(?P<negated>--no-ignore-scripts)\b"
    r"|(?<![\w.-])(?P<flag>--(?:config\.)?ignore-scripts)(?:[ \t]*=[ \t]*|[ \t]+)['\"]?"
    r"(?P<flag_value>false|0|no|off)\b"
    r"|\b(?:npm|pnpm|yarn)[ \t]+config[ \t]+set[ \t]+(?:-\S+[ \t]+)*(?P<config>ignore-scripts)"
    r"[ \t=]+['\"]?(?P<config_value>false|0)\b"
    r"|(?<![\w.-])(?P<rc>ignore-scripts)[ \t]*=[ \t]*['\"]?(?P<rc_value>false|0)\b"
    r"|\b(?P<yarn>yarn_enable_scripts)\s*[:=]\s*['\"]?(?P<yarn_value>true|1|yes|on)\b"
    r"|\b(?P<berry>enableScripts)(?:[ \t]*[:=][ \t]*|[ \t]+)['\"]?(?P<berry_value>true|1)\b",
    re.IGNORECASE,
)
_OVERRIDE_GROUPS = ("npm", "negated", "flag", "config", "rc", "yarn", "berry")
_COOLDOWN_OVERRIDES = (
    (
        "npm_days",
        re.compile(
            r"(?<![\w.-])(?P<option>npm_config_min_release_age|(?:--)?(?:config\.)?min-release-age)"
            r"(?:[ \t]*[:=][ \t]*|[ \t]+)['\"]?(?P<value>\d+(?:\.\d+)?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "pnpm_minutes",
        re.compile(
            r"(?<![\w.-])(?P<option>(?:npm|pnpm)_config_minimum_release_age|"
            r"(?:--)?(?:config\.)?minimum-release-age)"
            r"(?:[ \t]*[:=][ \t]*|[ \t]+)['\"]?(?P<value>\d+(?:\.\d+)?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "yarn",
        re.compile(
            r"(?<![\w.-])(?P<option>yarn_npm_minimal_age_gate|npmMinimalAgeGate)"
            r"(?:[ \t]*[:=][ \t]*|[ \t]+)['\"]?(?P<value>\d[\w.]*)",
            re.IGNORECASE,
        ),
    ),
)
_RENOVATE_PACKAGE_MATCHERS = (
    "matchPackageNames",
    "matchPackagePatterns",
    "matchPackagePrefixes",
    "matchDepNames",
    "matchDepPatterns",
    "matchDepPrefixes",
    "matchSourceUrls",
    "matchSourceUrlPrefixes",
)
_MATCH_ALL = frozenset({"*", "**", ".*", "/.*/", "/.+/", "/^.*$/", "/^.+$/"})
_PNPM_NPMRC_KEYS = (
    "minimum-release-age",
    "minimum-release-age-exclude",
    "strict-dep-builds",
    "only-built-dependencies",
    "never-built-dependencies",
    "dangerously-allow-all-builds",
)
_RENOVATE_FILES = (
    "renovate.json",
    "renovate.json5",
    ".github/renovate.json",
    ".github/renovate.json5",
    ".gitlab/renovate.json",
    ".gitlab/renovate.json5",
    ".renovaterc",
    ".renovaterc.json",
    ".renovaterc.json5",
)


def settings(repo_root: str | Path) -> dict[str, Any]:
    root = Path(repo_root)
    state = _State(root)
    if not root.is_dir():
        state.error(".", "repository root is not a directory")
        return state.result()
    _managers(state)
    _npmrc(state)
    _package_json(state)
    _pnpm_workspace(state)
    _yarnrc(state)
    _bunfig(state)
    _uv(state)
    _pip(state)
    _dependabot(state)
    _renovate(state)
    _actions(state)
    return state.result()


class _State:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.cooldown: dict[str, Any] = dict.fromkeys(COOLDOWN_KEYS)
        self.scripts: dict[str, Any] = {
            "npm_ignore_scripts": None,
            "npm12_allow_scripts": [],
            "pnpm_strict_dep_builds": None,
            "pnpm_allow_builds": [],
            "pnpm_only_built_dependencies": [],
            "pnpm_dangerously_allow_all_builds": None,
            "bun_trusted_dependencies": [],
            "bun_ignore_scripts": None,
            "yarn_enable_scripts": None,
            "pnpm_never_built_dependencies": [],
            "workflow_overrides": [],
        }
        self.actions: dict[str, Any] = {"pinned": 0, "unpinned": 0, "refs": [], "truncated": False}
        self.sources: dict[str, str] = {}
        self.exclusions: dict[str, list[str]] = {}
        self.dependabot: list[dict[str, Any]] = []
        self.managers: dict[str, str] = {}
        self.renovate_presets: list[str] = []
        self.renovate_rules: list[dict[str, Any]] = []
        self.cooldown_overrides: list[dict[str, Any]] = []
        self.ignored: list[dict[str, str]] = []
        self.pnpm_major: int | None = None
        self.errors: list[dict[str, str]] = []

    def pnpm_workspace_only(self) -> bool:
        return self.pnpm_major is not None and self.pnpm_major >= PNPM_SETTINGS_IN_WORKSPACE_ONLY

    def ignore(self, setting: str, rel: str, reason: str) -> None:
        self.ignored.append({"setting": setting, "file": rel, "reason": reason})

    def text(self, rel: str) -> str | None:
        path = self.root / rel
        try:
            if not path.is_file():
                return None
            with open(path, "rb") as handle:
                raw = handle.read(MAX_BYTES + 1)
        except OSError as exc:
            self.error(rel, f"cannot read: {exc}")
            return None
        if len(raw) > MAX_BYTES:
            self.error(rel, f"larger than {MAX_BYTES} bytes; not read")
            return None
        return raw.decode("utf-8-sig", errors="replace")

    def set(self, group: dict[str, Any], key: str, value: Any, rel: str) -> None:
        group[key] = value
        self.sources[key] = rel

    def exclude(self, manager: str, values: Any, rel: str) -> None:
        names = _names(values)
        if names:
            self.exclusions[manager] = sorted(set(self.exclusions.get(manager, [])) | set(names))
            self.sources[f"exclusions.{manager}"] = rel

    def error(self, rel: str, reason: str) -> None:
        self.errors.append({"file": rel, "reason": reason})

    def result(self) -> dict[str, Any]:
        status = "complete"
        if self.errors:
            status = "partial"
        return {
            "schema": SCHEMA,
            "cooldown": self.cooldown,
            "scripts": self.scripts,
            "actions": self.actions,
            "sources": self.sources,
            "cooldown_minutes": {
                key: cooldown_minutes(self.cooldown, key) for key in COOLDOWN_KEYS
            },
            "exclusions": self.exclusions,
            "dependabot": self.dependabot,
            "managers": self.managers,
            "renovate_presets": self.renovate_presets,
            "renovate_rules": self.renovate_rules,
            "cooldown_overrides": self.cooldown_overrides,
            "ignored": self.ignored,
            "errors": self.errors,
            "status": status,
        }


def _npmrc(state: _State) -> None:
    text = state.text(".npmrc")
    if text is None:
        return
    values: dict[str, list[str]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")) or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().lower()
        value = value.strip().strip("'\"")
        if key.endswith("[]"):
            values.setdefault(key[:-2], []).append(value)
        else:
            values[key] = [value]
    rel = ".npmrc"
    if state.pnpm_workspace_only():
        for key in _PNPM_NPMRC_KEYS:
            if values.pop(key, None) is not None:
                state.ignore(key, rel, "pnpm 11 reads pnpm settings from pnpm-workspace.yaml only")
    if "min-release-age" in values:
        state.set(state.cooldown, "npm_days", _number(values["min-release-age"][-1]), rel)
    if "ignore-scripts" in values:
        state.set(state.scripts, "npm_ignore_scripts", _bool(values["ignore-scripts"][-1]), rel)
    if "minimum-release-age" in values:
        state.set(state.cooldown, "pnpm_minutes", _number(values["minimum-release-age"][-1]), rel)
    if "strict-dep-builds" in values:
        strict = _bool(values["strict-dep-builds"][-1])
        state.set(state.scripts, "pnpm_strict_dep_builds", strict, rel)
    if "only-built-dependencies" in values:
        names = _split_list(values["only-built-dependencies"])
        state.set(state.scripts, "pnpm_only_built_dependencies", names, rel)
    if "dangerously-allow-all-builds" in values:
        allow_all = _bool(values["dangerously-allow-all-builds"][-1])
        state.set(state.scripts, "pnpm_dangerously_allow_all_builds", allow_all, rel)
    if "never-built-dependencies" in values:
        names = _split_list(values["never-built-dependencies"])
        state.set(state.scripts, "pnpm_never_built_dependencies", names, rel)
    for key in ("allow-scripts", "allowscripts"):
        if key in values:
            state.set(state.scripts, "npm12_allow_scripts", _split_list(values[key]), rel)
    if "min-release-age-exclude" in values:
        state.exclude("npm", _split_list(values["min-release-age-exclude"]), rel)
    if "minimum-release-age-exclude" in values:
        state.exclude("pnpm", _split_list(values["minimum-release-age-exclude"]), rel)


def _package_json(state: _State) -> None:
    text = state.text("package.json")
    if text is None:
        return
    try:
        data = json.loads(text)
    except ValueError as exc:
        state.error("package.json", f"could not parse: {exc}")
        return
    if not isinstance(data, dict):
        return
    rel = "package.json"
    pnpm = data.get("pnpm")
    if isinstance(pnpm, dict):
        _pnpm_build_lists(state, pnpm, rel)
        if "allowBuilds" in pnpm:
            state.set(state.scripts, "pnpm_allow_builds", _allowed(pnpm["allowBuilds"]), rel)
        if "strictDepBuilds" in pnpm:
            strict = _bool(pnpm["strictDepBuilds"])
            state.set(state.scripts, "pnpm_strict_dep_builds", strict, rel)
        if "minimumReleaseAge" in pnpm:
            minutes = _number(pnpm["minimumReleaseAge"])
            state.set(state.cooldown, "pnpm_minutes", minutes, rel)
    if "trustedDependencies" in data:
        trusted = _names(data["trustedDependencies"])
        state.set(state.scripts, "bun_trusted_dependencies", trusted, rel)
    if "allowScripts" in data:
        state.set(state.scripts, "npm12_allow_scripts", _allowed(data["allowScripts"]), rel)
    if isinstance(data.get("renovate"), dict):
        _renovate_config(state, data["renovate"], "package.json")


def _managers(state: _State) -> None:
    text = state.text("package.json")
    if text is None:
        return
    try:
        data = json.loads(text)
    except ValueError:
        return
    if not isinstance(data, dict):
        return
    manager = data.get("packageManager")
    if isinstance(manager, str) and "@" in manager:
        name, _, version = manager.partition("@")
        state.managers[name.strip()] = version.split("+")[0].strip()
    dev_engines = data.get("devEngines")
    if isinstance(dev_engines, dict) and isinstance(dev_engines.get("packageManager"), dict):
        declared = dev_engines["packageManager"]
        if isinstance(declared.get("name"), str) and isinstance(declared.get("version"), str):
            state.managers.setdefault(declared["name"].strip(), declared["version"].strip())
    engines = data.get("engines")
    if isinstance(engines, dict) and isinstance(engines.get("pnpm"), str):
        state.managers.setdefault("pnpm", engines["pnpm"].strip())
    match = re.search(r"(\d+)", state.managers.get("pnpm", ""))
    if match:
        state.pnpm_major = int(match.group(1))


def _pnpm_build_lists(state: _State, data: dict[str, Any], rel: str) -> None:
    for key, setting in (
        ("onlyBuiltDependencies", "pnpm_only_built_dependencies"),
        ("neverBuiltDependencies", "pnpm_never_built_dependencies"),
    ):
        if key not in data:
            continue
        if state.pnpm_workspace_only():
            state.ignore(key, rel, "removed in pnpm 11 (replaced by allowBuilds)")
            continue
        state.set(state.scripts, setting, _names(data[key]), rel)


def _pnpm_workspace(state: _State) -> None:
    rel = "pnpm-workspace.yaml"
    data = _yaml_mapping(state, rel)
    if data is None:
        return
    if "minimumReleaseAge" in data:
        state.set(state.cooldown, "pnpm_minutes", _number(data["minimumReleaseAge"]), rel)
    if "minimumReleaseAgeExclude" in data:
        state.exclude("pnpm", data["minimumReleaseAgeExclude"], rel)
    if "strictDepBuilds" in data:
        state.set(state.scripts, "pnpm_strict_dep_builds", _bool(data["strictDepBuilds"]), rel)
    if "allowBuilds" in data:
        state.set(state.scripts, "pnpm_allow_builds", _allowed(data["allowBuilds"]), rel)
    _pnpm_build_lists(state, data, rel)
    if "dangerouslyAllowAllBuilds" in data:
        allow_all = _bool(data["dangerouslyAllowAllBuilds"])
        state.set(state.scripts, "pnpm_dangerously_allow_all_builds", allow_all, rel)


def _yarnrc(state: _State) -> None:
    rel = ".yarnrc.yml"
    data = _yaml_mapping(state, rel)
    if data is None:
        return
    if data.get("npmMinimalAgeGate") is not None:
        state.set(state.cooldown, "yarn", str(data["npmMinimalAgeGate"]).strip(), rel)
    if "npmPreapprovedPackages" in data:
        state.exclude("yarn", data["npmPreapprovedPackages"], rel)
    if "enableScripts" in data:
        state.set(state.scripts, "yarn_enable_scripts", _bool(data["enableScripts"]), rel)


def _bunfig(state: _State) -> None:
    rel = "bunfig.toml"
    data = _toml(state, rel) or {}
    install = data.get("install")
    if not isinstance(install, dict):
        return
    if "minimumReleaseAge" in install:
        state.set(state.cooldown, "bun_seconds", _number(install["minimumReleaseAge"]), rel)
    if "minimumReleaseAgeExcludes" in install:
        state.exclude("bun", install["minimumReleaseAgeExcludes"], rel)
    if "ignoreScripts" in install:
        state.set(state.scripts, "bun_ignore_scripts", _bool(install["ignoreScripts"]), rel)


def _uv(state: _State) -> None:
    for rel, table in (("pyproject.toml", ("tool", "uv")), ("uv.toml", ())):
        data = _toml(state, rel)
        for key in table:
            if not isinstance(data, dict):
                break
            data = data.get(key)
        if not isinstance(data, dict):
            continue
        if data.get("exclude-newer") is not None:
            state.set(state.cooldown, "uv", str(data["exclude-newer"]).strip(), rel)
        if isinstance(data.get("exclude-newer-package"), dict):
            state.exclude("uv", list(data["exclude-newer-package"]), rel)


def _pip(state: _State) -> None:
    for rel in ("pip.conf", "pip.ini"):
        text = state.text(rel)
        if text is None:
            continue
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            parser.read_string(text)
        except configparser.Error as exc:
            state.error(rel, f"could not parse: {exc}")
            continue
        for section in ("global", "install"):
            for key in ("uploaded-prior-to", "uploaded_prior_to"):
                if parser.has_option(section, key):
                    state.set(state.cooldown, "pip", parser.get(section, key).strip(), rel)
    candidates = sorted(state.root.glob("requirements*.txt")) + sorted(
        state.root.glob("requirements/*.txt")
    )
    for path in candidates:
        rel = path.relative_to(state.root).as_posix()
        text = state.text(rel)
        if text is None:
            continue
        match = re.search(r"^\s*--uploaded-prior-to(?:\s*=\s*|\s+)(\S+)", text, re.MULTILINE)
        if match:
            state.set(state.cooldown, "pip", match.group(1).strip("'\""), rel)


def _dependabot(state: _State) -> None:
    for rel in (".github/dependabot.yml", ".github/dependabot.yaml"):
        data = _yaml_mapping(state, rel, nested=True)
        if data is None:
            continue
        updates = data.get("updates")
        if not isinstance(updates, list):
            return
        days: list[int | float] = []
        for update in updates:
            if not isinstance(update, dict):
                continue
            directories = _names(update.get("directories"))
            if isinstance(update.get("directory"), str):
                directories = [update["directory"], *directories]
            directories = [_normal_directory(item) for item in directories] or ["/"]
            directory = ",".join(directories)
            cooldown = update.get("cooldown")
            default_days = None
            if isinstance(cooldown, dict):
                default_days = _number(cooldown.get("default-days"))
                state.exclude("dependabot", cooldown.get("exclude"), rel)
            if default_days is not None:
                days.append(default_days)
            state.dependabot.append(
                {
                    "ecosystem": str(update.get("package-ecosystem") or ""),
                    "directory": directory,
                    "directories": directories,
                    "default_days": default_days,
                }
            )
        state.sources["dependabot"] = rel
        if days:
            state.set(state.cooldown, "dependabot_days", min(days), rel)
        return


def _normal_directory(value: str) -> str:
    directory = "/" + value.strip().strip("/")
    return directory


def _renovate(state: _State) -> None:
    for rel in _RENOVATE_FILES:
        text = state.text(rel)
        if text is None:
            continue
        try:
            data = jsonc.parse(text).value
        except jsonc.JsoncError:
            match = re.search(r"\bminimumReleaseAge['\"]?\s*:\s*['\"]([^'\"]+)['\"]", text)
            if match:
                state.set(state.cooldown, "renovate", match.group(1).strip(), rel)
            continue
        if isinstance(data, dict):
            _renovate_config(state, data, rel)
        return


def _renovate_config(state: _State, data: dict[str, Any], rel: str) -> None:
    if isinstance(data.get("minimumReleaseAge"), str):
        state.set(state.cooldown, "renovate", data["minimumReleaseAge"].strip(), rel)
    presets = data.get("extends")
    if isinstance(presets, list):
        state.renovate_presets = [str(item) for item in presets if isinstance(item, str)]
    rules = data.get("packageRules")
    if not isinstance(rules, list):
        return
    for rule in rules:
        if not isinstance(rule, dict) or "minimumReleaseAge" not in rule:
            continue
        patterns: list[str] = []
        for key in _RENOVATE_PACKAGE_MATCHERS:
            patterns.extend(_names(rule.get(key)))
        raw = rule["minimumReleaseAge"]
        value = None
        if isinstance(raw, str):
            value = raw.strip()
        state.renovate_rules.append(
            {
                "match": sorted(patterns),
                "all": not patterns or any(item in _MATCH_ALL for item in patterns),
                "minimum_release_age": value,
            }
        )
    if state.renovate_rules:
        state.sources["renovate_rules"] = rel


def _actions(state: _State) -> None:
    queue: list[Path] = []
    for pattern in (
        ".github/workflows/*.yml",
        ".github/workflows/*.yaml",
        ".github/actions/**/action.yml",
        ".github/actions/**/action.yaml",
    ):
        queue.extend(sorted(state.root.glob(pattern)))
    for name in ("action.yml", "action.yaml"):
        queue.append(state.root / name)
    try:
        root = state.root.resolve()
    except OSError:
        return
    seen: set[Path] = set()
    while queue:
        path = queue.pop(0)
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if resolved in seen or root not in resolved.parents or not resolved.is_file():
            continue
        if len(seen) >= MAX_ACTION_FILES:
            state.actions["truncated"] = True
            break
        seen.add(resolved)
        rel = resolved.relative_to(root).as_posix()
        text = state.text(rel)
        if text is None:
            continue
        _workflow_overrides(state, rel, text)
        for uses, line in _uses_values(text):
            if uses.startswith(("./", ".\\")):
                queue.extend(_local_action_files(root, uses))
                continue
            _count_action(state, rel, uses, line)
    if state.actions["refs"]:
        state.sources["actions"] = ".github/workflows"


def _count_action(state: _State, rel: str, uses: str, line: int) -> None:
    pinned, ref = _ref_pinned(uses)
    key = "unpinned"
    if pinned:
        key = "pinned"
    state.actions[key] += 1
    if len(state.actions["refs"]) >= MAX_ACTION_REFS:
        state.actions["truncated"] = True
        return
    state.actions["refs"].append(
        {"file": rel, "uses": _action_name(uses), "ref": ref, "pinned": pinned, "line": line}
    )


def _local_action_files(root: Path, uses: str) -> list[Path]:
    target = root / uses[2:].split("@")[0]
    if target.suffix in {".yml", ".yaml"}:
        return [target]
    return [target / "action.yml", target / "action.yaml"]


def _uses_values(text: str) -> list[tuple[str, int]]:
    hits = [
        (match.group(2), text.count("\n", 0, match.start(2)) + 1)
        for match in _USES.finditer(text)
        if not match.group(2).startswith(("*", "&"))
    ]
    parsed = _yaml_uses(text)
    if parsed is None:
        return hits
    values: list[tuple[str, int]] = []
    for value in parsed:
        hit = next((item for item in hits if item[0] == value), None)
        if hit is not None:
            hits.remove(hit)
            values.append(hit)
            continue
        position = text.find(value)
        values.append((value, text.count("\n", 0, max(position, 0)) + 1))
    return values


def _yaml_uses(text: str) -> list[str] | None:
    if yaml is None:
        return None
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    found: list[str] = []
    stack = [document]
    visited: set[int] = set()
    while stack:
        node = stack.pop()
        if id(node) in visited:
            continue
        if isinstance(node, dict):
            visited.add(id(node))
            for key, value in node.items():
                if key == "uses" and isinstance(value, str):
                    found.append(value.strip())
                elif isinstance(value, (dict, list)):
                    stack.append(value)
        elif isinstance(node, list):
            visited.add(id(node))
            stack.extend(reversed(node))
    return found


def _workflow_overrides(state: _State, rel: str, text: str) -> None:
    """CI lines that turn install scripts back on or lower a cooldown: environment
    variables, CLI flags (``--no-ignore-scripts``, ``--ignore-scripts false``,
    ``--config.ignore-scripts=false``, ``--min-release-age=0``), ``config set`` and
    lines written into .npmrc or .yarnrc.yml."""
    for match in _SCRIPT_OVERRIDES.finditer(text):
        if _commented(text, match.start()):
            continue
        groups = match.groupdict()
        for name in _OVERRIDE_GROUPS:
            if not groups[name]:
                continue
            setting = groups[name].lower()
            value = (groups.get(f"{name}_value") or "false").lower()
            if name == "negated":
                setting = "--ignore-scripts"
            state.scripts["workflow_overrides"].append(
                {
                    "file": rel,
                    "line": text.count("\n", 0, match.start()) + 1,
                    "setting": setting,
                    "value": value,
                }
            )
            state.sources["workflow_overrides"] = rel
            break
    for key, pattern in _COOLDOWN_OVERRIDES:
        for match in pattern.finditer(text):
            if _commented(text, match.start()):
                continue
            state.cooldown_overrides.append(
                {
                    "file": rel,
                    "line": text.count("\n", 0, match.start()) + 1,
                    "setting": key,
                    "option": match.group("option").lower(),
                    "value": match.group("value"),
                }
            )
            state.sources["cooldown_overrides"] = rel


def _commented(text: str, offset: int) -> bool:
    line_start = text.rfind("\n", 0, offset) + 1
    return text[line_start:offset].strip().startswith("#")


def _ref_pinned(uses: str) -> tuple[bool, str]:
    if uses.startswith("docker://"):
        _, _, digest = uses.partition("@")
        return bool(re.match(r"^sha256:[0-9a-f]{64}$", digest)), digest or uses
    _, at, ref = uses.rpartition("@")
    if not at:
        return False, ""
    return bool(_FULL_SHA.match(ref)), ref


def _action_name(uses: str) -> str:
    if uses.startswith("docker://"):
        return uses.split("@")[0]
    return uses.rpartition("@")[0] or uses


def _yaml_mapping(state: _State, rel: str, *, nested: bool = False) -> dict[str, Any] | None:
    text = state.text(rel)
    if text is None:
        return None
    if yaml is not None:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            state.error(rel, f"could not parse: {exc}")
            return None
        if isinstance(data, dict):
            return data
        return None
    if nested:
        state.error(rel, "PyYAML is not installed; not read")
        return None
    return _simple_yaml(text)


def _simple_yaml(text: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    current: str | None = None
    for raw_line in text.splitlines():
        line = re.sub(r"(^|\s)#.*$", "", raw_line).rstrip()
        if not line.strip():
            continue
        if not line.startswith((" ", "\t", "-")):
            key, _, value = line.partition(":")
            current = key.strip().strip("'\"")
            if value.strip():
                data[current] = _scalar(value.strip())
                current = None
            continue
        if current is None:
            continue
        item = line.strip()
        if item.startswith("-"):
            container = data.setdefault(current, [])
            if isinstance(container, list):
                container.append(_scalar(item[1:].strip()))
        elif ":" in item:
            container = data.setdefault(current, {})
            if isinstance(container, dict):
                key, _, value = item.partition(":")
                container[key.strip().strip("'\"")] = _scalar(value.strip())
    return data


def _scalar(value: str) -> Any:
    stripped = value.strip("'\"")
    lowered = stripped.lower()
    if value[:1] in {"'", '"'}:
        return stripped
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    number = _number(stripped)
    if number is not None:
        return number
    return stripped


def _toml(state: _State, rel: str) -> dict[str, Any] | None:
    text = state.text(rel)
    if text is None:
        return None
    try:
        return tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError) as exc:
        state.error(rel, f"could not parse: {exc}")
        return None


def _number(value: Any) -> int | float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str) and re.fullmatch(r"\s*\d+(?:\.\d+)?\s*", value):
        number = float(value)
        if number.is_integer():
            return int(number)
        return number
    return None


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in {"true", "yes", "on", "1"}:
        return True
    if isinstance(value, str) and value.strip().lower() in {"false", "no", "off", "0"}:
        return False
    return None


def _names(value: Any) -> list[str]:
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if isinstance(item, (str, int)) and str(item)]
    if isinstance(value, dict):
        return [str(key) for key in value]
    return []


def _split_list(values: list[str]) -> list[str]:
    names: list[str] = []
    for value in values:
        names.extend(_names(value))
    return names


def _allowed(value: Any) -> list[str]:
    if isinstance(value, dict):
        return sorted(str(key) for key, allowed in value.items() if allowed not in (False, None))
    return sorted(_names(value))


def duration_minutes(value: Any, bare_unit: str | None) -> float | None:
    """Minutes in a cooldown value; None when unset, absolute or unreadable."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        if bare_unit is None:
            return None
        return float(value) * _UNIT_MINUTES[bare_unit]
    text = str(value).strip()
    if not text:
        return None
    number = _number(text)
    if number is not None:
        if bare_unit is None:
            return None
        return float(number) * _UNIT_MINUTES[bare_unit]
    iso = _ISO_DURATION.match(text)
    if iso and any(iso.groupdict().values()):
        parts = iso.groupdict()
        total = 0.0
        for key, unit in (("w", 10080), ("d", 1440), ("h", 60), ("m", 1), ("s", 1 / 60)):
            if parts[key]:
                total += float(parts[key]) * unit
        return total
    pairs = _FRIENDLY_PART.findall(text)
    remainder = _FRIENDLY_PART.sub("", text).replace(",", "").replace("and", "").strip()
    if pairs and not remainder:
        total = 0.0
        for amount, unit in pairs:
            minutes = _UNIT_MINUTES.get(unit.lower())
            if minutes is None:
                return None
            total += float(amount) * minutes
        return total
    return None


def cooldown_minutes(cooldown: Mapping[str, Any], key: str) -> float | None:
    value = cooldown.get(key)
    units = {
        "npm_days": "d",
        "pnpm_minutes": "m",
        "yarn": "m",
        "bun_seconds": "s",
        "uv": None,
        "pip": None,
        "dependabot_days": "d",
        "renovate": None,
    }
    return duration_minutes(value, units.get(key))


def regressions(base: Any, head: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    old = _snapshot("base", base, found)
    new = _snapshot("head", head, found)
    if old is not None and new is not None:
        _cooldown_regressions(old, new, found)
        _renovate_rule_regressions(old, new, found)
        _dependabot_regressions(old, new, found)
        _exclusion_regressions(old, new, found)
        _script_regressions(old, new, found)
        _override_regressions(old, new, found)
        _cooldown_override_regressions(old, new, found)
        _action_regressions(old, new, found)
    found.sort(key=lambda item: (item["kind"], item["path"] or "", item["detail"]))
    return found


def _failed(side: str, detail: str, path: Any) -> dict[str, Any]:
    item = _item("check_failed", detail, None, "", None, None)
    if isinstance(path, str):
        item["path"] = path
    item["side"] = side
    return item


def _snapshot(side: str, value: Any, found: list[dict[str, Any]]) -> dict[str, Any] | None:
    if isinstance(value, (str, Path)):
        value = settings(value)
    if not isinstance(value, Mapping) or value.get("schema") != SCHEMA:
        found.append(_failed(side, f"{side} is not a {SCHEMA} snapshot or a repository path", None))
        return None
    snapshot = dict(value)
    errors = snapshot.get("errors")
    listed: list[Mapping[str, Any]] = []
    if isinstance(errors, list):
        listed = [error for error in errors if isinstance(error, Mapping)]
    status = snapshot.get("status")
    if status not in {None, "complete"} and not listed:
        found.append(
            _failed(side, f"{side} snapshot is {status}; some settings were not read", None)
        )
    for error in listed[:MAX_CHECK_FAILED]:
        detail = f"{side}: could not read {error.get('file')}: {error.get('reason')}"
        found.append(_failed(side, detail, error.get("file")))
    if any(error.get("file") == "." for error in listed):
        return None
    return snapshot


def _group(snapshot: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    group = snapshot.get(name)
    if isinstance(group, Mapping):
        return group
    return {}


def _path(old: Mapping[str, Any], new: Mapping[str, Any], key: str) -> str | None:
    for snapshot in (new, old):
        sources = _group(snapshot, "sources")
        if isinstance(sources.get(key), str):
            return sources[key]
    return None


def _item(kind: str, detail: str, path: str | None, setting: str, base: Any, head: Any) -> dict:
    return {
        "kind": kind,
        "detail": detail,
        "path": path,
        "setting": setting,
        "base": base,
        "head": head,
    }


def _major(snapshot: Mapping[str, Any], manager: str) -> int | None:
    version = _group(snapshot, "managers").get(manager)
    if isinstance(version, str):
        match = re.match(r"^\D*(\d+)(?:\.(\d+))?", version)
        if match:
            return int(match.group(1)) * 1000 + int(match.group(2) or 0)
    return None


def _default_minutes(snapshot: Mapping[str, Any], key: str) -> tuple[float | None, str]:
    if key == "pnpm_minutes":
        version = _major(snapshot, "pnpm")
        if version is not None and version >= 11000:
            return 1440.0, "pnpm 11's default of 1440 minutes applies"
    if key == "yarn":
        version = _major(snapshot, "yarn")
        if version is not None and version >= 4015:
            return 1440.0, "Yarn 4.15's default of 1d applies"
    return None, ""


def _cooldown_regressions(
    old: Mapping[str, Any], new: Mapping[str, Any], found: list[dict[str, Any]]
) -> None:
    before = _group(old, "cooldown")
    after = _group(new, "cooldown")
    for key in COOLDOWN_KEYS:
        if key == "dependabot_days" and _has_dependabot_entries(old):
            continue
        base_value = before.get(key)
        head_value = after.get(key)
        if base_value is None:
            continue
        base_minutes = cooldown_minutes(before, key)
        label = _COOLDOWN_LABELS[key]
        path = _path(old, new, key)
        if head_value is None:
            default, note = _default_minutes(new, key)
            if default is not None and base_minutes is not None and default >= base_minutes:
                continue
            detail = f"{label} was removed (was {base_value})"
            if note:
                detail = f"{detail}; {note}"
            found.append(_item("cooldown_removed", detail, path, key, base_value, None))
            continue
        head_minutes = cooldown_minutes(after, key)
        if base_minutes is None or head_minutes is None:
            continue
        if head_minutes < base_minutes:
            detail = f"{label} lowered from {base_value} to {head_value}"
            found.append(_item("cooldown_lowered", detail, path, key, base_value, head_value))


def _dependabot_entries(snapshot: Mapping[str, Any]) -> list[tuple[str, list[str], Any]]:
    entries: list[tuple[str, list[str], Any]] = []
    raw = snapshot.get("dependabot")
    if not isinstance(raw, list):
        return entries
    for entry in raw:
        if not isinstance(entry, Mapping):
            continue
        directories = entry.get("directories")
        if not isinstance(directories, list):
            directories = str(entry.get("directory") or "/").split(",")
        normal = [_normal_directory(str(item)) for item in directories]
        days = entry.get("default_days")
        if isinstance(days, bool) or not isinstance(days, (int, float)):
            days = None
        entries.append((str(entry.get("ecosystem") or "").lower(), normal, days))
    return entries


def _covers(head_directory: str, base_directory: str) -> bool:
    return (
        head_directory == base_directory
        or fnmatch.fnmatchcase(base_directory, head_directory)
        or fnmatch.fnmatchcase(head_directory, base_directory)
    )


def _effective_days(days: Any) -> float:
    if days is None:
        return DEPENDABOT_DEFAULT_DAYS
    return days


def _has_dependabot_entries(snapshot: Mapping[str, Any]) -> bool:
    entries = snapshot.get("dependabot")
    return isinstance(entries, list) and bool(entries)


def _dependabot_regressions(
    old: Mapping[str, Any], new: Mapping[str, Any], found: list[dict[str, Any]]
) -> None:
    if not _has_dependabot_entries(old):
        return
    before = _dependabot_entries(old)
    path = _path(old, new, "dependabot")
    for ecosystem, directories, head_days in _dependabot_entries(new):
        head_effective = _effective_days(head_days)
        matched = False
        for base_ecosystem, base_directories, base_days in before:
            if base_ecosystem != ecosystem:
                continue
            covered = [
                directory
                for directory in base_directories
                if any(_covers(head, directory) for head in directories)
            ]
            if not covered:
                continue
            matched = True
            base_effective = _effective_days(base_days)
            if head_effective < base_effective:
                where = f"{ecosystem} in {', '.join(covered)}"
                found.append(_dependabot_item(where, path, base_days, base_effective, head_days))
        if not matched and head_effective < DEPENDABOT_DEFAULT_DAYS:
            where = f"{ecosystem} in {', '.join(directories)}"
            found.append(_dependabot_item(where, path, None, DEPENDABOT_DEFAULT_DAYS, head_days))


def _dependabot_item(
    where: str, path: str | None, base_days: Any, base_effective: float, head_days: Any
) -> dict[str, Any]:
    if head_days is None:
        detail = (
            f"Dependabot cooldown for {where} was removed (was {base_days} days); "
            f"the {DEPENDABOT_DEFAULT_DAYS}-day default applies"
        )
        return _item("cooldown_removed", detail, path, "dependabot_days", base_days, None)
    detail = f"Dependabot cooldown for {where} lowered from {base_effective} to {head_days} days"
    return _item("cooldown_lowered", detail, path, "dependabot_days", base_days, head_days)


def _rules(snapshot: Mapping[str, Any]) -> dict[tuple[bool, tuple[str, ...]], Any]:
    rules: dict[tuple[bool, tuple[str, ...]], Any] = {}
    raw = snapshot.get("renovate_rules")
    if not isinstance(raw, list):
        return rules
    for rule in raw:
        if not isinstance(rule, Mapping) or not isinstance(rule.get("match"), list):
            continue
        key = (bool(rule.get("all")), tuple(str(item) for item in rule["match"]))
        age = rule.get("minimum_release_age")
        minutes: float | None = 0.0
        if isinstance(age, str):
            minutes = duration_minutes(age, None)
        if minutes is not None:
            rules[key] = (age, minutes)
    return rules


def _renovate_baseline(snapshot: Mapping[str, Any], rules: dict[Any, Any]) -> float | None:
    top = cooldown_minutes(_group(snapshot, "cooldown"), "renovate")
    if top is not None:
        return top
    broad = [minutes for (all_packages, _), (_, minutes) in rules.items() if all_packages]
    if broad:
        return broad[-1]
    return None


def _renovate_rule_regressions(
    old: Mapping[str, Any], new: Mapping[str, Any], found: list[dict[str, Any]]
) -> None:
    before = _rules(old)
    after = _rules(new)
    base_baseline = _renovate_baseline(old, before)
    head_baseline = _renovate_baseline(new, after)
    path = _path(old, new, "renovate_rules")
    for key, (age, minutes) in after.items():
        reference = base_baseline
        if key in before:
            reference = before[key][1]
        if reference is None or minutes >= reference:
            continue
        found.extend(_rule_items(key, age, minutes, path))
    for key, (_, base_minutes) in before.items():
        remaining = head_baseline or 0.0
        if key not in after and base_minutes > remaining:
            found.extend(_rule_items(key, None, remaining, path))


def _rule_items(
    key: tuple[bool, tuple[str, ...]], age: Any, minutes: float, path: str | None
) -> list[dict[str, Any]]:
    all_packages, patterns = key
    shown = age or "no minimum"
    if all_packages:
        kind = "cooldown_lowered"
        if minutes <= 0:
            kind = "cooldown_removed"
        detail = f"Renovate packageRules set minimumReleaseAge to {shown} for every package"
        return [_item(kind, detail, path, "renovate", None, age)]
    items = []
    for pattern in patterns:
        kind = "cooldown_lowered"
        if minutes <= 0:
            kind = "cooldown_exclusion_added"
        detail = f"Renovate packageRules set minimumReleaseAge to {shown} for {pattern}"
        item = _item(kind, detail, path, "renovate", None, age)
        item["package"] = pattern
        items.append(item)
    return items


def _override_regressions(
    old: Mapping[str, Any], new: Mapping[str, Any], found: list[dict[str, Any]]
) -> None:
    before = {
        (item.get("file"), item.get("setting"), item.get("value"))
        for item in _group(old, "scripts").get("workflow_overrides") or []
        if isinstance(item, Mapping)
    }
    reported: set[tuple[Any, Any, Any]] = set()
    for item in _group(new, "scripts").get("workflow_overrides") or []:
        if not isinstance(item, Mapping):
            continue
        key = (item.get("file"), item.get("setting"), item.get("value"))
        if key in before or key in reported:
            continue
        reported.add(key)
        detail = (
            f"{item.get('file')} sets {item.get('setting')}={item.get('value')}, which lets "
            "dependency install scripts run in CI"
        )
        entry = _item(
            "ignore_scripts_disabled",
            detail,
            item.get("file"),
            "workflow_overrides",
            None,
            item.get("value"),
        )
        entry["line"] = item.get("line")
        found.append(entry)


def _cooldown_override_regressions(
    old: Mapping[str, Any], new: Mapping[str, Any], found: list[dict[str, Any]]
) -> None:
    """A CI line that sets a shorter cooldown than base configures weakens it."""
    cooldown = _group(old, "cooldown")
    before = {
        (item.get("file"), item.get("setting"), str(item.get("value")))
        for item in old.get("cooldown_overrides") or []
        if isinstance(item, Mapping)
    }
    reported: set[tuple[Any, Any, str]] = set()
    for item in new.get("cooldown_overrides") or []:
        if not isinstance(item, Mapping) or item.get("setting") not in COOLDOWN_KEYS:
            continue
        key = (item.get("file"), item.get("setting"), str(item.get("value")))
        if key in before or key in reported:
            continue
        setting = str(item.get("setting"))
        base_minutes = cooldown_minutes(cooldown, setting)
        head_minutes = cooldown_minutes({setting: item.get("value")}, setting)
        if base_minutes is None or head_minutes is None or head_minutes >= base_minutes:
            continue
        reported.add(key)
        entry = _item(
            "cooldown_lowered",
            f"{item.get('file')} sets {item.get('option')}={item.get('value')} in CI, lowering "
            f"{_COOLDOWN_LABELS[setting]} from {cooldown.get(setting)}",
            item.get("file"),
            setting,
            cooldown.get(setting),
            item.get("value"),
        )
        entry["line"] = item.get("line")
        found.append(entry)


def _exclusion_regressions(
    old: Mapping[str, Any], new: Mapping[str, Any], found: list[dict[str, Any]]
) -> None:
    before = _group(old, "exclusions")
    after = _group(new, "exclusions")
    for manager, names in after.items():
        if not isinstance(names, list):
            continue
        known = set(before.get(manager) or [])
        for name in names:
            if name in known:
                continue
            item = _item(
                "cooldown_exclusion_added",
                f"{name} now skips the {manager} cooldown",
                _path(old, new, f"exclusions.{manager}"),
                f"exclusions.{manager}",
                None,
                name,
            )
            item["package"] = name
            found.append(item)


def _script_regressions(
    old: Mapping[str, Any], new: Mapping[str, Any], found: list[dict[str, Any]]
) -> None:
    before = _group(old, "scripts")
    after = _group(new, "scripts")
    for key, label in (
        ("npm_ignore_scripts", "npm ignore-scripts"),
        ("bun_ignore_scripts", "Bun install.ignoreScripts"),
    ):
        if before.get(key) is True and after.get(key) is not True:
            detail = f"{label} was turned off (was true, now {after.get(key)})"
            found.append(
                _item(
                    "ignore_scripts_disabled",
                    detail,
                    _path(old, new, key),
                    key,
                    True,
                    after.get(key),
                )
            )
    if before.get("yarn_enable_scripts") is False and after.get("yarn_enable_scripts") is not False:
        head = after.get("yarn_enable_scripts")
        detail = f"Yarn enableScripts was turned back on (was false, now {head})"
        path = _path(old, new, "yarn_enable_scripts")
        found.append(
            _item("ignore_scripts_disabled", detail, path, "yarn_enable_scripts", False, head)
        )
    if (
        before.get("pnpm_strict_dep_builds") is True
        and after.get("pnpm_strict_dep_builds") is not True
    ):
        head = after.get("pnpm_strict_dep_builds")
        version = _major(new, "pnpm")
        if not (head is None and version is not None and version >= 11000):
            detail = f"pnpm strictDepBuilds was turned off (was true, now {head})"
            path = _path(old, new, "pnpm_strict_dep_builds")
            found.append(
                _item(
                    "strict_dep_builds_disabled", detail, path, "pnpm_strict_dep_builds", True, head
                )
            )
    if (
        before.get("pnpm_dangerously_allow_all_builds") is not True
        and after.get("pnpm_dangerously_allow_all_builds") is True
    ):
        path = _path(old, new, "pnpm_dangerously_allow_all_builds")
        item = _item(
            "allow_builds_added",
            "pnpm dangerouslyAllowAllBuilds now lets every dependency run build scripts",
            path,
            "pnpm_dangerously_allow_all_builds",
            before.get("pnpm_dangerously_allow_all_builds"),
            True,
        )
        item["package"] = "*"
        found.append(item)
    pnpm_allowed = set(before.get("pnpm_allow_builds") or []) | set(
        before.get("pnpm_only_built_dependencies") or []
    )
    version = _major(new, "pnpm")
    if version is None or version < PNPM_SETTINGS_IN_WORKSPACE_ONLY * 1000:
        never_after = set(after.get("pnpm_never_built_dependencies") or [])
        for name in sorted(set(before.get("pnpm_never_built_dependencies") or []) - never_after):
            item = _item(
                "allow_builds_added",
                f"{name} removed from pnpm neverBuiltDependencies; it may now run build scripts",
                _path(old, new, "pnpm_never_built_dependencies"),
                "pnpm_never_built_dependencies",
                name,
                None,
            )
            item["package"] = name
            found.append(item)
    for key, kind, label in (
        ("pnpm_allow_builds", "allow_builds_added", "pnpm allowBuilds"),
        ("pnpm_only_built_dependencies", "allow_builds_added", "pnpm onlyBuiltDependencies"),
        ("bun_trusted_dependencies", "allow_builds_added", "Bun trustedDependencies"),
        ("npm12_allow_scripts", "allow_scripts_added", "npm allowScripts"),
    ):
        known = set(before.get(key) or [])
        if key.startswith("pnpm_"):
            known = pnpm_allowed
        for name in after.get(key) or []:
            if name in known:
                continue
            item = _item(kind, f"{name} added to {label}", _path(old, new, key), key, None, name)
            item["package"] = name
            found.append(item)


def _action_regressions(
    old: Mapping[str, Any], new: Mapping[str, Any], found: list[dict[str, Any]]
) -> None:
    base_refs = _group(old, "actions").get("refs") or []
    head_refs = _group(new, "actions").get("refs") or []
    pinned_before = {
        str(ref.get("uses")).lower()
        for ref in base_refs
        if isinstance(ref, Mapping) and ref.get("pinned")
    }
    unpinned_before = {
        (str(ref.get("uses")).lower(), ref.get("ref"))
        for ref in base_refs
        if isinstance(ref, Mapping) and not ref.get("pinned")
    }
    counts = _group(old, "actions")
    fully_pinned = counts.get("unpinned") == 0 and bool(counts.get("pinned"))
    reported: set[tuple[Any, Any, Any]] = set()
    for ref in head_refs:
        if not isinstance(ref, Mapping) or ref.get("pinned"):
            continue
        uses = str(ref.get("uses")).lower()
        key = (uses, ref.get("ref"), ref.get("file"))
        retagged = uses in pinned_before
        if (
            not (retagged or fully_pinned)
            or (uses, ref.get("ref")) in unpinned_before
            or key in reported
        ):
            continue
        reported.add(key)
        detail = (
            f"{ref.get('uses')} was pinned to a commit SHA and is now used at "
            f"{ref.get('ref') or 'no ref'}"
        )
        if not retagged:
            detail = (
                f"every action in base was pinned to a commit SHA; {ref.get('uses')} is added "
                f"at {ref.get('ref') or 'no ref'}"
            )
        item = _item(
            "action_unpinned",
            detail,
            ref.get("file"),
            "actions",
            "sha",
            ref.get("ref"),
        )
        item["line"] = ref.get("line")
        found.append(item)
