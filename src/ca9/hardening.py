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
        }
        self.actions: dict[str, Any] = {"pinned": 0, "unpinned": 0, "refs": [], "truncated": False}
        self.sources: dict[str, str] = {}
        self.exclusions: dict[str, list[str]] = {}
        self.dependabot: list[dict[str, Any]] = []
        self.managers: dict[str, str] = {}
        self.renovate_presets: list[str] = []
        self.errors: list[dict[str, str]] = []

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
    manager = data.get("packageManager")
    if isinstance(manager, str) and "@" in manager:
        name, _, version = manager.partition("@")
        state.managers[name.strip()] = version.split("+")[0].strip()
    pnpm = data.get("pnpm")
    if isinstance(pnpm, dict):
        if "onlyBuiltDependencies" in pnpm:
            names = _names(pnpm["onlyBuiltDependencies"])
            state.set(state.scripts, "pnpm_only_built_dependencies", names, rel)
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
    if "onlyBuiltDependencies" in data:
        names = _names(data["onlyBuiltDependencies"])
        state.set(state.scripts, "pnpm_only_built_dependencies", names, rel)
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
            directory = update.get("directory")
            if not isinstance(directory, str):
                directory = ",".join(_names(update.get("directories")))
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
                    "directory": directory or "/",
                    "default_days": default_days,
                }
            )
        state.sources["dependabot"] = rel
        if days:
            state.set(state.cooldown, "dependabot_days", min(days), rel)
        return


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


def _actions(state: _State) -> None:
    paths: list[Path] = []
    for pattern in (".github/workflows/*.yml", ".github/workflows/*.yaml"):
        paths.extend(state.root.glob(pattern))
    for pattern in (".github/actions/**/action.yml", ".github/actions/**/action.yaml"):
        paths.extend(state.root.glob(pattern))
    for name in ("action.yml", "action.yaml"):
        paths.append(state.root / name)
    for path in sorted(set(paths)):
        rel = path.relative_to(state.root).as_posix()
        text = state.text(rel)
        if text is None:
            continue
        for match in _USES.finditer(text):
            uses = match.group(2)
            if uses.startswith(("./", ".\\")):
                continue
            pinned, ref = _ref_pinned(uses)
            key = "unpinned"
            if pinned:
                key = "pinned"
            state.actions[key] += 1
            if len(state.actions["refs"]) >= MAX_ACTION_REFS:
                state.actions["truncated"] = True
                continue
            state.actions["refs"].append(
                {
                    "file": rel,
                    "uses": _action_name(uses),
                    "ref": ref,
                    "pinned": pinned,
                    "line": text.count("\n", 0, match.start(2)) + 1,
                }
            )
    if state.actions["refs"]:
        state.sources["actions"] = ".github/workflows"


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
    old = _snapshot(base)
    new = _snapshot(head)
    found: list[dict[str, Any]] = []
    _cooldown_regressions(old, new, found)
    _dependabot_regressions(old, new, found)
    _exclusion_regressions(old, new, found)
    _script_regressions(old, new, found)
    _action_regressions(old, new, found)
    found.sort(key=lambda item: (item["kind"], item["path"] or "", item["detail"]))
    return found


def _snapshot(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, (str, Path)):
        return settings(value)
    return {}


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


def _dependabot_entries(snapshot: Mapping[str, Any]) -> dict[tuple[str, str], Any]:
    entries: dict[tuple[str, str], Any] = {}
    raw = snapshot.get("dependabot")
    if isinstance(raw, list):
        for entry in raw:
            if isinstance(entry, Mapping):
                key = (str(entry.get("ecosystem")), str(entry.get("directory")))
                entries[key] = entry.get("default_days")
    return entries


def _has_dependabot_entries(snapshot: Mapping[str, Any]) -> bool:
    entries = snapshot.get("dependabot")
    return isinstance(entries, list) and bool(entries)


def _dependabot_regressions(
    old: Mapping[str, Any], new: Mapping[str, Any], found: list[dict[str, Any]]
) -> None:
    if not _has_dependabot_entries(old):
        return
    before = _dependabot_entries(old)
    after = _dependabot_entries(new)
    path = _path(old, new, "dependabot")
    for key, head_days in after.items():
        ecosystem, directory = key
        base_days = before.get(key)
        base_effective = DEPENDABOT_DEFAULT_DAYS
        if base_days is not None:
            base_effective = base_days
        head_effective = DEPENDABOT_DEFAULT_DAYS
        if head_days is not None:
            head_effective = head_days
        if head_effective >= base_effective:
            continue
        where = f"{ecosystem} in {directory}"
        if head_days is None:
            detail = (
                f"Dependabot cooldown for {where} was removed (was {base_days} days); "
                f"the {DEPENDABOT_DEFAULT_DAYS}-day default applies"
            )
            found.append(
                _item("cooldown_removed", detail, path, "dependabot_days", base_days, None)
            )
            continue
        detail = (
            f"Dependabot cooldown for {where} lowered from {base_effective} to {head_days} days"
        )
        found.append(
            _item("cooldown_lowered", detail, path, "dependabot_days", base_days, head_days)
        )


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
    for key, kind, label in (
        ("pnpm_allow_builds", "allow_builds_added", "pnpm allowBuilds"),
        ("pnpm_only_built_dependencies", "allow_builds_added", "pnpm onlyBuiltDependencies"),
        ("bun_trusted_dependencies", "allow_builds_added", "Bun trustedDependencies"),
        ("npm12_allow_scripts", "allow_scripts_added", "npm allowScripts"),
    ):
        known = set(before.get(key) or [])
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
        ref.get("uses") for ref in base_refs if isinstance(ref, Mapping) and ref.get("pinned")
    }
    unpinned_before = {
        (ref.get("uses"), ref.get("ref"))
        for ref in base_refs
        if isinstance(ref, Mapping) and not ref.get("pinned")
    }
    reported: set[tuple[Any, Any, Any]] = set()
    for ref in head_refs:
        if not isinstance(ref, Mapping) or ref.get("pinned"):
            continue
        uses = ref.get("uses")
        key = (uses, ref.get("ref"), ref.get("file"))
        if (
            uses not in pinned_before
            or (uses, ref.get("ref")) in unpinned_before
            or key in reported
        ):
            continue
        reported.add(key)
        item = _item(
            "action_unpinned",
            f"{uses} was pinned to a commit SHA and is now used at {ref.get('ref') or 'no ref'}",
            ref.get("file"),
            "actions",
            "sha",
            ref.get("ref"),
        )
        item["line"] = ref.get("line")
        found.append(item)
