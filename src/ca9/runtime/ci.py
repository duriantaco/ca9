from __future__ import annotations

import os
import shlex
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ca9.package_feed import default_cache_root

CI_SETUP_SCHEMA = "ca9.ci.setup.v1"
CI_DOCTOR_SCHEMA = "ca9.ci.doctor.v1"
SHIM_NAMES = ("npm", "pip", "python")


@dataclass(frozen=True)
class CISetupResult:
    shim_dir: Path
    shims: tuple[str, ...]
    github_path: Path | None = None
    github_path_updated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": CI_SETUP_SCHEMA,
            "shim_dir": str(self.shim_dir),
            "shims": list(self.shims),
            "github_path": str(self.github_path) if self.github_path else None,
            "github_path_updated": self.github_path_updated,
        }


@dataclass(frozen=True)
class CIDoctorResult:
    shim_dir: Path
    provider: str
    shims_installed: bool
    github_path_configured: bool
    github_path_contains_shim_dir: bool
    path_contains_shim_dir: bool
    missing_shims: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.shims_installed and (
            self.path_contains_shim_dir or self.github_path_contains_shim_dir
        )

    @property
    def exit_code(self) -> int:
        return 0 if self.ok else 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": CI_DOCTOR_SCHEMA,
            "ok": self.ok,
            "provider": self.provider,
            "shim_dir": str(self.shim_dir),
            "shims_installed": self.shims_installed,
            "missing_shims": list(self.missing_shims),
            "github_path_configured": self.github_path_configured,
            "github_path_contains_shim_dir": self.github_path_contains_shim_dir,
            "path_contains_shim_dir": self.path_contains_shim_dir,
            "warnings": list(self.warnings),
        }


def default_ci_shim_dir() -> Path:
    return default_cache_root() / "ci-shims"


def ci_setup_print_snippet() -> str:
    return "\n".join(
        [
            "# GitHub Actions",
            "ca9 setup ci install",
            "ca9 doctor ci",
        ]
    )


def install_ci_shims(
    *,
    shim_dir: Path | None = None,
    env: dict[str, str] | None = None,
    ca9_command: str = "ca9",
) -> CISetupResult:
    active_env = os.environ if env is None else env
    target_dir = (shim_dir or default_ci_shim_dir()).expanduser()
    target_dir.mkdir(parents=True, exist_ok=True)

    for name in SHIM_NAMES:
        shim_path = target_dir / name
        shim_path.write_text(_shim_script(name, target_dir, ca9_command))
        _make_executable(shim_path)

    github_path = _github_path(active_env)
    updated = False
    if github_path is not None:
        github_path.parent.mkdir(parents=True, exist_ok=True)
        existing = github_path.read_text().splitlines() if github_path.exists() else []
        if str(target_dir) not in existing:
            with github_path.open("a") as f:
                f.write(f"{target_dir}\n")
            updated = True

    return CISetupResult(
        shim_dir=target_dir,
        shims=SHIM_NAMES,
        github_path=github_path,
        github_path_updated=updated,
    )


def doctor_ci(
    *,
    shim_dir: Path | None = None,
    env: dict[str, str] | None = None,
) -> CIDoctorResult:
    active_env = os.environ if env is None else env
    target_dir = (shim_dir or default_ci_shim_dir()).expanduser()
    missing = tuple(name for name in SHIM_NAMES if not _is_executable_file(target_dir / name))
    github_path = _github_path(active_env)
    github_path_contains = False
    if github_path is not None and github_path.exists():
        github_path_contains = str(target_dir) in github_path.read_text().splitlines()
    path_contains = _path_contains(active_env.get("PATH", ""), target_dir)
    warnings: list[str] = []
    if github_path is None:
        warnings.append("GITHUB_PATH is not set; GitHub Actions PATH setup is unavailable")
    if missing:
        warnings.append("missing or non-executable shims: " + ", ".join(missing))
    if not path_contains and not github_path_contains:
        warnings.append("shim directory is not on PATH and has not been written to GITHUB_PATH")

    return CIDoctorResult(
        shim_dir=target_dir,
        provider="github-actions" if active_env.get("GITHUB_ACTIONS") else "unknown",
        shims_installed=not missing,
        missing_shims=missing,
        github_path_configured=github_path is not None,
        github_path_contains_shim_dir=github_path_contains,
        path_contains_shim_dir=path_contains,
        warnings=tuple(warnings),
    )


def format_ci_setup(result: CISetupResult) -> str:
    lines = [
        "ca9 CI shims installed",
        f"Shim dir: {result.shim_dir}",
        "Shims: " + ", ".join(result.shims),
    ]
    if result.github_path:
        state = "updated" if result.github_path_updated else "already configured"
        lines.append(f"GitHub PATH: {state} ({result.github_path})")
    else:
        lines.append("GitHub PATH: not configured; add the shim dir to PATH manually")
    return "\n".join(lines)


def format_ci_doctor(result: CIDoctorResult) -> str:
    lines = [
        f"ca9 CI doctor: {'ok' if result.ok else 'needs attention'}",
        f"Provider: {result.provider}",
        f"Shim dir: {result.shim_dir}",
        f"Shims installed: {str(result.shims_installed).lower()}",
        f"GITHUB_PATH configured: {str(result.github_path_configured).lower()}",
        f"GITHUB_PATH contains shim dir: {str(result.github_path_contains_shim_dir).lower()}",
        f"Current PATH contains shim dir: {str(result.path_contains_shim_dir).lower()}",
    ]
    if result.warnings:
        lines.append("Warnings:")
        lines.extend(f"  - {warning}" for warning in result.warnings)
    return "\n".join(lines)


def _shim_script(name: str, shim_dir: Path, ca9_command: str) -> str:
    if name == "python":
        route_condition = (
            'if [ "${1:-}" = "-m" ] && [ "${2:-}" = "pip" ] '
            '&& [ "${3:-}" = "install" ]; then\n'
            "  export CA9_SHIM_BYPASS=1\n"
            '  exec "$CA9_COMMAND" run -- python "$@"\n'
            "fi\n"
            'real_cmd="$(find_real)" || exit 127\n'
            'exec "$real_cmd" "$@"\n'
        )
    elif name == "npm":
        route_condition = (
            'if [ "${1:-}" = "install" ] || [ "${1:-}" = "i" ]; then\n'
            "  export CA9_SHIM_BYPASS=1\n"
            f'  exec "$CA9_COMMAND" run -- {name} "$@"\n'
            "fi\n"
            'real_cmd="$(find_real)" || exit 127\n'
            'exec "$real_cmd" "$@"\n'
        )
    else:
        route_condition = (
            'if [ "${1:-}" = "install" ]; then\n'
            "  export CA9_SHIM_BYPASS=1\n"
            f'  exec "$CA9_COMMAND" run -- {name} "$@"\n'
            "fi\n"
            'real_cmd="$(find_real)" || exit 127\n'
            'exec "$real_cmd" "$@"\n'
        )

    return (
        "#!/bin/sh\n"
        "set -eu\n"
        f"CA9_SHIM_DIR={shlex.quote(str(shim_dir))}\n"
        f"CA9_SHIM_NAME={shlex.quote(name)}\n"
        f"CA9_COMMAND={shlex.quote(ca9_command)}\n"
        "\n"
        "find_real() {\n"
        "  old_ifs=$IFS\n"
        "  IFS=:\n"
        "  for dir in $PATH; do\n"
        "    IFS=$old_ifs\n"
        '    if [ -z "$dir" ]; then dir=.; fi\n'
        '    if [ "$dir" = "$CA9_SHIM_DIR" ]; then IFS=:; continue; fi\n'
        '    candidate="$dir/$CA9_SHIM_NAME"\n'
        '    if [ -x "$candidate" ]; then printf \'%s\\n\' "$candidate"; return 0; fi\n'
        "    IFS=:\n"
        "  done\n"
        "  IFS=$old_ifs\n"
        '  echo "ca9 shim: cannot find real $CA9_SHIM_NAME" >&2\n'
        "  return 1\n"
        "}\n"
        "\n"
        'if [ "${CA9_SHIM_BYPASS:-}" = "1" ]; then\n'
        '  real_cmd="$(find_real)" || exit 127\n'
        '  exec "$real_cmd" "$@"\n'
        "fi\n"
        f"{route_condition}"
    )


def _make_executable(path: Path) -> None:
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _is_executable_file(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def _github_path(env: dict[str, str]) -> Path | None:
    value = env.get("GITHUB_PATH")
    if not value:
        return None
    return Path(value).expanduser()


def _path_contains(path_value: str, target_dir: Path) -> bool:
    return any(
        Path(part).expanduser() == target_dir for part in path_value.split(os.pathsep) if part
    )
