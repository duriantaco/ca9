from __future__ import annotations

import os
import shlex
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ca9.runtime.ci import SHIM_NAMES, install_ci_shims

SHELL_SETUP_SCHEMA = "ca9.shell.setup.v1"
SHELL_TEARDOWN_SCHEMA = "ca9.shell.teardown.v1"
SHELL_DOCTOR_SCHEMA = "ca9.shell.doctor.v1"
MANAGED_BLOCK_START = "# ca9-managed-block:start"
MANAGED_BLOCK_END = "# ca9-managed-block:end"


@dataclass(frozen=True)
class ShellSetupResult:
    profile_path: Path
    shim_dir: Path
    shims: tuple[str, ...]
    backup_path: Path | None = None
    changed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SHELL_SETUP_SCHEMA,
            "profile_path": str(self.profile_path),
            "shim_dir": str(self.shim_dir),
            "shims": list(self.shims),
            "backup_path": str(self.backup_path) if self.backup_path else None,
            "changed": self.changed,
        }


@dataclass(frozen=True)
class ShellTeardownResult:
    profile_path: Path
    backup_path: Path | None = None
    removed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SHELL_TEARDOWN_SCHEMA,
            "profile_path": str(self.profile_path),
            "backup_path": str(self.backup_path) if self.backup_path else None,
            "removed": self.removed,
        }


@dataclass(frozen=True)
class ShellDoctorResult:
    profile_path: Path
    shim_dir: Path
    shims_installed: bool
    profile_contains_block: bool
    path_contains_shim_dir: bool
    missing_shims: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.shims_installed and (self.profile_contains_block or self.path_contains_shim_dir)

    @property
    def exit_code(self) -> int:
        return 0 if self.ok else 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SHELL_DOCTOR_SCHEMA,
            "ok": self.ok,
            "profile_path": str(self.profile_path),
            "shim_dir": str(self.shim_dir),
            "shims_installed": self.shims_installed,
            "missing_shims": list(self.missing_shims),
            "profile_contains_block": self.profile_contains_block,
            "path_contains_shim_dir": self.path_contains_shim_dir,
            "warnings": list(self.warnings),
        }


def shell_setup_print_snippet(
    *,
    shim_dir: Path | None = None,
    env: dict[str, str] | None = None,
) -> str:
    active_env = os.environ if env is None else env
    target_dir = (shim_dir or default_shell_shim_dir(active_env)).expanduser()
    return _managed_block(target_dir, active_env)


def install_shell_setup(
    *,
    profile_path: Path | None = None,
    shim_dir: Path | None = None,
    env: dict[str, str] | None = None,
    ca9_command: str = "ca9",
) -> ShellSetupResult:
    active_env = os.environ if env is None else env
    target_profile = (profile_path or default_shell_profile(active_env)).expanduser()
    target_dir = (shim_dir or default_shell_shim_dir(active_env)).expanduser()
    install_ci_shims(shim_dir=target_dir, env={}, ca9_command=ca9_command)

    existing = _read_text(target_profile)
    updated = _replace_managed_block(existing, _managed_block(target_dir, active_env))
    changed = updated != existing
    backup_path = None
    if changed:
        backup_path = _write_backup(target_profile, existing)
        target_profile.parent.mkdir(parents=True, exist_ok=True)
        target_profile.write_text(updated)

    return ShellSetupResult(
        profile_path=target_profile,
        shim_dir=target_dir,
        shims=SHIM_NAMES,
        backup_path=backup_path,
        changed=changed,
    )


def teardown_shell_setup(
    *,
    profile_path: Path | None = None,
    env: dict[str, str] | None = None,
) -> ShellTeardownResult:
    active_env = os.environ if env is None else env
    target_profile = (profile_path or default_shell_profile(active_env)).expanduser()
    existing = _read_text(target_profile)
    updated, removed = _remove_managed_blocks(existing)
    backup_path = None
    if removed:
        backup_path = _write_backup(target_profile, existing)
        target_profile.write_text(updated)
    return ShellTeardownResult(
        profile_path=target_profile,
        backup_path=backup_path,
        removed=removed,
    )


def doctor_shell(
    *,
    profile_path: Path | None = None,
    shim_dir: Path | None = None,
    env: dict[str, str] | None = None,
) -> ShellDoctorResult:
    active_env = os.environ if env is None else env
    target_profile = (profile_path or default_shell_profile(active_env)).expanduser()
    target_dir = (shim_dir or default_shell_shim_dir(active_env)).expanduser()
    missing = tuple(name for name in SHIM_NAMES if not _is_executable_file(target_dir / name))
    profile_text = _read_text(target_profile)
    profile_contains = _contains_managed_block(profile_text)
    path_contains = _path_contains(active_env.get("PATH", ""), target_dir)
    warnings: list[str] = []
    if missing:
        warnings.append("missing or non-executable shims: " + ", ".join(missing))
    if not profile_contains:
        warnings.append(f"profile does not contain ca9 managed block: {target_profile}")
    if not path_contains and profile_contains:
        warnings.append("current shell has not sourced the ca9 managed block yet")

    return ShellDoctorResult(
        profile_path=target_profile,
        shim_dir=target_dir,
        shims_installed=not missing,
        missing_shims=missing,
        profile_contains_block=profile_contains,
        path_contains_shim_dir=path_contains,
        warnings=tuple(warnings),
    )


def format_shell_setup(result: ShellSetupResult) -> str:
    lines = [
        "ca9 shell setup installed",
        f"Profile: {result.profile_path}",
        f"Shim dir: {result.shim_dir}",
        "Shims: " + ", ".join(result.shims),
        f"Profile changed: {str(result.changed).lower()}",
    ]
    if result.backup_path:
        lines.append(f"Backup: {result.backup_path}")
    return "\n".join(lines)


def format_shell_teardown(result: ShellTeardownResult) -> str:
    lines = [
        "ca9 shell setup removed" if result.removed else "ca9 shell setup not present",
        f"Profile: {result.profile_path}",
    ]
    if result.backup_path:
        lines.append(f"Backup: {result.backup_path}")
    return "\n".join(lines)


def format_shell_doctor(result: ShellDoctorResult) -> str:
    lines = [
        f"ca9 shell doctor: {'ok' if result.ok else 'needs attention'}",
        f"Profile: {result.profile_path}",
        f"Shim dir: {result.shim_dir}",
        f"Shims installed: {str(result.shims_installed).lower()}",
        f"Profile contains managed block: {str(result.profile_contains_block).lower()}",
        f"Current PATH contains shim dir: {str(result.path_contains_shim_dir).lower()}",
    ]
    if result.warnings:
        lines.append("Warnings:")
        lines.extend(f"  - {warning}" for warning in result.warnings)
    return "\n".join(lines)


def default_shell_shim_dir(env: dict[str, str] | None = None) -> Path:
    active_env = os.environ if env is None else env
    cache_root = active_env.get("CA9_CACHE_DIR")
    if cache_root:
        return Path(cache_root).expanduser() / "bin"
    return Path(active_env.get("HOME", str(Path.home()))).expanduser() / ".cache" / "ca9" / "bin"


def default_shell_profile(env: dict[str, str] | None = None) -> Path:
    active_env = os.environ if env is None else env
    home = Path(active_env.get("HOME", str(Path.home()))).expanduser()
    shell_name = Path(active_env.get("SHELL", "")).name
    if shell_name == "zsh":
        return home / ".zshrc"
    if shell_name == "bash":
        return home / ".bashrc"
    return home / ".profile"


def _managed_block(shim_dir: Path, env: dict[str, str]) -> str:
    path_expr = _shell_path_assignment(shim_dir, env)
    return "\n".join(
        [
            MANAGED_BLOCK_START,
            f"export PATH={path_expr}",
            MANAGED_BLOCK_END,
            "",
        ]
    )


def _shell_path_assignment(shim_dir: Path, env: dict[str, str]) -> str:
    home = Path(env.get("HOME", str(Path.home()))).expanduser()
    default_dir = home / ".cache" / "ca9" / "bin"
    if shim_dir.expanduser() == default_dir:
        return '"$HOME/.cache/ca9/bin:$PATH"'
    return f"{shlex.quote(str(shim_dir.expanduser()))}:$PATH"


def _replace_managed_block(existing: str, block: str) -> str:
    without, _ = _remove_managed_blocks(existing)
    prefix = without.rstrip("\n")
    if prefix:
        return f"{prefix}\n\n{block}"
    return block


def _remove_managed_blocks(text: str) -> tuple[str, bool]:
    lines = text.splitlines(keepends=True)
    output: list[str] = []
    index = 0
    removed = False
    while index < len(lines):
        if lines[index].strip() != MANAGED_BLOCK_START:
            output.append(lines[index])
            index += 1
            continue
        removed = True
        index += 1
        while index < len(lines) and lines[index].strip() != MANAGED_BLOCK_END:
            index += 1
        if index < len(lines):
            index += 1
        while index < len(lines) and not lines[index].strip():
            index += 1
    return "".join(output).rstrip("\n") + ("\n" if output else ""), removed


def _contains_managed_block(text: str) -> bool:
    return MANAGED_BLOCK_START in text and MANAGED_BLOCK_END in text


def _write_backup(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    backup = path.with_name(f"{path.name}.ca9-backup-{timestamp}")
    backup.write_text(content)
    return backup


def _read_text(path: Path) -> str:
    try:
        return path.read_text()
    except FileNotFoundError:
        return ""


def _is_executable_file(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def _path_contains(path_value: str, target_dir: Path) -> bool:
    return any(
        Path(part).expanduser() == target_dir for part in path_value.split(os.pathsep) if part
    )
