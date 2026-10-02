from __future__ import annotations

import os
import shlex
import shutil
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ca9.package_feed import default_cache_root

CI_SETUP_SCHEMA = "ca9.ci.setup.v1"
CI_DOCTOR_SCHEMA = "ca9.ci.doctor.v1"
SHIM_NAMES = ("npm", "npx", "pip", "pip3", "python", "python3")
SHIM_MARKER = "# ca9-shim"
# Written next to generated shims so any shim (and ca9 run) can skip the whole directory.
SHIM_DIR_MARKER = ".ca9-shims"
# Pre-marker shims are recognised by their generated preamble.
_LEGACY_SHIM_SIGNATURE = b"\nCA9_SHIM_NAME="


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
    shadowed_shims: tuple[tuple[str, str], ...] = ()

    @property
    def ok(self) -> bool:
        return (
            self.shims_installed
            and (self.path_contains_shim_dir or self.github_path_contains_shim_dir)
            and not self.shadowed_shims
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
            "shadowed_shims": shadowed_shims_to_dicts(self.shadowed_shims),
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
    (target_dir / SHIM_DIR_MARKER).write_text("ca9 package-manager shims\n")

    for name in SHIM_NAMES:
        shim_path = target_dir / name
        shim_path.write_text(_shim_script(name, target_dir.absolute(), ca9_command))
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
    path_value = active_env.get("PATH", "")
    path_contains = path_contains_dir(path_value, target_dir)
    shadowed = find_shadowed_shims(target_dir, path_value) if path_contains else ()
    warnings: list[str] = []
    if github_path is None:
        warnings.append("GITHUB_PATH is not set; GitHub Actions PATH setup is unavailable")
    if missing:
        warnings.append("missing or non-executable shims: " + ", ".join(missing))
    if not path_contains and not github_path_contains:
        warnings.append("shim directory is not on PATH and has not been written to GITHUB_PATH")
    warnings.extend(
        shadowed_shim_warning(
            name,
            resolved,
            target_dir,
            fix=(
                "re-run `ca9 setup ci install` after actions/setup-node, actions/setup-python, "
                "or virtualenv activation so the shim directory is first on PATH"
            ),
        )
        for name, resolved in shadowed
    )

    return CIDoctorResult(
        shim_dir=target_dir,
        provider="github-actions" if active_env.get("GITHUB_ACTIONS") else "unknown",
        shims_installed=not missing,
        missing_shims=missing,
        github_path_configured=github_path is not None,
        github_path_contains_shim_dir=github_path_contains,
        path_contains_shim_dir=path_contains,
        warnings=tuple(warnings),
        shadowed_shims=shadowed,
    )


def find_shadowed_shims(shim_dir: Path, path_value: str) -> tuple[tuple[str, str], ...]:
    """Return (name, resolved path) for shims that PATH lookup does not reach first."""
    shadowed: list[tuple[str, str]] = []
    for name in SHIM_NAMES:
        shim = shim_dir / name
        if not _is_executable_file(shim):
            continue
        resolved = shutil.which(name, path=path_value)
        if resolved and not _same_path(Path(resolved), shim):
            shadowed.append((name, resolved))
    return tuple(shadowed)


def shadowed_shim_warning(name: str, resolved: str, shim_dir: Path, *, fix: str) -> str:
    return (
        f"`{name}` resolves to {resolved}, not the ca9 shim in {shim_dir}; "
        f"installs through it bypass ca9. Fix: {fix}"
    )


def shadowed_shims_to_dicts(shadowed: tuple[tuple[str, str], ...]) -> list[dict[str, str]]:
    return [{"name": name, "resolved": resolved} for name, resolved in shadowed]


def resolve_real_executable(
    command: str,
    *,
    env: Mapping[str, str] | None = None,
) -> str | None:
    """Find the package-manager binary ca9 should execute, skipping ca9 shims.

    ``ca9 run`` executes the resolved path directly, so nested installs started by
    lifecycle scripts go back through the shims without recursing into ca9.
    """
    active_env = os.environ if env is None else env
    if os.sep in command or (os.altsep and os.altsep in command):
        if not is_ca9_shim(Path(command)):
            return command
        command = Path(command).name
    cache_root = active_env.get("CA9_CACHE_DIR")
    root = Path(cache_root).expanduser() if cache_root else default_cache_root()
    # Default CI and shell shim directories, plus any directory carrying the shim marker.
    skip_dirs = (root / "ci-shims", root / "bin")
    for entry in active_env.get("PATH", os.defpath).split(os.pathsep):
        directory = Path(entry or ".")
        if (directory / SHIM_DIR_MARKER).is_file() or any(
            _same_path(directory, shim_dir) for shim_dir in skip_dirs
        ):
            continue
        candidate = directory / command
        if _is_executable_file(candidate) and not is_ca9_shim(candidate):
            return str(candidate)
    return None


def is_ca9_shim(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            head = f.read(512)
    except OSError:
        return False
    return head.startswith(b"#!") and (
        f"\n{SHIM_MARKER}".encode() in head or _LEGACY_SHIM_SIGNATURE in head
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


# Shared shell helpers. Shims stay POSIX sh so pass-through commands never start Python.
_SHIM_FUNCTIONS = r"""
find_real() {
  # Only called via $(find_real), so the IFS and noglob changes stay in that subshell.
  set -f
  IFS=:
  for dir in $PATH; do
    if [ -z "$dir" ]; then dir=.; fi
    # Compare by inode (-ef) so "$CA9_SHIM_DIR/", "//" or symlinked spellings still match.
    if [ "$dir" -ef "$CA9_SHIM_DIR" ] || [ -f "$dir/.ca9-shims" ]; then continue; fi
    candidate="$dir/$CA9_SHIM_NAME"
    if [ -f "$candidate" ] && [ -x "$candidate" ] \
      && ! [ "$candidate" -ef "$CA9_SHIM_DIR/$CA9_SHIM_NAME" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  echo "ca9 shim: cannot find real $CA9_SHIM_NAME" >&2
  return 1
}

run_real() {
  real_cmd="$(find_real)" || exit 127
  exec "$real_cmd" "$@"
}

route_to_ca9() {
  exec "$CA9_COMMAND" run -- "$CA9_SHIM_NAME" "$@"
}
"""

_NPM_CLASSIFIER = r"""
npm_value_option() {
  case "$1" in
    --loglevel|--prefix|-C|--workspace|-w|--registry|--userconfig|--globalconfig|--cache|\
--tag|--otp|--scope|--omit|--include|--install-strategy|--before|--ca|--cafile|--cert|--key|\
--proxy|--https-proxy|--noproxy|--node-options|--script-shell|--shell|--editor|--umask|\
--logs-dir|--logs-max|--location|-L|--init-module|--cpu|--os|--libc|--auth-type|--access|\
--fetch-retries|--fetch-retry-factor|--fetch-retry-mintimeout|--fetch-retry-maxtimeout|\
--fetch-timeout|--maxsockets|--user-agent|--heading|--depth|--call|-c|--package|\
--save-prefix|--tag-version-prefix|--preid|--message|-m|--sbom-format|--sbom-type|\
--expect-result-count|--diff|--diff-unified|--diff-src-prefix|--diff-dst-prefix|\
--lockfile-version|--local-address|--replace-registry-host|--searchexclude|--searchlimit|\
--searchopts|--searchstaleness|--viewer|--git|--node-gyp|--npm-version|--provenance-file|\
--cidr|--which|--init-author-name|--init-author-email|--init-author-url|--init-license|\
--init-version|--cache-max|--cache-min|--pack-destination|--audit-level)
      return 0 ;;
  esac
  return 1
}

npm_classify() {
  ambiguous=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --)
        shift
        if [ "$#" -eq 0 ]; then break; fi
        npm_classify_command "$@"
        return 0 ;;
      --*=*)
        shift ;;
      -g|--global|-s|--silent|-q|--quiet|-d|-dd|-ddd|--verbose|-l|--long|-p|--parseable|\
--json|-f|--force|-y|--yes|--offline|--prefer-offline|--prefer-online|--ignore-scripts|\
--foreground-scripts|--if-present|-ws|--ws|--workspaces|-iwr|--include-workspace-root|\
--dry-run|--legacy-peer-deps|--strict-peer-deps|--no-*|-h|--help|-H|--usage|-v|--version|\
--unicode|--timing|--progress|--production|--save|-S|--save-dev|-D|--save-optional|-O|\
--save-exact|-E|--save-prod|-P|--save-peer|--save-bundle|-B|--audit|--fund|--global-style|\
--legacy-bundling|--package-lock|--package-lock-only|--read-only|--link|--bin-links|\
--install-links|--update-notifier|--color|--browser|--strict-ssl|--engine-strict|--all|-a)
        shift
        case "${1:-}" in true|false) shift ;; esac ;;
      -*)
        if npm_value_option "$1"; then
          if [ "$#" -lt 2 ]; then ca9_action=route; return 0; fi
          shift 2
        else
          # Unknown flag: npm treats it as boolean, but the subcommand is no longer certain.
          ambiguous=1
          shift
          case "${1:-}" in true|false) shift ;; esac
        fi ;;
      *)
        npm_classify_command "$@"
        return 0 ;;
    esac
  done
  if [ "$ambiguous" = 1 ]; then ca9_action=route; else ca9_action=pass; fi
  return 0
}

npm_classify_command() {
  command_name=$1
  shift
  case "$command_name" in
    run|run-script|rum|urn|test|tst|t|start|stop|restart|ls|list|la|ll|view|info|show|v|\
config|c|get|set|version|verison|help|help-search|whoami|outdated|search|find|s|se|ping|\
prefix|root|bin|docs|home|bugs|issues|repo|explain|why|fund|query|sbom|pkg|cache|completion|\
doctor|diff|dist-tag|dist-tags|owner|author|access|org|ogr|team|token|profile|star|unstar|\
stars|deprecate|unpublish|login|logout|adduser|add-user|hook|find-dupes|shrinkwrap)
      ca9_action=pass ;;
    audit)
      ca9_action=pass
      for arg in "$@"; do
        if [ "$arg" = fix ]; then ca9_action=route; fi
      done ;;
    pack|publish)
      # Packing the current project is fine; a positional spec fetches and prepares it.
      ca9_action=pass
      while [ "$#" -gt 0 ]; do
        case "$1" in
          --*=*) shift ;;
          -*)
            if npm_value_option "$1" && [ "$#" -ge 2 ]; then shift 2; else shift; fi ;;
          *)
            ca9_action=route
            shift ;;
        esac
      done ;;
    *)
      # install/i/add/ci/install-test/update/exec/x/init/create/rebuild/dedupe/link/
      # uninstall/prune/edit/explore, abbreviations, and anything unknown.
      ca9_action=route ;;
  esac
  if [ "$ambiguous" = 1 ]; then ca9_action=route; fi
  return 0
}
"""

_PIP_CLASSIFIER = r"""
pip_classify() {
  ambiguous=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --*=*)
        shift ;;
      -h|--help|-V|--version|--isolated|--require-virtualenv|--no-input|--no-color|\
--disable-pip-version-check|--no-cache-dir|--debug|--no-python-version-warning|--verbose|\
--quiet)
        shift ;;
      --python|--cache-dir|--log|--log-file|--local-log|--proxy|--retries|--timeout|\
--trusted-host|--cert|--client-cert|--exists-action|--use-feature|--use-deprecated|\
--keyring-provider|--resume-retries)
        if [ "$#" -lt 2 ]; then ca9_action=route; return 0; fi
        shift 2 ;;
      -[vqVh]*)
        case "$1" in -*[!vqVh]*) ambiguous=1 ;; esac
        shift ;;
      -*)
        ambiguous=1
        shift ;;
      *)
        break ;;
    esac
  done
  if [ "$#" -eq 0 ]; then
    ca9_action=pass
  else
    case "$1" in
      list|show|freeze|check|config|help|cache|index|inspect|hash|completion|debug|uninstall|\
search)
        ca9_action=pass ;;
      *)
        # install, download, wheel (sdist builds run code), lock, and anything unknown.
        ca9_action=route ;;
    esac
  fi
  if [ "$ambiguous" = 1 ]; then ca9_action=route; fi
  return 0
}
"""

_PYTHON_CLASSIFIER = r"""
python_module() {
  module=$1
  shift
  case "$module" in
    pip|pip.*) pip_classify "$@" ;;
    *) ca9_action=pass ;;
  esac
  return 0
}

python_classify() {
  ca9_action=pass
  while [ "$#" -gt 0 ]; do
    arg=$1
    shift
    case "$arg" in
      --check-hash-based-pycs)
        if [ "$#" -gt 0 ]; then shift; fi ;;
      --help|--help-*|--version|--)
        return 0 ;;
      --*)
        ca9_action=route
        return 0 ;;
      -?*)
        flags=${arg#-}
        while [ -n "$flags" ]; do
          flag=${flags%"${flags#?}"}
          flags=${flags#?}
          case "$flag" in
            b|B|d|E|i|I|O|P|q|s|S|u|v|x) ;;
            c|h|V|\?)
              return 0 ;;
            m)
              if [ -z "$flags" ]; then
                if [ "$#" -eq 0 ]; then return 0; fi
                flags=$1
                shift
              fi
              python_module "$flags" "$@"
              return 0 ;;
            W|X)
              if [ -z "$flags" ] && [ "$#" -gt 0 ]; then shift; fi
              flags= ;;
            *)
              ca9_action=route
              return 0 ;;
          esac
        done ;;
      *)
        return 0 ;;
    esac
  done
  return 0
}
"""


def _shim_script(name: str, shim_dir: Path, ca9_command: str) -> str:
    if name == "npm":
        functions = _NPM_CLASSIFIER
        dispatch = 'ca9_action=route\nnpm_classify "$@"\n'
    elif name in {"pip", "pip3"}:
        functions = _PIP_CLASSIFIER
        dispatch = 'ca9_action=route\npip_classify "$@"\n'
    elif name in {"python", "python3"}:
        functions = _PIP_CLASSIFIER + _PYTHON_CLASSIFIER
        dispatch = 'ca9_action=route\npython_classify "$@"\n'
    else:
        # npx always executes package code; ca9 run decides whether it is supported.
        functions = ""
        dispatch = (
            'ca9_action=route\ncase "$#:${1:-}" in\n'
            "  0:|1:--version|1:-v|1:--help|1:-h) ca9_action=pass ;;\n"
            "esac\n"
        )

    return (
        "#!/bin/sh\n"
        f"{SHIM_MARKER}: generated by ca9 setup; routes package installs through ca9 run\n"
        "set -u\n"
        f"CA9_SHIM_DIR={shlex.quote(str(shim_dir))}\n"
        f"CA9_SHIM_NAME={shlex.quote(name)}\n"
        f"CA9_COMMAND={shlex.quote(ca9_command)}\n"
        f"{_SHIM_FUNCTIONS}{functions}\n"
        'if [ "${CA9_SHIM_BYPASS:-}" = "1" ]; then run_real "$@"; fi\n'
        f"{dispatch}"
        'if [ "$ca9_action" = pass ]; then run_real "$@"; fi\n'
        'route_to_ca9 "$@"\n'
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


def _same_path(left: Path, right: Path) -> bool:
    try:
        return os.path.samefile(left, right)
    except OSError:
        return left.expanduser().absolute() == right.expanduser().absolute()


def path_contains_dir(path_value: str, target_dir: Path) -> bool:
    return any(
        _same_path(Path(part).expanduser(), target_dir)
        for part in path_value.split(os.pathsep)
        if part
    )
