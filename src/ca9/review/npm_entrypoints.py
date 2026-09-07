"""Resolve declared npm executable files without running package or shell code."""

from __future__ import annotations

import posixpath
import re
import shlex
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import PurePosixPath
from typing import Any

ENTRYPOINT_FIELDS = ("main", "module", "browser", "exports", "imports", "bin")
_LEGACY_EXTENSIONS = (".js", ".json", ".node")
_LIFECYCLE_HOOKS = ("preinstall", "install", "postinstall", "prepare")


@dataclass
class Entrypoints:
    paths: set[str] = field(default_factory=set)
    node_paths: set[str] = field(default_factory=set)
    directory_bins: dict[str, str] | None = None
    default_main: str | None = None
    issues: list[str] = field(default_factory=list)


def _local_path(root: str, value: str) -> str | None:
    if value.startswith("/") or "\\" in value or ":" in value or "\x00" in value:
        return None
    path = posixpath.normpath(posixpath.join(root, value))
    if path == ".." or path.startswith("../"):
        return None
    return "" if path == "." else path


def _join(root: str, path: str) -> str:
    return f"{root}/{path}" if root else path


def resolve_manifest_entrypoints(
    manifest: dict[str, Any],
    root: str,
    files: set[str],
    manifests: dict[str, dict[str, Any]],
) -> Entrypoints:
    """Collect paths relative to the archive's package root for one manifest.

    Legacy Node resolution searches .js/.json/.node, including its root-index
    fallback. Export/import targets remain exact. Package scripts deliberately
    support only simple local invocations; shell expansion and external tools
    leave explicit gaps instead of being guessed or executed.
    """
    result = Entrypoints()

    def load_file(path: str) -> str | None:
        if path in files:
            return path
        return next((path + ext for ext in _LEGACY_EXTENSIONS if path + ext in files), None)

    def load_index(path: str) -> str | None:
        return next(
            (
                _join(path, "index" + ext)
                for ext in _LEGACY_EXTENSIONS
                if _join(path, "index" + ext) in files
            ),
            None,
        )

    def load_main(data: dict[str, Any], directory: str) -> str | None:
        main = data.get("main")
        if isinstance(main, str) and main:
            target = _local_path(directory, main)
            if target is None:
                return None
            found = load_file(target) or load_index(target)
            if found is not None:
                return found
        return load_index(directory)

    def add(path: str, *, node: bool) -> None:
        result.paths.add(path)
        if node:
            result.node_paths.add(path)

    def visit(field: str, value: Any, *, local: bool = True) -> None:
        if isinstance(value, dict):
            for condition, target in value.items():
                if condition == "types" and field in {"exports", "imports"}:
                    continue
                visit(field, target, local=field != "browser")
            return
        if isinstance(value, list):
            for target in value:
                visit(field, target, local=local)
            return
        if not isinstance(value, str):
            return
        if field == "exports" and not value.startswith("./"):
            result.issues.append(f"Invalid nonlocal export target: {value}")
            return
        if field == "imports" and not value.startswith("./"):
            return
        if not local and not value.startswith("./"):
            return
        path = _local_path(root, value)
        # Node export/import target paths cannot traverse package scopes.
        if field in {"exports", "imports"} and any(
            part in {"..", "node_modules"} for part in PurePosixPath(value).parts
        ):
            path = None
        target = None
        if path is not None:
            if field in {"exports", "imports"} and "*" in path:
                matches = {filename for filename in files if fnmatchcase(filename, path)}
                for match in matches:
                    add(match, node=True)
                if matches:
                    return
            elif field == "main":
                target = load_main(manifest, root)
            elif field in {"module", "browser"}:
                target = load_file(path) or load_index(path)
            else:
                target = path if path in files else None
        if target is not None:
            add(target, node=field != "bin")
        else:
            result.issues.append(
                f"Declared local entrypoint cannot be resolved in artifact: {field}:{value}"
            )

    for entry_field in ENTRYPOINT_FIELDS:
        visit(entry_field, manifest.get(entry_field))
    if "main" not in manifest:
        target = load_index(root)
        if target is not None:
            result.default_main = posixpath.relpath(target, root or ".")
            add(target, node=True)

    directories = manifest.get("directories", {})
    if not isinstance(directories, dict):
        result.issues.append("Invalid manifest directories declaration")
    elif "bin" in directories:
        directory = directories["bin"]
        if "bin" in manifest:
            result.issues.append("Conflicting bin and directories.bin declarations")
        elif not isinstance(directory, str) or not directory:
            result.issues.append("Invalid directories.bin declaration")
        else:
            path = _local_path(root, directory)
            if path is None:
                result.issues.append("Invalid directories.bin path")
            else:
                prefix = path + "/" if path else ""
                candidates = [
                    name
                    for name in sorted(files)
                    if name.startswith(prefix)
                    and not any(part.startswith(".") for part in name[len(prefix) :].split("/"))
                ]
                result.directory_bins = {}
                for name in candidates:
                    command = PurePosixPath(name).name
                    if command in result.directory_bins:
                        result.issues.append(f"Ambiguous directories.bin command: {command}")
                    result.directory_bins[command] = posixpath.relpath(name, root or ".")
                    add(name, node=False)
                if not candidates:
                    result.issues.append("directories.bin has no resolvable executable files")

    scripts = manifest.get("scripts", {})
    if isinstance(scripts, dict):
        for hook in _LIFECYCLE_HOOKS:
            command = scripts.get(hook)
            if not isinstance(command, str) or not command.strip():
                continue
            target, node, reason = _lifecycle_target(command)
            if reason:
                result.issues.append(f"Unresolved lifecycle command ({hook}): {reason}")
                continue
            if target is None:
                continue
            path = _local_path(root, target)
            resolved = None
            if path is not None:
                if node:
                    resolved = load_file(path)
                    if resolved is None:
                        resolved = load_main(manifests.get(_join(path, "package.json"), {}), path)
                elif path in files:
                    resolved = path
            if resolved is None:
                result.issues.append(
                    f"Local lifecycle target cannot be resolved ({hook}): {target}"
                )
            else:
                add(resolved, node=node)
    return result


def _lifecycle_target(command: str) -> tuple[str | None, bool, str | None]:
    # Reject shell syntax before shlex discards quoting. This conservative check
    # can over-report a quoted metacharacter, but cannot hide an expanded target.
    if re.search(r"[;&|<>`$\r\n]", command):
        return None, False, "shell expansion or command chaining exceeds static resolution"
    try:
        words = shlex.split(command, posix=True)
    except ValueError:
        return None, False, "invalid shell quoting"
    if not words:
        return None, False, None
    executable, *arguments = words
    if executable in {"echo", "printf", "true", "false", ":"}:
        return None, False, None
    if executable in {"node", "nodejs"}:
        # Other Node flags can load preloads or inline code; do not discard them.
        while arguments and arguments[0] in {"--no-warnings", "--enable-source-maps"}:
            arguments.pop(0)
        if arguments and arguments[0] == "--":
            arguments.pop(0)
        if not arguments or arguments[0].startswith("-"):
            return (
                None,
                True,
                "Node flags, inline code or standard input require separate inspection",
            )
        return arguments[0], True, None
    if executable.startswith(("./", "../")) or "/" in executable:
        return executable, False, None
    return None, False, "external executable or script indirection is not resolved in this artifact"
