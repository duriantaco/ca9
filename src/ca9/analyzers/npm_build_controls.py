from __future__ import annotations

import ast
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from ca9.artifacts.model import ArtifactFile, ArtifactSnapshot

MAX_BINDING_GYP_BYTES = 256 * 1024
MAX_BINDING_GYP_NODES = 10_000

_SHELL_SUBSTITUTION_RE = re.compile(r"[<>^]!@?(?:[-\w.]+)?\(")
_SCALAR_TYPES = (str, int, float, bool, type(None))
_EXECUTABLE_GYP_KEYS = {
    "actions": "binding-gyp-actions",
    "rules": "binding-gyp-rules",
    "postbuilds": "binding-gyp-postbuilds",
    "msvs_prebuild": "binding-gyp-msvs-prebuild",
    "msvs_postbuild": "binding-gyp-msvs-postbuild",
    "msvs_external_builder_build_cmd": "binding-gyp-msvs-external-builder",
    "msvs_external_builder_clean_cmd": "binding-gyp-msvs-external-builder",
    "msvs_external_builder_clcompile_cmd": "binding-gyp-msvs-external-builder",
    "run_as": "binding-gyp-run-as",
    "make_global_settings": "binding-gyp-make-global-settings",
    "includes": "binding-gyp-includes",
    "dependencies": "binding-gyp-dependencies",
    "conditions": "binding-gyp-conditions",
    "target_conditions": "binding-gyp-conditions",
}
_GYP_KEY_OPERATOR_PREFIXES = frozenset("+=?!/")


@dataclass(frozen=True)
class NativeBuildControlAnalysis:
    """Safety result for executable controls in npm native-build metadata.

    ``safe`` describes the ``binding.gyp`` files that were found. A result with
    ``binding_gyp_present=False`` is therefore safe but does not prove that a
    source build is possible; callers can make that distinction explicitly.
    """

    safe: bool
    binding_gyp_present: bool
    reasons: tuple[str, ...] = ()


def analyze_native_build_controls(
    snapshots: Iterable[ArtifactSnapshot],
) -> NativeBuildControlAnalysis:
    """Conservatively inspect ``binding.gyp`` files in verified npm snapshots.

    GYP ``actions`` and ``rules`` can run arbitrary commands during a native
    build. Command substitutions such as ``<!(command)`` and ``<!@(command)``
    can do the same while expanding a value. Files that cannot be inspected
    within fixed resource limits are unsafe rather than silently skipped.
    """

    control_files = [
        file
        for snapshot in snapshots
        for file in snapshot.files
        if _is_gyp_control_file(file.relative_path)
    ]
    binding_gyp_present = any(_is_binding_gyp(file.relative_path) for file in control_files)
    if not control_files:
        return NativeBuildControlAnalysis(safe=True, binding_gyp_present=False)

    reasons: list[str] = []
    for file in control_files:
        reasons.extend(_analyze_binding_gyp(file))

    unique_reasons = tuple(dict.fromkeys(reasons))
    return NativeBuildControlAnalysis(
        safe=not unique_reasons,
        binding_gyp_present=binding_gyp_present,
        reasons=unique_reasons,
    )


def _is_binding_gyp(relative_path: str) -> bool:
    return relative_path.replace("\\", "/").rsplit("/", 1)[-1].casefold() == "binding.gyp"


def _is_gyp_control_file(relative_path: str) -> bool:
    name = relative_path.replace("\\", "/").rsplit("/", 1)[-1].casefold()
    return name == "binding.gyp" or name.endswith((".gyp", ".gypi"))


def _analyze_binding_gyp(file: ArtifactFile) -> list[str]:
    if file.size < 0:
        return ["binding-gyp-invalid-size"]
    if file.size > MAX_BINDING_GYP_BYTES:
        return ["binding-gyp-too-large"]

    try:
        with file.path.open("rb") as stream:
            raw = stream.read(MAX_BINDING_GYP_BYTES + 1)
    except OSError:
        return ["binding-gyp-read-error"]

    if len(raw) > MAX_BINDING_GYP_BYTES:
        return ["binding-gyp-too-large"]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return ["binding-gyp-invalid-utf8"]

    parsed = _parse_gyp(text)
    if parsed is None:
        return ["binding-gyp-invalid-format"]
    return _inspect_gyp_values(parsed)


def _parse_gyp(text: str) -> Any | None:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        pass

    # GYP files commonly use Python-style single-quoted literals, comments,
    # and trailing commas. literal_eval accepts those without executing code.
    try:
        return ast.literal_eval(text)
    except (MemoryError, RecursionError, SyntaxError, ValueError):
        return None


def _inspect_gyp_values(root: Any) -> list[str]:
    if not isinstance(root, dict):
        return ["binding-gyp-invalid-format"]

    reasons: list[str] = []
    stack = [root]
    visited = 0
    while stack:
        value = stack.pop()
        visited += 1
        if visited > MAX_BINDING_GYP_NODES:
            reasons.append("binding-gyp-analysis-limit")
            break

        if isinstance(value, dict):
            for key, child in value.items():
                if not isinstance(key, str):
                    reasons.append("binding-gyp-invalid-format")
                    continue
                normalized_key = key.casefold()
                for executable_key, reason in _EXECUTABLE_GYP_KEYS.items():
                    suffix = (
                        normalized_key[len(executable_key) :]
                        if normalized_key.startswith(executable_key)
                        else ""
                    )
                    if normalized_key == executable_key or (
                        suffix and suffix[0] in _GYP_KEY_OPERATOR_PREFIXES
                    ):
                        # Merge/filter decorations (for example ``actions+``)
                        # are interpreted by GYP as the underlying executable
                        # key. Includes/dependencies can import other build
                        # files, so unresolved control graphs require review.
                        reasons.append(reason)
                        break
                if _SHELL_SUBSTITUTION_RE.search(key):
                    reasons.append("binding-gyp-shell-substitution")
                stack.append(child)
            continue

        if isinstance(value, list):
            stack.extend(value)
            continue

        if isinstance(value, str):
            if _SHELL_SUBSTITUTION_RE.search(value):
                reasons.append("binding-gyp-shell-substitution")
            continue

        if not isinstance(value, _SCALAR_TYPES):
            reasons.append("binding-gyp-invalid-format")

    return list(dict.fromkeys(reasons))
