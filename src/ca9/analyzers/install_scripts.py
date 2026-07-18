from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ca9.analyzers.package_code import (
    NPM_INSTALL_HOOKS,
    NPM_PREPARE_HOOK,
    NPM_SCRIPT_EXEC_RE,
)

VERDICT_DENY = "deny"
VERDICT_REVIEW = "review"
VERDICT_ALLOW_CANDIDATE = "allow-candidate"

_VERDICT_ORDER = {VERDICT_ALLOW_CANDIDATE: 0, VERDICT_REVIEW: 1, VERDICT_DENY: 2}


@dataclass(frozen=True)
class KnownScriptPattern:
    id: str
    commands: tuple[str, ...]
    verdict: str = VERDICT_ALLOW_CANDIDATE
    note: str | None = None
    requires_verified_artifact_analysis: bool = False


# Whole-command matches only, compared after whitespace normalization. A single
# appended token (for example `&& curl ...`) breaks the match and prevents the
# hook from being an allow candidate, so these never act as substring allowances.
# Native build commands are familiar, but the command alone is not proof that
# the package being built is safe. They become allow candidates only after the
# caller has verified and analyzed the package artifact.
KNOWN_SCRIPT_PATTERNS: tuple[KnownScriptPattern, ...] = (
    KnownScriptPattern(
        id="benign:node-gyp",
        commands=("node-gyp rebuild",),
        requires_verified_artifact_analysis=True,
    ),
    KnownScriptPattern(
        id="benign:node-gyp-build",
        commands=("node-gyp-build",),
        requires_verified_artifact_analysis=True,
    ),
    KnownScriptPattern(
        id="benign:prebuild-native",
        commands=(
            "prebuild-install || node-gyp rebuild",
            "prebuild-install || node-gyp-build",
        ),
        requires_verified_artifact_analysis=True,
    ),
    KnownScriptPattern(
        id="benign:node-pre-gyp",
        commands=("node-pre-gyp install --fallback-to-build",),
        requires_verified_artifact_analysis=True,
    ),
    KnownScriptPattern(
        id="helper:husky",
        commands=("husky install", "husky"),
        verdict=VERDICT_REVIEW,
        note="skippable",
    ),
    KnownScriptPattern(
        id="helper:patch-package",
        commands=("patch-package",),
        verdict=VERDICT_REVIEW,
        note="mutates-installed-code",
    ),
)

_CONTROL_CHARACTER_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
_HORIZONTAL_WHITESPACE_RE = re.compile(r"[ \t]+")


@dataclass(frozen=True)
class ScriptHook:
    name: str
    command: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "command": self.command}


@dataclass(frozen=True)
class ScriptClassification:
    verdict: str
    reasons: tuple[str, ...]
    notes: tuple[str, ...] = ()


def classify_install_scripts(
    hooks: tuple[ScriptHook, ...],
    *,
    deny_reasons: tuple[str, ...] = (),
    scripts_available: bool = True,
    verified_artifact_analysis: bool = False,
) -> ScriptClassification:
    reasons: list[str] = list(deny_reasons)
    notes: list[str] = []
    verdict = VERDICT_DENY if deny_reasons else VERDICT_ALLOW_CANDIDATE

    if not scripts_available:
        reasons.append("scripts-unavailable")
        return ScriptClassification(_worst(verdict, VERDICT_REVIEW), _unique(reasons))

    if not hooks:
        reasons.append("lock-manifest-mismatch")
        return ScriptClassification(_worst(verdict, VERDICT_REVIEW), _unique(reasons))

    for hook in hooks:
        hook_verdict, hook_reason, hook_note = _classify_hook(
            hook,
            verified_artifact_analysis=verified_artifact_analysis,
        )
        verdict = _worst(verdict, hook_verdict)
        reasons.append(hook_reason)
        if hook_note:
            notes.append(hook_note)
    return ScriptClassification(verdict, _unique(reasons), _unique(notes))


def install_hooks_from_manifest(
    manifest: dict[str, Any],
    *,
    include_prepare: bool = False,
) -> tuple[ScriptHook, ...]:
    scripts = manifest.get("scripts")
    if not isinstance(scripts, dict):
        return ()
    hooks: list[ScriptHook] = []
    hook_names = (*NPM_INSTALL_HOOKS, NPM_PREPARE_HOOK) if include_prepare else NPM_INSTALL_HOOKS
    for name in hook_names:
        command = scripts.get(name)
        if isinstance(command, str) and command.strip(" \t"):
            hooks.append(ScriptHook(name=name, command=command.strip(" \t")))
    return tuple(hooks)


def _classify_hook(
    hook: ScriptHook,
    *,
    verified_artifact_analysis: bool,
) -> tuple[str, str, str | None]:
    if _CONTROL_CHARACTER_RE.search(hook.command):
        return VERDICT_DENY, "npm-install-script-control-character", None
    command = _HORIZONTAL_WHITESPACE_RE.sub(" ", hook.command).strip(" ")
    if NPM_SCRIPT_EXEC_RE.search(command):
        return VERDICT_DENY, "npm-install-script-exec", None
    for pattern in KNOWN_SCRIPT_PATTERNS:
        if command in pattern.commands:
            if pattern.requires_verified_artifact_analysis and not verified_artifact_analysis:
                return VERDICT_REVIEW, pattern.id, "verified-artifact-analysis-required"
            if pattern.verdict != VERDICT_ALLOW_CANDIDATE:
                return pattern.verdict, pattern.id, pattern.note
            return VERDICT_ALLOW_CANDIDATE, pattern.id, pattern.note
    return VERDICT_REVIEW, "no-benign-match", None


def _worst(left: str, right: str) -> str:
    return left if _VERDICT_ORDER[left] >= _VERDICT_ORDER[right] else right


def _unique(values: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))
