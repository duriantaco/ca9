"""Comparable declarations and bounded static observations from verified npm artifacts.

The caller verifies archive integrity before supplying a snapshot. These observations
do not establish JavaScript semantic equivalence or prove that a package is benign.
"""

from __future__ import annotations

import hashlib
import json
import re
from bisect import bisect_right
from collections import Counter
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from ca9.analyzers import package_code
from ca9.artifacts.model import ArtifactFile, ArtifactSnapshot
from ca9.review.npm_entrypoints import ENTRYPOINT_FIELDS, resolve_manifest_entrypoints

_JS_SUFFIXES = {".js", ".cjs", ".mjs"}
_SUPPORTED_SUFFIXES = _JS_SUFFIXES | {".py", ".pth"}
_UNSUPPORTED_SUFFIXES = {
    ".node",
    ".wasm",
    ".so",
    ".dll",
    ".exe",
    ".dylib",
    ".bin",
    ".a",
    ".o",
    ".ts",
    ".mts",
    ".cts",
    ".tsx",
    ".jsx",
    ".coffee",
    ".vue",
    ".svelte",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".cmd",
    ".bat",
    ".ps1",
    ".rb",
    ".pl",
    ".php",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".go",
    ".rs",
    ".java",
    ".class",
    ".jar",
}
_DEPENDENCY_GROUPS = (
    "dependencies",
    "optionalDependencies",
    "peerDependencies",
    "devDependencies",
)
_JS_TOKEN = re.compile(
    r"[A-Za-z_$][\w$]*|(?:\d+(?:\.\d*)?)|===|!==|>>>|\*\*=|=>|==|!=|<=|>=|"
    r"\+\+|--|&&|\|\||\?\?|\?\.|\*\*|<<|>>|\+=|-=|\*=|/=|%=|&=|\|=|\^=|.",
    re.DOTALL,
)
_REGEX_PREFIXES = {"=", "(", "[", "{", ",", ":", ";", "return", "=>", "!", "?", "&&", "||", "??"}


@dataclass(frozen=True)
class BehaviorFact:
    kind: str
    key: str
    value: object
    action: str = "info"

    def to_dict(self) -> dict[str, object]:
        return {"kind": self.kind, "key": self.key, "value": self.value, "action": self.action}


@dataclass(frozen=True)
class BehaviorProfile:
    facts: tuple[BehaviorFact, ...]
    issues: tuple[str, ...]
    declarations_complete: bool = False


def inspect_snapshot(snapshot: ArtifactSnapshot) -> BehaviorProfile:
    """Inspect declared behavior and existing static rules without executing code."""
    issues: list[str] = []
    paths = [file.relative_path for file in snapshot.files]
    if len(paths) != len(set(paths)):
        return BehaviorProfile((), ("Archive contains duplicate file paths",))
    roots = [
        file
        for file in snapshot.files
        if file.relative_path in {"package.json", "package/package.json"}
    ]
    if len(roots) != 1:
        return BehaviorProfile((), ("Archive needs one unambiguous root package.json",))
    root = roots[0]
    text = _read_relevant_file(root, issues)
    if text is None:
        return BehaviorProfile((), tuple(issues))
    manifest = _manifest(text, root.relative_path, issues)
    if manifest is None or not _matching_identity(snapshot, manifest, issues):
        return BehaviorProfile((), tuple(issues))

    prefix = "package/" if root.relative_path.startswith("package/") else ""
    # Read every manifest first. Nested executable declarations must contribute
    # paths before the file loop decides which extensionless files are relevant.
    package_files = {
        file.relative_path.removeprefix(prefix): file
        for file in snapshot.files
        if not prefix or file.relative_path.startswith(prefix)
    }
    manifests = {"package.json": manifest}
    declarations_complete = True
    for path, file in sorted(package_files.items()):
        if path == "package.json" or PurePosixPath(path).name != "package.json":
            continue
        nested_text = _read_relevant_file(file, issues)
        if nested_text is not None:
            nested = _manifest(nested_text, path, issues)
            if nested is not None:
                manifests[path] = nested
            else:
                declarations_complete = False
        else:
            declarations_complete = False

    facts: list[BehaviorFact] = []
    entry_paths: set[str] = set()
    node_entry_paths: set[str] = set()
    for manifest_path, data in sorted(manifests.items()):
        directory = str(PurePosixPath(manifest_path).parent)
        directory = "" if directory == "." else directory
        manifest_issues: list[str] = []
        declared = _manifest_facts(data, manifest_issues)
        if manifest_issues:
            declarations_complete = False
        entries = resolve_manifest_entrypoints(data, directory, set(package_files), manifests)
        entry_paths.update(entries.paths)
        node_entry_paths.update(entries.node_paths)
        manifest_issues.extend(entries.issues)
        if entries.default_main is not None:
            declared.append(BehaviorFact("entrypoint", "main", entries.default_main, "review"))
        if entries.directory_bins is not None:
            declared.append(BehaviorFact("entrypoint", "bin", entries.directory_bins, "review"))
        scripts = data.get("scripts", {})
        binding = f"{directory}/binding.gyp" if directory else "binding.gyp"
        if (
            binding in package_files
            and data.get("gypfile") is not False
            and isinstance(scripts, dict)
            and not any(scripts.get(hook) for hook in ("preinstall", "install"))
        ):
            declared.append(
                BehaviorFact(
                    "lifecycle_script",
                    "install",
                    {"command": "node-gyp rebuild", "execution": "implicit_npm_install"},
                    "review",
                )
            )
        facts.extend(
            BehaviorFact(
                fact.kind,
                fact.key if manifest_path == "package.json" else f"{manifest_path}:{fact.key}",
                fact.value,
                fact.action,
            )
            for fact in declared
        )
        issues.extend(f"{manifest_path}: {issue}" for issue in manifest_issues)
    for file in sorted(snapshot.files, key=lambda item: item.relative_path):
        path = file.relative_path.removeprefix(prefix)
        suffix = PurePosixPath(path).suffix.lower()
        if prefix and not file.relative_path.startswith(prefix):
            issues.append(f"File outside npm package root is not inspected: {file.relative_path}")
            continue
        if path.lower().endswith((".d.ts", ".d.cts", ".d.mts")) and path not in entry_paths:
            continue
        if suffix in _UNSUPPORTED_SUFFIXES or PurePosixPath(path).name == "binding.gyp":
            issues.append(f"Unsupported code or native file: {path}")
            continue
        if PurePosixPath(path).name == "package.json":
            continue
        relevant = suffix in _SUPPORTED_SUFFIXES or path in entry_paths
        if not relevant:
            continue
        code = text if file is root else _read_relevant_file(file, issues)
        if code is None:
            continue
        if suffix == ".json":
            _json_data(code, path, issues)
            continue
        analysis_file = file
        if (
            not suffix
            and path in entry_paths
            and (path in node_entry_paths or re.match(r"#![^\n]*\bnode(?:\s|$)", code))
        ):
            suffix = ".js"
            analysis_file = ArtifactFile(file.relative_path + ".js", file.path, file.size)
        if suffix not in _SUPPORTED_SUFFIXES:
            issues.append(f"Unsupported executable entrypoint format: {path}")
            continue
        if suffix in _JS_SUFFIXES:
            code = _normalize_javascript(code, path, issues)
        for finding in package_code._analyze_file(snapshot, analysis_file, code):
            rule = finding.signal_type
            evidence = _observation_evidence(code, rule, suffix)
            action = "block" if finding.metadata.get("action") == "block" else "review"
            facts.append(
                BehaviorFact(
                    "code_observation",
                    f"{rule}:{path}",
                    {
                        "rule_id": rule,
                        "file": path,
                        "evidence_sha256": hashlib.sha256(evidence.encode()).hexdigest(),
                        "evidence_preview": evidence[:480],
                        "description": finding.metadata.get("reason", ""),
                    },
                    action,
                )
            )
    return BehaviorProfile(
        tuple(sorted(facts, key=lambda fact: (fact.kind, fact.key))),
        tuple(sorted(set(issues))),
        declarations_complete,
    )


def _read_relevant_file(file: ArtifactFile, issues: list[str]) -> str | None:
    if file.size > package_code.MAX_TEXT_BYTES:
        issues.append(f"Relevant file exceeds text inspection limit: {file.relative_path}")
        return None
    try:
        with file.path.open("rb") as stream:
            raw = stream.read(package_code.MAX_TEXT_BYTES + 1)
    except OSError:
        issues.append(f"Relevant file could not be read: {file.relative_path}")
        return None
    if len(raw) > package_code.MAX_TEXT_BYTES:
        issues.append(f"Relevant file exceeds text inspection limit: {file.relative_path}")
        return None
    if b"\x00" in raw:
        issues.append(f"Relevant file contains binary data: {file.relative_path}")
        return None
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        issues.append(f"Relevant file is not valid UTF-8: {file.relative_path}")
        return None


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON constant: {value}")


def _json_data(text: str, path: str, issues: list[str]) -> Any:
    try:
        data = json.loads(
            text, object_pairs_hook=_unique_json_object, parse_constant=_reject_json_constant
        )
    except (ValueError, RecursionError):
        issues.append(f"Invalid or ambiguous JSON: {path}")
        return None
    pending = [(data, 0)]
    while pending:
        value, depth = pending.pop()
        if depth > 64:
            issues.append(f"JSON nesting exceeds inspection limit: {path}")
            return None
        children = (
            value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
        )
        pending.extend((child, depth + 1) for child in children)
    return data


def _manifest(text: str, path: str, issues: list[str]) -> dict[str, Any] | None:
    count = len(issues)
    manifest = _json_data(text, path, issues)
    if len(issues) > count:
        return None
    if not isinstance(manifest, dict):
        issues.append(f"Package manifest is not an object: {path}")
        return None
    return manifest


def _matching_identity(
    snapshot: ArtifactSnapshot, manifest: dict[str, Any], issues: list[str]
) -> bool:
    expected_names = {snapshot.package.name}
    alias_targets = set()
    specifiers = snapshot.package.metadata.get("requested_specifiers", [])
    if isinstance(specifiers, (list, tuple)):
        for specifier in specifiers:
            if isinstance(specifier, str) and specifier.startswith("npm:"):
                target = specifier[4:]
                split = target.rfind("@")
                alias_targets.add(target[:split] if split > 0 else target)
    if alias_targets:
        expected_names = alias_targets
    if (
        len(expected_names) != 1
        or not isinstance(manifest.get("name"), str)
        or manifest["name"] not in expected_names
    ):
        issues.append("Root package manifest name does not match the locked package identity")
        return False
    if not snapshot.package.version or manifest.get("version") != snapshot.package.version:
        issues.append("Root package manifest version does not match the locked version")
        return False
    return True


def _manifest_facts(manifest: dict[str, Any], issues: list[str]) -> list[BehaviorFact]:
    facts: list[BehaviorFact] = []
    module_type = manifest.get("type", "unspecified")
    if module_type not in ("commonjs", "module", "unspecified") or (
        module_type == "unspecified" and "type" in manifest
    ):
        issues.append("Invalid manifest module type declaration")
    else:
        # Omission is explicit: its interpretation can depend on the Node
        # version and syntax detection, so do not equate it with CommonJS.
        facts.append(BehaviorFact("module_format", "type", module_type, "review"))
    if "gypfile" in manifest and not isinstance(manifest["gypfile"], bool):
        issues.append("Invalid manifest gypfile declaration")
    directories = manifest.get("directories", {})
    if not isinstance(directories, dict):
        issues.append("Invalid manifest directories declaration")
    elif "bin" in directories:
        if "bin" in manifest:
            issues.append("Conflicting bin and directories.bin declarations")
        elif not isinstance(directories["bin"], str) or not directories["bin"]:
            issues.append("Invalid directories.bin declaration")
    scripts = manifest.get("scripts", {})
    if not isinstance(scripts, dict):
        issues.append("Manifest scripts field is not an object")
    else:
        for hook in (*package_code.NPM_INSTALL_HOOKS, package_code.NPM_PREPARE_HOOK):
            if hook not in scripts:
                continue
            command = scripts[hook]
            if not isinstance(command, str):
                issues.append(f"Manifest lifecycle script is not a string: {hook}")
                continue
            if not command.strip():
                continue
            action = "block" if package_code.NPM_SCRIPT_EXEC_RE.search(command) else "review"
            facts.append(
                BehaviorFact(
                    "lifecycle_script",
                    hook,
                    {
                        "command": command.strip(),
                        "execution": "declared_prepare" if hook == "prepare" else "npm_install",
                    },
                    action,
                )
            )
    for field in ENTRYPOINT_FIELDS:
        if field not in manifest:
            continue
        value = manifest[field]
        if not _valid_entrypoint(field, value):
            issues.append(f"Invalid manifest entrypoint declaration: {field}")
            continue
        # Conditional export/import key ordering controls which target Node uses.
        if field in {"exports", "imports"}:
            value = _ordered_conditions(value)
        facts.append(BehaviorFact("entrypoint", field, value, "review"))
    for group in _DEPENDENCY_GROUPS:
        dependencies = manifest.get(group, {})
        if not isinstance(dependencies, dict):
            issues.append(f"Invalid manifest dependency group: {group}")
            continue
        for name, specifier in sorted(dependencies.items()):
            if not name or not isinstance(specifier, str):
                issues.append(f"Invalid manifest dependency declaration: {group}:{name}")
                continue
            facts.append(BehaviorFact("dependency", f"{group}:{name}", specifier, "review"))
    for field in ("bundledDependencies", "bundleDependencies", "peerDependenciesMeta"):
        if field in manifest:
            value = manifest[field]
            valid = (
                isinstance(value, dict)
                if field == "peerDependenciesMeta"
                else (
                    isinstance(value, bool)
                    or isinstance(value, list)
                    and all(isinstance(name, str) for name in value)
                )
            )
            if valid:
                facts.append(BehaviorFact("dependency", field, value, "review"))
            else:
                issues.append(f"Invalid manifest dependency declaration: {field}")
    return facts


def _valid_entrypoint(field: str, value: Any) -> bool:
    if field in {"main", "module"}:
        return isinstance(value, str)
    if field == "bin":
        return (
            isinstance(value, str)
            or isinstance(value, dict)
            and all(isinstance(item, str) for item in value.values())
        )
    if field == "browser":
        return (
            isinstance(value, (str, bool))
            or isinstance(value, dict)
            and all(isinstance(item, (str, bool)) for item in value.values())
        )
    if value is None or isinstance(value, str):
        return True
    if isinstance(value, list):
        return all(_valid_entrypoint(field, item) for item in value)
    if isinstance(value, dict):
        return all(_valid_entrypoint(field, item) for item in value.values())
    return False


def _ordered_conditions(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            "ordered_conditions": [[key, _ordered_conditions(item)] for key, item in value.items()]
        }
    if isinstance(value, list):
        return [_ordered_conditions(item) for item in value]
    return value


def _normalize_javascript(text: str, path: str, issues: list[str]) -> str:
    """Normalize lexical spacing for heuristic rules; this is not a JS parser."""
    tokens = []
    offset = 0
    while offset < len(text):
        char = text[offset]
        if char.isspace():
            offset += 1
            continue
        if text.startswith("//", offset):
            newline = text.find("\n", offset)
            offset = len(text) if newline < 0 else newline + 1
            continue
        if text.startswith("/*", offset):
            end = text.find("*/", offset + 2)
            if end < 0:
                issues.append(f"Unterminated JavaScript comment: {path}")
                break
            offset = end + 2
            continue
        if char in "'\"`" or (char == "/" and (not tokens or tokens[-1] in _REGEX_PREFIXES)):
            end = offset + 1
            in_class = False
            closed = False
            while end < len(text):
                if text[end] == "\\":
                    end += 2
                    continue
                if char == "/":
                    if text[end] == "[":
                        in_class = True
                    elif text[end] == "]":
                        in_class = False
                if text[end] == char and not in_class:
                    end += 1
                    closed = True
                    break
                end += 1
            if not closed:
                issues.append(f"Unterminated JavaScript literal: {path}")
            if char == "/":
                while end < len(text) and text[end].isalpha():
                    end += 1
            tokens.append(text[offset:end])
            offset = end
            continue
        match = _JS_TOKEN.match(text, offset)
        assert match is not None
        tokens.append(match.group())
        offset = match.end()

    output = []
    previous = ""
    for token in tokens:
        if previous and (
            (previous[-1].isalnum() or previous[-1] in "_$")
            and (token[0].isalnum() or token[0] in "_$")
            or previous[-1] in "+-*/&|"
            and token[0] in "+-*/&|"
        ):
            output.append(" ")
        output.append(token)
        if token == ";":
            output.append("\n")
        previous = token
    return "".join(output)


def _observation_evidence(text: str, rule: str, suffix: str) -> str:
    if suffix not in _JS_SUFFIXES:
        # Python observations retain the whole file's AST when parseable, so
        # line and indentation changes are excluded without rewriting strings.
        import ast

        try:
            return ast.dump(ast.parse(text), include_attributes=False)
        except SyntaxError:
            return text
    patterns = {
        "npm-encoded-execution": (package_code._JS_ENCODED_EXEC_RE,),
        "npm-credential-exfiltration": (
            package_code._JS_CREDENTIAL_RE,
            package_code._JS_NETWORK_RE,
            package_code._JS_PROCESS_RE,
        ),
    }.get(rule, ())
    boundaries = [match.end() for match in re.finditer(";\n", text)]
    ranges: Counter[tuple[int, int]] = Counter()
    for pattern in patterns:
        for match in pattern.finditer(text):
            start_index = bisect_right(boundaries, match.start())
            end_index = bisect_right(boundaries, match.end())
            start = boundaries[start_index - 1] if start_index else 0
            end = boundaries[end_index] - 1 if end_index < len(boundaries) else len(text)
            ranges[(start, end)] += 1
    contexts = sorted((text[start:end], count) for (start, end), count in ranges.items())
    # Preserve repetition counts, but unrelated statement ordering is not a new
    # observation of these rules. No truncated line snippets enter the identity.
    return json.dumps(sorted(contexts), ensure_ascii=False)
