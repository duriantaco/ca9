"""Deterministic deltas between two published artifacts of the same package.

Each side is reduced to behaviours with a comparison identity. A behaviour is
reported only when its identity is absent from the old artifact; identities
present in both versions are counted as unchanged. Nothing here imports,
installs or executes package code: Python is parsed with ``ast`` and every
other file is read as bounded text or bytes.
"""

from __future__ import annotations

import ast
import hashlib
import json
import posixpath
import re
import sys
from collections import Counter
from dataclasses import dataclass, field, replace
from pathlib import PurePosixPath
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from ca9.analyzers import package_code as pc
from ca9.artifacts.model import ArtifactFile, ArtifactSnapshot
from ca9.review.behavior import inspect_snapshot
from ca9.review.npm_entrypoints import resolve_manifest_entrypoints
from ca9.review.redaction import redact_text

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python < 3.11
    import tomli as tomllib

BLOCK_KINDS = (
    "new_pth_code",
    "new_sitecustomize",
    "new_install_hook",
    "new_decode_exec",
    "new_git_or_url_dependency",
    "ships_agent_or_editor_hook",
)
WARN_KINDS = (
    "new_import_time_network",
    "new_import_time_exec",
    "obfuscation_growth",
    "new_native_binary",
    "publisher_change",
)
MAX_DELTAS_PER_KIND = 20
MAX_SNIPPET = 200
MAX_IMPORT_MODULES = 400
MAX_JS_REACHABLE = 3000
OBFUSCATION_MIN_BYTES = 20 * 1024
_TEXT_LIMIT = pc.MAX_TEXT_BYTES
_HASH_CHUNK = 1024 * 1024
_NATIVE_SUFFIXES = (".so", ".pyd", ".dll", ".dylib", ".node", ".exe")
_NATIVE_MAGIC = (
    b"\x7fELF",
    b"MZ",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
)
_STARTUP_MODULES = ("sitecustomize", "usercustomize")
_STARTUP_SUFFIXES = (".py", ".pyc", ".so", ".pyd")
_SDIST_NON_PACKAGES = frozenset(
    {"tests", "test", "testing", "docs", "doc", "examples", "example", "benchmarks", "scripts"}
)
_SDIST_ROOT_SCRIPTS = frozenset({"setup.py", "conftest.py", "noxfile.py", "tasks.py", "fabfile.py"})
_BUILD_HOOK_FILES = frozenset({"setup.py", "hatch_build.py", "pdm_build.py", "build.py"})
_STANDARD_BACKENDS = frozenset(
    {
        "setuptools.build_meta",
        "setuptools.build_meta:__legacy__",
        "hatchling.build",
        "flit_core.buildapi",
        "flit.buildapi",
        "poetry.core.masonry.api",
        "poetry.masonry.api",
        "pdm.backend",
        "pdm.pep517.api",
        "maturin",
        "scikit_build_core.build",
        "mesonpy",
        "sipbuild.api",
        "uv_build",
        "whey",
        "enscons.api",
        "pbr.build",
        "jupyter_packaging.build_api",
        "hatchling.ouroboros",
        "setuptools_rust.build_meta",
        "py_build_cmake.build",
        "meson_python",
        "cython_cmake.build",
        "backend",
    }
)
_AGENT_FILES = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".gemini/settings.json",
    ".vscode/tasks.json",
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
)
_AGENT_ENV_RE = re.compile(
    r"(?:ANTHROPIC|OPENAI|GEMINI|GOOGLE|AZURE_OPENAI|CLAUDE)_[A-Z_]*(?:BASE_URL|API_BASE|ENDPOINT)",
    re.I,
)
_RULE_EXEC_RE = re.compile(
    r"\b(?:run|execute|exec)\b|`[^`\n]*\b(?:node|python3?|bash|sh|curl|wget|npx|bun|uvx)\b",
    re.I,
)
_NPM_URL_SPEC = re.compile(
    r"^(?:git\+|git:|github:|gitlab:|bitbucket:|gist:|https?:|file:|link:)|"
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:#.*)?$",
    re.I,
)
_NPM_DEPENDENCY_GROUPS = ("dependencies", "optionalDependencies", "peerDependencies")
_NPM_INSTALL_HOOKS = ("preinstall", "install", "postinstall")
_JS_SUFFIXES = (".js", ".cjs", ".mjs")
_JS_SPEC_RE = re.compile(
    r"(?:\brequire\s*\(\s*|\bimport\s*\(\s*|\bfrom\s*|\bimport\s+)(['\"])([^'\"\n]{1,300})\1"
)
_JS_EXEC_MODULES = frozenset({"child_process", "vm"})
_JS_NETWORK_MODULES = frozenset({"http", "https", "net", "tls", "dgram", "dns", "http2"})
_JS_BINDING_RE = re.compile(r"\bprocess\s*\.\s*(?:binding|_linkedBinding|dlopen)\s*\(")
_OBFUSCATED_IDENT_RE = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
_HEX_ESCAPE_RE = re.compile(r"\\x[0-9a-fA-F]{2}")
_BLOB_RE = re.compile(r"[A-Za-z0-9+/=_-]{10000,}")
_PY_EXEC_NAMES = frozenset({"exec", "eval", "execfile"})
_DECODE_EXEC_HINT = re.compile(
    r"exec|eval|compile|decode|loads|unhexlify|fromhex|Popen|system|spawn|subprocess|"
    r"getattr|__import__|import_module|globals|builtins|sys\.modules|urlopen"
)
_NPM_CODE_RULE_KINDS = {
    "npm-encoded-execution": ("new_decode_exec", "decodes data and executes it"),
    "npm-obfuscated-require": (
        "new_decode_exec",
        "builds a sensitive module name at runtime before loading it",
    ),
    "encoded-execution": ("new_decode_exec", "decodes data and executes it"),
    "npm-credential-exfiltration": (
        "new_import_time_network",
        "reads credentials or dumps the environment next to network or process code",
    ),
    "npm-wallet-network-hijack": (
        "new_import_time_network",
        "replaces fetch/XMLHttpRequest or wallet provider methods",
    ),
    "credential-network-exfiltration": (
        "new_import_time_network",
        "reads credentials or dumps the environment next to network code",
    ),
}


@dataclass(frozen=True)
class Behaviour:
    kind: str
    identity: tuple
    path: str
    line: int | None
    snippet: str
    detail: str
    level: str

    def delta(self) -> dict[str, Any]:
        snippet = redact_text(" ".join(self.snippet.split()))
        if len(snippet) > MAX_SNIPPET:
            snippet = snippet[: MAX_SNIPPET - 3] + "..."
        return {
            "kind": self.kind,
            "path": redact_text(self.path),
            "line": self.line,
            "snippet": snippet,
            "detail": redact_text(self.detail),
        }


@dataclass
class DiffResult:
    block: list[dict[str, Any]] = field(default_factory=list)
    warn: list[dict[str, Any]] = field(default_factory=list)
    info: list[dict[str, Any]] = field(default_factory=list)
    unchanged_risky: Counter = field(default_factory=Counter)
    limitations: list[str] = field(default_factory=list)


@dataclass
class _Entry:
    path: str
    install_path: str
    file: ArtifactFile


class _Cache:
    """Parse results shared by both sides; identical files are analysed once."""

    def __init__(self) -> None:
        self.trees: dict[str, ast.Module | None] = {}
        self.calls: dict[tuple[str, bool], list[_PyCall] | None] = {}
        self.encoded: dict[str, list[int]] = {}


class _Side:
    """One artifact: package-relative paths, content digests and bounded reads."""

    def __init__(
        self, snapshot: ArtifactSnapshot, ecosystem: str, cache: _Cache | None = None
    ) -> None:
        self.cache = cache or _Cache()
        self.snapshot = snapshot
        self.ecosystem = ecosystem
        self.kind = snapshot.artifact.kind
        self.entries: dict[str, _Entry] = {}
        self.root_prefix = _root_prefix(snapshot, ecosystem)
        for file in snapshot.files:
            path = file.relative_path
            if self.root_prefix:
                if not path.startswith(self.root_prefix):
                    path = "../" + path
                else:
                    path = path[len(self.root_prefix) :]
            self.entries[path] = _Entry(path, self._install_path(path), file)
        self._hashes: dict[str, str] = {}
        self._texts: dict[str, str | None] = {}

    def _install_path(self, path: str) -> str:
        if self.kind == "wheel":
            parts = path.split("/")
            if len(parts) > 2 and parts[0].endswith(".data"):
                if parts[1] in {"purelib", "platlib"}:
                    return "/".join(parts[2:])
                if parts[1] == "data":
                    rest = "/".join(parts[2:])
                    match = re.match(r"(?:lib/python[0-9.]*|Lib)/site-packages/(.+)", rest)
                    if match:
                        return match.group(1)
            return path
        if self.kind == "sdist" and path.startswith("src/"):
            return path[4:]
        return path

    def digest(self, path: str) -> str:
        if path not in self._hashes:
            digest = hashlib.sha256()
            try:
                with self.entries[path].file.path.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(_HASH_CHUNK), b""):
                        digest.update(chunk)
                self._hashes[path] = digest.hexdigest()
            except OSError:
                self._hashes[path] = f"unreadable:{path}"
        return self._hashes[path]

    def text(self, path: str) -> str | None:
        if path not in self._texts:
            entry = self.entries[path]
            raw = pc._read_bytes(entry.file, _TEXT_LIMIT + 1)
            if raw is None or len(raw) > _TEXT_LIMIT:
                self._texts[path] = None
            else:
                self._texts[path] = pc._decode_text(raw)
        return self._texts[path]

    def head(self, path: str, size: int = 4096) -> bytes:
        raw = pc._read_bytes(self.entries[path].file, size)
        return raw or b""

    def tree(self, path: str) -> ast.Module | None:
        digest = self.digest(path)
        if digest not in self.cache.trees:
            self.cache.trees[digest] = _python_tree(self.text(path))
        return self.cache.trees[digest]

    def calls(self, path: str, import_time_only: bool) -> list[_PyCall] | None:
        key = (self.digest(path), import_time_only)
        if key not in self.cache.calls:
            text = self.text(path)
            tree = self.tree(path)
            calls = None
            if text is not None and tree is not None:
                calls = _python_calls(text, tree, import_time_only=import_time_only)
            self.cache.calls[key] = calls
        return self.cache.calls[key]

    def encoded_lines(self, path: str) -> list[int]:
        digest = self.digest(path)
        if digest not in self.cache.encoded:
            lines: list[int] = []
            tree = self.tree(path)
            if tree is not None:
                try:
                    events = pc._tree_events(tree, 0)
                except RecursionError:
                    events = []
                lines = sorted(event.line for event in events if event.kind == "encoded_exec")
            self.cache.encoded[digest] = lines
        return self.cache.encoded[digest]

    def top_modules(self) -> set[str]:
        modules = set()
        for entry in self.entries.values():
            first = entry.install_path.split("/", 1)[0]
            if first.endswith((".dist-info", ".egg-info", ".data")) or first.startswith(".."):
                continue
            if "/" in entry.install_path:
                modules.add(first)
            elif first.endswith((".py", ".pyc", ".so", ".pyd")):
                modules.add(first.split(".", 1)[0])
        return modules


def diff_artifacts(
    old: ArtifactSnapshot,
    new: ArtifactSnapshot,
    ecosystem: str,
) -> DiffResult:
    """Behaviours of ``new`` whose identity is absent from ``old``."""
    cache = _Cache()
    before = _Side(old, ecosystem, cache)
    after = _Side(new, ecosystem, cache)
    changed = _changed_paths(before, after)
    result = DiffResult()
    old_behaviours: list[Behaviour] = []
    new_behaviours: list[Behaviour] = []
    collectors = [
        _agent_hook_behaviours,
        _native_binary_behaviours,
    ]
    if ecosystem == "pypi":
        old_behaviours.extend(_pth_behaviours(before, None))
        new_behaviours.extend(_pth_behaviours(after, before.top_modules()))
        collectors.extend(
            [
                _startup_module_behaviours,
                _python_dependency_behaviours,
                _build_hook_behaviours,
                _python_import_time_behaviours,
            ]
        )
    else:
        collectors.extend([_npm_manifest_behaviours, _npm_import_time_behaviours])
    for collect in collectors:
        old_behaviours.extend(collect(before, result))
        new_behaviours.extend(collect(after, result))
    old_changed, new_changed = _changed_file_behaviours(before, after, changed, result)
    old_behaviours.extend(old_changed)
    new_behaviours.extend(new_changed)
    _assemble(old_behaviours, new_behaviours, result)
    return result


def _assemble(
    old_behaviours: list[Behaviour], new_behaviours: list[Behaviour], result: DiffResult
) -> None:
    old_ids = {item.identity for item in old_behaviours}
    reported: set[tuple] = set()
    counts: Counter = Counter()
    ordered = sorted(
        new_behaviours, key=lambda item: (item.kind, item.path, item.line or 0, item.snippet)
    )
    for item in ordered:
        key = item.identity
        if key in reported:
            continue
        reported.add(key)
        if key in old_ids:
            if item.level in {"block", "warn"}:
                result.unchanged_risky[item.kind] += 1
            continue
        target = {"block": result.block, "warn": result.warn}.get(item.level, result.info)
        counts[(item.level, item.kind)] += 1
        if counts[(item.level, item.kind)] <= MAX_DELTAS_PER_KIND:
            target.append(item.delta())
    for (level, kind), count in sorted(counts.items()):
        if count > MAX_DELTAS_PER_KIND:
            result.limitations.append(
                f"{count - MAX_DELTAS_PER_KIND} more {level} deltas of kind {kind} not listed"
            )


def _root_prefix(snapshot: ArtifactSnapshot, ecosystem: str) -> str:
    paths = [file.relative_path for file in snapshot.files]
    if not paths:
        return ""
    if snapshot.artifact.kind == "npm-tarball" or ecosystem == "npm":
        if "package/package.json" in paths:
            return "package/"
        firsts = {path.split("/", 1)[0] for path in paths if "/" in path}
        if len(firsts) == 1:
            first = next(iter(firsts))
            if f"{first}/package.json" in paths:
                return first + "/"
        return ""
    if snapshot.artifact.kind == "sdist":
        firsts = {path.split("/", 1)[0] for path in paths}
        if len(firsts) == 1 and all("/" in path for path in paths):
            return next(iter(firsts)) + "/"
    return ""


def _changed_paths(before: _Side, after: _Side) -> set[str]:
    changed = set()
    for path in before.entries.keys() | after.entries.keys():
        if path not in before.entries or path not in after.entries:
            changed.add(path)
            continue
        old_entry = before.entries[path]
        new_entry = after.entries[path]
        if old_entry.file.size != new_entry.file.size or before.digest(path) != after.digest(path):
            changed.add(path)
    return changed


def _line_of(text: str, needle: str) -> tuple[int | None, str]:
    if not needle:
        return None, ""
    index = text.find(needle)
    if index < 0:
        return None, ""
    return pc._line_snippet(text, index)


def _python_tree(text: str | None) -> ast.Module | None:
    if text is None:
        return None
    return pc._parse_python(text)


def _has_code(tree: ast.Module | None) -> bool:
    if tree is None:
        return True
    for index, node in enumerate(tree.body):
        if isinstance(node, ast.Pass):
            continue
        if (
            index == 0
            and isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            continue
        return True
    return False


def _ast_fingerprint(text: str | None, raw_digest: str) -> str:
    tree = _python_tree(text)
    if tree is None:
        return raw_digest
    return hashlib.sha256(ast.dump(tree, include_attributes=False).encode()).hexdigest()


def _pth_behaviours(side: _Side, baseline_modules: set[str] | None) -> list[Behaviour]:
    """Executable .pth lines; ``baseline_modules`` are the old release's top-level modules.

    A new line blocks when it runs process, network, decode or dynamic exec code, cannot
    be parsed, or imports a module that the old release did not ship. A new line that
    only imports standard-library modules or modules already in the old release still
    runs at every interpreter start and is reported as import-time execution.
    """
    behaviours = []
    for path in side.entries:
        if not path.lower().endswith(".pth"):
            continue
        text = side.text(path)
        if text is None:
            behaviours.append(
                Behaviour(
                    "new_pth_code",
                    ("pth-unreadable", path, side.digest(path)),
                    path,
                    None,
                    "",
                    "startup .pth file is too large or binary to inspect",
                    "block",
                )
            )
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if not line.startswith(("import ", "import\t")):
                continue
            kind, level, detail = _pth_line_level(line.strip(), baseline_modules)
            behaviours.append(
                Behaviour(
                    kind,
                    ("pth", " ".join(line.split())),
                    path,
                    number,
                    line,
                    detail,
                    level,
                )
            )
    return behaviours


def _pth_line_level(line: str, baseline_modules: set[str] | None) -> tuple[str, str, str]:
    prefix = ".pth import line runs at every interpreter start"
    verdict = pc._pth_line_verdict(line)
    tree = pc._parse_python(line)
    if verdict == "critical" or tree is None:
        return "new_pth_code", "block", f"{prefix} and runs process, network, decode or exec code"
    if baseline_modules is None:
        return "new_pth_code", "block", prefix
    imported = _pth_imports(tree, 0)
    unknown = sorted(
        name
        for name in imported
        if name not in sys.stdlib_module_names and name not in baseline_modules
    )
    if unknown:
        return (
            "new_pth_code",
            "block",
            f"{prefix} and imports modules the old release did not ship: {', '.join(unknown)}",
        )
    return (
        "new_import_time_exec",
        "warn",
        f"{prefix}; it imports only standard-library modules or modules already in the "
        "old release and runs no process, network, decode or dynamic exec code",
    )


def _pth_imports(tree: ast.Module, depth: int) -> set[str]:
    ctx = pc._PyContext(tree)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call) and node.args:
            name, _obfuscated = ctx.resolve(node.func)
            folded, _built = pc._fold(node.args[0], ctx, 0)
            if folded is None:
                continue
            if name in {"__import__", "importlib.import_module"}:
                names.add(folded.split(".")[0])
            elif name in _PY_EXEC_NAMES and depth < 2:
                nested = pc._parse_python(folded)
                if nested is None:
                    names.add("<unparsed exec>")
                else:
                    names.update(_pth_imports(nested, depth + 1))
    return names


def _startup_module_behaviours(side: _Side, result: DiffResult) -> list[Behaviour]:
    behaviours = []
    for path, entry in side.entries.items():
        install_name = PurePosixPath(entry.install_path).name.lower()
        stem = install_name.partition(".")[0]
        if stem not in _STARTUP_MODULES or not install_name.endswith(_STARTUP_SUFFIXES):
            continue
        top_level = "/" not in entry.install_path
        text = None
        if install_name.endswith(".py"):
            text = side.text(path)
            tree = side.tree(path)
            if text is not None and tree is not None and not _has_code(tree):
                continue
            fingerprint = _ast_fingerprint(text, side.digest(path))
        else:
            fingerprint = side.digest(path)
        identity: tuple = ("startup", entry.install_path.lower())
        location = "top-level, imported automatically at interpreter start"
        if top_level:
            identity = ("startup", entry.install_path.lower(), fingerprint)
        else:
            location = "nested; runs when its directory is put on sys.path"
        first_line, snippet = _first_code_line(text)
        behaviours.append(
            Behaviour(
                "new_sitecustomize",
                identity,
                path,
                first_line,
                snippet,
                f"{stem} module with code ({location})",
                "block",
            )
        )
    return behaviours


def _first_code_line(text: str | None) -> tuple[int | None, str]:
    if not text:
        return None, ""
    lines = text.splitlines()
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped and not stripped.startswith(("#", '"""', "'''")):
            return number, stripped
    return 1, "".join(lines[:1])


def _agent_hook_behaviours(side: _Side, result: DiffResult) -> list[Behaviour]:
    behaviours = []
    for path in side.entries:
        lowered = path.lower()
        rule = "/.cursor/rules/" in "/" + lowered
        matched = rule or any(
            lowered == suffix or lowered.endswith("/" + suffix) for suffix in _AGENT_FILES
        )
        if not matched:
            continue
        text = side.text(path) or ""
        executes, line, snippet, detail = _agent_file_trigger(lowered, text)
        level = "info"
        if executes:
            level = "block"
        behaviours.append(
            Behaviour(
                "ships_agent_or_editor_hook",
                ("agent", path, side.digest(path)),
                path,
                line,
                snippet,
                detail,
                level,
            )
        )
    return behaviours


def _agent_file_trigger(lowered: str, text: str) -> tuple[bool, int | None, str, str]:
    data = _jsonc(text)
    if "/.cursor/rules/" in "/" + lowered:
        always = re.search(r"^\s*alwaysApply\s*:\s*true\s*$", text, re.M | re.I)
        command = _RULE_EXEC_RE.search(text)
        if always and command:
            line, snippet = pc._line_snippet(text, command.start())
            return True, line, snippet, "always-applied Cursor rule instructs the agent to run code"
        return False, None, "", "Cursor rule file shipped in the package"
    if lowered.endswith("tasks.json"):
        for task in _json_tasks(data):
            options = task.get("runOptions")
            if isinstance(options, dict) and options.get("runOn") == "folderOpen":
                command = " ".join(
                    str(part)
                    for part in [task.get("command", ""), *(task.get("args") or [])]
                    if isinstance(part, (str, int))
                )
                line, _ = _line_of(text, "folderOpen")
                return True, line, command, "VS Code task runs automatically on folderOpen"
        if data is None and re.search(r"\"runOn\"\s*:\s*\"folderOpen\"", text):
            line, snippet = _line_of(text, "folderOpen")
            return True, line, snippet, "VS Code task runs automatically on folderOpen"
        return False, None, "", "VS Code tasks file without a folderOpen task"
    if lowered.endswith("mcp.json"):
        servers = {}
        if isinstance(data, dict):
            for key in ("mcpServers", "servers"):
                if isinstance(data.get(key), dict):
                    servers.update(data[key])
        if servers or (data is None and re.search(r"\"(?:mcpServers|servers)\"", text)):
            name, server = next(iter(servers.items()), ("", {}))
            snippet = _server_command(server)
            line, _ = _line_of(text, name or "ervers")
            return True, line, snippet, "MCP config starts servers when an agent opens the folder"
        return False, None, "", "MCP config without servers"
    if isinstance(data, dict):
        hooks = data.get("hooks")
        if isinstance(hooks, dict) and hooks:
            event = next(iter(hooks))
            command = _first_command(hooks)
            line, _ = _line_of(text, command or event)
            return True, line, command, f"agent settings define a {event} hook"
        env = data.get("env")
        if isinstance(env, dict):
            for key, value in env.items():
                if _AGENT_ENV_RE.search(str(key)):
                    line, _ = _line_of(text, str(key))
                    return True, line, f"{key}={value}", "agent settings override the model API URL"
        for key in ("apiKeyHelper", "mcpServers", "enableAllProjectMcpServers"):
            if data.get(key):
                line, snippet = _line_of(text, key)
                return True, line, snippet, f"agent settings set {key}"
        return False, None, "", "agent settings without hooks, API overrides or MCP servers"
    match = re.search(r"\"hooks\"\s*:|BASE_URL|apiKeyHelper|mcpServers", text)
    if match is not None:
        line, snippet = pc._line_snippet(text, match.start())
        return True, line, snippet, "unparseable agent settings mention hooks or API overrides"
    return False, None, "", "agent settings file shipped in the package"


def _jsonc(text: str) -> Any:
    if not text.strip():
        return None
    try:
        return json.loads(text)
    except ValueError:
        pass
    output = []
    index = 0
    in_string = False
    while index < len(text):
        char = text[index]
        if in_string:
            output.append(char)
            if char == "\\" and index + 1 < len(text):
                output.append(text[index + 1])
                index += 2
                continue
            if char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            output.append(char)
            index += 1
            continue
        if text.startswith("//", index):
            newline = text.find("\n", index)
            index = len(text)
            if newline >= 0:
                index = newline
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = len(text)
            if end >= 0:
                index = end + 2
            continue
        output.append(char)
        index += 1
    cleaned = re.sub(r",(\s*[}\]])", r"\1", "".join(output))
    try:
        return json.loads(cleaned)
    except ValueError:
        return None


def _json_tasks(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict) or not isinstance(data.get("tasks"), list):
        return []
    return [task for task in data["tasks"] if isinstance(task, dict)]


def _first_command(value: Any) -> str:
    stack = [value]
    while stack:
        item = stack.pop(0)
        if isinstance(item, dict):
            command = item.get("command")
            if isinstance(command, str):
                return command
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return ""


def _server_command(server: Any) -> str:
    if not isinstance(server, dict):
        return ""
    if isinstance(server.get("url"), str):
        return server["url"]
    parts = [server.get("command", "")]
    args = server.get("args")
    if isinstance(args, list):
        parts.extend(args)
    return " ".join(str(part) for part in parts if isinstance(part, (str, int)))


def _native_binary_behaviours(side: _Side, result: DiffResult) -> list[Behaviour]:
    behaviours = []
    for path, entry in side.entries.items():
        lowered = path.lower()
        native = lowered.endswith(_NATIVE_SUFFIXES) or ".so." in PurePosixPath(lowered).name
        if not native and entry.file.size >= 4:
            head = side.head(path, 8)
            native = head.startswith(_NATIVE_MAGIC) and not lowered.endswith(".class")
            if native and head.startswith(b"MZ") and entry.file.size < 512:
                native = False
        if not native:
            continue
        identity = re.sub(r"[0-9a-f]{6,}|\d+", "#", lowered)
        behaviours.append(
            Behaviour(
                "new_native_binary",
                ("native", identity),
                path,
                None,
                "",
                f"native binary ({entry.file.size} bytes); static rules cannot inspect it",
                "warn",
            )
        )
    return behaviours


def _python_dependency_behaviours(side: _Side, result: DiffResult) -> list[Behaviour]:
    behaviours = []
    for path, requirement_text, line in _python_requirements(side):
        try:
            requirement = Requirement(requirement_text)
        except InvalidRequirement:
            continue
        name = str(canonicalize_name(requirement.name))
        if requirement.url:
            behaviours.append(
                Behaviour(
                    "new_git_or_url_dependency",
                    ("dep-url", name, requirement.url),
                    path,
                    line,
                    requirement_text,
                    f"dependency {name} installs from a direct URL or git reference",
                    "block",
                )
            )
        else:
            behaviours.append(
                Behaviour(
                    "new_dependency",
                    ("dep", name),
                    path,
                    line,
                    requirement_text,
                    f"new dependency {name}",
                    "info",
                )
            )
    return behaviours


def _python_requirements(side: _Side) -> list[tuple[str, str, int | None]]:
    found: list[tuple[str, str, int | None]] = []
    for path in sorted(side.entries):
        parts = path.split("/")
        metadata = (
            len(parts) == 2 and parts[0].endswith(".dist-info") and parts[1] == "METADATA"
        ) or path == "PKG-INFO"
        if metadata:
            text = side.text(path) or ""
            header = text.split("\n\n", 1)[0]
            for number, line in enumerate(header.splitlines(), start=1):
                if line.lower().startswith("requires-dist:"):
                    found.append((path, line.split(":", 1)[1].strip(), number))
        elif path.endswith(".egg-info/requires.txt") and path.count("/") <= 2:
            text = side.text(path) or ""
            for number, line in enumerate(text.splitlines(), start=1):
                stripped = line.strip()
                if stripped and not stripped.startswith(("[", "#")):
                    found.append((path, stripped, number))
        elif path == "pyproject.toml":
            data = _toml(side.text(path))
            project = _table(data, "project")
            groups = [project.get("dependencies")]
            optional = project.get("optional-dependencies")
            if isinstance(optional, dict):
                groups.extend(optional.values())
            groups.append(_table(data, "build-system").get("requires"))
            text = side.text(path) or ""
            for group in groups:
                if not isinstance(group, list):
                    continue
                for item in group:
                    if isinstance(item, str):
                        line, _ = _line_of(text, item)
                        found.append((path, item, line))
    return found


def _table(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    if isinstance(value, dict):
        return value
    return {}


def _toml(text: str | None) -> dict[str, Any]:
    if not text:
        return {}
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError, RecursionError):
        return {}
    if not isinstance(data, dict):
        return {}
    return data


@dataclass(frozen=True)
class _PyCall:
    category: str
    callee: str
    line: int
    snippet: str


def _python_calls(text: str, tree: ast.Module, *, import_time_only: bool) -> list[_PyCall] | None:
    try:
        ctx = pc._PyContext(tree)
        import_time = None
        if import_time_only:
            import_time = pc._import_time_nodes(tree)
        calls: list[_PyCall] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if import_time is not None and id(node) not in import_time:
                continue
            name, _obfuscated = ctx.resolve(node.func)
            category = _call_category(node, name, ctx)
            if category is None:
                continue
            _line, snippet = pc._line_snippet(text, pc._offset_for_line(text, node.lineno))
            calls.append(_PyCall(category, name or "?", node.lineno, snippet))
        return calls
    except RecursionError:
        return None


def _call_category(node: ast.Call, name: str | None, ctx: Any) -> str | None:
    if name in pc._PROCESS_CALLS:
        arguments = [*node.args, *(item.value for item in node.keywords)]
        if any(pc._data_kinds(argument, ctx) & {"decoded", "fetched"} for argument in arguments):
            return "decode_exec"
        return "exec"
    if name in _PY_EXEC_NAMES and node.args:
        argument = node.args[0]
        if pc._data_kinds(argument, ctx) & {"decoded", "fetched"}:
            return "decode_exec"
        if _reads_local_file(argument, ctx):
            return None
        source, _folded = pc._fold(argument, ctx, 0)
        if source is None:
            return "exec"
        nested = pc._python_events(source, 1) or []
        if any(event.kind in pc._RISKY_NESTED_KINDS for event in nested):
            return "exec"
        return None
    if name in pc._NETWORK_CALLS and name not in pc._NETWORK_CLIENT_CALLS:
        return "network"
    if (
        ctx.imports_socket
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"send", "sendall", "sendto", "connect"}
    ):
        return "network"
    return None


def _reads_local_file(node: ast.AST, ctx: Any) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name, _obfuscated = ctx.resolve(child.func)
            if name in {"open", "io.open", "codecs.open"}:
                return True
            if isinstance(child.func, ast.Attribute) and child.func.attr in {
                "read_text",
                "read_bytes",
            }:
                return True
    return False


def _build_hook_behaviours(side: _Side, result: DiffResult) -> list[Behaviour]:
    if side.kind != "sdist":
        return []
    behaviours = []
    pyproject: dict[str, Any] = {}
    if "pyproject.toml" in side.entries:
        pyproject = _toml(side.text("pyproject.toml"))
    build = _table(pyproject, "build-system")
    backend = build.get("build-backend")
    backend_paths = build.get("backend-path")
    hook_files = {path for path in side.entries if path in _BUILD_HOOK_FILES}
    if isinstance(backend, str) and backend:
        in_tree = isinstance(backend_paths, list) and bool(backend_paths)
        text = side.text("pyproject.toml") or ""
        line, snippet = _line_of(text, "build-backend")
        if in_tree or backend not in _STANDARD_BACKENDS:
            detail = f"non-standard build backend {backend}"
            if in_tree:
                detail = "in-tree build backend runs code from the sdist at install time"
            behaviours.append(
                Behaviour(
                    "new_install_hook",
                    ("backend", backend, in_tree),
                    "pyproject.toml",
                    line,
                    snippet,
                    detail,
                    "block",
                )
            )
        else:
            behaviours.append(
                Behaviour(
                    "build_backend",
                    ("backend", backend),
                    "pyproject.toml",
                    line,
                    snippet,
                    f"build backend {backend}",
                    "info",
                )
            )
        if in_tree:
            module = backend.split(":", 1)[0].replace(".", "/")
            for root in backend_paths:
                if isinstance(root, str):
                    base = posixpath.normpath(root).strip("./")
                    for candidate in (f"{module}.py", f"{module}/__init__.py"):
                        joined = posixpath.join(base, candidate)
                        if joined in side.entries:
                            hook_files.add(joined)
    for path in sorted(hook_files):
        text = side.text(path)
        if text is None:
            continue
        calls = side.calls(path, False)
        if calls is None:
            match = pc._SETUP_EXEC_RE.search(text)
            if match:
                line, snippet = pc._line_snippet(text, match.start())
                calls = [_PyCall("exec", match.group(0), line, snippet)]
            else:
                calls = []
        for call in calls:
            behaviours.append(
                Behaviour(
                    "new_install_hook",
                    ("build-call", call.category, call.callee),
                    path,
                    call.line,
                    call.snippet,
                    f"{path} runs {call.callee} during build or install",
                    "block",
                )
            )
    return behaviours


def _python_import_time_behaviours(side: _Side, result: DiffResult) -> list[Behaviour]:
    modules: dict[str, str] = {}
    for path, entry in side.entries.items():
        install = entry.install_path
        if not install.endswith(".py") or install.startswith("../"):
            continue
        parts = install[:-3].split("/")
        if parts[-1] == "__init__":
            parts = parts[:-1]
        if not parts or any(not part.isidentifier() for part in parts):
            continue
        if side.kind == "sdist" and (
            parts[0] in _SDIST_NON_PACKAGES or (len(parts) == 1 and install in _SDIST_ROOT_SCRIPTS)
        ):
            continue
        modules.setdefault(".".join(parts), path)
    roots = sorted(name for name in modules if "." not in name)
    seen: set[str] = set()
    queue = list(roots)
    behaviours: list[Behaviour] = []
    while queue and len(seen) < MAX_IMPORT_MODULES:
        module = queue.pop(0)
        if module in seen or module not in modules:
            continue
        seen.add(module)
        path = modules[module]
        text = side.text(path)
        if text is None:
            continue
        tree = side.tree(path)
        if tree is None:
            continue
        package = module
        if not path.endswith("__init__.py"):
            package = module.rpartition(".")[0]
        for target in _module_imports(tree, package):
            for prefix in _prefixes(target):
                if prefix in modules and prefix not in seen:
                    queue.append(prefix)
        for call in side.calls(path, True) or []:
            if call.category == "decode_exec":
                continue
            kind = "new_import_time_network"
            if call.category == "exec":
                kind = "new_import_time_exec"
            behaviours.append(
                Behaviour(
                    kind,
                    ("import-time", call.category, call.callee),
                    path,
                    call.line,
                    call.snippet,
                    f"{call.callee} runs when {module} is imported",
                    "warn",
                )
            )
    if queue and len(seen) >= MAX_IMPORT_MODULES:
        result.limitations.append(
            f"import-time analysis stopped after {MAX_IMPORT_MODULES} modules"
        )
    return behaviours


def _module_imports(tree: ast.Module, package: str) -> list[str]:
    import_time = pc._import_time_nodes(tree)
    targets = []
    for node in ast.walk(tree):
        if id(node) not in import_time:
            continue
        if isinstance(node, ast.Import):
            targets.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parts = [part for part in package.split(".") if part]
                if node.level - 1 > len(parts):
                    continue
                parts = parts[: len(parts) - (node.level - 1)]
                if node.module:
                    parts.append(node.module)
                base = ".".join(parts)
            if not base:
                continue
            targets.append(base)
            targets.extend(f"{base}.{alias.name}" for alias in node.names if alias.name != "*")
    return targets


def _prefixes(name: str) -> list[str]:
    parts = name.split(".")
    return [".".join(parts[: index + 1]) for index in range(len(parts))]


def _npm_manifest(side: _Side) -> dict[str, Any] | None:
    if "package.json" not in side.entries:
        return None
    data = _jsonc(side.text("package.json") or "")
    if not isinstance(data, dict):
        return None
    return data


def _npm_manifest_behaviours(side: _Side, result: DiffResult) -> list[Behaviour]:
    behaviours = []
    for path in sorted(side.entries):
        if PurePosixPath(path).name != "package.json":
            continue
        bundled = path.startswith("node_modules/") or "/node_modules/" in path
        if path != "package.json" and not bundled:
            continue
        text = side.text(path) or ""
        data = _jsonc(text)
        if not isinstance(data, dict):
            continue
        scripts = _table(data, "scripts")
        prefix = ""
        if path != "package.json":
            prefix = posixpath.dirname(path) + ":"
        for hook in (*_NPM_INSTALL_HOOKS, "prepare"):
            command = scripts.get(hook)
            if not isinstance(command, str) or not command.strip():
                continue
            line, _ = _line_of(text, f'"{hook}"')
            if hook == "prepare":
                behaviours.append(
                    Behaviour(
                        "new_prepare_script",
                        ("npm-prepare", prefix, command.strip()),
                        path,
                        line,
                        command,
                        "prepare scripts do not run when a registry tarball is installed",
                        "info",
                    )
                )
                continue
            behaviours.append(
                Behaviour(
                    "new_install_hook",
                    ("npm-hook", prefix + hook, command.strip()),
                    path,
                    line,
                    command,
                    f"npm runs the {hook} script on install",
                    "block",
                )
            )
        binding = posixpath.join(posixpath.dirname(path), "binding.gyp")
        if (
            binding in side.entries
            and data.get("gypfile") is not False
            and not any(isinstance(scripts.get(hook), str) for hook in ("preinstall", "install"))
        ):
            behaviours.append(
                Behaviour(
                    "new_install_hook",
                    ("npm-hook", prefix + "install", "node-gyp rebuild"),
                    binding,
                    None,
                    "node-gyp rebuild",
                    "binding.gyp makes npm compile native code on install",
                    "block",
                )
            )
        if path != "package.json":
            continue
        for group in _NPM_DEPENDENCY_GROUPS:
            dependencies = data.get(group)
            if not isinstance(dependencies, dict):
                continue
            for name, spec in sorted(dependencies.items()):
                if not isinstance(spec, str):
                    continue
                line, _ = _line_of(text, f'"{name}"')
                if _NPM_URL_SPEC.search(spec.strip()):
                    behaviours.append(
                        Behaviour(
                            "new_git_or_url_dependency",
                            ("dep-url", name, spec.strip()),
                            path,
                            line,
                            f'"{name}": "{spec}"',
                            f"{group} entry {name} installs from git, a URL or a local path",
                            "block",
                        )
                    )
                else:
                    behaviours.append(
                        Behaviour(
                            "new_dependency",
                            ("dep", name),
                            path,
                            line,
                            f'"{name}": "{spec}"',
                            f"new {group} entry {name}",
                            "info",
                        )
                    )
    return behaviours


def _npm_import_time_behaviours(side: _Side, result: DiffResult) -> list[Behaviour]:
    manifest = _npm_manifest(side)
    if manifest is None:
        return []
    files = set(side.entries)
    manifests = {"package.json": manifest}
    entries = resolve_manifest_entrypoints(manifest, "", files, manifests)
    queue = sorted(path for path in entries.paths if path.endswith(_JS_SUFFIXES))
    seen: set[str] = set()
    behaviours: list[Behaviour] = []
    while queue and len(seen) < MAX_JS_REACHABLE:
        path = queue.pop(0)
        if path in seen or path not in side.entries:
            continue
        seen.add(path)
        text = side.text(path)
        if text is None:
            continue
        for match in _JS_SPEC_RE.finditer(text):
            spec = match.group(2)
            if spec.startswith("."):
                target = _resolve_js(posixpath.dirname(path), spec, files)
                if target is not None and target not in seen:
                    queue.append(target)
                continue
            module = spec.removeprefix("node:").split("/", 1)[0]
            kind = None
            if module in _JS_EXEC_MODULES:
                kind = "new_import_time_exec"
            elif module in _JS_NETWORK_MODULES:
                kind = "new_import_time_network"
            if kind is None:
                continue
            line, snippet = pc._line_snippet(text, match.start())
            behaviours.append(
                Behaviour(
                    kind,
                    ("js-capability", module),
                    path,
                    line,
                    snippet,
                    f"package code loaded from its entry points now uses the {module} module",
                    "warn",
                )
            )
        binding = _JS_BINDING_RE.search(text)
        if binding:
            line, snippet = pc._line_snippet(text, binding.start())
            behaviours.append(
                Behaviour(
                    "new_import_time_exec",
                    ("js-capability", "process.binding"),
                    path,
                    line,
                    snippet,
                    "package code loaded from its entry points reaches native process bindings",
                    "warn",
                )
            )
    if queue and len(seen) >= MAX_JS_REACHABLE:
        result.limitations.append(
            f"entry-point reachability stopped after {MAX_JS_REACHABLE} files"
        )
    return behaviours


def _resolve_js(directory: str, spec: str, files: set[str]) -> str | None:
    base = posixpath.normpath(posixpath.join(directory, spec.split("?", 1)[0]))
    if base.startswith(".."):
        return None
    for candidate in (
        base,
        *(base + suffix for suffix in _JS_SUFFIXES),
        *(posixpath.join(base, "index" + suffix) for suffix in _JS_SUFFIXES),
    ):
        if candidate in files:
            return candidate
    return None


def _changed_file_behaviours(
    before: _Side,
    after: _Side,
    changed: set[str],
    result: DiffResult,
) -> tuple[list[Behaviour], list[Behaviour]]:
    """Code rules for files that differ; byte-identical files behave identically."""
    old_digests = {before.digest(path) for path in before.entries if path in changed}
    old_list: list[Behaviour] = []
    new_list: list[Behaviour] = []
    for side, target in ((before, old_list), (after, new_list)):
        for path in sorted(changed):
            if path not in side.entries:
                continue
            if side is after and after.digest(path) in old_digests:
                continue
            target.extend(_file_code_behaviours(side, path))
    if before.ecosystem == "npm":
        old_list.extend(_npm_observations(before, changed, result))
        new_list.extend(_npm_observations(after, changed, result))
    return old_list, new_list


def _file_code_behaviours(side: _Side, path: str) -> list[Behaviour]:
    lowered = path.lower()
    behaviours: list[Behaviour] = []
    if lowered.endswith(_JS_SUFFIXES + (".py",)):
        behaviours.extend(_obfuscation_behaviours(side, path))
    if side.ecosystem != "pypi" or not lowered.endswith(".py"):
        return behaviours
    text = side.text(path)
    if text is None:
        return behaviours
    if not _DECODE_EXEC_HINT.search(text):
        return behaviours
    calls = side.calls(path, False)
    if calls is None:
        match = pc._ENCODED_EXEC_RE.search(text)
        if match:
            line, snippet = pc._line_snippet(text, match.start())
            calls = [_PyCall("decode_exec", "exec", line, snippet)]
        else:
            calls = []
    encoded_lines = side.encoded_lines(path)
    first = next((call for call in calls if call.category == "decode_exec"), None)
    if first is None and encoded_lines:
        line = encoded_lines[0]
        _, snippet = pc._line_snippet(text, pc._offset_for_line(text, line))
        first = _PyCall("decode_exec", "exec", line, snippet)
    if first is not None:
        behaviours.append(
            Behaviour(
                "new_decode_exec",
                ("decode-exec", side.entries[path].install_path),
                path,
                first.line,
                first.snippet,
                "decoded or downloaded data reaches exec, eval or a process call",
                "block",
            )
        )
    return behaviours


def _obfuscation_behaviours(side: _Side, path: str) -> list[Behaviour]:
    entry = side.entries[path]
    if entry.file.size < OBFUSCATION_MIN_BYTES:
        return []
    raw = pc._read_bytes(entry.file, _TEXT_LIMIT)
    if raw is None:
        return []
    text = pc._decode_text(raw) or ""
    reason = ""
    offset = 0
    identifiers = list(_OBFUSCATED_IDENT_RE.finditer(text))
    escapes = _HEX_ESCAPE_RE.findall(text)
    blob = _BLOB_RE.search(text)
    if len(identifiers) >= 100:
        reason = f"{len(identifiers)} obfuscator-style _0x identifiers"
        offset = identifiers[0].start()
    elif len(escapes) >= 1000 and len(escapes) * 4 >= 0.15 * len(text):
        reason = f"{len(escapes)} hex-escaped characters"
        offset = text.find(escapes[0])
    elif blob is not None and path.lower().endswith(".py"):
        reason = f"{len(blob.group(0))}-character encoded string"
        offset = blob.start()
    if not reason:
        return []
    line, snippet = pc._line_snippet(text, offset)
    return [
        Behaviour(
            "obfuscation_growth",
            ("obfuscated", path),
            path,
            line,
            snippet[:120],
            f"large obfuscated file ({entry.file.size} bytes, {reason})",
            "warn",
        )
    ]


def _npm_observations(side: _Side, changed: set[str], result: DiffResult) -> list[Behaviour]:
    snapshot = side.snapshot
    prefix = side.root_prefix
    keep = []
    for file in snapshot.files:
        path = file.relative_path.removeprefix(prefix)
        if PurePosixPath(path).name == "package.json" or path in changed:
            keep.append(file)
    reduced = replace(snapshot, files=tuple(keep))
    try:
        profile = inspect_snapshot(reduced)
    except (RecursionError, ValueError) as exc:
        result.limitations.append(f"npm code observations unavailable: {exc}")
        return []
    if any("does not match the locked" in issue for issue in profile.issues):
        result.limitations.append(
            "package.json name or version does not match the registry release"
        )
    behaviours = []
    for fact in profile.facts:
        if fact.kind != "code_observation" or not isinstance(fact.value, dict):
            continue
        rule = str(fact.value.get("rule_id", ""))
        mapped = _NPM_CODE_RULE_KINDS.get(rule)
        if mapped is None:
            continue
        kind, detail = mapped
        level = "warn"
        if kind in BLOCK_KINDS:
            level = "block"
        path = str(fact.value.get("file", ""))
        preview = str(fact.value.get("evidence_preview", ""))
        line = None
        if path in side.entries:
            text = side.text(path)
            if text is not None:
                line = _rule_line(text, rule)
        behaviours.append(
            Behaviour(
                kind,
                ("npm-rule", rule, path),
                path,
                line,
                preview,
                f"{rule}: {detail}",
                level,
            )
        )
    return behaviours


def _rule_line(text: str, rule: str) -> int | None:
    pattern = {
        "npm-encoded-execution": pc._JS_ENCODED_EXEC_RE,
        "npm-obfuscated-require": pc._JS_OBFUSCATED_REQUIRE_HINT_RE,
        "npm-credential-exfiltration": pc._JS_CREDENTIAL_RE,
        "encoded-execution": pc._ENCODED_EXEC_RE,
    }.get(rule)
    if pattern is None:
        return None
    match = pattern.search(text)
    if match is None:
        return None
    return text.count("\n", 0, match.start()) + 1
