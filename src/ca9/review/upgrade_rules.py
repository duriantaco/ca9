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
import time
from collections import Counter
from dataclasses import dataclass, field, replace
from pathlib import PurePosixPath
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from ca9.analyzers import package_code as pc
from ca9.artifacts.model import ArtifactFile, ArtifactSnapshot
from ca9.review.behavior import _normalize_javascript
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
    "ambiguous_package_contents",
    "shadows_system_command",
    "uninspectable_import_time_code",
    "lockfile_artifact_mismatch",
)
WARN_KINDS = (
    "new_import_time_network",
    "new_import_time_exec",
    "obfuscation_growth",
    "new_native_binary",
    "publisher_change",
    "install_script_changed",
    "native_binary_changed",
)
MAX_SCAN_BYTES = 32 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
SCAN_CHUNK = 1024 * 1024
SCAN_OVERLAP = 16 * 1024
SHADOWED_COMMANDS = frozenset(
    {"node", "npm", "npx", "git", "pip", "pip3", "python", "python3", "sh", "bash", "curl"}
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
_JS_DECODE_HINT = re.compile(
    r"Buffer\.from\s*\([^;]{0,200}?['\"](?:base64|hex)['\"]|\batob\s*\(|"
    r"String\.fromCharCode\s*\("
)
_JS_DECODED_SINK_RE = re.compile(
    r"(?<![\w$])(?P<sink>require|import|eval|Function|execSync|exec|spawnSync|spawn|execFile)"
    r"\s*\(\s*(?P<decoder>[A-Za-z_$][\w$]*)\s*\(\s*['\"`]"
)
_HEX_ESCAPE_RE = re.compile(r"\\x[0-9a-fA-F]{2}")
_DEFAULT_EXPORT_FUNCTION_RE = re.compile(
    r"module\.exports\s*=\s*(?:function\b|\(|[\w$]+\s*=>)|export\s+default\s+function\b"
)
_PY_DECODE_HINT = re.compile(
    r"b64decode|b32decode|b16decode|a85decode|b85decode|decodebytes|decompress|unhexlify|"
    r"fromhex|marshal|codecs\.decode|a2b_"
)
_URL_IN_TEXT_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://([^/\s'\"`)\]]+)", re.I)
_SHELL_META_RE = re.compile(r"\||;|&&|\$\(|`|>\s*/")
_SHELL_PIPE_RE = re.compile(
    r"\b(?:curl|wget)\b[^\n|;&]{0,300}\|\s*(?:sudo\s+)?"
    r"(?:ba|z|da)?sh\b|\b(?:curl|wget)\b[^\n|;&]{0,300}\|\s*(?:sudo\s+)?"
    r"(?:python[0-9.]*|node|perl|ruby)\b|"
    r"\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]{0,300}\|\s*"
    r"(?:iex|Invoke-Expression)\b",
    re.I,
)
_JS_EXEC_CALL_RE = re.compile(
    r"(?<![\w$])(?P<sink>execSync|exec|spawnSync|spawn|execFileSync|execFile|fork)"
    r"\s*\((?P<args>[^;\n]{0,400})"
)
_DECODE_TEXT_RE = re.compile(r"\batob\s*\(|Buffer\.from|fromCharCode|b64decode")
_GYP_COMMAND_RE = re.compile(r"<!@?\(([^)]*)\)|['\"]action['\"]\s*:\s*\[([^\]]*)\]")
_HOOK_RUNNERS = {
    "node": "js",
    "nodejs": "js",
    "bun": "js",
    "sh": "sh",
    "bash": "sh",
    "zsh": "sh",
    "python": "py",
    "python3": "py",
}
_GYP_TOOLS = frozenset(
    {"node-gyp", "node-gyp-build", "prebuild-install", "node-pre-gyp", "cmake-js"}
)
_LITERAL_RE = re.compile(r"(['\"`])(?:\\.|(?!\1).)*\1|\b\d+(?:\.\d+)*\b", re.S)
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
    incomplete: list[str] = field(default_factory=list)


@dataclass
class _Entry:
    path: str
    install_path: str
    file: ArtifactFile


class AnalysisTimeout(Exception):
    """The review deadline passed while an artifact was being analysed."""


class _Cache:
    """Parse results shared by both sides; identical files are analysed once."""

    def __init__(self, deadline: float | None = None) -> None:
        self.trees: dict[str, ast.Module | None] = {}
        self.calls: dict[tuple[str, bool], list[_PyCall] | None] = {}
        self.encoded: dict[str, list[int]] = {}
        self.deadline = deadline

    def check(self) -> None:
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise AnalysisTimeout("review deadline reached during analysis")


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
        self.role = "new"
        self.ambiguous: list[tuple[str, str]] = []
        self.unparsed: set[str] = set()
        self.proven: set[str] = set()
        self.root_prefix = _root_prefix(snapshot, ecosystem)
        folded: dict[str, str] = {}
        for file in snapshot.files:
            path = self._package_path(file.relative_path)
            if path is None:
                continue
            key = path.casefold()
            if key in folded:
                self.ambiguous.append((path, folded[key]))
            folded[key] = path
            self.entries[path] = _Entry(path, self._install_path(path), file)
        self._hashes: dict[str, str] = {}
        self._texts: dict[str, str | None] = {}
        self._memo: dict[str, Any] = {}

    def _package_path(self, relative: str) -> str | None:
        """The path the installer writes; npm strips the first component of every entry."""
        if self.kind == "npm-tarball" or self.ecosystem == "npm":
            _first, separator, rest = relative.partition("/")
            if not separator or not rest:
                return None
            return rest
        if self.root_prefix:
            if not relative.startswith(self.root_prefix):
                return "../" + relative
            return relative[len(self.root_prefix) :]
        return relative

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
            self.cache.check()
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
            self._texts[path] = self.read_text(path, _TEXT_LIMIT)
        return self._texts[path]

    def read_text(self, path: str, limit: int, *, allow_nul: bool = False) -> str | None:
        """Decoded text up to ``limit`` bytes; a leading BOM is removed as Node and site do.

        ``allow_nul`` decodes files with NUL bytes too: Node runs JavaScript that hides a
        NUL in a string literal, so code files are not skipped as binary.
        """
        raw = pc._read_bytes(self.entries[path].file, limit + 1)
        if raw is None or len(raw) > limit:
            return None
        text = pc._decode_text(raw)
        if text is None and allow_nul:
            text = raw.decode("utf-8", errors="replace")
        if text is None:
            return None
        return text.removeprefix("\ufeff")

    def memo(self, key: str, build: Any) -> Any:
        if key not in self._memo:
            self._memo[key] = build()
        return self._memo[key]

    def head(self, path: str, size: int = 4096) -> bytes:
        raw = pc._read_bytes(self.entries[path].file, size)
        return raw or b""

    def tree(self, path: str) -> ast.Module | None:
        digest = self.digest(path)
        if digest not in self.cache.trees:
            text = self.text(path)
            if text is None and self.entries[path].file.size <= MAX_SCAN_BYTES:
                text = self.read_text(path, MAX_SCAN_BYTES)
            self.cache.trees[digest] = _python_tree(text)
        tree = self.cache.trees[digest]
        if tree is None:
            self.unparsed.add(path)
        return tree

    def calls(self, path: str, import_time_only: bool) -> list[_PyCall] | None:
        key = (self.digest(path), import_time_only)
        if key not in self.cache.calls:
            tree = self.tree(path)
            text = self.text(path)
            if text is None and tree is not None:
                text = self.read_text(path, MAX_SCAN_BYTES)
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
    *,
    deadline: float | None = None,
    changed_binaries: str = "info",
) -> DiffResult:
    """Behaviours of ``new`` whose identity is absent from ``old``.

    ``changed_binaries`` is the level for native binaries replaced under the same name:
    "info" by default, because nearly every release of a compiled package rebuilds them.
    """
    cache = _Cache(deadline)
    before = _Side(old, ecosystem, cache)
    before.role = "old"
    after = _Side(new, ecosystem, cache)
    old_behaviours, new_behaviours, result = _collect(before, after, before.top_modules())
    new_behaviours.extend(_changed_binary_behaviour(before, after, changed_binaries))
    _assemble(old_behaviours, new_behaviours, result)
    return result


def diff_new_package(
    new: ArtifactSnapshot,
    ecosystem: str,
    *,
    deadline: float | None = None,
) -> DiffResult:
    """Review a newly added package on its own, against an empty baseline.

    Blocks only on signals that are rare in legitimate new packages: startup .pth code
    (tiered as for upgrades, the package's own modules counting as shipped), top-level
    sitecustomize/usercustomize, decode-and-exec, agent/editor hook files and git/URL
    dependencies. Install hooks, nested startup modules, import-time network or exec
    and obfuscation are warnings; native binaries are informational.
    """
    cache = _Cache(deadline)
    before = _Side(replace(new, files=()), ecosystem, cache)
    before.role = "old"
    after = _Side(new, ecosystem, cache)
    _old, new_behaviours, result = _collect(before, after, after.top_modules())
    _assemble([], [_new_package_level(item) for item in new_behaviours], result)
    return result


def _new_package_level(item: Behaviour) -> Behaviour:
    level = item.level
    install_hook = item.kind == "new_install_hook" and level == "block"
    nested_startup = item.kind == "new_sitecustomize" and len(item.identity) == 2
    if install_hook or nested_startup:
        level = "warn"
    elif item.kind == "new_native_binary":
        level = "info"
    elif item.kind in {"new_dependency", "install_script_changed"}:
        level = "drop"
    return replace(item, level=level)


def _collect(
    before: _Side, after: _Side, baseline_modules: set[str]
) -> tuple[list[Behaviour], list[Behaviour], DiffResult]:
    ecosystem = after.ecosystem
    changed = _changed_paths(before, after)
    result = DiffResult()
    old_behaviours: list[Behaviour] = []
    new_behaviours: list[Behaviour] = []
    collectors = [
        _agent_hook_behaviours,
        _native_binary_behaviours,
        _ambiguity_behaviours,
        _command_behaviours,
    ]
    if ecosystem == "pypi":
        old_behaviours.extend(_pth_behaviours(before, None))
        new_behaviours.extend(_pth_behaviours(after, baseline_modules))
        collectors.extend(
            [
                _startup_module_behaviours,
                _python_dependency_behaviours,
                _build_hook_behaviours,
                _python_import_time_behaviours,
                _sourceless_behaviours,
            ]
        )
    else:
        collectors.extend(
            [_npm_manifest_behaviours, _npm_import_time_behaviours, _install_time_behaviours]
        )
    for collect in collectors:
        after.cache.check()
        old_behaviours.extend(collect(before, result))
        new_behaviours.extend(collect(after, result))
    old_changed, new_changed = _changed_file_behaviours(before, after, changed, result)
    old_behaviours.extend(old_changed)
    new_behaviours.extend(new_changed)
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    for path in sorted((after.unparsed & changed) - after.proven):
        if path.lower().endswith(".py"):
            result.incomplete.append(
                f"{path} could not be parsed by Python {version}; only text rules were applied"
            )
    return old_behaviours, new_behaviours, result


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
            if item.level in {"block", "warn"} and item.kind != "install_script_changed":
                result.unchanged_risky[item.kind] += 1
            continue
        if item.level == "drop":
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
            kind, level, detail = _pth_line_level(side, line.strip(), baseline_modules)
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


def _pth_line_level(
    side: _Side, line: str, baseline_modules: set[str] | None
) -> tuple[str, str, str]:
    prefix = ".pth import line runs at every interpreter start"
    verdict = pc._pth_line_verdict(line)
    tree = pc._parse_python(line)
    if verdict == "critical" or tree is None:
        return "new_pth_code", "block", f"{prefix} and runs process, network, decode or exec code"
    if baseline_modules is None:
        return "new_pth_code", "block", prefix
    imported = _pth_imports(tree, 0)
    shipped = side.top_modules()
    unexpected = sorted(
        name
        for name in imported
        if (name in shipped and name not in baseline_modules)
        or (name not in shipped and name not in sys.stdlib_module_names)
    )
    if unexpected:
        return (
            "new_pth_code",
            "block",
            f"{prefix} and imports modules the old release did not ship: {', '.join(unexpected)}",
        )
    for name in sorted(imported & shipped):
        risky = _runs_risky_code(side, name)
        if risky is not None:
            return (
                "new_pth_code",
                "block",
                f"{prefix} and imports {name}, whose import-time code runs {risky}",
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
        location = _startup_location(entry.install_path)
        if location is None:
            continue
        stem, top_level = location
        install_name = PurePosixPath(entry.install_path).name.lower()
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


def _startup_location(install_path: str) -> tuple[str, bool] | None:
    """(module name, top-level) for sitecustomize/usercustomize modules and packages."""
    parts = install_path.lower().split("/")
    name = parts[-1]
    if not name.endswith(_STARTUP_SUFFIXES):
        return None
    stem = name.partition(".")[0]
    module_parts = parts[:-1]
    if stem == "__init__" and len(parts) >= 2:
        stem = parts[-2]
        module_parts = parts[:-2]
    if stem not in _STARTUP_MODULES:
        return None
    return stem, not module_parts


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


def _is_native(side: _Side, path: str) -> bool:
    def build() -> bool:
        entry = side.entries[path]
        lowered = path.lower()
        native = lowered.endswith(_NATIVE_SUFFIXES) or ".so." in PurePosixPath(lowered).name
        if not native and entry.file.size >= 4:
            head = side.head(path, 8)
            native = head.startswith(_NATIVE_MAGIC) and not lowered.endswith(".class")
            if native and head.startswith(b"MZ") and entry.file.size < 512:
                native = False
        return native

    return side.memo(f"native:{path}", build)


def _native_identity(path: str) -> str:
    return re.sub(r"[0-9a-f]{6,}|\d+", "#", path.lower())


def _native_binary_behaviours(side: _Side, result: DiffResult) -> list[Behaviour]:
    behaviours = []
    for path, entry in side.entries.items():
        if not _is_native(side, path):
            continue
        behaviours.append(
            Behaviour(
                "new_native_binary",
                ("native", _native_identity(path)),
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
            text = side.read_text(path, MAX_MANIFEST_BYTES) or ""
            header = text.split("\n\n", 1)[0]
            for number, line in enumerate(header.splitlines(), start=1):
                if line.lower().startswith("requires-dist:"):
                    found.append((path, line.split(":", 1)[1].strip(), number))
        elif path.endswith(".egg-info/requires.txt") and path.count("/") <= 2:
            text = side.read_text(path, MAX_MANIFEST_BYTES) or ""
            for number, line in enumerate(text.splitlines(), start=1):
                stripped = line.strip()
                if stripped and not stripped.startswith(("[", "#")):
                    found.append((path, stripped, number))
        elif path == "pyproject.toml":
            data = _toml(side.read_text(path, MAX_MANIFEST_BYTES))
            project = _table(data, "project")
            groups = [project.get("dependencies")]
            optional = project.get("optional-dependencies")
            if isinstance(optional, dict):
                groups.extend(optional.values())
            groups.append(_table(data, "build-system").get("requires"))
            text = side.read_text(path, MAX_MANIFEST_BYTES) or ""
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
    markers: tuple[str, ...] = ()


def _python_calls(text: str, tree: ast.Module, *, import_time_only: bool) -> list[_PyCall] | None:
    try:
        ctx = pc._PyContext(tree)
        import_time = None
        if import_time_only:
            import_time = _import_time_with_local_calls(tree)
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
            calls.append(
                _PyCall(category, name or "?", node.lineno, snippet, _call_markers(node, category))
            )
        return calls
    except RecursionError:
        return None


def _call_markers(node: ast.Call, category: str) -> tuple[str, ...]:
    """What makes a process or exec call risky: URLs, shell syntax, shell=True, decoded data."""
    markers = set()
    if category == "decode_exec":
        markers.add("decoded")
    for keyword in node.keywords:
        if (
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
        ):
            markers.add("shell=True")
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            markers.update(f"url:{host}" for host in _url_hosts(child.value))
            if _SHELL_META_RE.search(child.value):
                markers.add("shell-syntax")
    return tuple(sorted(markers))


def _url_hosts(text: str) -> set[str]:
    return {match.group(1).lower() for match in _URL_IN_TEXT_RE.finditer(text)}


def _import_time_with_local_calls(tree: ast.Module) -> set[int]:
    """Module-level nodes plus the bodies of module functions called at import time."""
    found = pc._import_time_nodes(tree)
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    pending = [tree]
    expanded: set[str] = set()
    for _round in range(4):
        called = set()
        for scope in pending:
            for node in ast.walk(scope):
                if (
                    isinstance(node, ast.Call)
                    and id(node) in found
                    and isinstance(node.func, ast.Name)
                    and node.func.id in functions
                    and node.func.id not in expanded
                ):
                    called.add(node.func.id)
        if not called:
            break
        pending = []
        for name in sorted(called):
            expanded.add(name)
            body = ast.Module(body=functions[name].body, type_ignores=[])
            found |= pc._import_time_nodes(body)
            pending.append(body)
    return found


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
    for path in sorted(_with_local_imports(side, hook_files)):
        text = side.text(path)
        if text is None:
            continue
        calls = side.calls(path, False)
        if calls is None:
            match = pc._SETUP_EXEC_RE.search(text)
            if match:
                line, snippet = pc._line_snippet(text, match.start())
                calls = [_PyCall("exec", match.group(0), line, snippet)]
                side.proven.add(path)
            else:
                calls = []
        for call in calls:
            detail = f"{path} runs {call.callee} during build or install"
            if call.markers:
                detail += f" with {', '.join(call.markers)}"
            behaviours.append(
                Behaviour(
                    "new_install_hook",
                    ("build-call", call.category, call.callee, call.markers),
                    path,
                    call.line,
                    call.snippet,
                    detail,
                    "block",
                )
            )
        behaviours.append(_install_body_behaviour(side, path, "py"))
    return behaviours


def _with_local_imports(side: _Side, hook_files: set[str]) -> set[str]:
    """Build hook files plus the sdist's own modules they import (they run at build too)."""
    modules = _python_modules(side)
    found = set(hook_files)
    queue = sorted(hook_files)
    while queue and len(found) < MAX_IMPORT_MODULES:
        path = queue.pop(0)
        tree = side.tree(path)
        if tree is None:
            continue
        for target in _module_imports(tree, ""):
            for prefix in _prefixes(target):
                module_path = modules.get(prefix)
                if module_path is not None and module_path not in found:
                    found.add(module_path)
                    queue.append(module_path)
    return found


def _python_modules(side: _Side) -> dict[str, str]:
    """Importable module names mapped to their source path."""

    def build() -> dict[str, str]:
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
                parts[0] in _SDIST_NON_PACKAGES
                or (len(parts) == 1 and install in _SDIST_ROOT_SCRIPTS)
            ):
                continue
            modules.setdefault(".".join(parts), path)
        return modules

    return side.memo("modules", build)


def _import_graph(side: _Side, roots: list[str]) -> tuple[list[tuple[str, str]], set[str], bool]:
    """Modules executed when ``roots`` are imported, every name they import, and truncation."""
    modules = _python_modules(side)
    seen: list[tuple[str, str]] = []
    visited: set[str] = set()
    imported: set[str] = set()
    queue = list(roots)
    while queue and len(visited) < MAX_IMPORT_MODULES:
        side.cache.check()
        module = queue.pop(0)
        if module in visited or module not in modules:
            continue
        visited.add(module)
        path = modules[module]
        seen.append((module, path))
        tree = side.tree(path)
        if tree is None:
            continue
        package = module
        if not path.endswith("__init__.py"):
            package = module.rpartition(".")[0]
        for target in _module_imports(tree, package):
            for prefix in _prefixes(target):
                imported.add(prefix)
                if prefix in modules and prefix not in visited:
                    queue.append(prefix)
    return seen, imported, bool(queue)


def _default_graph(side: _Side) -> tuple[list[tuple[str, str]], set[str], bool]:
    roots = sorted(name for name in _python_modules(side) if "." not in name)
    return side.memo("graph", lambda: _import_graph(side, roots))


def _python_import_time_behaviours(side: _Side, result: DiffResult) -> list[Behaviour]:
    seen, _imported, truncated = _default_graph(side)
    behaviours: list[Behaviour] = []
    for module, path in seen:
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
    if truncated:
        result.limitations.append(
            f"import-time analysis stopped after {MAX_IMPORT_MODULES} modules"
        )
    return behaviours


def _runs_risky_code(side: _Side, module: str) -> str | None:
    """The first process, network, exec or decode call run when ``module`` is imported."""

    def build() -> str | None:
        seen, _imported, _truncated = _import_graph(side, [module])
        for _name, path in seen:
            for call in side.calls(path, True) or []:
                return f"{call.callee} in {path}"
            if side.encoded_lines(path):
                return f"decode-and-exec in {path}"
        return None

    return side.memo(f"risky:{module}", build)


def _sourceless_behaviours(side: _Side, result: DiffResult) -> list[Behaviour]:
    """Bytecode modules shipped without source; blocked when imported at import or startup."""
    _seen, imported, _truncated = _default_graph(side)
    startup = _startup_imports(side)
    sources = {entry.install_path for entry in side.entries.values()}
    behaviours = []
    for path, entry in side.entries.items():
        install = entry.install_path
        if not install.endswith(".pyc") or "__pycache__/" in install or install[:-1] in sources:
            continue
        parts = install[:-4].split("/")
        if parts[-1] == "__init__":
            parts = parts[:-1]
        module = ".".join(parts)
        detail = "bytecode without source: its code cannot be inspected statically"
        if module in imported or parts[0] in startup:
            behaviours.append(
                Behaviour(
                    "uninspectable_import_time_code",
                    ("sourceless-imported", install, side.digest(path)),
                    path,
                    None,
                    "",
                    f"{detail}, and it is imported at import time or interpreter start",
                    "block",
                )
            )
        else:
            behaviours.append(
                Behaviour(
                    "new_native_binary", ("sourceless", install), path, None, "", detail, "warn"
                )
            )
    return behaviours


def _startup_imports(side: _Side) -> set[str]:
    names: set[str] = set()
    for path, entry in side.entries.items():
        lowered = path.lower()
        if lowered.endswith(".pth"):
            text = side.text(path) or ""
            for line in text.splitlines():
                if line.startswith(("import ", "import\t")):
                    tree = pc._parse_python(line.strip())
                    if tree is not None:
                        names.update(_pth_imports(tree, 0))
        elif _startup_location(entry.install_path) is not None and lowered.endswith(".py"):
            tree = side.tree(path)
            if tree is not None:
                names.update(target.split(".")[0] for target in _module_imports(tree, ""))
    return names


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
    data = _manifest_data(side, "package.json", None)[1]
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
        text, data = _manifest_data(side, path, result)
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
        side.cache.check()
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
        reachable = _js_reachable(side)
        for path in sorted(changed):
            if path not in side.entries:
                continue
            if side is after and after.digest(path) in old_digests:
                continue
            side.cache.check()
            target.extend(_file_code_behaviours(side, path, path in reachable, result))
    return old_list, new_list


def _code_text(side: _Side, path: str, result: DiffResult) -> str | None:
    """Text of a code file up to the scan cap; beyond it the review is incomplete."""
    text = side.text(path)
    if text is not None:
        return text
    size = side.entries[path].file.size
    if size <= _TEXT_LIMIT:
        return side.read_text(path, _TEXT_LIMIT, allow_nul=True)
    if size > MAX_SCAN_BYTES:
        if side.role == "new":
            result.incomplete.append(
                f"{path} ({size} bytes) exceeds the {MAX_SCAN_BYTES // (1024 * 1024)} MB "
                "scan cap and was not inspected"
            )
        return None
    return side.read_text(path, MAX_SCAN_BYTES, allow_nul=True)


def _chunks(text: str) -> list[str]:
    if len(text) <= SCAN_CHUNK:
        return [text]
    return [
        text[start : start + SCAN_CHUNK + SCAN_OVERLAP] for start in range(0, len(text), SCAN_CHUNK)
    ]


def _file_code_behaviours(
    side: _Side, path: str, js_like: bool, result: DiffResult
) -> list[Behaviour]:
    lowered = path.lower()
    behaviours: list[Behaviour] = []
    python = lowered.endswith(".py")
    js_like = js_like or lowered.endswith(_JS_SUFFIXES)
    if not (python or js_like):
        return behaviours
    if lowered.endswith(_JS_SUFFIXES + (".py",)):
        behaviours.extend(_obfuscation_behaviours(side, path))
    text = _code_text(side, path, result)
    if text is None:
        return behaviours
    if js_like:
        behaviours.extend(_decoded_sink_behaviours(side, path, text))
    if side.ecosystem == "npm":
        behaviours.extend(_npm_code_behaviours(side, path, text, js_like and not python))
    if side.ecosystem == "pypi" and python:
        behaviours.extend(_python_decode_exec(side, path, text))
    return behaviours


def _python_decode_exec(side: _Side, path: str, text: str) -> list[Behaviour]:
    tree = side.tree(path)
    if tree is None:
        for chunk in _chunks(text):
            match = pc._ENCODED_EXEC_RE.search(chunk)
            if match:
                side.proven.add(path)
                line, snippet = pc._line_snippet(chunk, match.start())
                if len(chunk) != len(text):
                    line = None
                return [_decode_exec_behaviour(side, path, line, snippet)]
        return []
    if not _DECODE_EXEC_HINT.search(text):
        return []
    calls = side.calls(path, False) or []
    first = next((call for call in calls if call.category == "decode_exec"), None)
    encoded_lines = side.encoded_lines(path)
    if first is None and encoded_lines:
        line = encoded_lines[0]
        _, snippet = pc._line_snippet(text, pc._offset_for_line(text, line))
        first = _PyCall("decode_exec", "exec", line, snippet)
    if first is None:
        first = _cross_module_decode_exec(side, path, tree, text)
    if first is None:
        return []
    return [_decode_exec_behaviour(side, path, first.line, first.snippet)]


def _decode_exec_behaviour(side: _Side, path: str, line: int | None, snippet: str) -> Behaviour:
    return Behaviour(
        "new_decode_exec",
        ("decode-exec", side.entries[path].install_path),
        path,
        line,
        snippet,
        "decoded or downloaded data reaches exec, eval or a process call",
        "block",
    )


def _module_name(install_path: str) -> str:
    parts = install_path.removesuffix(".py").split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _python_decoders(side: _Side) -> set[str]:
    """Module-level functions in this package that call a decoder (base64, zlib, marshal...)."""

    def build() -> set[str]:
        decoders: set[str] = set()
        for module, path in _python_modules(side).items():
            text = side.text(path)
            if text is None or not _PY_DECODE_HINT.search(text):
                continue
            tree = side.tree(path)
            if tree is None:
                continue
            ctx = pc._PyContext(tree)
            for node in tree.body:
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        name, _obfuscated = ctx.resolve(child.func)
                        if name in pc._DECODE_CALLS:
                            decoders.add(f"{module}.{node.name}")
                            break
        return decoders

    return side.memo("decoders", build)


def _cross_module_decode_exec(
    side: _Side, path: str, tree: ast.Module, text: str
) -> _PyCall | None:
    """exec/eval/process calls fed by a decoder function defined in another package module."""
    decoders = _python_decoders(side)
    if not decoders:
        return None
    module = _module_name(side.entries[path].install_path)
    package = module
    if not path.endswith("__init__.py"):
        package = module.rpartition(".")[0]
    local = _relative_bindings(tree, package)
    ctx = pc._PyContext(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name, _obfuscated = ctx.resolve(node.func)
        if name not in _PY_EXEC_NAMES and name not in pc._PROCESS_CALLS:
            continue
        for argument in [*node.args, *(item.value for item in node.keywords)]:
            for child in ast.walk(argument):
                if not isinstance(child, ast.Call):
                    continue
                callee = _qualified_callee(child.func, ctx, local)
                if callee in decoders:
                    _line, snippet = pc._line_snippet(text, pc._offset_for_line(text, node.lineno))
                    return _PyCall("decode_exec", name or "?", node.lineno, snippet)
    return None


def _relative_bindings(tree: ast.Module, package: str) -> dict[str, str]:
    bindings: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or not node.level:
            continue
        parts = [part for part in package.split(".") if part]
        if node.level - 1 > len(parts):
            continue
        parts = parts[: len(parts) - (node.level - 1)]
        if node.module:
            parts.append(node.module)
        base = ".".join(parts)
        for alias in node.names:
            bindings[alias.asname or alias.name] = f"{base}.{alias.name}".strip(".")
    return bindings


def _qualified_callee(func: ast.AST, ctx: Any, local: dict[str, str]) -> str | None:
    if isinstance(func, ast.Name) and func.id in local:
        return local[func.id]
    if (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Name)
        and func.value.id in local
    ):
        return f"{local[func.value.id]}.{func.attr}"
    name, _obfuscated = ctx.resolve(func)
    return name


def _npm_code_behaviours(side: _Side, path: str, text: str, javascript: bool) -> list[Behaviour]:
    """ca9's package-code rules on one file, without depending on the manifest parse."""
    entry = side.entries[path]
    relative = path
    if javascript and not path.lower().endswith(_JS_SUFFIXES):
        relative = path + ".js"
    analysis_file = ArtifactFile(relative, entry.file.path, entry.file.size)
    findings = []
    if javascript and len(text) <= _TEXT_LIMIT:
        findings = pc._analyze_file(
            side.snapshot, analysis_file, _normalize_javascript(text, path, [])
        )
    else:
        for chunk in _chunks(text):
            findings.extend(pc._analyze_file(side.snapshot, analysis_file, chunk))
    behaviours = []
    seen: set[str] = set()
    for finding in findings:
        rule = finding.signal_type
        mapped = _NPM_CODE_RULE_KINDS.get(rule)
        if mapped is None or rule in seen:
            continue
        seen.add(rule)
        kind, detail = mapped
        level = "warn"
        if kind in BLOCK_KINDS:
            level = "block"
        line, snippet = _rule_location(text, rule)
        if not snippet and finding.evidence:
            snippet = str(finding.evidence[0].metadata.get("snippet") or "")
        behaviours.append(
            Behaviour(
                kind,
                ("npm-rule", rule, path),
                path,
                line,
                snippet,
                f"{rule}: {detail}",
                level,
            )
        )
    return behaviours


def _js_reachable(side: _Side) -> set[str]:
    """Files Node loads from the entry points and install scripts, whatever their extension."""

    def build() -> set[str]:
        if side.ecosystem != "npm":
            return set()
        roots = set(_npm_install_targets(side))
        manifest = _npm_manifest(side)
        if manifest is not None:
            roots.update(
                resolve_manifest_entrypoints(
                    manifest, "", set(side.entries), {"package.json": manifest}
                ).paths
            )
        return _js_closure(side, roots)

    return side.memo("js-reachable", build)


def _js_closure(side: _Side, roots: set[str]) -> set[str]:
    files = set(side.entries)
    seen: set[str] = set()
    queue = sorted(path for path in roots if path in files)
    while queue and len(seen) < MAX_JS_REACHABLE:
        side.cache.check()
        path = queue.pop(0)
        if path in seen:
            continue
        seen.add(path)
        if path.lower().endswith((".json", ".node", ".gyp")):
            continue
        text = side.text(path)
        if text is None:
            continue
        for match in _JS_SPEC_RE.finditer(text):
            spec = match.group(2)
            if spec.startswith("."):
                target = _resolve_js(posixpath.dirname(path), spec, files)
                if target is not None and target not in seen:
                    queue.append(target)
    return seen


def _decoded_sink_behaviours(side: _Side, path: str, text: str) -> list[Behaviour]:
    """A module load, eval or process call fed by a decoder of a string literal.

    ``require(_d('...'))`` where ``_d`` decodes base64, hex or character codes (defined in
    the same file or imported from a relative module) hides which module or command runs;
    benign code names its modules and commands directly.
    """
    for chunk in _chunks(text):
        for match in _JS_DECODED_SINK_RE.finditer(chunk):
            name = match.group("decoder")
            source = _decoder_source(side, path, chunk, name)
            if source is None:
                continue
            line, snippet = pc._line_snippet(chunk, match.start())
            return [
                Behaviour(
                    "new_decode_exec",
                    ("decoded-sink", path),
                    path,
                    line,
                    snippet,
                    f"{match.group('sink')} receives a value decoded by {name} ({source})",
                    "block",
                )
            ]
    return []


def _decoder_source(side: _Side, path: str, text: str, name: str) -> str | None:
    if _JS_DECODE_HINT.search(text) and _is_local_decoder(text, name):
        return "defined in this file"
    escaped = re.escape(name)
    patterns = (
        rf"(?:const|let|var)\s*\{{[^}}]*\b{escaped}\b[^}}]*\}}\s*=\s*require\(\s*['\"](\.[^'\"]+)['\"]",
        rf"(?:const|let|var)\s+{escaped}\s*=\s*require\(\s*['\"](\.[^'\"]+)['\"]",
        rf"import\s*\{{[^}}]*\b{escaped}\b[^}}]*\}}\s*from\s*['\"](\.[^'\"]+)['\"]",
        rf"import\s+{escaped}\s+from\s*['\"](\.[^'\"]+)['\"]",
    )
    files = set(side.entries)
    for index, pattern in enumerate(patterns):
        match = re.search(pattern, text)
        if match is None:
            continue
        target = _resolve_js(posixpath.dirname(path), match.group(1), files)
        if target is None:
            continue
        module_text = side.text(target) or ""
        if not _JS_DECODE_HINT.search(module_text):
            continue
        default_import = index in (1, 3)
        if _is_local_decoder(module_text, name) or (
            default_import and _DEFAULT_EXPORT_FUNCTION_RE.search(module_text)
        ):
            return f"imported from {target}"
    return None


def _is_local_decoder(text: str, name: str) -> bool:
    escaped = re.escape(name)
    definition = re.compile(
        rf"function\s+{escaped}\s*(?=\()|(?<![\w$.]){escaped}\s*=\s*(?=function\b|\(|[\w$]+\s*=>)"
    )
    for found in definition.finditer(text):
        if _JS_DECODE_HINT.search(_function_body(text, found.end())):
            return True
    return False


def _function_body(text: str, start: int, limit: int = 2000) -> str:
    """The braced body (or arrow expression) that follows a definition, bounded."""
    window = text[start : start + limit]
    brace = window.find("{")
    arrow = window.find("=>")
    if arrow >= 0 and (brace < 0 or arrow < brace):
        rest = window[arrow + 2 :].lstrip()
        if not rest.startswith("{"):
            end = re.search(r"[;\n]", rest)
            if end is None:
                return rest
            return rest[: end.start()]
        brace = window.find("{", arrow)
    if brace < 0:
        return ""
    depth = 0
    for index in range(brace, len(window)):
        char = window[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return window[brace : index + 1]
    return window[brace:]


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


def _npm_install_targets(side: _Side) -> dict[str, str]:
    """Files npm runs at install time (path -> language), from lifecycle commands and gyp."""

    def build() -> dict[str, str]:
        targets: dict[str, str] = {}
        files = set(side.entries)
        for path in sorted(side.entries):
            if PurePosixPath(path).name != "package.json":
                continue
            if path != "package.json" and "node_modules/" not in path:
                continue
            directory = posixpath.dirname(path)
            data = _manifest_data(side, path, None)[1]
            if not isinstance(data, dict):
                continue
            scripts = _table(data, "scripts")
            for hook in _NPM_INSTALL_HOOKS:
                command = scripts.get(hook)
                if isinstance(command, str):
                    targets.update(_command_targets(command, directory, scripts, files, 0))
            binding = posixpath.join(directory, "binding.gyp")
            if binding in files and data.get("gypfile") is not False:
                targets[binding] = "gyp"
        closure = _js_closure(side, {path for path, kind in targets.items() if kind == "js"})
        for path in closure:
            targets.setdefault(path, "js")
        return targets

    return side.memo("install-targets", build)


def _command_targets(
    command: str, directory: str, scripts: dict[str, Any], files: set[str], depth: int
) -> dict[str, str]:
    targets: dict[str, str] = {}
    for segment in re.split(r"&&|\|\||;|\|", command):
        words = [word.strip("'\"") for word in segment.split()]
        while words and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", words[0]):
            words.pop(0)
        if not words:
            continue
        program = posixpath.basename(words[0])
        arguments = [word for word in words[1:] if not word.startswith("-")]
        if program in _HOOK_RUNNERS and arguments:
            path = _local_file(directory, arguments[0], files, _HOOK_RUNNERS[program])
            if path is not None:
                targets[path] = _HOOK_RUNNERS[program]
        elif program in _GYP_TOOLS:
            binding = posixpath.join(directory, "binding.gyp")
            if binding in files:
                targets[binding] = "gyp"
        elif program in {"npm", "yarn", "pnpm"} and depth < 3:
            names = [word for word in arguments if word not in {"run", "run-script"}]
            nested = None
            if names:
                nested = scripts.get(names[0])
            if isinstance(nested, str):
                targets.update(_command_targets(nested, directory, scripts, files, depth + 1))
        elif "/" in words[0]:
            path = _local_file(directory, words[0], files, "sh")
            if path is not None:
                targets[path] = _language_of(path)
    return targets


def _local_file(directory: str, value: str, files: set[str], language: str) -> str | None:
    base = posixpath.normpath(posixpath.join(directory, value))
    if base.startswith(".."):
        return None
    candidates = [base]
    if language == "js":
        candidates.extend(base + suffix for suffix in _JS_SUFFIXES)
        candidates.extend(posixpath.join(base, "index" + suffix) for suffix in _JS_SUFFIXES)
    return next((candidate for candidate in candidates if candidate in files), None)


def _language_of(path: str) -> str:
    lowered = path.lower()
    if lowered.endswith(_JS_SUFFIXES):
        return "js"
    if lowered.endswith(".py"):
        return "py"
    return "sh"


def _install_time_behaviours(side: _Side, result: DiffResult) -> list[Behaviour]:
    """What npm install-time files do: shell pipes, risky process arguments, download+run.

    Hooks are never judged by their command string alone: the files they execute (and the
    files those require) are install-time code, so a body that starts piping a download into
    a shell blocks even when ``postinstall: node install.js`` is unchanged.
    """
    behaviours: list[Behaviour] = []
    for path, language in sorted(_npm_install_targets(side).items()):
        text = _code_text(side, path, result)
        if text is None:
            continue
        behaviours.extend(_install_signatures(path, text, language))
        behaviours.append(_install_body_behaviour(side, path, language))
    return behaviours


def _install_signatures(path: str, text: str, language: str) -> list[Behaviour]:
    behaviours = []
    for chunk in _chunks(text):
        for match in _SHELL_PIPE_RE.finditer(chunk):
            line, snippet = pc._line_snippet(chunk, match.start())
            hosts = tuple(sorted(_url_hosts(match.group(0))))
            behaviours.append(
                Behaviour(
                    "new_install_hook",
                    ("install-pipe", hosts),
                    path,
                    line,
                    snippet,
                    "install-time code pipes a download into a shell or interpreter",
                    "block",
                )
            )
        for argument, offset in _process_arguments(chunk, language):
            markers = set()
            hosts = _url_hosts(argument)
            if hosts:
                markers.add("url")
            if _SHELL_META_RE.search(argument):
                markers.add("shell-syntax")
            if _DECODE_TEXT_RE.search(argument):
                markers.add("decoded")
            if not markers:
                continue
            line, snippet = pc._line_snippet(chunk, offset)
            behaviours.append(
                Behaviour(
                    "new_install_hook",
                    ("install-exec", tuple(sorted(markers)), tuple(sorted(hosts))),
                    path,
                    line,
                    snippet,
                    f"install-time process call with {', '.join(sorted(markers))} arguments",
                    "block",
                )
            )
        download = pc._JS_DOWNLOAD_RE.search(chunk)
        if download is not None and pc._JS_EXECUTE_RE.search(chunk):
            line, snippet = pc._line_snippet(chunk, download.start())
            behaviours.append(
                Behaviour(
                    "new_install_hook",
                    ("install-download-execute",),
                    path,
                    line,
                    snippet,
                    "install-time code downloads and executes a program",
                    "block",
                )
            )
    return behaviours


def _process_arguments(text: str, language: str) -> list[tuple[str, int]]:
    if language == "js":
        return [(match.group("args"), match.start()) for match in _JS_EXEC_CALL_RE.finditer(text)]
    if language == "gyp":
        return [
            (match.group(1) or match.group(2) or "", match.start())
            for match in _GYP_COMMAND_RE.finditer(text)
        ]
    found = []
    offset = 0
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            found.append((stripped, offset))
        offset += len(line)
    return found


def _install_body_behaviour(side: _Side, path: str, language: str) -> Behaviour:
    """Install-time code that changed beyond its literals (versions, messages) is a warning."""
    return Behaviour(
        "install_script_changed",
        ("install-body", path, _install_fingerprint(side, path, language)),
        path,
        None,
        "",
        "install-time code changed beyond version strings and other literals",
        "warn",
    )


def _install_fingerprint(side: _Side, path: str, language: str) -> str:
    text = side.text(path)
    if text is None:
        return side.digest(path)
    if language == "py":
        tree = side.tree(path)
        if tree is not None:
            shape = _LiteralShape().visit(ast.parse(text))
            return hashlib.sha256(ast.dump(shape, include_attributes=False).encode()).hexdigest()
    if language == "js":
        text = _normalize_javascript(text, path, [])
    shape = _LITERAL_RE.sub(_literal_placeholder, " ".join(text.split()))
    return hashlib.sha256(shape.encode()).hexdigest()


def _literal_placeholder(match: re.Match[str]) -> str:
    hosts = sorted(_url_hosts(match.group(0)))
    if hosts:
        return "URL(" + ",".join(hosts) + ")"
    return "L"


class _LiteralShape(ast.NodeTransformer):
    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if isinstance(node.value, (str, bytes)):
            text = node.value
            if isinstance(text, bytes):
                text = text.decode("latin-1")
            hosts = sorted(_url_hosts(text))
            if hosts:
                return ast.Constant("URL(" + ",".join(hosts) + ")")
            return ast.Constant("L")
        if isinstance(node.value, (int, float, complex)) and not isinstance(node.value, bool):
            return ast.Constant(0)
        return node


def _manifest_data(side: _Side, path: str, result: DiffResult | None) -> tuple[str, Any]:
    """package.json parsed like npm: BOM stripped, last duplicate key wins, larger size cap."""

    def build() -> tuple[str, Any, list[str], int | None]:
        text = side.read_text(path, MAX_MANIFEST_BYTES)
        if text is None:
            return "", None, [], side.entries[path].file.size
        duplicates: list[str] = []

        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            seen: set[str] = set()
            for key, _value in items:
                if key in seen:
                    duplicates.append(key)
                seen.add(key)
            return dict(items)

        try:
            data = json.loads(text, object_pairs_hook=pairs)
        except (ValueError, RecursionError):
            data = _jsonc(text)
        return text, data, duplicates, None

    text, data, duplicates, oversized = side.memo(f"manifest:{path}", build)
    if result is not None and side.role == "new":
        if oversized is not None:
            message = (
                f"{path} ({oversized} bytes) exceeds the {MAX_MANIFEST_BYTES // (1024 * 1024)} "
                "MB manifest cap or is not text; its scripts and dependencies were not read"
            )
            if message not in result.incomplete:
                result.incomplete.append(message)
        if duplicates:
            message = (
                f"{path} has duplicate keys ({', '.join(sorted(set(duplicates))[:5])}); "
                "analysed with the last value, as npm does"
            )
            if message not in result.limitations:
                result.limitations.append(message)
    return text, data


def _ambiguity_behaviours(side: _Side, result: DiffResult) -> list[Behaviour]:
    behaviours = []
    for path, prior in side.ambiguous:
        detail = (
            f"two archive entries install to {path}; npm strips the first path component of "
            "every entry, so the last one silently replaces the other"
        )
        if path != prior:
            detail = (
                f"{prior} and {path} differ only by case and overwrite each other on "
                "case-insensitive file systems (macOS, Windows)"
            )
        behaviours.append(
            Behaviour(
                "ambiguous_package_contents",
                ("ambiguous", path.casefold()),
                path,
                None,
                f"{prior} / {path}",
                detail,
                "block",
            )
        )
    return behaviours


def _command_behaviours(side: _Side, result: DiffResult) -> list[Behaviour]:
    """New executables named like common system tools (node, git, pip, sh, curl...)."""
    package = canonicalize_name(side.snapshot.package.name.rsplit("/", 1)[-1])
    behaviours = []
    for name, path in _declared_commands(side):
        command = re.sub(r"\.(?:exe|cmd|ps1|bat|py)$", "", name.lower())
        if command not in SHADOWED_COMMANDS or canonicalize_name(command) == package:
            continue
        behaviours.append(
            Behaviour(
                "shadows_system_command",
                ("command", command),
                path,
                None,
                name,
                f"installs an executable named {command}, which shadows the system command",
                "block",
            )
        )
    return behaviours


def _declared_commands(side: _Side) -> list[tuple[str, str]]:
    commands: list[tuple[str, str]] = []
    if side.ecosystem == "npm":
        if "package.json" not in side.entries:
            return commands
        data = _manifest_data(side, "package.json", None)[1]
        if not isinstance(data, dict):
            return commands
        binaries = data.get("bin")
        if isinstance(binaries, str):
            commands.append((str(data.get("name", "")).rsplit("/", 1)[-1], "package.json"))
        elif isinstance(binaries, dict):
            commands.extend((str(name), "package.json") for name in binaries)
        directories = _table(data, "directories")
        folder = directories.get("bin")
        if isinstance(folder, str) and folder:
            prefix = posixpath.normpath(folder).strip("./") + "/"
            commands.extend(
                (PurePosixPath(path).name, path) for path in side.entries if path.startswith(prefix)
            )
        return commands
    for path in side.entries:
        parts = path.split("/")
        if len(parts) == 2 and parts[0].endswith(".dist-info") and parts[1] == "entry_points.txt":
            section = ""
            for line in (side.text(path) or "").splitlines():
                stripped = line.strip()
                if stripped.startswith("["):
                    section = stripped.strip("[]").strip()
                elif section in {"console_scripts", "gui_scripts"} and "=" in stripped:
                    commands.append((stripped.split("=", 1)[0].strip(), path))
        elif len(parts) == 3 and parts[0].endswith(".data") and parts[1] == "scripts":
            commands.append((parts[2], path))
    return commands


def _changed_binary_behaviour(before: _Side, after: _Side, level: str) -> list[Behaviour]:
    """Native binaries replaced under the same name (digest changed)."""
    old: dict[str, set[str]] = {}
    for path in before.entries:
        if _is_native(before, path):
            old.setdefault(_native_identity(path), set()).add(before.digest(path))
    changed = sorted(
        path
        for path in after.entries
        if _is_native(after, path)
        and _native_identity(path) in old
        and after.digest(path) not in old[_native_identity(path)]
    )
    if not changed:
        return []
    listed = ", ".join(changed[:5])
    return [
        Behaviour(
            "native_binary_changed",
            ("native-changed", tuple(changed)),
            changed[0],
            None,
            "",
            f"{len(changed)} native binaries changed under the same name: {listed}",
            level,
        )
    ]


def _rule_location(text: str, rule: str) -> tuple[int | None, str]:
    patterns = {
        "npm-encoded-execution": (pc._JS_ENCODED_EXEC_RE, pc._JS_SINK_WRAPS_DECODE_RE),
        "npm-obfuscated-require": (pc._JS_OBFUSCATED_REQUIRE_HINT_RE,),
        "npm-credential-exfiltration": (pc._JS_CREDENTIAL_RE,),
        "encoded-execution": (pc._ENCODED_EXEC_RE,),
    }.get(rule, ())
    for pattern in patterns:
        match = pattern.search(text)
        if match is not None:
            return pc._line_snippet(text, match.start())
    return None, ""
