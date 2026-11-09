"""Deterministic deltas between two published artifacts of the same package.

Each side is reduced to behaviours with a comparison identity. A behaviour is
reported only when its identity is absent from the old artifact; identities
present in both versions are counted as unchanged. Nothing here imports,
installs or executes package code: Python is parsed with ``ast`` and every
other file is read as bounded text or bytes.
"""

from __future__ import annotations

import ast
import base64
import binascii
import contextlib
import hashlib
import ipaddress
import json
import posixpath
import re
import shlex
import sys
import time
from collections import Counter, deque
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import PurePosixPath
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from ca9.analyzers import package_code as pc
from ca9.artifacts.model import ArtifactFile, ArtifactSnapshot
from ca9.review import code_context
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
    "obfuscation_growth",
    "new_import_time_exec",
    "new_import_time_network",
    "new_exfiltration_host",
)
WARN_KINDS = (
    "new_import_time_network",
    "new_import_time_exec",
    "new_native_binary",
    "publisher_change",
    "install_script_changed",
    "native_binary_changed",
    "provenance_dropped",
    "new_outbound_host",
)
MAX_SCAN_BYTES = 32 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
SCAN_CHUNK = 1024 * 1024
SCAN_OVERLAP = 16 * 1024
SHADOWED_COMMANDS = frozenset(
    {
        "bash",
        "bun",
        "bunx",
        "curl",
        "deno",
        "docker",
        "gh",
        "git",
        "kubectl",
        "make",
        "node",
        "npm",
        "npx",
        "pip",
        "pip3",
        "pipx",
        "pnpm",
        "pnpx",
        "poetry",
        "python",
        "python3",
        "scp",
        "sh",
        "ssh",
        "sudo",
        "tsc",
        "uv",
        "uvx",
        "wget",
        "yarn",
        "yarnpkg",
        "zsh",
    }
)
_COMMAND_PROVIDERS = {
    "bunx": frozenset({"bun"}),
    "npx": frozenset({"npm"}),
    "pip3": frozenset({"pip"}),
    "pnpm": frozenset({"corepack", "@pnpm/exe"}),
    "pnpx": frozenset({"pnpm", "corepack", "@pnpm/exe"}),
    "tsc": frozenset({"typescript"}),
    "uvx": frozenset({"uv"}),
    "yarn": frozenset({"corepack", "@yarnpkg/cli-dist"}),
    "yarnpkg": frozenset({"yarn", "corepack", "@yarnpkg/cli-dist"}),
}
MAX_DELTAS_PER_KIND = 20
MAX_SNIPPET = 200
MAX_IMPORT_MODULES = 4000
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
_FAT_MACHO_MAGIC = (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf")
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
    r"(?:\brequire\s*\(\s*|\bimport\s*\(\s*|\bfrom\s*|\bimport\s+|"
    r"\bprocess\s*(?:\.\s*getBuiltinModule|\[\s*['\"`]getBuiltinModule['\"`]\s*\])\s*\(\s*)"
    r"(['\"`])([^'\"`\n$\\]{1,300})\1"
)
_JS_EXEC_MODULES = frozenset({"child_process", "vm"})
_JS_NETWORK_MODULES = frozenset({"http", "https", "net", "tls", "dgram", "dns", "http2"})
_JS_BINDING_RE = re.compile(r"\bprocess\s*\.\s*(?:binding|_linkedBinding|dlopen)\s*\(")
_DISGUISE_SUFFIXES = frozenset(
    {
        ".bat",
        ".bmp",
        ".cfg",
        ".cjs",
        ".css",
        ".csv",
        ".gif",
        ".htm",
        ".html",
        ".ico",
        ".ini",
        ".jpeg",
        ".jpg",
        ".js",
        ".json",
        ".lock",
        ".map",
        ".md",
        ".mjs",
        ".mp3",
        ".otf",
        ".pdf",
        ".png",
        ".ps1",
        ".pth",
        ".py",
        ".pyi",
        ".pyw",
        ".rst",
        ".sh",
        ".svg",
        ".toml",
        ".ts",
        ".ttf",
        ".txt",
        ".wav",
        ".webp",
        ".woff",
        ".woff2",
        ".xml",
        ".yaml",
        ".yml",
    }
)
_NATIVE_LOADERS = frozenset(
    {
        "ctypes.CDLL",
        "ctypes.OleDLL",
        "ctypes.PyDLL",
        "ctypes.WinDLL",
        "ctypes.cdll.LoadLibrary",
        "ctypes.oledll.LoadLibrary",
        "ctypes.pydll.LoadLibrary",
        "ctypes.windll.LoadLibrary",
    }
)
_NATIVE_LOADER_HINT = re.compile(r"ctypes|cffi|dlopen|LoadLibrary")
_HOST = (
    r"((?:\d{1,3}\.){3}\d{1,3}|\[[0-9A-Fa-f:]+\]|[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})"
)
_ANY_URL_HOST_RE = re.compile(r"(?:https?|wss?)://" + _HOST, re.I)
_QUOTED_URL_HOST_RE = re.compile(r"""['"`](?:https?|wss?)://""" + _HOST, re.I)
_BARE_IP_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")
_IPV4 = r"((?:\d{1,3}\.){3}\d{1,3})"
_SOCKET_IP_RE = re.compile(
    r"\b(?:connect|connect_ex|createConnection|create_connection|request|get|post|put|fetch|"
    r"urlopen|open|sendto|Socket|socket|HTTPConnection|HTTPSConnection|WebSocket|dial|Dial)"
    r"""\s*\(\s*(?:\d{2,5}\s*,\s*)?\(?\s*['"`]""" + _IPV4 + r"""(?::\d{1,5})?['"`]|"""
    r"""(?<![\w$.\])])\(\s*['"`]""" + _IPV4 + r"""['"`]\s*,\s*\d{2,5}\s*\)|"""
    r"""\b(?:host(?:name)?|address|addr|server|remote_?host)['"]?\s*[:=]\s*['"`]"""
    + _IPV4
    + r"""['"`]|['"`]"""
    + _IPV4
    + r""":\d{2,5}['"`]""",
    re.I,
)
_HOST_NETWORK_RE = {
    "npm": re.compile(
        r"\bfetch\s*\(|XMLHttpRequest|\bhttps?\.(?:request|get)\s*\(|\baxios\b|sendBeacon|"
        r"new\s+WebSocket|\bnet\.(?:connect|createConnection)\s*\(|\btls\.connect\s*\(|"
        r"""['"`](?:curl|wget)['"`\s]"""
    ),
    "pypi": re.compile(
        r"urlopen\s*\(|urlretrieve\s*\(|\brequests\.(?:get|post|put|patch|request|Session)|"
        r"\bhttpx\.|\baiohttp\.|\.connect\s*\(|create_connection\s*\(|http\.client|"
        r"""['"](?:curl|wget)['"\s]"""
    ),
}
_HOST_CODE_SUFFIXES = {"npm": _JS_SUFFIXES, "pypi": (".py",)}
_HOST_SKIP_PARTS = frozenset(
    {
        "test",
        "tests",
        "__tests__",
        "docs",
        "doc",
        "example",
        "examples",
        "fixtures",
        "benchmark",
        "benchmarks",
    }
)
_IGNORED_HOST_RE = re.compile(
    r"(?:^|\.)(?:localhost|example\.(?:com|org|net)|test|invalid|local|localdomain)$", re.I
)
_SENSITIVE_NEAR_HOST_RE = re.compile(
    r"private_?key|secret_?key|seed_?phrase|\bseed\b|mnemonic|keypair|key_pair|"
    r"\bprocess\.env\b(?!\s*[.\[])|os\.environ\b(?!\s*(?:\.get|\[))|"
    r"\bid_(?:rsa|ed25519|ecdsa)\b|\.ssh[/\\]|aws_secret_access_key|\.npmrc|\.pypirc|"
    r"\.git-credentials",
    re.I,
)
SENSITIVE_WINDOW = 600
_GENERATED_NAME_RE = re.compile(r"[0-9a-f]{16,}")
_NATIVE_SOURCE_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".pyx", ".rs", ".f90", ".f", ".m")
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
_HOOK_DOWNLOAD_RE = re.compile(
    r"\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b|\bhttps?://", re.I
)
_HOOK_RUN_RE = re.compile(
    r"\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\|\s*(?:python[0-9.]*|node|perl|ruby|iex)\b|"
    r"\bchmod\b|&&\s*\.{1,2}/|\b(?:ba|z)?sh\s+-c\b|\bnode\s+-e\b|\bpython[0-9.]*\s+-c\b",
    re.I,
)
_HOOK_DECODE_RE = re.compile(
    r"\bbase64\s+(?:-d|--decode|-D)\b|\beval\b|\batob\s*\(|Buffer\.from|fromCharCode|"
    r"b64decode|FromBase64String",
    re.I,
)
_HOOK_SECRET_RE = re.compile(
    r"\$\{?[A-Z_]*(?:TOKEN|SECRET|PASSWORD|KEY)\b|\bprintenv\b|(?:^|[\s;&|(])env\s*(?:[|>)]|$)|"
    r"process\.env\b(?!\s*[.\[])|os\.environ\b(?!\s*(?:\.get|\[))|\.npmrc|\.ssh/"
)
_DECODE_TEXT_RE = re.compile(r"\batob\s*\(|Buffer\.from|fromCharCode|b64decode")
_JS_FILE_READ_RE = re.compile(r"\breadFile(?:Sync)?\s*\(")
_JS_CODE_SINK_RE = re.compile(
    r"(?:(?P<receiver>[\w$]+)\s*\.\s*)?(?<![\w$])(?P<sink>eval|Function)\s*\(|"
    r"\bnew\s+(?P<new_sink>Function)\s*\(|"
    r"(?<![\w$])(?P<vm_sink>runInThisContext|runInNewContext|runInContext|compileFunction)"
    r"\s*\(|"
    r"\bnew\s+(?:[\w$]+\s*\.\s*)?(?P<script_sink>Script)\s*\(|"
    r"\.\s*(?P<compile_sink>_compile)\s*(?:\.\s*(?:call|apply)\s*)?\("
)
_JS_GLOBAL_RECEIVERS = frozenset({"global", "globalThis", "window", "self"})
_JS_INDIRECT_EVAL_RE = re.compile(pc._JS_INDIRECT_EVAL)
_JS_MODULE_CTOR_RE = re.compile(
    r"""(?:\brequire\s*\(\s*|getBuiltinModule['"`\]\s]*\(\s*)['"`](?:node:)?module['"`]"""
)
_JS_COMPILE_CALL_RE = re.compile(r"\.\s*_compile\s*(?:\.\s*(?:call|apply)\s*)?\(")
_JS_DECODER_RE = re.compile(
    r"Buffer\.from\s*\([^;]{0,200}?['\"](?:base64|hex)['\"]|\batob\s*\(|"
    r"String\.fromCharCode\s*\(|\b(?:inflate|inflateRaw|gunzip|unzip|brotliDecompress)"
    r"(?:Sync)?\s*\("
)
_JS_LOOKUP_REQUIRE_RE = re.compile(r"\brequire\s*\(\s*(_0x[0-9a-fA-F]{2,8})\s*[(\[]")
_JS_LOOKUP_MODULES = frozenset(
    {
        "child_process",
        "dgram",
        "dns",
        "http",
        "http2",
        "https",
        "module",
        "net",
        "tls",
        "vm",
        "worker_threads",
    }
)
_BASE64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")
_JS_VM_REQUIRE_RE = re.compile(
    r"""(?:\brequire\s*\(\s*|\bfrom\s+|\bimport\s*\(\s*|getBuiltinModule['"`\]\s]*\(\s*)"""
    r"""['"`](?:node:)?vm['"`]"""
)
_JS_STRING_RE = re.compile(r"'([^'\\\n]*)'|\"([^\"\\\n]*)\"|`([^`\\]*)`")
_JS_NOT_NAMES = frozenset(
    {
        "toString",
        "String",
        "Buffer",
        "from",
        "utf8",
        "await",
        "new",
        "this",
        "null",
        "undefined",
        "require",
        "module",
        "exports",
        "__filename",
        "__dirname",
    }
)
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
_FILE_READ_CALLS = frozenset(
    {
        "open",
        "io.open",
        "codecs.open",
        "io.open_code",
        "pkgutil.get_data",
        "importlib.resources.read_text",
        "importlib.resources.read_binary",
        "importlib_resources.read_text",
        "importlib_resources.read_binary",
    }
)
_FILE_READ_ATTRS = frozenset({"read_text", "read_bytes"})
_FILE_RUN_CALLS = frozenset(
    {
        "runpy.run_path",
        "runpy.run_module",
        "imp.load_source",
        "imp.load_compiled",
        "imp.load_module",
        "imp.load_package",
    }
)
_LOADER_RUN_ATTRS = frozenset({"load_module", "exec_module"})
_CLIENT_NETWORK_METHODS = frozenset(
    {
        "connect",
        "delete",
        "endheaders",
        "fetch",
        "get",
        "getresponse",
        "head",
        "open",
        "options",
        "patch",
        "perform",
        "post",
        "put",
        "putrequest",
        "request",
        "request_encode_body",
        "request_encode_url",
        "send",
        "stream",
        "urlopen",
        "ws_connect",
    }
)
_DYNAMIC_IMPORTS = frozenset({"importlib.import_module", "__import__", "importlib.__import__"})
_SCRIPT_RUNNERS = frozenset(
    {
        "bash",
        "bun",
        "cmd",
        "cscript",
        "dash",
        "deno",
        "ksh",
        "mshta",
        "node",
        "nodejs",
        "perl",
        "powershell",
        "pwsh",
        "py",
        "python",
        "python2",
        "python3",
        "pythonw",
        "regsvr32",
        "rundll32",
        "ruby",
        "sh",
        "wscript",
        "zsh",
    }
)
_PYTHON_RUNNERS = frozenset({"py", "python", "python2", "python3", "pythonw"})
_NODE_RUNNERS = frozenset({"node", "nodejs", "bun", "deno"})
_DOWNLOAD_OUTPUTS = {
    "curl": frozenset({"-o", "--output"}),
    "wget": frozenset({"-O", "--output-document"}),
}
_RISKY_INLINE_KINDS = frozenset(
    {
        "blob",
        "credential_path",
        "decode",
        "encoded_exec",
        "exec_risky",
        "harvest",
        "network",
        "process",
    }
)
_JS_INLINE_RISK_RE = re.compile(
    r"child_process|\beval\s*\(|\bFunction\s*\(|"
    r"""require\s*\(\s*['"`](?:node:)?(?:https?|net|tls|dgram|vm)['"`]|\bfetch\s*\("""
)
_PATH_WRAPPERS = frozenset(
    {
        "str",
        "os.fspath",
        "os.path.abspath",
        "os.path.realpath",
        "os.path.expanduser",
        "pathlib.Path",
        "Path",
    }
)
_EXEC_BIT_NAMES = frozenset(
    {"S_IXUSR", "S_IXGRP", "S_IXOTH", "S_IEXEC", "S_IRWXU", "S_IRWXG", "S_IRWXO"}
)
_MAX_BINDINGS = 8
_MAX_BINDING_DEPTH = 4
_MAX_EXPANDED_NODES = 4000
_MAX_SOURCES = 40
_MAX_JS_SINKS = 50
_STAGER_HINT = re.compile(r"chmod|urlretrieve|curl|wget|\.write|copyfileobj")
_DECODE_EXEC_HINT = re.compile(
    r"exec|eval|compile|decode|loads|unhexlify|fromhex|Popen|system|spawn|subprocess|"
    r"getattr|__import__|import_module|globals|builtins|sys\.modules|urlopen"
)
_NPM_CODE_RULE_KINDS = {
    "npm-encoded-execution": ("new_decode_exec", "decodes data and executes it", "block"),
    "npm-obfuscated-require": (
        "new_decode_exec",
        "builds a sensitive module name at runtime before loading it",
        "block",
    ),
    "encoded-execution": ("new_decode_exec", "decodes data and executes it", "block"),
    "npm-credential-exfiltration": (
        "new_import_time_network",
        "reads credentials or dumps the environment next to network or process code",
        "warn",
    ),
    "npm-wallet-network-hijack": (
        "new_import_time_network",
        "replaces fetch/XMLHttpRequest or wallet provider methods",
        "block",
    ),
    "credential-network-exfiltration": (
        "new_import_time_network",
        "reads credentials or dumps the environment next to network code",
        "warn",
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
        self.imports: dict[tuple[str, str, str], list[str]] = {}
        self.hosts: dict[str, frozenset[str]] = {}
        self.digests: dict[tuple[str, int], str] = {}
        self.natives: dict[str, set[str]] = {}
        self.decoders: dict[tuple[str, str], frozenset[str]] = {}
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
        self.first_release = False
        self.native_release = False
        self.changed: set[str] = set()
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
            file = self.entries[path].file
            key = (str(file.path), file.size)
            if key not in self.cache.digests:
                self.cache.check()
                digest = hashlib.sha256()
                try:
                    with file.path.open("rb") as stream:
                        for chunk in iter(lambda: stream.read(_HASH_CHUNK), b""):
                            digest.update(chunk)
                except OSError:
                    self._hashes[path] = f"unreadable:{path}"
                    return self._hashes[path]
                self.cache.digests[key] = digest.hexdigest()
            self._hashes[path] = self.cache.digests[key]
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
    native_release: bool = False,
    cache: _Cache | None = None,
    context_lines: int = 0,
) -> DiffResult:
    """Behaviours of ``new`` whose identity is absent from ``old``.

    ``changed_binaries`` is the level for native binaries replaced under the same name:
    "info" by default, because nearly every release of a compiled package rebuilds them.
    ``native_release`` says the old release shipped compiled wheels: when ``old`` holds no
    native binary (an sdist, or the pure wheel picked for this machine) and the project
    already builds native code (those wheels, or C/Cython/Rust sources in the sdist), the
    new binaries are build output of that code, reported as info, not new native code.
    ``cache`` (from ``analysis_cache``) shares parse results between diffs of one release.
    ``context_lines`` above 0 gives each block and warn delta in a text file of the package
    a ``context``: the diff of that file within that many lines of the delta's line.
    """
    if cache is None:
        cache = _Cache(deadline)
    before = _Side(old, ecosystem, cache)
    before.role = "old"
    before.native_release = native_release
    after = _Side(new, ecosystem, cache)
    old_behaviours, new_behaviours, result = _collect(before, after, before.top_modules())
    new_behaviours.extend(_changed_binary_behaviour(before, after, changed_binaries))
    if _builds_native(before, native_release):
        new_behaviours = [_as_build_output(item) for item in new_behaviours]
    new_behaviours = _without_new_hook_commands(old_behaviours, new_behaviours)
    _assemble(old_behaviours, new_behaviours, result, _describer(before, after, context_lines))
    return result


def analysis_cache(deadline: float | None = None) -> _Cache:
    """Parse results keyed by file content, shared by the diffs of one release's files."""
    return _Cache(deadline)


def content_digest(file: ArtifactFile, cache: _Cache) -> str:
    """SHA-256 of a file's bytes, remembered for the review."""
    key = (str(file.path), file.size)
    if key not in cache.digests:
        digest = hashlib.sha256()
        try:
            with file.path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(_HASH_CHUNK), b""):
                    digest.update(chunk)
        except OSError:
            return f"unreadable:{file.path}"
        cache.digests[key] = digest.hexdigest()
    return cache.digests[key]


def native_paths(snapshot: ArtifactSnapshot, cache: _Cache) -> set[str]:
    """Paths of a wheel's native binaries, by name or by ELF, PE or Mach-O header."""
    key = snapshot.artifact.url or str(snapshot.extract_dir)
    if key not in cache.natives:
        side = _Side(snapshot, "pypi", cache)
        cache.natives[key] = {path for path in side.entries if _is_native(side, path)}
    return cache.natives[key]


def native_name(path: str) -> bool:
    """Named like a compiled binary: a native suffix, or a versioned shared library."""
    lowered = path.lower()
    return lowered.endswith(_NATIVE_SUFFIXES) or ".so." in PurePosixPath(lowered).name


def native_head(head: bytes, size: int) -> bool:
    """Starts like an ELF, PE or (thin or universal) Mach-O image."""
    if head.startswith(b"MZ"):
        return size >= 512
    return head.startswith(_NATIVE_MAGIC + _FAT_MACHO_MAGIC)


def _builds_native(before: _Side, native_release: bool) -> bool:
    if any(_is_native(before, path) for path in before.entries):
        return False
    if native_release:
        return True
    return before.kind == "sdist" and any(
        path.lower().endswith(_NATIVE_SOURCE_SUFFIXES) or path.endswith("Cargo.toml")
        for path in before.entries
    )


def _as_build_output(item: Behaviour) -> Behaviour:
    if item.kind != "new_native_binary" or item.identity[:1] != ("native",):
        return item
    return replace(
        item,
        level="info",
        detail=f"{item.detail}; the old release builds native code, compared here against "
        "a file without binaries",
    )


def diff_new_package(
    new: ArtifactSnapshot,
    ecosystem: str,
    *,
    deadline: float | None = None,
    context_lines: int = 0,
) -> DiffResult:
    """Review a first release (no earlier version) as an upgrade from an empty release.

    Everything the release ships is new, so every behaviour keeps its upgrade level:
    install hooks, startup .pth code (a .pth import of the package's own modules counts
    as a module no earlier release shipped), sitecustomize/usercustomize at any depth,
    decode-and-exec, exec of shipped files, agent/editor hooks, shadowed commands and
    git/URL dependencies block; import-time network or exec, obfuscation and native
    binaries warn. Only the plain dependency list is left out: every dependency is new.
    ``context_lines`` above 0 gives each block and warn delta in a text file a ``context``:
    that part of the new file, every line added.
    """
    cache = _Cache(deadline)
    before = _Side(replace(new, files=()), ecosystem, cache)
    before.role = "old"
    after = _Side(new, ecosystem, cache)
    after.first_release = True
    _old, new_behaviours, result = _collect(before, after, set())
    new_behaviours = _without_new_hook_commands([], new_behaviours)
    new_behaviours = [_first_release_level(item) for item in new_behaviours]
    _assemble([], new_behaviours, result, _describer(before, after, context_lines))
    return result


def _first_release_level(item: Behaviour) -> Behaviour:
    if item.kind == "new_dependency":
        return replace(item, level="drop")
    return item


def _collect(
    before: _Side, after: _Side, baseline_modules: set[str]
) -> tuple[list[Behaviour], list[Behaviour], DiffResult]:
    ecosystem = after.ecosystem
    changed = _changed_paths(before, after)
    before.changed = changed
    after.changed = changed
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
            [
                _npm_manifest_behaviours,
                _npm_import_time_behaviours,
                _install_time_behaviours,
                _js_file_exec_behaviours,
            ]
        )
    for collect in collectors:
        after.cache.check()
        old_behaviours.extend(collect(before, result))
        new_behaviours.extend(collect(after, result))
    old_changed, new_changed = _changed_file_behaviours(before, after, changed, result)
    old_behaviours.extend(old_changed)
    new_behaviours.extend(new_changed)
    if ecosystem == "pypi":
        new_behaviours.extend(_top_level_behaviours(before, after))
        new_behaviours.extend(_native_loader_behaviours(before, after))
    new_behaviours.extend(_outbound_host_behaviours(before, after))
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    for path in sorted((after.unparsed & changed) - after.proven):
        if path.lower().endswith(".py"):
            result.incomplete.append(
                f"{path} could not be parsed by Python {version}; only text rules were applied"
            )
    return old_behaviours, new_behaviours, result


def _assemble(
    old_behaviours: list[Behaviour],
    new_behaviours: list[Behaviour],
    result: DiffResult,
    describe: Callable[[Behaviour], str | None] | None = None,
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
            delta = item.delta()
            if describe is not None and item.level in {"block", "warn"}:
                context = describe(item)
                if context is not None:
                    delta["context"] = context
            target.append(delta)
    for (level, kind), count in sorted(counts.items()):
        if count > MAX_DELTAS_PER_KIND:
            result.limitations.append(
                f"{count - MAX_DELTAS_PER_KIND} more {level} deltas of kind {kind} not listed"
            )


def _describer(
    before: _Side, after: _Side, context_lines: int
) -> Callable[[Behaviour], str | None] | None:
    """The diff excerpt of a behaviour's file around its line; None for a binary file, a
    path that is not a file of the new artifact, or a file that could not be shown (the
    excerpt is for display and never fails the review)."""
    if context_lines <= 0:
        return None
    diffs: dict[str, code_context.FileDiff | None] = {}

    def describe(item: Behaviour) -> str | None:
        entry = after.entries.get(item.path)
        if entry is None:
            return None
        try:
            if item.path not in diffs:
                diffs[item.path] = _file_diff(before, entry.file, item.path)
            diff = diffs[item.path]
            if diff is None:
                return None
            return code_context.excerpt(diff, item.line, context_lines)
        except Exception:
            diffs[item.path] = None
            return None

    return describe


def _file_diff(before: _Side, file: ArtifactFile, path: str) -> code_context.FileDiff | None:
    new = code_context.read_lines(file)
    if new is None:
        return None
    old = None
    if path in before.entries:
        old = code_context.read_lines(before.entries[path].file)
    return code_context.FileDiff(old, new)


def paired_files(
    old: ArtifactSnapshot, new: ArtifactSnapshot, ecosystem: str
) -> list[tuple[str, ArtifactFile | None, ArtifactFile | None]]:
    """Every package path of the two artifacts with its file on each side (None where a
    side does not ship it), by the paths the installer writes."""
    before = _Side(old, ecosystem)
    after = _Side(new, ecosystem)
    paired: list[tuple[str, ArtifactFile | None, ArtifactFile | None]] = []
    for path in sorted(before.entries.keys() | after.entries.keys()):
        files: list[ArtifactFile | None] = [None, None]
        for index, side in enumerate((before, after)):
            entry = side.entries.get(path)
            if entry is not None:
                files[index] = entry.file
        paired.append((path, files[0], files[1]))
    return paired


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
        for offset, line in pc.pth_lines(text):
            if not line.startswith(("import ", "import\t")):
                continue
            number = pc.pth_line_number(text, offset)
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


def _top_level_behaviours(before: _Side, after: _Side) -> list[Behaviour]:
    """Top-level packages a wheel adds to site-packages under another distribution's name.

    pip writes ``requests/__init__.py`` over the installed requests distribution's file,
    so a wheel that ships a top-level name not taken from its own name can replace another
    package's code. In an upgrade every such name the old release did not ship blocks. A
    first release has no old release, so only names that imitate another distribution
    block: one the package itself requires, or a near miss of its own name (reqeusts
    shipping requests/). Names that carry a long hex hash are generated by compilers (mypyc
    helper modules) and cannot be another distribution's package.
    """
    if after.kind != "wheel":
        return []
    package = after.snapshot.package.name
    own = _plain_name(package)
    shipped = {_plain_name(name) for name in _top_level_paths(before)}
    required = set()
    if after.first_release:
        required = {_plain_name(name) for name in _required_names(after)}
    behaviours = []
    for name, path in sorted(_top_level_paths(after).items()):
        plain = _plain_name(name)
        if (
            plain in shipped
            or name.lower() in _SDIST_NON_PACKAGES
            or name.lower() in _STARTUP_MODULES
            or _GENERATED_NAME_RE.search(name)
            or _named_after(plain, own)
        ):
            continue
        detail = (
            f"installs top-level {name}, which the old release did not ship and which is not "
            f"named after {package}: pip writes it over the files of whichever installed "
            "distribution owns that name"
        )
        if after.first_release:
            if plain in required:
                detail = (
                    f"installs top-level {name}, the package of its own dependency {name}: "
                    "installing it overwrites that distribution's files"
                )
            elif _near_miss(plain, own):
                detail = (
                    f"installs top-level {name}, a name close to but not taken from its own "
                    f"({package}): a lookalike that ships the real package's name is "
                    "imported in its place"
                )
            else:
                continue
        behaviours.append(
            Behaviour(
                "ambiguous_package_contents",
                ("top-level", plain),
                path,
                None,
                name,
                detail,
                "block",
            )
        )
    return behaviours


def _native_loader_behaviours(before: _Side, after: _Side) -> list[Behaviour]:
    """A previously pure-Python package that now ships a native library and loads it with
    ctypes or cffi: native code no static rule can inspect, run by the package itself. A
    first release has no previous release to call pure, so it is not judged here."""
    if not before.entries or before.native_release:
        return []
    if any(_is_native(before, path) for path in before.entries):
        return []
    if before.kind == "sdist" and _builds_native(before, False):
        return []
    added = {
        PurePosixPath(path).name.lower(): path
        for path in after.entries
        if path not in before.entries and _is_native(after, path)
    }
    if not added:
        return []
    stems = {name.split(".", 1)[0]: path for name, path in added.items()}
    behaviours = []
    for path in sorted(after.changed):
        if path not in after.entries or not path.lower().endswith(".py"):
            continue
        text = after.text(path)
        if text is None or not _NATIVE_LOADER_HINT.search(text):
            continue
        tree = after.tree(path)
        if tree is None:
            continue
        ctx = pc._PyContext(tree)
        bindings = _bindings(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name, _obfuscated = ctx.resolve(node.func)
            attribute = _attribute_name(node.func)
            if name not in _NATIVE_LOADERS and attribute not in {"dlopen", "LoadLibrary"}:
                continue
            arguments = [*node.args, *(item.value for item in node.keywords)]
            strings = " ".join(_strings_in(arguments, bindings)).lower()
            uses_file = any(
                isinstance(child, ast.Name) and child.id == "__file__"
                for argument in arguments
                for child in _expanded(argument, bindings)
            )
            library = next(
                (shipped for stem, shipped in stems.items() if stem and stem in strings), None
            )
            if library is None and uses_file:
                library = next(iter(sorted(added.values())))
            if library is None:
                continue
            line, snippet = pc._line_snippet(text, pc._offset_for_line(text, node.lineno))
            behaviours.append(
                Behaviour(
                    "uninspectable_import_time_code",
                    ("native-load", after.entries[library].install_path),
                    path,
                    line,
                    snippet,
                    f"loads {library} with {name or attribute}; the previous release was pure "
                    "Python and shipped no native code",
                    "block",
                )
            )
            break
    return behaviours


def _outbound_host_behaviours(before: _Side, after: _Side) -> list[Behaviour]:
    """A hard-coded URL host or IP that no file of the old release mentions, in a changed
    code file that makes network calls: where use-time exfiltration sends data.

    BLOCK (new_exfiltration_host) when the host is a raw public or link-local IP, or key
    material (private/secret key, seed, mnemonic, keypair) or a whole-environment dump sits
    within a few hundred characters of it; WARN (new_outbound_host) otherwise, because SDK
    upgrades legitimately add regional or API hosts that carry an API token. Hosts the new
    manifest declares, local and documentation names, and tests/docs/examples are ignored.
    A first release has no old release, so every host is new: only the BLOCK form counts.
    """
    ecosystem = after.ecosystem
    old_hosts = _side_hosts(before)
    declared = _declared_hosts(after)
    behaviours: list[Behaviour] = []
    reported: set[str] = set()
    for path in sorted(after.changed):
        if path not in after.entries or not _host_code_file(path, ecosystem):
            continue
        text = _host_text(after, path)
        if not text or not _HOST_NETWORK_RE[ecosystem].search(text):
            continue
        for host, offset in _code_hosts(text):
            if host in reported or host in old_hosts or host in declared or _ignored_host(host):
                continue
            raw_ip = _is_ip(host)
            window = text[max(0, offset - SENSITIVE_WINDOW) : offset + SENSITIVE_WINDOW]
            sensitive = _SENSITIVE_NEAR_HOST_RE.search(window)
            if after.first_release and not (raw_ip and sensitive):
                continue
            reported.add(host)
            line, snippet = pc._line_snippet(text, offset)
            if raw_ip or sensitive:
                reason = "a raw IP address"
                if sensitive and not raw_ip:
                    reason = f"{sensitive.group(0)} next to it"
                elif sensitive:
                    reason = f"a raw IP address with {sensitive.group(0)} next to it"
                behaviours.append(
                    Behaviour(
                        "new_exfiltration_host",
                        ("outbound-host", host),
                        path,
                        line,
                        snippet,
                        f"network code now sends requests to {host}, which the old release "
                        f"never mentions: {reason}",
                        "block",
                    )
                )
            else:
                behaviours.append(
                    Behaviour(
                        "new_outbound_host",
                        ("outbound-host", host),
                        path,
                        line,
                        snippet,
                        f"network code now contacts {host}, a host the old release never mentions",
                        "warn",
                    )
                )
    return behaviours


def _host_code_file(path: str, ecosystem: str) -> bool:
    lowered = path.lower()
    if lowered.endswith((".map", ".d.ts")) or not lowered.endswith(_HOST_CODE_SUFFIXES[ecosystem]):
        return False
    return not set(lowered.split("/")[:-1]) & _HOST_SKIP_PARTS


def _host_text(side: _Side, path: str) -> str:
    text = side.text(path)
    if text is None and side.entries[path].file.size <= MAX_SCAN_BYTES:
        text = side.read_text(path, MAX_SCAN_BYTES, allow_nul=True)
    return text or ""


def _side_hosts(side: _Side) -> set[str]:
    """Every URL host and dotted-quad IP in any text file of the release."""

    def build() -> set[str]:
        hosts: set[str] = set()
        for path in side.entries:
            if side.entries[path].file.size <= MAX_SCAN_BYTES:
                hosts.update(_file_hosts(side, path))
        return hosts

    return side.memo("hosts", build)


def _file_hosts(side: _Side, path: str) -> frozenset[str]:
    digest = side.digest(path)
    if digest not in side.cache.hosts:
        text = side.text(path)
        if text is None:
            text = side.read_text(path, MAX_SCAN_BYTES)
        found: set[str] = set()
        if text:
            found.update(match.group(1).lower() for match in _ANY_URL_HOST_RE.finditer(text))
            found.update(match.group(1) for match in _BARE_IP_RE.finditer(text))
        side.cache.hosts[digest] = frozenset(found)
    return side.cache.hosts[digest]


def _declared_hosts(side: _Side) -> set[str]:
    hosts: set[str] = set()
    for path in side.entries:
        name = PurePosixPath(path).name
        top = (
            "/" not in path or path.count("/") == 1 and path.split("/", 1)[0].endswith(".dist-info")
        )
        if top and name in {"package.json", "METADATA", "PKG-INFO", "pyproject.toml", "setup.cfg"}:
            text = side.read_text(path, MAX_MANIFEST_BYTES) or ""
            hosts.update(match.group(1).lower() for match in _ANY_URL_HOST_RE.finditer(text))
    return hosts


def _code_hosts(text: str) -> list[tuple[str, int]]:
    found: list[tuple[str, int]] = []
    for match in _QUOTED_URL_HOST_RE.finditer(text):
        found.append((match.group(1).lower().strip("[]"), match.start(1)))
        if len(found) >= 2000:
            return found
    for match in _SOCKET_IP_RE.finditer(text):
        ip = next(group for group in match.groups() if group)
        found.append((ip, match.start()))
    return found


def _ignored_host(host: str) -> bool:
    if _IGNORED_HOST_RE.search(host):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return bool(re.fullmatch(r"[\d.]+", host))
    private = address.is_private and not address.is_link_local
    return (
        address.is_loopback
        or private
        or address.is_unspecified
        or address.is_multicast
        or address.is_reserved
    )


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _top_level_paths(side: _Side) -> dict[str, str]:
    """Importable top-level names a wheel installs, each with the file that defines it."""
    found: dict[str, str] = {}
    for path, entry in sorted(side.entries.items()):
        install = entry.install_path
        first = install.split("/", 1)[0]
        if first.endswith((".dist-info", ".egg-info", ".data")) or first.startswith(".."):
            continue
        if "/" in install:
            name = first
        elif first.endswith((".py", ".pyc", ".so", ".pyd")):
            name = first.split(".", 1)[0]
        else:
            continue
        if not name.isidentifier():
            continue
        if name not in found or install == f"{name}/__init__.py":
            found[name] = path
    return found


def _required_names(side: _Side) -> set[str]:
    names = set()
    for _path, requirement_text, _line in _python_requirements(side):
        try:
            names.add(Requirement(requirement_text).name)
        except InvalidRequirement:
            continue
    return names


def _plain_name(name: str) -> str:
    return re.sub(r"[-_.]+", "", name.rsplit("/", 1)[-1].lower())


def _named_after(plain: str, own: str) -> bool:
    if plain == own:
        return True
    return len(plain) >= 3 and (plain in own or own in plain)


def _near_miss(plain: str, own: str) -> bool:
    """Within two edits (a swap of neighbours counts as one) of the package's own name."""
    if min(len(plain), len(own)) < 4 or abs(len(plain) - len(own)) > 2:
        return False
    previous_row: list[int] = []
    row = list(range(len(own) + 1))
    for i in range(1, len(plain) + 1):
        current = [i] + [0] * len(own)
        for j in range(1, len(own) + 1):
            cost = 0
            if plain[i - 1] != own[j - 1]:
                cost = 1
            current[j] = min(row[j] + 1, current[j - 1] + 1, row[j - 1] + cost)
            if i > 1 and j > 1 and plain[i - 1] == own[j - 2] and plain[i - 2] == own[j - 1]:
                current[j] = min(current[j], previous_row[j - 2] + 1)
        previous_row, row = row, current
    return row[len(own)] <= 2


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


def _native_format(side: _Side, path: str) -> str:
    head = side.head(path, 4)
    if head.startswith(b"MZ"):
        return "PE"
    if head.startswith(b"\x7fELF"):
        return "ELF"
    return "Mach-O"


def _native_identity(path: str) -> str:
    """Path of a native file with versions and Python ABI tags removed, so a module rebuilt
    as ``_core.cpython-314-darwin.so`` or ``_core.abi3.so`` keeps one identity."""
    directory, _slash, name = path.lower().rpartition("/")
    extension = re.fullmatch(r"([^.]+)(?:\.[^./]+)?\.(?:so|pyd)", name)
    if extension is not None:
        name = f"{extension.group(1)}.pyext"
    return re.sub(r"[0-9a-f]{6,}|\d+", "#", f"{directory}/{name}")


def _native_binary_behaviours(side: _Side, result: DiffResult) -> list[Behaviour]:
    """Native binaries; one named like code, text, data or media (a PE/ELF/Mach-O image in a
    ``.py``, ``.js``, ``.json``, ``.png``...) is disguised, which a build never produces."""
    behaviours = []
    for path, entry in side.entries.items():
        if not _is_native(side, path):
            continue
        suffix = PurePosixPath(path.lower()).suffix
        if suffix in _DISGUISE_SUFFIXES:
            side.proven.add(path)
            behaviours.append(
                Behaviour(
                    "ambiguous_package_contents",
                    ("disguised-native", path, side.digest(path)),
                    path,
                    None,
                    "",
                    f"{_native_format(side, path)} native binary ({entry.file.size} bytes) "
                    f"named like a {suffix} file",
                    "block",
                )
            )
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


def declared_dependencies(snapshot: ArtifactSnapshot, ecosystem: str) -> dict[str, str]:
    """Dependencies an artifact installs by default: npm ``dependencies``,
    ``optionalDependencies`` and ``peerDependencies`` (name -> range), or PyPI requirements
    that apply without extras (canonical name -> requirement text)."""
    side = _Side(snapshot, ecosystem)
    found: dict[str, str] = {}
    if ecosystem == "npm":
        manifest = _npm_manifest(side) or {}
        for group in _NPM_DEPENDENCY_GROUPS:
            values = manifest.get(group)
            if isinstance(values, dict):
                for name, spec in values.items():
                    if isinstance(name, str) and isinstance(spec, str):
                        found.setdefault(name, spec)
        return found
    for _path, text, _line in _python_requirements(side):
        try:
            requirement = Requirement(text)
        except InvalidRequirement:
            continue
        if requirement.url:
            continue
        if requirement.marker is not None:
            try:
                if not requirement.marker.evaluate({"extra": ""}):
                    continue
            except Exception:
                continue
        found.setdefault(str(canonicalize_name(requirement.name)), text)
    return found


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
    sources: tuple[str, ...] = ()
    fallback: str | None = None


def _python_calls(text: str, tree: ast.Module, *, import_time_only: bool) -> list[_PyCall] | None:
    """Risky calls; ``file_exec`` calls run code read from a file and keep the strings
    that name it in ``sources`` and their category without the file in ``fallback``."""
    try:
        ctx = pc._PyContext(tree)
        bindings = _bindings(tree)
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
                client = _client_call(node, ctx, bindings)
                if client is not None:
                    category = "network"
                    name = client
            markers = _call_markers(node, category or "")
            sources = _file_exec_sources(node, name, ctx, bindings)
            fallback = None
            if sources is not None:
                fallback = category
                category = "file_exec"
            if category is None:
                continue
            _line, snippet = pc._line_snippet(text, pc._offset_for_line(text, node.lineno))
            callee = name or _attribute_name(node.func) or "?"
            calls.append(
                _PyCall(category, callee, node.lineno, snippet, markers, sources or (), fallback)
            )
        return calls
    except RecursionError:
        return None


def _client_call(node: ast.Call, ctx: Any, bindings: dict[str, list[ast.AST]]) -> str | None:
    """``Client.method`` when a network method is called on an HTTP client object: built in
    the same expression (``requests.Session().post``), bound to a name, or opened by
    ``with``. Building a client sends nothing; calling these methods does."""
    func = node.func
    if not isinstance(func, ast.Attribute) or func.attr not in _CLIENT_NETWORK_METHODS:
        return None
    pending: list[tuple[ast.AST, int]] = [(func.value, 0)]
    seen: set[str] = set()
    while pending:
        receiver, depth = pending.pop(0)
        if isinstance(receiver, ast.Call):
            name, _obfuscated = ctx.resolve(receiver.func)
            if name in pc._NETWORK_CLIENT_CALLS:
                return f"{name}.{func.attr}"
        elif (
            isinstance(receiver, ast.Name)
            and depth < _MAX_BINDING_DEPTH
            and receiver.id not in seen
            and receiver.id in bindings
        ):
            seen.add(receiver.id)
            pending.extend((value, depth + 1) for value in bindings[receiver.id])
    return None


def _attribute_name(func: ast.AST) -> str | None:
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _bindings(tree: ast.Module) -> dict[str, list[ast.AST]]:
    """Values assigned to each plain name anywhere in the module, a few per name."""
    bindings: dict[str, list[ast.AST]] = {}
    for node in ast.walk(tree):
        pairs: list[tuple[ast.AST, ast.AST]] = []
        if isinstance(node, ast.Assign):
            pairs = [(target, node.value) for target in node.targets]
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and node.value is not None:
            pairs = [(node.target, node.value)]
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            pairs = [
                (item.optional_vars, item.context_expr)
                for item in node.items
                if item.optional_vars is not None
            ]
        for target, value in pairs:
            if isinstance(target, ast.Name):
                values = bindings.setdefault(target.id, [])
                if len(values) < _MAX_BINDINGS:
                    values.append(value)
    return bindings


def _expanded(node: ast.AST, bindings: dict[str, list[ast.AST]]) -> list[ast.AST]:
    """``node`` and its children, with plain names replaced by what was assigned to them."""
    found: list[ast.AST] = []
    pending = [(node, 0)]
    names: set[str] = set()
    while pending and len(found) < _MAX_EXPANDED_NODES:
        current, depth = pending.pop(0)
        for child in ast.walk(current):
            found.append(child)
            if (
                isinstance(child, ast.Name)
                and depth < _MAX_BINDING_DEPTH
                and child.id not in names
                and child.id in bindings
            ):
                names.add(child.id)
                pending.extend((value, depth + 1) for value in bindings[child.id])
    return found


def _strings_in(nodes: list[ast.AST], bindings: dict[str, list[ast.AST]]) -> tuple[str, ...]:
    strings: list[str] = []
    for node in nodes:
        for child in _expanded(node, bindings):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                if child.value not in strings:
                    strings.append(child.value)
            if len(strings) >= _MAX_SOURCES:
                return tuple(strings)
    return tuple(strings)


def _file_exec_sources(
    node: ast.Call, name: str | None, ctx: Any, bindings: dict[str, list[ast.AST]]
) -> tuple[str, ...] | None:
    """Strings naming the file whose content this call executes; None when it runs no file.

    Covers exec/eval of a file's text (also through compile, marshal or a decoder),
    execfile, runpy, imp loaders and ``load_module``/``exec_module`` of a loader or spec.
    """
    func = node.func
    if name in _PY_EXEC_NAMES and node.args:
        if name == "execfile":
            return _strings_in([node.args[0]], bindings)
        for child in _expanded(node.args[0], bindings):
            if not isinstance(child, ast.Call):
                continue
            read, _obfuscated = ctx.resolve(child.func)
            if read in _FILE_READ_CALLS:
                return _strings_in(
                    [*child.args, *(item.value for item in child.keywords)], bindings
                )
            if isinstance(child.func, ast.Attribute) and child.func.attr in _FILE_READ_ATTRS:
                return _strings_in([child.func.value, *child.args], bindings)
        return None
    arguments = [*node.args, *(item.value for item in node.keywords)]
    if name in _FILE_RUN_CALLS:
        return _strings_in(arguments, bindings)
    if isinstance(func, ast.Attribute) and func.attr in _LOADER_RUN_ATTRS:
        return _strings_in([func.value, *arguments], bindings)
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
    """Module-level nodes plus the bodies of module functions that import time starts:
    called by name, passed to threading.Thread/Timer, multiprocessing.Process, an
    executor's submit, atexit.register or signal.signal (or decorated with
    ``@atexit.register``), including lambdas passed there."""
    found = pc._import_time_nodes(tree)
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    ctx = pc._PyContext(tree)
    pending: list[ast.AST] = [tree]
    expanded: set[str] = set()
    decorated = {
        name
        for name, node in functions.items()
        if any(_registers_callback(decorator, ctx) for decorator in node.decorator_list)
    }
    for _round in range(4):
        called = set(decorated - expanded)
        lambdas: list[ast.AST] = []
        for scope in pending:
            for node in ast.walk(scope):
                if not isinstance(node, ast.Call) or id(node) not in found:
                    continue
                references = list(_callback_references(node, ctx))
                if isinstance(node.func, ast.Name):
                    references.append(node.func)
                for reference in references:
                    if isinstance(reference, ast.Name) and reference.id in functions:
                        if reference.id not in expanded:
                            called.add(reference.id)
                    elif isinstance(reference, ast.Lambda):
                        lambdas.append(reference.body)
        if not called and not lambdas:
            break
        pending = []
        for body in lambdas:
            found |= {id(child) for child in ast.walk(body)}
            pending.append(body)
        for name in sorted(called):
            expanded.add(name)
            body = ast.Module(body=functions[name].body, type_ignores=[])
            found |= pc._import_time_nodes(body)
            pending.append(body)
    return found


_CALLBACK_ARGUMENTS = {
    "threading.Thread": (None, "target"),
    "threading.Timer": (1, "function"),
    "multiprocessing.Process": (None, "target"),
    "atexit.register": (0, None),
    "signal.signal": (1, "handler"),
}


def _registers_callback(node: ast.AST, ctx: Any) -> bool:
    name, _obfuscated = ctx.resolve(node)
    return name == "atexit.register"


def _callback_references(node: ast.Call, ctx: Any) -> list[ast.AST]:
    name, _obfuscated = ctx.resolve(node.func)
    position, keyword = _CALLBACK_ARGUMENTS.get(name or "", (None, None))
    if name is None and isinstance(node.func, ast.Attribute) and node.func.attr == "submit":
        position = 0
    references = []
    if position is not None and len(node.args) > position:
        references.append(node.args[position])
    for item in node.keywords:
        if keyword is not None and item.arg == keyword:
            references.append(item.value)
    return references


def _call_category(node: ast.Call, name: str | None, ctx: Any) -> str | None:
    if name in pc._PROCESS_CALLS:
        arguments = [*node.args, *(item.value for item in node.keywords)]
        if any(pc._data_kinds(argument, ctx) & {"decoded", "fetched"} for argument in arguments):
            return "decode_exec"
        if any(_inline_code_risky(command) for command in _commands(node, name, ctx)):
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


@dataclass(frozen=True)
class _Token:
    keys: frozenset[str]
    text: str | None
    rendered: str = ""


def _commands(node: ast.Call, name: str | None, ctx: Any) -> list[list[_Token]]:
    """The argv of a process call, or each command of a shell string, as tokens that
    carry the path keys of their expressions (names, folded constants, f-string fields)."""
    if not node.args:
        return []
    first = node.args[0]
    if name and name.startswith(("os.exec", "os.spawn")):
        position = 1 if name.startswith("os.spawn") else 0
        if len(node.args) <= position:
            return []
        program = _token(node.args[position], ctx)
        rest = []
        if len(node.args) > position + 1 and isinstance(
            node.args[position + 1], (ast.List, ast.Tuple)
        ):
            rest = [_token(item, ctx) for item in node.args[position + 1].elts[1:]]
        return [[program, *rest]]
    if name == "asyncio.create_subprocess_exec":
        return [[_token(item, ctx) for item in node.args]]
    if isinstance(first, (ast.List, ast.Tuple)):
        return [[_token(item, ctx) for item in first.elts]]
    text = _rendered(first, ctx)
    if text is None:
        return []
    commands = []
    for part in re.split(r"&&|\|\||;|\|", text):
        try:
            words = shlex.split(part, posix=True)
        except ValueError:
            words = part.split()
        if words:
            commands.append([_word_token(word) for word in words])
    return commands


def _rendered(node: ast.AST, ctx: Any) -> str | None:
    """A string expression's text; f-string fields that do not fold become ``${name}``."""
    folded, _built = pc._fold(node, ctx, 0)
    if folded is not None:
        return folded
    if not isinstance(node, ast.JoinedStr):
        return None
    parts = []
    for value in node.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            parts.append(value.value)
        elif isinstance(value, ast.FormattedValue):
            inner, _built = pc._fold(value.value, ctx, 0)
            if inner is not None:
                parts.append(inner)
            elif isinstance(value.value, ast.Name):
                parts.append("${" + value.value.id + "}")
            else:
                parts.append("${expr}")
    return "".join(parts)


def _word_token(word: str) -> _Token:
    field = re.fullmatch(r"\$\{(\w+)\}", word)
    if field is not None:
        return _Token(frozenset({f"name:{field.group(1)}"}), None, field.group(1))
    return _Token(frozenset({f"const:{word}"}), word, word)


def _token(node: ast.AST, ctx: Any) -> _Token:
    resolved, _obfuscated = ctx.resolve(node)
    if resolved == "sys.executable":
        return _Token(frozenset({"const:python"}), "python")
    keys = _path_keys(node, ctx)
    text = None
    rendered = _rendered(node, ctx)
    if rendered is None:
        rendered = ast.unparse(node)[:200]
    elif "${" not in rendered:
        text = rendered
    return _Token(frozenset(keys), text, rendered)


def _path_keys(node: ast.AST, ctx: Any) -> set[str]:
    for _depth in range(4):
        if isinstance(node, ast.Call) and len(node.args) == 1:
            name, _obfuscated = ctx.resolve(node.func)
            if name in _PATH_WRAPPERS:
                node = node.args[0]
                continue
        break
    keys = set()
    if isinstance(node, ast.Name):
        keys.add(f"name:{node.id}")
    folded = _rendered(node, ctx)
    if folded is not None:
        whole = re.fullmatch(r"\$\{(\w+)\}", folded)
        if whole is not None:
            keys.add(f"name:{whole.group(1)}")
        elif "${" not in folded:
            keys.add(f"const:{folded}")
    if not isinstance(node, (ast.Name, ast.Constant)):
        keys.add("expr:" + ast.dump(node, include_attributes=False))
    return keys


def _program(token: _Token) -> str:
    if token.text is None:
        return ""
    return re.sub(r"\.exe$", "", posixpath.basename(token.text.replace("\\", "/")).lower())


def _inline_code_risky(command: list[_Token]) -> bool:
    """``python -c CODE`` or ``node -e CODE`` whose code decodes, downloads, starts processes
    or evaluates decoded or risky code: parsed as code, the way a .pth line is. Exec of code
    built locally from literals alone (``exec(compile(textwrap.dedent('...')))``) delivers
    nothing and does not count."""
    if not command:
        return False
    program = _program(command[0])
    flags = set()
    if program in _PYTHON_RUNNERS or re.fullmatch(r"python[\d.]*", program):
        flags = {"-c"}
    elif program in _NODE_RUNNERS:
        flags = {"-e", "--eval", "-p", "--print"}
    for index, token in enumerate(command[1:-1], start=1):
        if token.text not in flags:
            continue
        code = command[index + 1].rendered
        if program in _NODE_RUNNERS:
            return bool(
                _JS_INLINE_RISK_RE.search(code)
                or pc._JS_ENCODED_EXEC_RE.search(code)
                or pc._JS_SINK_WRAPS_DECODE_RE.search(code)
            )
        events = pc._python_events(code, 1)
        if events is None:
            return bool(
                pc._ENCODED_EXEC_RE.search(code) or re.search(r"\b(?:exec|eval)\s*\(", code)
            )
        return any(event.kind in _RISKY_INLINE_KINDS for event in events)
    return False


def _python_stager_behaviours(side: _Side, path: str, text: str) -> list[Behaviour]:
    """A file staged and then run: decoded or downloaded bytes written to a path, a
    download with urlretrieve or curl/wget -o, or chmod +x, followed by a process call that
    runs that path directly or through an interpreter (``[sys.executable, p]``). Upgrades
    report it wherever it runs; a first release only at import time, since installer tools
    legitimately fetch and run binaries when called."""
    tree = side.tree(path)
    if tree is None or not _STAGER_HINT.search(text):
        return []
    try:
        chains = _stager_chains(tree)
    except RecursionError:
        return []
    import_time = None
    if side.first_release:
        import_time = _import_time_with_local_calls(tree)
    behaviours = []
    for shape, node, staged in chains:
        if import_time is not None and id(node) not in import_time:
            continue
        line, snippet = pc._line_snippet(text, pc._offset_for_line(text, node.lineno))
        detail = {
            "decoded": f"writes decoded data to {staged} and runs it",
            "downloaded": f"downloads {staged} and runs it",
            "executable": f"makes {staged} executable and runs it",
        }[shape]
        behaviours.append(
            Behaviour(
                "new_decode_exec",
                ("stager", side.entries[path].install_path, shape),
                path,
                line,
                snippet,
                detail,
                "block",
            )
        )
    return behaviours


def _stager_chains(tree: ast.Module) -> list[tuple[str, ast.Call, str]]:
    ctx = pc._PyContext(tree)
    bindings = _bindings(tree)
    staged: dict[str, tuple[str, str]] = {}
    runs: list[tuple[ast.Call, list[_Token]]] = []

    def stage(keys: set[str] | frozenset[str], shape: str, label: str) -> None:
        for key in keys:
            if key not in staged or shape != "executable":
                staged[key] = (shape, label)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name, _obfuscated = ctx.resolve(node.func)
        if name in {"urllib.request.urlretrieve", "urllib.urlretrieve"}:
            target = node.args[1] if len(node.args) > 1 else _keyword(node, "filename")
            if target is not None:
                stage(_path_keys(target, ctx), "downloaded", ast.unparse(target)[:80])
        elif name in {"os.chmod", "os.lchmod"} and len(node.args) > 1:
            if _sets_exec_bit(node.args[1], ctx):
                stage(_path_keys(node.args[0], ctx), "executable", ast.unparse(node.args[0])[:80])
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "chmod" and node.args:
            if _sets_exec_bit(node.args[0], ctx):
                keys = _receiver_keys(node.func.value, ctx, bindings)
                stage(keys, "executable", ast.unparse(node.func.value)[:80])
        elif isinstance(node.func, ast.Attribute) and node.func.attr in {
            "write",
            "write_bytes",
            "write_text",
        }:
            if node.args:
                kinds = pc._data_kinds(node.args[0], ctx)
                shape = ""
                if "fetched" in kinds:
                    shape = "downloaded"
                elif "decoded" in kinds:
                    shape = "decoded"
                if shape:
                    keys = _receiver_keys(node.func.value, ctx, bindings)
                    stage(keys, shape, _file_label(node.func.value, ctx, bindings))
        elif name == "shutil.copyfileobj" and len(node.args) > 1:
            if pc._data_kinds(node.args[0], ctx) & {"fetched", "decoded"}:
                keys = _receiver_keys(node.args[1], ctx, bindings)
                stage(keys, "downloaded", _file_label(node.args[1], ctx, bindings))
        if name in pc._PROCESS_CALLS or (name or "").startswith(("os.exec", "os.spawn")):
            for command in _commands(node, name, ctx):
                _stage_command(command, stage)
                runs.append((node, command))
    chains: list[tuple[str, ast.Call, str]] = []
    reported: set[str] = set()
    for node, command in runs:
        for keys in _run_targets(command):
            hit = next((staged[key] for key in sorted(keys) if key in staged), None)
            if hit is not None and hit[0] not in reported:
                reported.add(hit[0])
                chains.append((hit[0], node, hit[1]))
    return chains


def _stage_command(command: list[_Token], stage: Any) -> None:
    program = _program(command[0])
    if program in _DOWNLOAD_OUTPUTS:
        flags = _DOWNLOAD_OUTPUTS[program]
        for index, token in enumerate(command[:-1]):
            if token.text in flags:
                target = command[index + 1]
                stage(target.keys, "downloaded", target.rendered)
    elif program == "chmod" and len(command) > 2:
        mode = command[1].text or ""
        if "x" in mode or re.fullmatch(r"0?[0-7]*[1357][0-7]?[0-7]?|0?[0-7]?[1357][0-7]?", mode):
            for target in command[2:]:
                stage(target.keys, "executable", target.rendered)


def _run_targets(command: list[_Token]) -> list[frozenset[str]]:
    """Path keys of what a command executes: the program, or the script an interpreter
    is given (not ``-c``/``-e`` code, ``-m`` modules or flags)."""
    if not command:
        return []
    program = _program(command[0])
    if program in _SCRIPT_RUNNERS or re.fullmatch(r"python[\d.]*", program):
        for token in command[1:]:
            text = token.text or ""
            if text in {"-c", "-e", "-m", "--eval", "-p", "--print", "/c", "-Command", "-c:"}:
                return []
            if text.startswith("-"):
                continue
            return [token.keys]
        return []
    return [command[0].keys]


def _receiver_keys(node: ast.AST, ctx: Any, bindings: dict[str, list[ast.AST]]) -> set[str]:
    """Keys of the file a handle or Path object refers to: ``open(P)``, ``Path(P)``, or a
    name bound to one of those (``with open(P) as f``)."""
    keys = set()
    values = [node]
    if isinstance(node, ast.Name):
        keys.add(f"name:{node.id}")
        values.extend(bindings.get(node.id, []))
    for value in values:
        if isinstance(value, ast.Call) and value.args:
            name, _obfuscated = ctx.resolve(value.func)
            if name in {"open", "io.open", "codecs.open", "pathlib.Path", "Path"}:
                keys |= _path_keys(value.args[0], ctx)
        elif value is not node:
            keys |= _path_keys(value, ctx)
    return keys


def _file_label(node: ast.AST, ctx: Any, bindings: dict[str, list[ast.AST]]) -> str:
    values = [node]
    if isinstance(node, ast.Name):
        values.extend(bindings.get(node.id, []))
    for value in values:
        if isinstance(value, ast.Call) and value.args:
            name, _obfuscated = ctx.resolve(value.func)
            if name in {"open", "io.open", "codecs.open", "pathlib.Path", "Path"}:
                return ast.unparse(value.args[0])[:80]
    return ast.unparse(node)[:80]


def _keyword(node: ast.Call, name: str) -> ast.AST | None:
    return next((item.value for item in node.keywords if item.arg == name), None)


def _sets_exec_bit(node: ast.AST, ctx: Any) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, int):
            if not isinstance(child.value, bool) and child.value & 0o111:
                return True
        if isinstance(child, ast.Attribute) and child.attr in _EXEC_BIT_NAMES:
            return True
        if isinstance(child, ast.Name) and child.id in _EXEC_BIT_NAMES:
            return True
    return False


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
            category = call.category
            if category == "file_exec":
                category = call.fallback
            if category is None:
                continue
            detail = f"{path} runs {call.callee} during build or install"
            if call.markers:
                detail += f" with {', '.join(call.markers)}"
            behaviours.append(
                Behaviour(
                    "new_install_hook",
                    ("build-call", category, call.callee, call.markers),
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
    """Build hook files plus the sdist's own modules they import and the shipped files they
    exec (both run at build too)."""
    modules = _python_modules(side)
    found = set(hook_files)
    queue = sorted(hook_files)
    while queue and len(found) < MAX_IMPORT_MODULES:
        path = queue.pop(0)
        tree = side.tree(path)
        if tree is None:
            continue
        targets = []
        for target in _module_imports(tree, "", everywhere=True):
            targets.extend(modules.get(prefix) for prefix in _prefixes(target))
        targets.extend(_exec_targets(side, path, False))
        for module_path in targets:
            if module_path is not None and module_path not in found:
                found.add(module_path)
                queue.append(module_path)
    return found


def _exec_targets(side: _Side, path: str, import_time_only: bool) -> list[str]:
    """Shipped files whose code ``path`` executes with exec, runpy or a file loader."""
    targets = []
    for call in side.calls(path, import_time_only) or []:
        if call.category == "file_exec":
            target = _exec_target(side, path, call)
            if target is not None and target not in targets:
                targets.append(target)
    return targets


def _exec_target(side: _Side, path: str, call: _PyCall) -> str | None:
    if call.callee == "runpy.run_module":
        modules = _python_modules(side)
        for value in call.sources:
            if value in modules:
                return modules[value]
    return _shipped_file(side, path, call.sources)


def _shipped_file(side: _Side, caller: str, values: tuple[str, ...]) -> str | None:
    """The artifact file that path fragments in ``caller`` name, as installed next to it."""
    by_install = side.memo(
        "install-paths", lambda: {entry.install_path: key for key, entry in side.entries.items()}
    )
    directory = posixpath.dirname(side.entries[caller].install_path)
    cleaned = []
    for value in values:
        text = value.replace("\\", "/").strip()
        if text and len(text) <= 300 and "\n" not in text:
            cleaned.append(text)
    parts = [text.strip("/") for text in cleaned if text.strip("/") not in {"", "."}]
    candidates = []
    for text in [*cleaned, "/".join(parts)]:
        relative = text.lstrip("/")
        if relative:
            candidates.append(posixpath.normpath(posixpath.join(directory, relative)))
            candidates.append(posixpath.normpath(relative))
    for candidate in candidates:
        found = by_install.get(candidate)
        if found is not None and found != caller:
            return found
    for text in cleaned:
        tail = posixpath.normpath(text.lstrip("/"))
        if tail in {".", ".."} or tail.startswith("../") or "." not in posixpath.basename(tail):
            continue
        matches = [
            key
            for install, key in by_install.items()
            if (install == tail or install.endswith("/" + tail)) and key != caller
        ]
        if len(matches) == 1:
            return matches[0]
    return None


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
    """Modules executed when ``roots`` are imported, every name they import, and truncation.

    Changed modules are visited before unchanged ones, so a cap reached in a large package
    still covers the code that changed."""
    modules = _python_modules(side)
    names = {path: name for name, path in modules.items()}
    seen: list[tuple[str, str]] = []
    visited: set[str] = set()
    imported: set[str] = set()
    changed: deque[str] = deque()
    others: deque[str] = deque()

    def push(name: str) -> None:
        if name in modules and name not in visited:
            if modules[name] in side.changed:
                changed.append(name)
            else:
                others.append(name)

    for root in roots:
        push(root)
    while (changed or others) and len(visited) < MAX_IMPORT_MODULES:
        side.cache.check()
        module = changed.popleft() if changed else others.popleft()
        if module in visited:
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
        key = (side.digest(path), package, module)
        if key not in side.cache.imports:
            side.cache.imports[key] = _module_imports(tree, package, module)
        for target in side.cache.imports[key]:
            for prefix in _prefixes(target):
                imported.add(prefix)
                push(prefix)
        for target in _exec_targets(side, path, True):
            name = names.get(target)
            if name is not None:
                push(name)
    remaining = [name for name in (*changed, *others) if name not in visited]
    return seen, imported, bool(remaining)


def _default_graph(side: _Side) -> tuple[list[tuple[str, str]], set[str], bool]:
    """Every top of an import chain is a root: plain top-level modules and the first
    importable level under a PEP 420 namespace directory (no ``__init__.py``)."""
    modules = _python_modules(side)
    roots = sorted(
        name for name in modules if not any(prefix in modules for prefix in _prefixes(name)[:-1])
    )
    return side.memo("graph", lambda: _import_graph(side, roots))


def _python_import_time_behaviours(side: _Side, result: DiffResult) -> list[Behaviour]:
    seen, _imported, truncated = _default_graph(side)
    behaviours: list[Behaviour] = []
    for module, path in seen:
        for call in side.calls(path, True) or []:
            if call.category == "file_exec":
                behaviours.append(_file_exec_behaviour(side, path, module, call))
                continue
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
                    "block",
                )
            )
    if truncated and side.role == "new":
        result.incomplete.append(
            f"import-time analysis stopped after {MAX_IMPORT_MODULES} modules; changed modules "
            "were visited first, the rest were not inspected"
        )
    return behaviours


def _file_exec_behaviour(side: _Side, path: str, module: str, call: _PyCall) -> Behaviour:
    """Import-time code run from a shipped file blocks; the file's code shape is part of the
    identity unless it is a module, whose own calls the import graph already follows."""
    target = _exec_target(side, path, call)
    if target is None:
        return Behaviour(
            "new_decode_exec",
            ("file-exec", side.entries[path].install_path, call.callee),
            path,
            call.line,
            call.snippet,
            f"{call.callee} runs code read from a file when {module} is imported; "
            "the file could not be resolved in the package",
            "block",
        )
    install = side.entries[target].install_path
    identity: tuple = ("file-exec", install)
    if not install.endswith(".py"):
        identity = ("file-exec", install, _install_fingerprint(side, target, "py"))
    return Behaviour(
        "new_decode_exec",
        identity,
        path,
        call.line,
        call.snippet,
        f"{call.callee} runs code read from {install} when {module} is imported",
        "block",
    )


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
            for _offset, line in pc.pth_lines(text):
                if line.startswith(("import ", "import\t")):
                    tree = pc._parse_python(line.strip())
                    if tree is not None:
                        names.update(_pth_imports(tree, 0))
        elif _startup_location(entry.install_path) is not None and lowered.endswith(".py"):
            tree = side.tree(path)
            if tree is not None:
                names.update(target.split(".")[0] for target in _module_imports(tree, ""))
    return names


def _module_imports(
    tree: ast.Module, package: str, module: str = "", *, everywhere: bool = False
) -> list[str]:
    """Modules imported at import time: import statements and ``importlib.import_module``
    or ``__import__`` calls with a constant name (relative names resolved as importlib
    does, against ``package=``, ``__name__`` or ``__package__``)."""
    import_time = pc._import_time_nodes(tree)
    ctx = pc._PyContext(tree)
    targets = []
    for node in ast.walk(tree):
        if not everywhere and id(node) not in import_time:
            continue
        if isinstance(node, ast.Call):
            target = _dynamic_import(node, ctx, package, module)
            if target:
                targets.append(target)
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


def _dynamic_import(node: ast.Call, ctx: Any, package: str, module: str) -> str | None:
    name, _obfuscated = ctx.resolve(node.func)
    if name not in _DYNAMIC_IMPORTS or not node.args:
        return None
    target, _folded = pc._fold(node.args[0], ctx, 0)
    if not target:
        return None
    if not target.startswith("."):
        return target
    anchor_node = None
    if name == "importlib.import_module":
        if len(node.args) > 1:
            anchor_node = node.args[1]
        for keyword in node.keywords:
            if keyword.arg == "package":
                anchor_node = keyword.value
    anchor = None
    if isinstance(anchor_node, ast.Name) and anchor_node.id == "__name__":
        anchor = module or package
    elif isinstance(anchor_node, ast.Name) and anchor_node.id == "__package__":
        anchor = package
    elif anchor_node is not None:
        anchor, _folded = pc._fold(anchor_node, ctx, 0)
    if not anchor:
        return None
    level = len(target) - len(target.lstrip("."))
    parts = anchor.split(".")
    if level - 1 >= len(parts):
        return None
    base = ".".join(parts[: len(parts) - (level - 1)])
    rest = target[level:]
    if not rest:
        return base
    return f"{base}.{rest}"


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
            behaviours.extend(_npm_hook_behaviours(path, line, prefix + hook, command))
        binding = posixpath.join(posixpath.dirname(path), "binding.gyp")
        if (
            binding in side.entries
            and data.get("gypfile") is not False
            and not any(isinstance(scripts.get(hook), str) for hook in ("preinstall", "install"))
        ):
            behaviours.extend(
                _npm_hook_behaviours(
                    binding,
                    None,
                    prefix + "install",
                    "node-gyp rebuild",
                    "binding.gyp makes npm compile native code on install",
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


def _npm_hook_behaviours(
    path: str, line: int | None, event: str, command: str, detail: str = ""
) -> list[Behaviour]:
    """An install hook: the event itself (new: block), its command (changed: warn) and the
    download-and-run, decode/eval and exfiltration sinks the command uses (new: block)."""
    hook = event.rpartition(":")[2]
    behaviours = [
        Behaviour(
            "new_install_hook",
            ("npm-hook", event),
            path,
            line,
            command,
            detail or f"npm runs the {hook} script on install",
            "block",
        ),
        Behaviour(
            "install_script_changed",
            ("npm-hook-command", event, " ".join(command.split())),
            path,
            line,
            command,
            f"the {hook} install hook command changed; npm runs it on install",
            "warn",
        ),
    ]
    for sink, what in _hook_command_sinks(command):
        behaviours.append(
            Behaviour(
                "new_install_hook",
                ("npm-hook-sink", sink),
                path,
                line,
                command,
                f"the {hook} install hook command now {what}",
                "block",
            )
        )
    return behaviours


def _hook_command_sinks(command: str) -> list[tuple[str, str]]:
    sinks = []
    download = _HOOK_DOWNLOAD_RE.search(command) is not None
    if _SHELL_PIPE_RE.search(command) or (download and _HOOK_RUN_RE.search(command)):
        sinks.append(("download-execute", "downloads and runs a program or code"))
    if _HOOK_DECODE_RE.search(command):
        sinks.append(("decode-eval", "decodes or evaluates code"))
    if download and _HOOK_SECRET_RE.search(command):
        sinks.append(("exfiltration", "sends environment or credential data over the network"))
    return sinks


def _without_new_hook_commands(
    old_behaviours: list[Behaviour], new_behaviours: list[Behaviour]
) -> list[Behaviour]:
    """The command of a hook event the old release lacks is part of that new hook."""
    events = {item.identity for item in old_behaviours if item.identity[:1] == ("npm-hook",)}
    return [
        item
        for item in new_behaviours
        if item.identity[:1] != ("npm-hook-command",) or ("npm-hook", item.identity[1]) in events
    ]


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
        if binding and not _JS_BINDING_RE.search(_normalize_javascript(text, path, [])):
            binding = None
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
        behaviours.extend(_js_runtime_module_behaviours(side, path, text))
    if side.ecosystem == "npm":
        behaviours.extend(_npm_code_behaviours(side, path, text, js_like and not python))
    if side.ecosystem == "pypi" and python:
        behaviours.extend(_python_decode_exec(side, path, text))
        behaviours.extend(_python_stager_behaviours(side, path, text))
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
    first = next((call for call in calls if "decode_exec" in {call.category, call.fallback}), None)
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
            key = (side.digest(path), module)
            if key not in side.cache.decoders:
                side.cache.decoders[key] = frozenset(_module_decoders(side, module, path))
            decoders.update(side.cache.decoders[key])
        return decoders

    return side.memo("decoders", build)


def _module_decoders(side: _Side, module: str, path: str) -> set[str]:
    text = side.text(path)
    if text is None or not _PY_DECODE_HINT.search(text):
        return set()
    tree = side.tree(path)
    if tree is None:
        return set()
    decoders = set()
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
        kind, detail, level = mapped
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


def _js_runtime_module_behaviours(side: _Side, path: str, text: str) -> list[Behaviour]:
    """Code that becomes a module at runtime: a decoded string compiled with
    ``Module.prototype._compile``, or ``require`` of a name looked up in an obfuscator
    string array that holds a process, network or vm module (plainly or base64-encoded)."""
    behaviours = []
    if _JS_MODULE_CTOR_RE.search(text) and _JS_DECODER_RE.search(text):
        for match in _JS_COMPILE_CALL_RE.finditer(text):
            argument = _call_argument(text, match.end())
            if _js_file_read(text, argument) is not None:
                continue
            line, snippet = pc._line_snippet(text, match.start())
            behaviours.append(
                Behaviour(
                    "new_decode_exec",
                    ("decoded-compile", path),
                    path,
                    line,
                    snippet,
                    "decodes a string and compiles it as a module with Module._compile",
                    "block",
                )
            )
            break
    lookup = _JS_LOOKUP_REQUIRE_RE.search(text)
    if lookup is not None:
        module = _lookup_module(text)
        if module is not None:
            line, snippet = pc._line_snippet(text, lookup.start())
            behaviours.append(
                Behaviour(
                    "new_decode_exec",
                    ("lookup-require", path),
                    path,
                    line,
                    snippet,
                    f"loads modules through an obfuscator string-array lookup whose array "
                    f"holds {module}",
                    "block",
                )
            )
    return behaviours


def _lookup_module(text: str) -> str | None:
    for count, match in enumerate(_JS_STRING_RE.finditer(text)):
        if count >= 20000:
            break
        value = next((group for group in match.groups() if group is not None), "")
        candidates = [value]
        if _BASE64_TOKEN_RE.fullmatch(value):
            with contextlib.suppress(binascii.Error, ValueError, UnicodeDecodeError):
                candidates.append(base64.b64decode(value, validate=True).decode("ascii"))
        for candidate in candidates:
            name = candidate.strip().removeprefix("node:")
            if name in _JS_LOOKUP_MODULES:
                return name
    return None


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


def _js_file_exec_behaviours(side: _Side, result: DiffResult) -> list[Behaviour]:
    """eval, Function, vm or Module._compile fed by a file read, in code Node loads from
    the entry points or runs at install time. The evaluated file's code shape is part of
    the identity, so a payload swapped into an unchanged loader is new."""
    install = _npm_install_targets(side)
    behaviours: list[Behaviour] = []
    for path in sorted(_js_reachable(side)):
        if path not in side.entries or install.get(path, "js") != "js":
            continue
        if path.lower().endswith((".json", ".node", ".gyp")):
            continue
        text = side.text(path)
        if text is None or not _JS_FILE_READ_RE.search(text):
            continue
        context = "load"
        when = "when the package is loaded"
        if path in install:
            context = "install"
            when = "at install time"
        sinks = 0
        for chunk in _chunks(text):
            for match in _JS_CODE_SINK_RE.finditer(chunk):
                sink = _js_sink(match, text)
                if sink is None:
                    continue
                sinks += 1
                if sinks > _MAX_JS_SINKS:
                    break
                region = _js_file_read(chunk, _call_argument(chunk, match.end()))
                if region is None:
                    continue
                side.cache.check()
                target = _shipped_file(side, path, _js_strings(region))
                line, snippet = pc._line_snippet(chunk, match.start())
                if len(chunk) != len(text):
                    line = None
                if target is None:
                    identity: tuple = ("js-file-exec", context, path, sink)
                    detail = (
                        f"{sink} runs code read from a file {when}; the file could not be "
                        "resolved in the package"
                    )
                else:
                    identity = (
                        "js-file-exec",
                        context,
                        target,
                        _install_fingerprint(side, target, "js"),
                    )
                    detail = f"{sink} runs code read from {target} {when}"
                behaviours.append(
                    Behaviour("new_decode_exec", identity, path, line, snippet, detail, "block")
                )
    return behaviours


def _js_sink(match: re.Match[str], text: str) -> str | None:
    if match.group("sink"):
        receiver = match.group("receiver")
        if receiver is not None and receiver not in _JS_GLOBAL_RECEIVERS:
            return None
        return match.group("sink")
    if match.group("new_sink"):
        return "new Function"
    if match.group("vm_sink"):
        return match.group("vm_sink")
    if match.group("script_sink"):
        if _JS_VM_REQUIRE_RE.search(text) is None:
            return None
        return "vm.Script"
    return "Module._compile"


def _call_argument(text: str, start: int, limit: int = 2000) -> str:
    """The text between the parenthesis before ``start`` and its matching close."""
    depth = 1
    quote = None
    end = min(len(text), start + limit)
    index = start
    while index < end:
        char = text[index]
        if quote is not None:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = None
        elif char in "'\"`":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[start:index]
        index += 1
    return text[start:end]


def _js_file_read(text: str, argument: str) -> str | None:
    """The path expression of a file read that feeds ``argument``, directly or through one
    variable, a readFile callback parameter or a promise result."""
    direct = _JS_FILE_READ_RE.search(argument)
    if direct is not None:
        return _call_argument(argument, direct.end())
    names = []
    for name in re.findall(r"[A-Za-z_$][\w$]*", argument):
        if name not in _JS_NOT_NAMES and name not in names:
            names.append(name)
    for name in names[:5]:
        escaped = re.escape(name)
        for binding in re.finditer(
            rf"(?<![\w$.]){escaped}\s*=(?![=>])\s*(?P<rhs>[^;\n]{{0,400}})", text
        ):
            rhs = binding.group("rhs")
            read = _JS_FILE_READ_RE.search(rhs)
            if read is not None:
                return _call_argument(rhs, read.end())
        callback = re.search(
            rf"\breadFile\s*\((?P<args>[^;]{{0,400}}?)(?:function\s*[\w$]*\s*)?"
            rf"\(\s*[\w$]+\s*,\s*{escaped}\s*\)",
            text,
        )
        if callback is not None:
            return callback.group("args")
        then = re.search(
            rf"\breadFile\s*\((?P<args>[^;]{{0,400}}?)\)\s*\.\s*then\s*\(\s*(?:async\s*)?"
            rf"(?:function\s*[\w$]*\s*)?\(?\s*{escaped}\b",
            text,
        )
        if then is not None:
            return then.group("args")
    return None


def _js_strings(text: str) -> tuple[str, ...]:
    strings = []
    for match in _JS_STRING_RE.finditer(text):
        value = next((group for group in match.groups() if group is not None), "")
        value = re.sub(r"\$\{[^}]*\}", "/", value)
        if value and value not in strings:
            strings.append(value)
    return tuple(strings[:_MAX_SOURCES])


def _decoder_source(side: _Side, path: str, text: str, name: str) -> str | None:
    if _JS_DECODE_HINT.search(text) and _is_local_decoder(text, name):
        return "defined in this file"
    escaped = re.escape(name)
    patterns = (
        rf"(?:const|let|var)\s*\{{[^}}]*\b{escaped}\b[^}}]*\}}\s*=\s*require\(\s*['\"`](\.[^'\"`$]+)['\"`]",
        rf"(?:const|let|var)\s+{escaped}\s*=\s*require\(\s*['\"`](\.[^'\"`$]+)['\"`]",
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
    elif blob is not None and path.lower().endswith(_JS_SUFFIXES):
        payload = _js_executed_blob(text)
        if payload is not None:
            reason = f"{len(payload.group(0))}-character encoded string decoded into eval"
            offset = payload.start()
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
            "block",
        )
    ]


def _js_executed_blob(text: str) -> re.Match[str] | None:
    """A large encoded string (not a data: URI or inline source map) in a file that decodes
    data and evaluates code; embedded wasm, fonts and source maps have no eval."""
    if not _JS_DECODER_RE.search(text):
        return None
    sink = _JS_INDIRECT_EVAL_RE.search(text) is not None or any(
        _js_sink(match, text) is not None for match in _JS_CODE_SINK_RE.finditer(text)
    )
    if not sink:
        return None
    for blob in _BLOB_RE.finditer(text):
        if "base64," not in text[max(0, blob.start() - 40) : blob.start()]:
            return blob
    return None


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
        sinks = _install_sinks(chunk, text, language)
        if download is not None and sinks:
            line, snippet = pc._line_snippet(chunk, download.start())
            behaviours.append(
                Behaviour(
                    "new_install_hook",
                    ("install-download-execute", sinks),
                    path,
                    line,
                    snippet,
                    "install-time code downloads and executes a program or code "
                    f"({', '.join(sinks)})",
                    "block",
                )
            )
    return behaviours


def _install_sinks(chunk: str, text: str, language: str) -> tuple[str, ...]:
    """How install-time code can run what it downloads: process calls, chmod, shell pipes
    and, in JavaScript, eval/Function/vm/Module._compile. A sink the old release did not
    use makes the download-and-run behaviour new even when the file already downloaded."""
    sinks = {
        re.sub(r"[\s(.|]", "", match.group(0)).lower()
        for match in pc._JS_EXECUTE_RE.finditer(chunk)
    }
    if language == "js":
        for match in _JS_CODE_SINK_RE.finditer(chunk):
            sink = _js_sink(match, text)
            if sink is not None:
                sinks.add(sink.lower())
    return tuple(sorted(sinks))


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
    full_name = side.snapshot.package.name.lower()
    package = canonicalize_name(full_name.rsplit("/", 1)[-1])
    behaviours = []
    for name, path in _declared_commands(side):
        command = re.sub(r"\.(?:exe|cmd|ps1|bat|py)$", "", name.lower())
        if command not in SHADOWED_COMMANDS or canonicalize_name(command) == package:
            continue
        if full_name in _COMMAND_PROVIDERS.get(command, frozenset()):
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
