"""Find committed files that make agents and editors run code, and MCP server configs."""

from __future__ import annotations

import ipaddress
import os
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ca9.agent_config import commands, impersonation, jsonc
from ca9.agent_config.mcp_launch import non_public_indexes, parse_launch

try:
    import tomllib
except ImportError:
    import tomli as tomllib

SCHEMA = "ca9.agent_hooks.v1"
MAX_FILE_BYTES = 32 * 1024 * 1024
TAIL_BYTES = 1024 * 1024
MAX_WALK_ENTRIES = 200_000
MAX_ITEMS = 500
MAX_DUPLICATES = 50

_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "site-packages",
        "bower_components",
        ".yarn",
        ".pnpm-store",
    }
)
_CONFIG_DIRECTORIES = frozenset(
    {
        ".claude",
        ".gemini",
        ".cursor",
        ".codex",
        ".vscode",
        ".roo",
        ".amazonq",
        ".windsurf",
        ".kiro",
        ".zed",
    }
)
_HOOK_ROLES = frozenset(
    {
        "claude_settings",
        "gemini_settings",
        "cursor_hooks",
        "codex_hooks",
        "vscode_tasks",
        "code_workspace",
        "kiro_hook",
    }
)
_AGENT_NAMES = {
    "kiro": "Kiro",
    "claude": "Claude Code",
    "gemini": "Gemini CLI",
    "cursor": "Cursor",
    "codex": "Codex",
    "vscode": "VS Code",
}
_CLAUDE_STRING_COMMANDS = (
    "apiKeyHelper",
    "awsAuthRefresh",
    "awsCredentialExport",
    "gcpAuthRefresh",
    "otelHeadersHelper",
)
_GEMINI_COMMANDS = (
    ("tools", "discoveryCommand"),
    ("tools", "callCommand"),
    (None, "toolDiscoveryCommand"),
    (None, "toolCallCommand"),
)
_BASE_URL_VARIABLES = {
    "ANTHROPIC_BASE_URL": "anthropic",
    "ANTHROPIC_API_URL": "anthropic",
    "ANTHROPIC_BEDROCK_BASE_URL": "bedrock",
    "ANTHROPIC_VERTEX_BASE_URL": "vertex",
    "ANTHROPIC_FOUNDRY_BASE_URL": "foundry",
    "OPENAI_BASE_URL": "openai",
    "OPENAI_API_BASE": "openai",
    "OPENAI_API_BASE_URL": "openai",
    "GOOGLE_GEMINI_BASE_URL": "gemini",
    "GEMINI_BASE_URL": "gemini",
}
_OFFICIAL_HOSTS = {
    "anthropic": re.compile(r"^api\.anthropic\.com$"),
    "openai": re.compile(r"^api\.openai\.com$"),
    "gemini": re.compile(r"^generativelanguage\.googleapis\.com$"),
    "bedrock": re.compile(r"^bedrock-runtime(?:-fips)?\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?$"),
    "vertex": re.compile(r"^(?:[a-z0-9-]+-)?aiplatform\.googleapis\.com$"),
    "foundry": re.compile(r"^[a-z0-9-]+\.services\.ai\.azure\.com$"),
}
_CODE_LOADING_ENV = frozenset(
    {"NODE_OPTIONS", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PYTHONSTARTUP"}
)
_INDEX_ENV = frozenset(
    {
        "NPM_CONFIG_REGISTRY",
        "YARN_NPM_REGISTRY_SERVER",
        "BUN_CONFIG_REGISTRY",
        "UV_INDEX",
        "UV_INDEX_URL",
        "UV_EXTRA_INDEX_URL",
        "UV_DEFAULT_INDEX",
        "UV_FIND_LINKS",
        "PIP_INDEX_URL",
        "PIP_EXTRA_INDEX_URL",
        "PIP_FIND_LINKS",
    }
)
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_SALVAGE_COMMAND = re.compile(r'"command"\s*:\s*("(?:[^"\\]|\\.)*")', re.DOTALL)


@dataclass
class Hook:
    file: str
    kind: str
    event: str
    command: str
    line: int
    agent: str
    padded: bool = False
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class Server:
    file: str
    name: str
    argv: list[str]
    line: int
    url: str | None = None
    cwd: str | None = None
    env: dict[str, str] = field(default_factory=dict)


@dataclass
class EnvOverride:
    file: str
    variable: str
    value: str
    line: int


@dataclass
class FileResult:
    hooks: list[Hook] = field(default_factory=list)
    servers: list[Server] = field(default_factory=list)
    env_overrides: list[EnvOverride] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    duplicates: list[dict[str, Any]] = field(default_factory=list)


def role_for(path: str | Path) -> str | None:
    parts = [part.lower() for part in Path(str(path).replace("\\", "/")).parts]
    if not parts:
        return None
    name = parts[-1]
    parent = ""
    grand = ""
    if len(parts) >= 2:
        parent = parts[-2]
    if len(parts) >= 3:
        grand = parts[-3]
    if name == ".mcp.json":
        return "mcp"
    if name in {"opencode.json", "opencode.jsonc"}:
        return "opencode"
    if name.endswith(".code-workspace"):
        return "code_workspace"
    if name.endswith(".kiro.hook") and (grand, parent) == (".kiro", "hooks"):
        return "kiro_hook"
    roles = {
        (".claude", "settings.json"): "claude_settings",
        (".claude", "settings.local.json"): "claude_settings",
        (".gemini", "settings.json"): "gemini_settings",
        (".cursor", "mcp.json"): "mcp",
        (".cursor", "hooks.json"): "cursor_hooks",
        (".codex", "hooks.json"): "codex_hooks",
        (".codex", "config.toml"): "codex_config",
        (".vscode", "tasks.json"): "vscode_tasks",
        (".vscode", "mcp.json"): "mcp",
        (".vscode", "settings.json"): "vscode_settings",
        (".roo", "mcp.json"): "mcp",
        (".amazonq", "mcp.json"): "mcp",
        (".windsurf", "mcp.json"): "mcp",
        (".zed", "settings.json"): "zed_settings",
    }
    if (parent, name) in roles:
        return roles[(parent, name)]
    if (grand, parent, name) == (".kiro", "settings", "mcp.json"):
        return "mcp"
    return None


def is_agent_config_path(path: str | Path) -> bool:
    """True for files that make an agent or editor run code or start MCP servers."""
    return role_for(path) is not None


def analyze_text(rel_path: str, text: str, *, truncated: bool = False) -> FileResult:
    """Hooks, MCP servers and API base-URL overrides declared in one config file.

    ``truncated`` marks text that is only the head and tail of an oversized file:
    hook files are then searched for command strings instead of parsed.
    """
    result = FileResult()
    role = role_for(rel_path)
    if role is None:
        return result
    if truncated and role in _HOOK_ROLES:
        _salvage(rel_path, role, text, result, force=True)
        return result
    if role == "codex_config":
        _codex_config(rel_path, text, result)
        return result
    try:
        document = jsonc.parse(text)
    except jsonc.JsoncError as exc:
        result.errors.append({"file": rel_path, "reason": f"could not parse: {exc}"})
        _salvage(rel_path, role, text, result)
        return result
    for duplicate in document.duplicates[:MAX_DUPLICATES]:
        result.duplicates.append(
            {
                "file": rel_path,
                "key": duplicate.path,
                "line": document.line(duplicate.last),
                "first_line": document.line(duplicate.first),
            }
        )
    value = document.value
    if not isinstance(value, jsonc.LineDict):
        return result
    if role == "claude_settings":
        _hooks_block(rel_path, document, value, "claude", "claude_hook", result)
        _claude_commands(rel_path, document, value, result)
        _claude_plugins(rel_path, document, value, result)
        _env_overrides(rel_path, document, value.get("env"), result)
        _servers_block(rel_path, document, value, result)
    elif role == "gemini_settings":
        _hooks_block(rel_path, document, value, "gemini", "gemini_hook", result)
        _gemini_commands(rel_path, document, value, result)
        _servers_block(rel_path, document, value, result)
    elif role == "cursor_hooks":
        _hooks_block(rel_path, document, value, "cursor", "cursor_hook", result)
    elif role == "codex_hooks":
        _hooks_block(rel_path, document, value, "codex", "codex_hook", result)
    elif role == "vscode_tasks":
        _tasks(rel_path, document, value, result)
    elif role == "code_workspace":
        tasks = value.get("tasks")
        if isinstance(tasks, jsonc.LineDict):
            _tasks(rel_path, document, tasks, result)
    elif role == "vscode_settings":
        mcp = value.get("mcp")
        if isinstance(mcp, jsonc.LineDict):
            _servers_block(rel_path, document, mcp, result)
    elif role == "kiro_hook":
        _kiro_hook(rel_path, document, value, result)
    elif role == "opencode":
        _named_servers(rel_path, document, value.get("mcp"), result)
    elif role == "zed_settings":
        _named_servers(rel_path, document, value.get("context_servers"), result)
    else:
        _servers_block(rel_path, document, value, result)
    return result


def scan_repository(repo_root: str | Path) -> dict[str, Any]:
    root = Path(repo_root)
    inventory: dict[str, Any] = {
        "schema": SCHEMA,
        "hooks": [],
        "mcp_servers": [],
        "env_overrides": [],
        "files": [],
        "errors": [],
        "status": "complete",
        "truncated": False,
        "duplicate_keys": False,
        "duplicates": [],
    }
    findings: list[dict[str, Any]] = []
    try:
        resolved_root = root.resolve()
        if not resolved_root.is_dir():
            inventory["errors"].append(
                {"file": ".", "reason": "repository root is not a directory"}
            )
            inventory["status"] = "partial"
            return {"findings": findings, "inventory": inventory}
    except OSError as exc:
        inventory["errors"].append({"file": ".", "reason": f"cannot read repository root: {exc}"})
        inventory["status"] = "partial"
        return {"findings": findings, "inventory": inventory}
    walk = _config_paths(resolved_root)
    if not walk.complete:
        inventory["truncated"] = True
        inventory["errors"].append(
            {"file": ".", "reason": f"stopped after {MAX_WALK_ENTRIES} directory entries"}
        )
    inventory["errors"].extend(walk.errors)
    if walk.links:
        inventory["links"] = walk.links[:MAX_ITEMS]
    for rel, path in walk.files:
        text, error, truncated = _read(path, resolved_root)
        if error:
            inventory["errors"].append({"file": rel, "reason": error})
        if text is None:
            continue
        inventory["files"].append(rel)
        result = analyze_text(rel, text, truncated=truncated)
        inventory["errors"].extend(result.errors)
        findings.extend(_findings_for(result))
        _add_inventory(inventory, result)
    if inventory["errors"]:
        inventory["status"] = "partial"
    findings.sort(
        key=lambda item: (
            _SEVERITY_RANK.get(item["severity"], 4),
            str(item["file"]),
            item["line"] or 0,
            item["signal_type"],
            str(item["name"]),
        )
    )
    return {"findings": findings, "inventory": inventory}


@dataclass
class _Walk:
    """Config files as ``(path the agent opens, real file)``, plus link problems."""

    files: list[tuple[str, Path]] = field(default_factory=list)
    complete: bool = True
    errors: list[dict[str, str]] = field(default_factory=list)
    links: list[dict[str, str]] = field(default_factory=list)


def _config_paths(root: Path) -> _Walk:
    """Walk the repository, following symlinks that stay inside it.

    Agents open ``.claude/settings.json`` through a committed ``.claude`` link, so linked
    directories are walked under the in-repo path that reaches them. The real tree is
    walked first and links after it, a directory is entered once per (real path, name,
    parent name) so loops end, and a file reached by several paths is reported once,
    under its own path when that path has the same role. A config link that leaves the
    repository, dangles or cannot be read is an error, never a silent pass.
    """
    walk = _Walk()
    real_root = str(root)
    visited: set[tuple[str, str, str]] = set()
    candidates: list[tuple[str, Path, str, bool]] = []
    reported: set[tuple[str, str]] = set()
    seen = 0
    pending = [(real_root, "", "", False)]
    deferred: list[tuple[str, str, str, bool]] = []
    while pending or deferred:
        if not pending:
            pending.append(deferred.pop(0))
        directory, rel, name, linked = pending.pop()
        parent = posixpath.basename(posixpath.dirname(rel)).lower()
        key = (directory, name.lower(), parent)
        if key in visited:
            continue
        visited.add(key)
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
        except OSError as exc:
            if linked or _config_directory(name, parent):
                _walk_error(walk, rel, f"cannot list the directory: {exc.strerror or exc}")
            continue
        seen += len(entries)
        subdirectories = []
        for entry in entries:
            child = entry.name
            if rel:
                child = f"{rel}/{entry.name}"
            if entry.is_symlink():
                _follow_link(walk, real_root, entry, child, name, linked, candidates, deferred)
            elif entry.is_dir(follow_symlinks=False):
                if entry.name not in _SKIP_DIRS:
                    subdirectories.append((entry.path, child, entry.name, linked))
            elif role_for(child) is not None:
                candidates.append((child, Path(entry.path), entry.path, linked))
        pending.extend(reversed(subdirectories))
        if seen > MAX_WALK_ENTRIES:
            walk.complete = False
            break
    preferred: dict[tuple[str, str], tuple[str, bool]] = {}
    for child, _path, real, linked in candidates:
        group = (real, role_for(child) or "")
        current = preferred.get(group)
        if current is None or (current[1] and not linked):
            preferred[group] = (child, linked)
    for child, path, real, _linked in candidates:
        group = (real, role_for(child) or "")
        if preferred[group][0] == child and group not in reported:
            reported.add(group)
            walk.files.append((child, path))
    return walk


def _follow_link(
    walk: _Walk,
    real_root: str,
    entry: os.DirEntry[str],
    child: str,
    parent_name: str,
    linked: bool,
    candidates: list[tuple[str, Path, str, bool]],
    deferred: list[tuple[str, str, str, bool]],
) -> None:
    config = role_for(child) is not None or _config_directory(entry.name, parent_name.lower())
    try:
        target = os.path.realpath(entry.path)
        exists = os.path.exists(target)
        directory = os.path.isdir(target)
    except (OSError, ValueError) as exc:
        if config:
            _walk_error(walk, child, f"symlink cannot be resolved: {exc}")
        return
    inside = target == real_root or target.startswith(real_root + os.sep)
    if not exists:
        if config:
            _walk_error(walk, child, "symlink target is missing; not read")
        return
    if not inside:
        if config:
            _walk_error(walk, child, "symlink points outside the repository; not read")
        return
    relative = Path(target).relative_to(real_root).as_posix()
    if directory:
        if entry.name in _SKIP_DIRS:
            return
        deferred.append((target, child, entry.name, True))
    elif role_for(child) is not None:
        candidates.append((child, Path(target), target, True))
    else:
        return
    if not linked and len(walk.links) < MAX_ITEMS:
        walk.links.append({"path": child, "target": relative})


def _config_directory(name: str, parent: str) -> bool:
    lowered = name.lower()
    return lowered in _CONFIG_DIRECTORIES or (lowered == "settings" and parent == ".kiro")


def _walk_error(walk: _Walk, rel: str, reason: str) -> None:
    error = {"file": rel or ".", "reason": reason}
    if error not in walk.errors:
        walk.errors.append(error)


def _read(path: Path, root: Path) -> tuple[str | None, str | None, bool]:
    try:
        if path.is_symlink():
            target = path.resolve()
            if root not in target.parents and target != root:
                return None, "symlink points outside the repository; not read", False
        size = path.stat().st_size
        with open(path, "rb") as handle:
            raw = handle.read(MAX_FILE_BYTES)
            if size <= MAX_FILE_BYTES:
                return _decode(raw), None, False
            handle.seek(max(MAX_FILE_BYTES, size - TAIL_BYTES))
            tail = handle.read(TAIL_BYTES)
    except OSError as exc:
        return None, f"cannot read: {exc}", False
    error = (
        f"file is {size} bytes; searched the first {MAX_FILE_BYTES} and last {TAIL_BYTES} "
        "bytes for commands"
    )
    return _decode(raw) + "\n" + _decode(tail), error, True


def _decode(raw: bytes) -> str:
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def _hooks_block(
    rel: str,
    document: jsonc.Document,
    value: jsonc.LineDict,
    agent: str,
    kind: str,
    result: FileResult,
) -> None:
    hooks = value.get("hooks")
    if isinstance(hooks, jsonc.LineDict):
        for event, entries in hooks.items():
            _walk_handlers(rel, document, entries, str(event), None, agent, kind, result)
    elif isinstance(hooks, jsonc.LineList):
        _walk_handlers(rel, document, hooks, "unknown", None, agent, kind, result)


def _walk_handlers(
    rel: str,
    document: jsonc.Document,
    node: Any,
    event: str,
    matcher: str | None,
    agent: str,
    kind: str,
    result: FileResult,
) -> None:
    stack = [(node, matcher)]
    while stack:
        current, current_matcher = stack.pop()
        if isinstance(current, jsonc.LineList):
            stack.extend((item, current_matcher) for item in reversed(current))
            continue
        if not isinstance(current, jsonc.LineDict):
            continue
        if isinstance(current.get("matcher"), str):
            current_matcher = current["matcher"]
        handler_type = current.get("type")
        command = _command_text(current.get("command"))
        offset = current.offsets.get("command")
        if command is None and handler_type == "http" and isinstance(current.get("url"), str):
            command = current["url"]
            offset = current.offsets.get("url")
        if command is not None:
            extra: dict[str, Any] = {}
            if current_matcher is not None:
                extra["matcher"] = current_matcher
            if isinstance(handler_type, str):
                extra["handler_type"] = handler_type
            result.hooks.append(_hook(rel, document, kind, event, command, offset, agent, extra))
        for key, child in current.items():
            if key != "command" and isinstance(child, (jsonc.LineDict, jsonc.LineList)):
                stack.append((child, current_matcher))


def _command_text(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, jsonc.LineList) and value and all(isinstance(v, str) for v in value):
        return " ".join(value)
    if isinstance(value, jsonc.LineDict) and isinstance(value.get("value"), str):
        return value["value"]
    return None


def _hook(
    rel: str,
    document: jsonc.Document,
    kind: str,
    event: str,
    command: str,
    offset: int | None,
    agent: str,
    extra: dict[str, Any],
) -> Hook:
    padded = False
    if offset is not None:
        padded = commands.line_padded(document.text, document.line_start(offset), offset)
    return Hook(rel, kind, event, command, document.line(offset), agent, padded, extra)


def _claude_commands(
    rel: str, document: jsonc.Document, value: jsonc.LineDict, result: FileResult
) -> None:
    for key in _CLAUDE_STRING_COMMANDS:
        if isinstance(value.get(key), str) and value[key].strip():
            result.hooks.append(
                _hook(
                    rel,
                    document,
                    "claude_setting",
                    key,
                    value[key],
                    value.offsets[key],
                    "claude",
                    {},
                )
            )
    for key, child in value.items():
        if key == "hooks" or not isinstance(child, jsonc.LineDict):
            continue
        command = _command_text(child.get("command"))
        if child.get("type") == "command" and command is not None:
            offset = child.offsets.get("command")
            result.hooks.append(
                _hook(rel, document, "claude_setting", key, command, offset, "claude", {})
            )


def _claude_plugins(
    rel: str, document: jsonc.Document, value: jsonc.LineDict, result: FileResult
) -> None:
    """Plugins a committed settings file enables; their hooks and MCP servers run code that
    lives in the marketplace, not in this repository."""
    plugins = value.get("enabledPlugins")
    if not isinstance(plugins, jsonc.LineDict):
        return
    markets = value.get("extraKnownMarketplaces")
    for name, enabled in plugins.items():
        if enabled is not True:
            continue
        marketplace = _marketplace(markets, str(name).rpartition("@")[2])
        command = f"plugin {name}"
        if marketplace:
            command = f"plugin {name} from marketplace {marketplace}"
        result.hooks.append(
            _hook(
                rel,
                document,
                "claude_setting",
                "enabledPlugins",
                command,
                plugins.offsets.get(name),
                "claude",
                {"plugin": str(name), "marketplace": marketplace},
            )
        )


def _marketplace(markets: Any, name: str) -> str:
    if not isinstance(markets, jsonc.LineDict) or not name:
        return ""
    entry = markets.get(name)
    source = None
    if isinstance(entry, jsonc.LineDict):
        source = entry.get("source")
    if not isinstance(source, jsonc.LineDict):
        return ""
    kind = source.get("source")
    for key in ("repo", "url", "path"):
        if isinstance(source.get(key), str) and source[key].strip():
            return f"{kind}:{source[key].strip()}"
    return str(kind or "")


def _kiro_hook(
    rel: str, document: jsonc.Document, value: jsonc.LineDict, result: FileResult
) -> None:
    """A Kiro agent hook (``.kiro/hooks/*.kiro.hook``) whose ``then`` runs a command."""
    if value.get("enabled") is False:
        return
    action = value.get("then")
    if not isinstance(action, jsonc.LineDict):
        return
    command = _command_text(action.get("command"))
    if command is None:
        return
    event = "unknown"
    when = value.get("when")
    if isinstance(when, jsonc.LineDict) and isinstance(when.get("type"), str):
        event = when["type"]
    extra: dict[str, Any] = {}
    if isinstance(action.get("type"), str):
        extra["handler_type"] = action["type"]
    result.hooks.append(
        _hook(
            rel, document, "kiro_hook", event, command, action.offsets.get("command"), "kiro", extra
        )
    )


def _named_servers(rel: str, document: jsonc.Document, servers: Any, result: FileResult) -> None:
    """opencode ``mcp`` and Zed ``context_servers``: a name per server, the command as a
    list, a string with ``args``, or ``{path, args, env}``."""
    if not isinstance(servers, jsonc.LineDict):
        return
    for name, config in servers.items():
        if not isinstance(config, jsonc.LineDict) or config.get("enabled") is False:
            continue
        line = document.line(servers.offsets[name])
        command = config.get("command")
        if isinstance(command, jsonc.LineDict):
            config = {**config, **command, "command": command.get("path")}
        server = _server(rel, str(name), config, line)
        if server is not None:
            result.servers.append(server)


def _gemini_commands(
    rel: str, document: jsonc.Document, value: jsonc.LineDict, result: FileResult
) -> None:
    for parent_key, key in _GEMINI_COMMANDS:
        container = value
        event = key
        if parent_key is not None:
            container = value.get(parent_key)
            event = f"{parent_key}.{key}"
        if not isinstance(container, jsonc.LineDict):
            continue
        command = container.get(key)
        if isinstance(command, str) and command.strip():
            offset = container.offsets[key]
            result.hooks.append(
                _hook(rel, document, "gemini_setting", event, command, offset, "gemini", {})
            )


def _env_overrides(rel: str, document: jsonc.Document, env: Any, result: FileResult) -> None:
    if not isinstance(env, jsonc.LineDict):
        return
    for variable, raw in env.items():
        family = _BASE_URL_VARIABLES.get(str(variable).upper())
        if family is None or not isinstance(raw, str) or not raw.strip():
            continue
        if _official_endpoint(family, raw):
            continue
        result.env_overrides.append(
            EnvOverride(rel, str(variable), raw.strip(), document.line(env.offsets[variable]))
        )


def _official_endpoint(family: str, value: str) -> bool:
    try:
        parsed = urlsplit(value.strip())
        port = parsed.port
    except ValueError:
        return False
    if parsed.scheme != "https" or parsed.username is not None or parsed.password is not None:
        return False
    if port not in {None, 443}:
        return False
    return bool(_OFFICIAL_HOSTS[family].match((parsed.hostname or "").lower()))


def redact_url(value: str) -> str:
    try:
        parsed = urlsplit(value.strip())
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        return commands.display(value)[:120]
    if not parsed.scheme or not host:
        return commands.display(value)[:120]
    netloc = host
    if port:
        netloc = f"{host}:{port}"
    return f"{parsed.scheme}://{netloc}{parsed.path}"[:300]


def _servers_block(
    rel: str, document: jsonc.Document, value: jsonc.LineDict, result: FileResult
) -> None:
    for key in ("mcpServers", "servers"):
        servers = value.get(key)
        if not isinstance(servers, jsonc.LineDict):
            continue
        for name, config in servers.items():
            if isinstance(config, jsonc.LineDict):
                server = _server(rel, str(name), config, document.line(servers.offsets[name]))
                if server is not None:
                    result.servers.append(server)


def _server(rel: str, name: str, config: dict[str, Any], line: int) -> Server | None:
    url = None
    for key in ("url", "serverUrl", "httpUrl"):
        if isinstance(config.get(key), str) and config[key].strip():
            url = config[key].strip()
            break
    raw_command = config.get("command")
    argv: list[str] = []
    if isinstance(raw_command, str) and raw_command.strip():
        argv = [raw_command]
    elif isinstance(raw_command, list):
        argv = [str(item) for item in raw_command if isinstance(item, (str, int, float))]
    raw_args = config.get("args")
    if isinstance(raw_args, list):
        argv.extend(str(item) for item in raw_args if isinstance(item, (str, int, float)))
    if not argv and url is None:
        return None
    env: dict[str, str] = {}
    for key in ("env", "environment"):
        if isinstance(config.get(key), dict):
            env.update(
                {str(k): str(v) for k, v in config[key].items() if isinstance(v, (str, int, float))}
            )
    cwd = None
    if isinstance(config.get("cwd"), str):
        cwd = config["cwd"]
    return Server(rel, name, argv, line, url, cwd, env)


def _tasks(rel: str, document: jsonc.Document, value: jsonc.LineDict, result: FileResult) -> None:
    tasks = value.get("tasks")
    if not isinstance(tasks, jsonc.LineList):
        return
    by_label: dict[str, jsonc.LineDict] = {}
    for task in tasks:
        if isinstance(task, jsonc.LineDict):
            for key in ("label", "taskName"):
                if isinstance(task.get(key), str):
                    by_label.setdefault(task[key], task)
            if isinstance(task.get("script"), str):
                by_label.setdefault(f"npm: {task['script']}", task)
    global_shells = _shell_variants(value)
    queue: list[tuple[jsonc.LineDict, str | None]] = []
    for task in tasks:
        if isinstance(task, jsonc.LineDict) and _runs_on_folder_open(task):
            queue.append((task, None))
    visited: set[int] = set()
    while queue:
        task, via = queue.pop(0)
        if id(task) in visited:
            continue
        visited.add(id(task))
        label = _task_label(task)
        for command, offset in _task_commands(task, global_shells):
            extra: dict[str, Any] = {"label": label}
            if via is not None:
                extra["via"] = via
            result.hooks.append(
                _hook(rel, document, "vscode_task", "folderOpen", command, offset, "vscode", extra)
            )
        for dependency in _dependencies(task.get("dependsOn")):
            target = by_label.get(dependency)
            if target is not None:
                queue.append((target, label))


def _runs_on_folder_open(task: jsonc.LineDict) -> bool:
    for scope in (task, task.get("windows"), task.get("osx"), task.get("linux")):
        if isinstance(scope, dict):
            options = scope.get("runOptions")
            if isinstance(options, dict) and str(options.get("runOn", "")).lower() == "folderopen":
                return True
    return False


def _task_label(task: jsonc.LineDict) -> str:
    for key in ("label", "taskName"):
        if isinstance(task.get(key), str):
            return task[key]
    if isinstance(task.get("script"), str):
        return f"npm: {task['script']}"
    return "unnamed task"


def _dependencies(value: Any) -> list[str]:
    items = value
    if not isinstance(value, list):
        items = [value]
    names: list[str] = []
    for item in items:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, dict):
            for key in ("task", "label"):
                if isinstance(item.get(key), str):
                    names.append(item[key])
            if isinstance(item.get("script"), str):
                names.append(f"npm: {item['script']}")
    return names


def _shell_variants(scope: Any) -> dict[str, list[str]]:
    variants: dict[str, list[str]] = {}
    for platform in ("", "windows", "osx", "linux"):
        container = scope
        if platform and isinstance(scope, dict):
            container = scope.get(platform)
        elif platform:
            container = None
        shell = _shell_of(container)
        if shell:
            variants[platform] = shell
    return variants


def _shell_of(container: Any) -> list[str]:
    if not isinstance(container, dict):
        return []
    options = container.get("options")
    if not isinstance(options, dict) or not isinstance(options.get("shell"), dict):
        return []
    shell = options["shell"]
    parts: list[str] = []
    if isinstance(shell.get("executable"), str):
        parts.append(shell["executable"])
    if isinstance(shell.get("args"), list):
        parts.extend(_arg_text(arg) for arg in shell["args"])
    return [part for part in parts if part]


def _arg_text(arg: Any) -> str:
    if isinstance(arg, str):
        return arg
    if isinstance(arg, dict) and isinstance(arg.get("value"), str):
        return arg["value"]
    if isinstance(arg, list):
        return " ".join(_arg_text(item) for item in arg)
    return ""


def _task_commands(
    task: jsonc.LineDict, global_shells: dict[str, list[str]]
) -> list[tuple[str, int | None]]:
    own_shells = _shell_variants(task)
    commands_found: list[tuple[str, int | None]] = []
    seen: set[str] = set()
    for platform in ("", "windows", "osx", "linux"):
        scope = task
        if platform:
            scope = task.get(platform)
            if not isinstance(scope, jsonc.LineDict):
                continue
        command = _command_text(scope.get("command"))
        offset = scope.offsets.get("command")
        args = scope.get("args")
        if command is None and platform:
            command = _command_text(task.get("command"))
            offset = task.offsets.get("command")
        if not isinstance(args, list):
            args = task.get("args")
        shell = own_shells.get(platform) or own_shells.get("") or global_shells.get(platform)
        if not shell:
            shell = global_shells.get("", [])
        if command is None and isinstance(task.get("script"), str):
            command = f"npm run {task['script']}"
            offset = task.offsets.get("script")
        if command is None:
            if platform or not shell:
                continue
            command = ""
        pieces = [*shell, command]
        if isinstance(args, list):
            pieces.extend(_arg_text(arg) for arg in args)
        text = " ".join(piece for piece in pieces if piece)
        if text and text not in seen:
            seen.add(text)
            if offset is None:
                offset = _first_offset(scope)
            commands_found.append((text, offset))
    return commands_found


def _first_offset(scope: jsonc.LineDict) -> int | None:
    for key in ("label", "type", "runOptions"):
        if key in scope.offsets:
            return scope.offsets[key]
    return None


def _codex_config(rel: str, text: str, result: FileResult) -> None:
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError) as exc:
        result.errors.append({"file": rel, "reason": f"could not parse: {exc}"})
        return
    servers = data.get("mcp_servers")
    if isinstance(servers, dict):
        for name, config in servers.items():
            if isinstance(config, dict):
                line = _toml_line(text, rf"^\s*\[\s*mcp_servers\.[\"']?{re.escape(str(name))}")
                server = _server(rel, str(name), config, line)
                if server is not None:
                    result.servers.append(server)
    providers = data.get("model_providers")
    if isinstance(providers, dict):
        for provider, config in providers.items():
            if not isinstance(config, dict) or not isinstance(config.get("base_url"), str):
                continue
            value = config["base_url"].strip()
            if value and not _official_endpoint("openai", value):
                line = _toml_line(
                    text, rf"^\s*\[\s*model_providers\.[\"']?{re.escape(str(provider))}"
                )
                result.env_overrides.append(
                    EnvOverride(rel, f"model_providers.{provider}.base_url", value, line)
                )


def _toml_line(text: str, pattern: str) -> int:
    match = re.search(pattern, text, re.MULTILINE)
    if match is None:
        return 1
    return text.count("\n", 0, match.start()) + 1


def _salvage(rel: str, role: str, text: str, result: FileResult, *, force: bool = False) -> None:
    if role not in _HOOK_ROLES:
        return
    if (
        role in {"vscode_tasks", "code_workspace"}
        and not force
        and "folderopen" not in text.lower()
    ):
        return
    agent, kind, event = _salvage_identity(role)
    for match in _SALVAGE_COMMAND.finditer(text):
        try:
            command = jsonc.parse(match.group(1)).value
        except jsonc.JsoncError:
            continue
        if isinstance(command, str) and command.strip():
            line = text.count("\n", 0, match.start(1)) + 1
            result.hooks.append(
                Hook(rel, kind, event, command, line, agent, False, {"unparsed": True})
            )


def _salvage_identity(role: str) -> tuple[str, str, str]:
    if role in {"vscode_tasks", "code_workspace"}:
        return "vscode", "vscode_task", "folderOpen"
    agent = role.split("_")[0]
    return agent, f"{agent}_hook", "unparsed"


def _findings_for(result: FileResult) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for hook in result.hooks:
        findings.append(_hook_finding(hook))
    for server in result.servers:
        findings.extend(_server_findings(server))
    for override in result.env_overrides:
        findings.append(_override_finding(override))
    for duplicate in result.duplicates:
        findings.append(_duplicate_finding(duplicate))
    return findings


def _duplicate_finding(duplicate: dict[str, Any]) -> dict[str, Any]:
    key = duplicate["key"]
    return _finding(
        "agent_config_ambiguous",
        "MEDIUM",
        "investigate",
        key,
        f"{duplicate['file']} defines {key} more than once",
        f"{key} appears at lines {duplicate['first_line']} and {duplicate['line']}. Agents and "
        f"editors keep the last value, so a reviewer reading the first one sees a different "
        f"command than the one that runs. Only the last value was checked.",
        "Remove the duplicate key so the file has one unambiguous value.",
        {"key": key, "first_line": duplicate["first_line"], "last_line": duplicate["line"]},
        duplicate["file"],
        duplicate["line"],
    )


def _finding(
    signal: str,
    severity: str,
    action: str,
    name: str,
    title: str,
    reason: str,
    remediation: str,
    evidence: dict[str, Any],
    file: str,
    line: int,
    ecosystem: str | None = None,
    version: str | None = None,
) -> dict[str, Any]:
    return {
        "signal_type": signal,
        "severity": severity,
        "action": action,
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "title": title,
        "reason": reason,
        "remediation": remediation,
        "evidence": evidence,
        "file": file,
        "line": line,
    }


def _hook_finding(hook: Hook) -> dict[str, Any]:
    traits = commands.classify(hook.command)
    shown = commands.display(hook.command)
    padded = hook.padded or traits["padded"]
    evidence: dict[str, Any] = {
        "kind": hook.kind,
        "event": hook.event,
        "command": commands.bounded(hook.command),
        "display_command": shown,
        "executable": traits["executable"],
        "script": traits["script"],
        "fetches_remote": traits["fetches_remote"],
        "decodes_and_executes": traits["decodes_and_executes"],
        "disguised_script": traits["disguised_script"],
        "hidden_by_padding": padded,
        **hook.extra,
    }
    dangers = []
    if traits["fetches_remote"]:
        dangers.append("downloads and runs remote code")
    if traits["decodes_and_executes"]:
        dangers.append("decodes and runs an encoded payload")
    if traits["disguised_script"]:
        dangers.append(f"runs {traits['disguised_script']}, a script disguised as a non-code file")
    severity = "HIGH"
    action = "investigate"
    if dangers:
        severity = "CRITICAL"
        action = "block"
    agent = _AGENT_NAMES.get(hook.agent, hook.agent)
    notes = ""
    if dangers:
        notes = " It " + "; ".join(dangers) + "."
    if padded:
        notes += " The entry is hidden behind long whitespace padding."
    if hook.extra.get("unparsed"):
        notes += " The file could not be parsed; this command was recovered from its text."
    if hook.extra.get("plugin"):
        source = hook.extra.get("marketplace") or "a marketplace"
        return _finding(
            "agent_hook_command",
            severity,
            action,
            hook.event,
            f"{agent} enables plugin {hook.extra['plugin']} from {source}",
            f"Plugins ship hooks, MCP servers and commands that {agent} runs for anyone who "
            f"trusts this folder; their code lives in {source}, not in this repository.{notes}",
            "Enable plugins in user settings after reviewing them, or pin the marketplace to a "
            "reviewed commit; keep committed settings free of plugins the team did not vet.",
            evidence,
            hook.file,
            hook.line,
        )
    if hook.kind == "vscode_task":
        label = hook.extra.get("label", "unnamed task")
        trigger = "runs on folder open"
        if hook.extra.get("via"):
            trigger = f"runs on folder open through dependsOn of '{hook.extra['via']}'"
        return _finding(
            "editor_folder_open_task",
            severity,
            action,
            str(label),
            f"VS Code task '{label}' {trigger}: {shown}",
            f"Opening this folder in VS Code or a fork (Cursor, Windsurf) runs this command "
            f"without a prompt once automatic tasks are allowed; Mini Shai-Hulud, Hades and "
            f"PolinRider used this to persist.{notes}",
            'Remove runOptions.runOn "folderOpen" (or the task) unless the team added it on '
            "purpose, and review the file it runs.",
            evidence,
            hook.file,
            hook.line,
        )
    return _finding(
        "agent_hook_command",
        severity,
        action,
        hook.event,
        f"{agent} {hook.event} runs a command: {shown}",
        f"{agent} runs this committed command automatically ({hook.event}) for anyone who "
        f"opens the repository with it; the Shai-Hulud lineage planted SessionStart hooks "
        f"this way.{notes}",
        "Keep agent hooks out of committed settings unless the team reviewed them; check the "
        "exact command and any script it runs.",
        evidence,
        hook.file,
        hook.line,
    )


def _launch(server: Server) -> dict[str, Any] | None:
    """The server's launch, unpinned when its env points the package manager at another
    registry or index (npm_config_registry, UV_INDEX_URL, PIP_INDEX_URL...)."""
    launch = parse_launch(server.argv[0], server.argv[1:])
    if launch is None or not launch["fetches"]:
        return launch
    values = [
        part
        for key, value in server.env.items()
        if key.upper() in _INDEX_ENV
        for part in str(value).split()
    ]
    found = [url for url in non_public_indexes(values) if url not in launch.get("indexes", [])]
    if found:
        launch = {
            **launch,
            "pinned": False,
            "pinned_command": None,
            "indexes": [*launch.get("indexes", []), *found],
        }
    return launch


def _remote_findings(server: Server) -> list[dict[str, Any]]:
    """A remote MCP server reached over cleartext http, or at a bare IP address with no
    host name a certificate could prove: whoever sits on the path serves the tools."""
    try:
        parsed = urlsplit(server.url or "")
        host = (parsed.hostname or "").lower()
    except ValueError:
        return []
    if not host:
        return []
    address = None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if host == "localhost" or host.endswith(".localhost") or (address and address.is_loopback):
        return []
    problems = []
    if parsed.scheme.lower() == "http":
        problems.append("over cleartext http")
    if address is not None:
        problems.append("at a bare IP address")
    if not problems:
        return []
    target = redact_url(server.url or "")
    return [
        _finding(
            "mcp_server_unpinned",
            "MEDIUM",
            "warn",
            server.name,
            f"Remote MCP server '{server.name}' is reached {' and '.join(problems)}: {target}",
            f"The agent loads tools from {target} {' and '.join(problems)}, so anyone on the "
            "network path, or whoever holds that address, decides which tools and "
            "instructions the agent receives.",
            "Use an https URL with a host name the server's certificate proves, or remove the "
            "server from committed settings.",
            {
                "server": server.name,
                "url": target,
                "transport": "http",
                "cleartext": parsed.scheme.lower() == "http",
                "bare_ip": address is not None,
            },
            server.file,
            server.line,
            "remote",
            None,
        )
    ]


def _server_findings(server: Server) -> list[dict[str, Any]]:
    if not server.argv:
        return _remote_findings(server)
    launch = _launch(server)
    if launch is None:
        return []
    shown = commands.display(" ".join(server.argv))
    base = {
        "server": server.name,
        "command": shown,
        "argv": [commands.bounded(part) for part in server.argv[:64]],
        "package": launch["package"],
        "launcher": launch["launcher"],
        "spec": launch["spec"],
        "source": launch["source"],
    }
    for key in ("indexes", "extra_packages"):
        if launch.get(key):
            base[key] = launch[key]
    findings: list[dict[str, Any]] = []
    hidden = _hidden_launch(server)
    if hidden is not None:
        path, where = hidden
        findings.append(
            _finding(
                "mcp_server_hidden_path",
                "HIGH",
                "block",
                server.name,
                f"MCP server '{server.name}' runs code from a {where}: {path}",
                f"The server launches {path}, which lives in a {where} outside the repository. "
                f"SANDWORM_MODE registered rogue MCP servers pointing at ~/.dev-utils/server.js "
                f"this way; nothing in the repository shows what that file does.",
                "Remove this server; committed configs should launch reviewed packages at exact "
                "versions, not files from hidden or temporary directories.",
                {**base, "path": path, "location": where},
                server.file,
                server.line,
                launch["ecosystem"],
                launch["version"],
            )
        )
    if launch["fetches"] and not launch["pinned"]:
        reason = (
            f"Each start fetches whatever {launch['package']} resolves to at that moment "
            f"({launch['launcher']}); postmark-mcp shipped fifteen clean versions before "
            f"1.0.16 started copying every email to the attacker."
        )
        loose = [item["package"] for item in launch.get("extra_packages", []) if not item["pinned"]]
        if launch.get("indexes"):
            reason = (
                f"Each start fetches {launch['package']} from {', '.join(launch['indexes'])}, "
                "not the public registry, so whoever runs that index decides which code runs, "
                "whatever version is pinned."
            )
        elif loose and launch["pinned"] is False and launch.get("version"):
            reason = (
                f"The launch also installs {', '.join(loose)} without an exact version; each "
                "start runs whatever those resolve to."
            )
        findings.append(
            _finding(
                "mcp_server_unpinned",
                "MEDIUM",
                "warn",
                server.name,
                f"MCP server '{server.name}' is not pinned: {shown}",
                reason,
                "Pin an exact, reviewed version (pkg@1.2.3, pkg==1.2.3, a full git commit or an "
                "image digest).",
                base,
                server.file,
                server.line,
                launch["ecosystem"],
                launch["version"],
            )
        )
    lookalike = impersonation.check(launch["ecosystem"], launch["package"])
    if lookalike is not None:
        findings.append(
            _finding(
                "mcp_server_impersonation",
                "MEDIUM",
                "investigate",
                server.name,
                f"MCP server package {launch['package']} looks like {lookalike['vendor']} but is "
                f"not published by it",
                f"'{lookalike['matched']}' in {launch['package']} points at "
                f"{lookalike['vendor']}, whose own packages come from {lookalike['expected']}; "
                f"SANDWORM_MODE (claud-code, cloude) and Hades (openai-mcp) used such names.",
                "Confirm the publisher and switch to the vendor's own package if one exists.",
                {**base, "vendor": lookalike["vendor"], "match": lookalike["reason"]},
                server.file,
                server.line,
                launch["ecosystem"],
                launch["version"],
            )
        )
    return findings


def _hidden_launch(server: Server) -> tuple[str, str] | None:
    return _hidden_in_argv(server.argv, server.cwd, server.env, 0)


def _hidden_in_argv(
    argv: list[str], cwd: str | None, env: dict[str, str], depth: int
) -> tuple[str, str] | None:
    if not argv or depth > 3:
        return None
    executable = argv[0]
    where = commands.hidden_location(executable)
    if where and not commands.toolchain_launcher(executable):
        return executable, where
    name = commands.basename(executable)
    if name in {"sh", "bash", "zsh", "dash", "cmd"} and len(argv) >= 3:
        inner = argv[2:]
        if len(inner) == 1:
            inner = commands.split_command(inner[0])
        found = _hidden_in_argv(inner, cwd, env, depth + 1)
        if found:
            return found
    for variable in _CODE_LOADING_ENV:
        for token in commands.split_command(env.get(variable, "")):
            where = commands.hidden_location(token)
            if where:
                return token, where
    launch = parse_launch(argv[0], argv[1:])
    if launch is None:
        return None
    candidates: list[str] = []
    if launch["source"] in {"local", "git", "url"}:
        candidates.append(str(launch["spec"]))
    for index, token in enumerate(argv[1:-1], start=1):
        if token in {"-r", "--require", "--import", "--loader", "--from", "--spec"}:
            candidates.append(argv[index + 1])
    for token in candidates:
        where = commands.hidden_location(token)
        if where:
            return token, where
    if cwd and launch["source"] in {"local", "installed"}:
        where = commands.hidden_location(cwd)
        if where:
            return cwd, where
    return None


def _override_finding(override: EnvOverride) -> dict[str, Any]:
    target = redact_url(override.value)
    return _finding(
        "agent_base_url_override",
        "HIGH",
        "investigate",
        override.variable,
        f"Committed agent settings send API traffic to {target}",
        f"{override.variable} in {override.file} redirects the agent's API requests, "
        f"including the API key header, to {target}. CVE-2026-21852 used a project-level "
        f"ANTHROPIC_BASE_URL to capture keys before the trust prompt.",
        "Remove the override from committed settings; set gateways in managed or user-level "
        "settings instead.",
        {"variable": override.variable, "target": target},
        override.file,
        override.line,
    )


def _add_inventory(inventory: dict[str, Any], result: FileResult) -> None:
    ambiguous = bool(result.duplicates)
    if ambiguous:
        inventory["duplicate_keys"] = True
        inventory["duplicates"].extend(result.duplicates)
    first_hook = len(inventory["hooks"])
    first_server = len(inventory["mcp_servers"])
    _add_entries(inventory, result)
    if ambiguous:
        for entry in inventory["hooks"][first_hook:] + inventory["mcp_servers"][first_server:]:
            entry["duplicate_keys"] = True


def _add_entries(inventory: dict[str, Any], result: FileResult) -> None:
    for hook in result.hooks:
        if len(inventory["hooks"]) >= MAX_ITEMS:
            inventory["truncated"] = True
            break
        entry = {
            "file": hook.file,
            "kind": hook.kind,
            "event": hook.event,
            "command": commands.bounded(hook.command),
            "line": hook.line,
        }
        for key in ("matcher", "label", "via", "handler_type"):
            if key in hook.extra:
                entry[key] = hook.extra[key]
        inventory["hooks"].append(entry)
    for server in result.servers:
        if len(inventory["mcp_servers"]) >= MAX_ITEMS:
            inventory["truncated"] = True
            break
        inventory["mcp_servers"].append(_server_inventory(server))
    for override in result.env_overrides:
        if len(inventory["env_overrides"]) >= MAX_ITEMS:
            inventory["truncated"] = True
            break
        inventory["env_overrides"].append(
            {
                "file": override.file,
                "variable": override.variable,
                "target": redact_url(override.value),
                "line": override.line,
            }
        )


def _server_inventory(server: Server) -> dict[str, Any]:
    if not server.argv:
        host = ""
        try:
            host = urlsplit(server.url or "").hostname or ""
        except ValueError:
            host = ""
        return {
            "file": server.file,
            "name": server.name,
            "command": "",
            "ecosystem": "remote",
            "package": host,
            "version": None,
            "pinned": False,
            "line": server.line,
            "url": redact_url(server.url or ""),
            "transport": "http",
            "fetches": False,
        }
    launch = _launch(server) or {}
    return {
        "file": server.file,
        "name": server.name,
        "command": commands.bounded(" ".join(server.argv)),
        "ecosystem": launch.get("ecosystem"),
        "package": launch.get("package"),
        "version": launch.get("version"),
        "pinned": bool(launch.get("pinned")),
        "line": server.line,
        "argv": [commands.bounded(part) for part in server.argv[:64]],
        "transport": "stdio",
        "fetches": bool(launch.get("fetches")),
        "launcher": launch.get("launcher"),
    }
