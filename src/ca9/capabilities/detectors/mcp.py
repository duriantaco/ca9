from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ca9.capabilities.models import Capability, Component, Property, generate_bom_ref, hash_content

_YAML_AVAILABLE = True
try:
    import yaml
except ImportError:
    _YAML_AVAILABLE = False


def detect_mcp(repo_path: Path) -> tuple[list[Component], list[Capability]]:
    components: list[Component] = []
    capabilities: list[Capability] = []

    config_files: list[Path] = []
    for pattern in ["mcp.json", "mcp.yaml", "mcp.yml", "servers.json"]:
        config_files.extend(repo_path.rglob(pattern))

    mcp_dir = repo_path / ".mcp"
    if mcp_dir.exists():
        config_files.extend(mcp_dir.rglob("*.json"))
        config_files.extend(mcp_dir.rglob("*.yaml"))
        config_files.extend(mcp_dir.rglob("*.yml"))

    for config_file in config_files:
        try:
            mcp_components, mcp_capabilities = parse_mcp_config(config_file, repo_path)
            components.extend(mcp_components)
            capabilities.extend(mcp_capabilities)
        except Exception:
            pass

    return components, capabilities


def parse_mcp_config(
    config_path: Path, repo_root: Path
) -> tuple[list[Component], list[Capability]]:
    components: list[Component] = []
    capabilities: list[Capability] = []

    with open(config_path) as f:
        if config_path.suffix in (".yaml", ".yml"):
            if not _YAML_AVAILABLE:
                return components, capabilities
            config = yaml.safe_load(f)
        else:
            config = json.load(f)

    if not config:
        return components, capabilities

    rel_path = config_path.relative_to(repo_root)
    evidence_prefix = str(rel_path)

    with open(config_path) as f:
        content_hash = hash_content(f.read())

    servers = config.get("servers", config.get("mcpServers", {}))

    if isinstance(servers, dict):
        for server_name, server_config in servers.items():
            server_component, server_capabilities = parse_mcp_server(
                server_name, server_config, evidence_prefix, content_hash
            )
            if server_component:
                components.append(server_component)
                capabilities.extend(server_capabilities)

    if "tools" in config:
        server_name = config.get("name", config_path.stem)
        server_component, server_capabilities = parse_mcp_server(
            server_name, config, evidence_prefix, content_hash
        )
        if server_component:
            components.append(server_component)
            capabilities.extend(server_capabilities)

    return components, capabilities


def parse_mcp_server(
    server_name: str,
    server_config: dict[str, Any],
    evidence_prefix: str,
    content_hash: str,
) -> tuple[Component, list[Capability]]:
    capabilities: list[Capability] = []

    bom_ref = generate_bom_ref("mcp_server", server_name)
    properties = [
        Property(name="ca9.ai.asset.kind", value="mcp_server"),
        Property(name="ca9.mcp.server.name", value=server_name),
        Property(name="ca9.location.file", value=evidence_prefix),
        Property(name="ca9.hash.content", value=f"sha256:{content_hash}"),
    ]

    command = server_config.get("command", "")
    url = server_config.get("url", "")
    if url:
        properties.append(Property(name="ca9.mcp.transport", value="http"))
    elif command:
        properties.append(Property(name="ca9.mcp.transport", value="stdio"))

    component = Component(
        type="service",
        name=f"mcp-server:{server_name}",
        version="1",
        bom_ref=bom_ref,
        properties=properties,
    )

    if is_filesystem_server(server_name, server_config):
        capabilities.extend(
            extract_filesystem_capabilities(server_name, server_config, bom_ref, evidence_prefix)
        )

    if has_shell_exec(server_name, server_config):
        capabilities.append(
            Capability(
                name="exec.shell", scope="*", asset=bom_ref, evidence=[f"{evidence_prefix}:1"]
            )
        )

    if has_database_tools(server_name, server_config):
        tools = server_config.get("tools", [])
        for tool in tools:
            tool_name = tool if isinstance(tool, str) else tool.get("name", "")
            tool_lower = tool_name.lower()
            if "read" in tool_lower or "query" in tool_lower:
                capabilities.append(
                    Capability(
                        name="db.read", scope="*", asset=bom_ref, evidence=[f"{evidence_prefix}:1"]
                    )
                )
            if any(kw in tool_lower for kw in ("write", "insert", "update")):
                capabilities.append(
                    Capability(
                        name="db.write", scope="*", asset=bom_ref, evidence=[f"{evidence_prefix}:1"]
                    )
                )

    if has_network_tools(server_name, server_config):
        capabilities.append(
            Capability(
                name="network.egress", scope="*", asset=bom_ref, evidence=[f"{evidence_prefix}:1"]
            )
        )

    return component, capabilities


def is_filesystem_server(server_name: str, config: dict[str, Any]) -> bool:
    name_lower = server_name.lower()
    if any(kw in name_lower for kw in ("filesystem", "file", "fs", "directory", "storage")):
        return True

    command = config.get("command", "").lower()
    desc = config.get("description", "").lower()
    if "filesystem" in command or "filesystem" in desc:
        return True

    for tool in config.get("tools", []):
        tool_name = (tool if isinstance(tool, str) else tool.get("name", "")).lower()
        if any(
            kw in tool_name
            for kw in ("read_file", "write_file", "list_directory", "create_directory")
        ):
            return True

    return False


def extract_filesystem_capabilities(
    server_name: str, config: dict[str, Any], bom_ref: str, evidence_prefix: str
) -> list[Capability]:
    capabilities: list[Capability] = []

    allowed_roots = config.get("allowedRoots", config.get("roots", config.get("paths", [])))
    if allowed_roots:
        scopes = [root if root.endswith("/**") else f"{root}/**" for root in allowed_roots]
    else:
        scopes = ["/**"]

    is_read_only = config.get("readOnly", False)
    has_read = True
    has_write = not is_read_only

    for tool in config.get("tools", []):
        tool_name = (tool if isinstance(tool, str) else tool.get("name", "")).lower()
        if any(kw in tool_name for kw in ("read", "list", "get")):
            has_read = True
        if any(kw in tool_name for kw in ("write", "create", "delete", "update", "modify", "edit")):
            has_write = True

    for scope in scopes:
        if has_read:
            capabilities.append(
                Capability(
                    name="filesystem.read",
                    scope=scope,
                    asset=bom_ref,
                    evidence=[f"{evidence_prefix}:1"],
                )
            )
        if has_write:
            capabilities.append(
                Capability(
                    name="filesystem.write",
                    scope=scope,
                    asset=bom_ref,
                    evidence=[f"{evidence_prefix}:1"],
                )
            )

    return capabilities


def has_shell_exec(server_name: str, config: dict[str, Any]) -> bool:
    if any(kw in server_name.lower() for kw in ("shell", "exec", "command", "bash", "terminal")):
        return True
    for tool in config.get("tools", []):
        tool_name = (tool if isinstance(tool, str) else tool.get("name", "")).lower()
        if any(kw in tool_name for kw in ("exec", "shell", "command", "run", "bash")):
            return True
    return False


def has_database_tools(server_name: str, config: dict[str, Any]) -> bool:
    if any(
        kw in server_name.lower()
        for kw in ("database", "db", "sql", "postgres", "mysql", "mongo", "redis")
    ):
        return True
    for tool in config.get("tools", []):
        tool_name = (tool if isinstance(tool, str) else tool.get("name", "")).lower()
        if any(kw in tool_name for kw in ("query", "sql", "db", "database")):
            return True
    return False


def has_network_tools(server_name: str, config: dict[str, Any]) -> bool:
    if any(
        kw in server_name.lower() for kw in ("network", "http", "fetch", "request", "api", "web")
    ):
        return True
    for tool in config.get("tools", []):
        tool_name = (tool if isinstance(tool, str) else tool.get("name", "")).lower()
        if any(kw in tool_name for kw in ("fetch", "http", "request", "api", "web", "curl")):
            return True
    return False
