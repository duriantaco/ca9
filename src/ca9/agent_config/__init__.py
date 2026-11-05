"""Agent and editor execution hooks, MCP server configs and API base-URL overrides.

``scan_repository(root)`` backs ``ca9.api.agent_config``; ``analyze_text`` and
``is_agent_config_path`` let package review apply the same checks to files a
package ships.
"""

from ca9.agent_config.mcp_launch import parse_launch
from ca9.agent_config.scanner import SCHEMA, analyze_text, is_agent_config_path, scan_repository

__all__ = ["SCHEMA", "analyze_text", "is_agent_config_path", "parse_launch", "scan_repository"]
