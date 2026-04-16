from __future__ import annotations

import re
from pathlib import Path

from ca9.capabilities.models import Capability, Component, Property, generate_bom_ref

TOOL_PATTERNS = {
    "langchain": {
        "decorators": [
            r"@tool\s*(?:\(.*?\))?\s*\n\s*def\s+(\w+)",
            r"@langchain_tool\s*(?:\(.*?\))?\s*\n\s*def\s+(\w+)",
        ],
        "classes": [r"class\s+(\w+)\(.*BaseTool", r"class\s+(\w+)\(.*StructuredTool"],
        "registrations": [
            r"Tool\s*\(\s*name\s*=\s*['\"](\w+)['\"]",
            r"StructuredTool\.from_function\s*\(\s*(\w+)",
        ],
    },
    "crewai": {
        "decorators": [r"@crewai\.tool\s*(?:\(.*?\))?\s*\n\s*def\s+(\w+)"],
        "classes": [r"class\s+(\w+)\(.*CrewAITool"],
        "registrations": [r"Tool\s*\(\s*name\s*=\s*['\"](\w+)['\"]"],
    },
    "autogen": {
        "decorators": [],
        "registrations": [
            r"register_function\s*\(\s*name\s*=\s*['\"](\w+)['\"]",
            r"register_for_execution\s*\(\s*name\s*=\s*['\"](\w+)['\"]",
            r"register_for_llm\s*\(\s*name\s*=\s*['\"](\w+)['\"]",
        ],
    },
    "semantic_kernel": {
        "decorators": [
            r"@kernel_function\s*(?:\(.*?\))?\s*\n\s*def\s+(\w+)",
            r"@sk_function\s*(?:\(.*?\))?\s*\n\s*def\s+(\w+)",
        ],
        "registrations": [r"kernel\.import_function\s*\(\s*['\"](\w+)['\"]"],
    },
}

_SKIP_DIRS = {"node_modules", ".git", "venv", "__pycache__", "dist", "build"}


def detect_agent_tools(repo_path: Path) -> tuple[list[Component], list[Capability]]:
    components: list[Component] = []
    capabilities: list[Capability] = []

    detected_tools: dict[tuple[str, str], tuple[str, list[str]]] = {}

    for code_file in repo_path.rglob("*.py"):
        if _SKIP_DIRS & set(code_file.parts):
            continue
        try:
            for tool_name, framework, evidence, caps_list in _detect_in_file(code_file, repo_path):
                key = (tool_name, framework)
                if key not in detected_tools:
                    detected_tools[key] = (evidence, caps_list)
                    component, caps = _create_component(tool_name, framework, evidence, caps_list)
                    components.append(component)
                    capabilities.extend(caps)
        except Exception:
            pass

    return components, capabilities


def _detect_in_file(code_file: Path, repo_root: Path) -> list[tuple[str, str, str, list[str]]]:
    detected: list[tuple[str, str, str, list[str]]] = []
    try:
        content = code_file.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return detected

    rel_path = str(code_file.relative_to(repo_root))

    for framework, patterns in TOOL_PATTERNS.items():
        for pattern in patterns.get("decorators", []):
            for match in re.finditer(pattern, content):
                tool_name = match.group(1)
                line_num = content[: match.start()].count("\n") + 1
                caps = _infer_capabilities(content, tool_name, match.start())
                detected.append((tool_name, framework, f"{rel_path}:{line_num}", caps))

        for pattern in patterns.get("classes", []):
            for match in re.finditer(pattern, content):
                tool_name = match.group(1)
                line_num = content[: match.start()].count("\n") + 1
                caps = _infer_capabilities(content, tool_name, match.start())
                detected.append((tool_name, framework, f"{rel_path}:{line_num}", caps))

        for pattern in patterns.get("registrations", []):
            for match in re.finditer(pattern, content):
                tool_name = match.group(1)
                line_num = content[: match.start()].count("\n") + 1
                caps = _infer_capabilities(content, tool_name, match.start())
                detected.append((tool_name, framework, f"{rel_path}:{line_num}", caps))

    has_crewai_import = bool(re.search(r"(?:from\s+crewai|import\s+crewai)", content))
    if has_crewai_import:
        reattributed: list[tuple[str, str, str, list[str]]] = []
        for tool_name, framework, evidence, caps in detected:
            if framework == "langchain" and not re.search(
                r"(?:from\s+langchain|import\s+langchain)", content
            ):
                reattributed.append((tool_name, "crewai", evidence, caps))
            else:
                reattributed.append((tool_name, framework, evidence, caps))
        detected = reattributed

    return detected


def _infer_capabilities(content: str, tool_name: str, start_pos: int) -> list[str]:
    capabilities: list[str] = []

    context_start = max(0, start_pos - 500)
    context_end = min(len(content), start_pos + 1000)
    context = content[context_start:context_end].lower()
    tool_lower = tool_name.lower()

    if any(
        kw in tool_lower for kw in ("file", "read", "write", "save", "load", "directory", "path")
    ):
        if "write" in tool_lower or "save" in tool_lower:
            capabilities.append("filesystem.write")
        if "read" in tool_lower or "load" in tool_lower:
            capabilities.append("filesystem.read")

    if any(kw in context for kw in ("open(", "pathlib", "os.path", "shutil")):
        capabilities.append("filesystem.read")

    if any(kw in tool_lower for kw in ("shell", "exec", "command", "run", "subprocess", "bash")):
        capabilities.append("exec.shell")
    if any(kw in context for kw in ("subprocess", "os.system", "exec(", "popen")):
        capabilities.append("exec.shell")

    if any(kw in tool_lower for kw in ("http", "api", "fetch", "request", "web", "url")):
        capabilities.append("network.egress")
    if any(kw in context for kw in ("requests.", "urllib.", "http", "fetch(")):
        capabilities.append("network.egress")

    if any(kw in tool_lower for kw in ("db", "database", "sql", "query")):
        if "write" in tool_lower or "insert" in tool_lower:
            capabilities.append("db.write")
        else:
            capabilities.append("db.read")
    if any(kw in context for kw in ("cursor.", "execute(", "query(", "insert ")):
        capabilities.append("db.read")

    return capabilities or ["tool.unknown"]


def _create_component(
    tool_name: str, framework: str, evidence: str, capabilities_list: list[str]
) -> tuple[Component, list[Capability]]:
    bom_ref = generate_bom_ref("agent_tool", framework, tool_name)
    properties = [
        Property(name="ca9.ai.asset.kind", value="agent_tool"),
        Property(name="ca9.agent.framework", value=framework),
        Property(name="ca9.agent.tool.name", value=tool_name),
        Property(name="ca9.location.file", value=evidence.split(":")[0]),
    ]
    component = Component(
        type="library",
        name=f"agent-tool:{framework}:{tool_name}",
        version="1",
        bom_ref=bom_ref,
        properties=properties,
    )

    capabilities: list[Capability] = []
    for cap_name in set(capabilities_list):
        if cap_name != "tool.unknown":
            capabilities.append(
                Capability(name=cap_name, scope="*", asset=bom_ref, evidence=[evidence])
            )

    return component, capabilities
