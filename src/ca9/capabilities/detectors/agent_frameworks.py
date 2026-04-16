from __future__ import annotations

import re
from pathlib import Path

from ca9.capabilities.models import Component, Property, generate_bom_ref

AGENT_FRAMEWORKS = {
    "langchain": {
        "import_patterns": [r"import\s+langchain", r"from\s+langchain\s+import"],
        "package_names": ["langchain", "langchain-core", "langchain-community"],
    },
    "llamaindex": {
        "import_patterns": [r"import\s+llama_index", r"from\s+llama_index\s+import"],
        "package_names": ["llama-index", "llama_index"],
    },
    "autogen": {
        "import_patterns": [r"import\s+autogen", r"from\s+autogen\s+import"],
        "package_names": ["pyautogen", "autogen"],
    },
    "crewai": {
        "import_patterns": [r"import\s+crewai", r"from\s+crewai\s+import"],
        "package_names": ["crewai"],
    },
    "semantic-kernel": {
        "import_patterns": [r"import\s+semantic_kernel", r"from\s+semantic_kernel\s+import"],
        "package_names": ["semantic-kernel"],
    },
    "haystack": {
        "import_patterns": [r"import\s+haystack", r"from\s+haystack\s+import"],
        "package_names": ["haystack-ai"],
    },
}

_SKIP_DIRS = {"node_modules", ".git", "venv", "__pycache__", "dist", "build"}


def detect_agent_frameworks(repo_path: Path) -> tuple[list[Component], list]:
    components: list[Component] = []

    code_files: list[Path] = []
    for pattern in ("*.py", "*.js", "*.ts", "*.jsx", "*.tsx"):
        code_files.extend(repo_path.rglob(pattern))

    detected_frameworks: set[str] = set()

    for code_file in code_files:
        if _SKIP_DIRS & set(code_file.parts):
            continue
        try:
            for framework, evidence in _detect_in_file(code_file, repo_path):
                if framework not in detected_frameworks:
                    detected_frameworks.add(framework)
                    components.append(_create_component(framework, evidence))
        except Exception:
            pass

    return components, []


def _detect_in_file(code_file: Path, repo_root: Path) -> list[tuple[str, str]]:
    detected: list[tuple[str, str]] = []
    try:
        content = code_file.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return detected

    rel_path = str(code_file.relative_to(repo_root))
    for framework, config in AGENT_FRAMEWORKS.items():
        for pattern in config["import_patterns"]:
            matches = list(re.finditer(pattern, content))
            if matches:
                line_num = content[: matches[0].start()].count("\n") + 1
                detected.append((framework, f"{rel_path}:{line_num}"))
                break

    return detected


def _create_component(framework: str, evidence: str) -> Component:
    bom_ref = generate_bom_ref("agent_framework", framework)
    properties = [
        Property(name="ca9.ai.asset.kind", value="agent_framework"),
        Property(name="ca9.agent.framework", value=framework),
        Property(name="ca9.location.file", value=evidence.split(":")[0]),
    ]
    return Component(
        type="library",
        name=f"agent-framework:{framework}",
        version="1",
        bom_ref=bom_ref,
        properties=properties,
    )
