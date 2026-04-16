from __future__ import annotations

import contextlib
import re
from pathlib import Path

from ca9.capabilities.models import (
    Component,
    Property,
    generate_bom_ref,
    hash_content,
    hash_content_short,
)

RISK_PATTERNS = [
    r"ignore\s+previous",
    r"bypass\s+safety",
    r"exfiltrate",
    r"reveal\s+secrets",
]

_SKIP_DIRS = {"node_modules", ".git", "venv", "__pycache__", "dist", "build"}


def detect_prompts(repo_path: Path) -> tuple[list[Component], list]:
    components: list[Component] = []

    components.extend(_detect_prompt_files(repo_path))
    components.extend(_detect_inline_prompts(repo_path))

    return components, []


def _detect_prompt_files(repo_path: Path) -> list[Component]:
    components: list[Component] = []

    extensions = [".prompt", ".jinja", ".jinja2", ".md"]
    priority_dirs = ["prompts", "agents", "system", ".prompts"]

    prompt_files: list[Path] = []
    for dir_name in priority_dirs:
        for ext in extensions:
            prompt_files.extend(repo_path.rglob(f"{dir_name}/**/*{ext}"))

    for ext in (".prompt", ".jinja", ".jinja2"):
        prompt_files.extend(repo_path.rglob(f"*{ext}"))

    prompt_files = list(set(prompt_files))

    for prompt_file in prompt_files:
        if _SKIP_DIRS & set(prompt_file.parts):
            continue
        try:
            component = _parse_prompt_file(prompt_file, repo_path)
            if component:
                components.append(component)
        except Exception:
            pass

    return components


def _parse_prompt_file(prompt_file: Path, repo_root: Path) -> Component:
    rel_path = str(prompt_file.relative_to(repo_root))
    content = prompt_file.read_text(encoding="utf-8", errors="ignore")
    content_hash_val = hash_content(content)
    prompt_type = _determine_prompt_type(prompt_file.name, content)
    bom_ref = generate_bom_ref("prompt", "file", rel_path)

    properties = [
        Property(name="ca9.ai.asset.kind", value="prompt"),
        Property(name="ca9.ai.prompt.type", value=prompt_type),
        Property(name="ca9.ai.prompt.source", value="file"),
        Property(name="ca9.location.file", value=rel_path),
        Property(name="ca9.location.line_start", value="1"),
        Property(name="ca9.hash.content", value=f"sha256:{content_hash_val}"),
    ]

    risk_signals = _detect_risk_signals(content)
    if risk_signals:
        properties.append(Property(name="ca9.ai.prompt.risk_signals", value=",".join(risk_signals)))

    return Component(
        type="data", name=f"prompt:{rel_path}", version="1", bom_ref=bom_ref, properties=properties
    )


def _detect_inline_prompts(repo_path: Path) -> list[Component]:
    components: list[Component] = []

    code_files: list[Path] = []
    for pattern in ("*.py", "*.js", "*.ts", "*.jsx", "*.tsx"):
        code_files.extend(repo_path.rglob(pattern))

    for code_file in code_files:
        if _SKIP_DIRS & set(code_file.parts):
            continue
        with contextlib.suppress(Exception):
            components.extend(_parse_inline_prompts(code_file, repo_path))

    return components


def _parse_inline_prompts(code_file: Path, repo_root: Path) -> list[Component]:
    components: list[Component] = []
    try:
        content = code_file.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return components

    rel_path = str(code_file.relative_to(repo_root))

    python_pattern = r'("""|\'\'\')(.+?)\1'
    js_pattern = r"`(.+?)`"
    patterns = [python_pattern, js_pattern] if code_file.suffix == ".py" else [js_pattern]

    llm_keywords = [
        "system",
        "developer",
        "instructions",
        "prompt",
        "openai",
        "anthropic",
        "llm",
        "chatgpt",
        "claude",
        "gpt",
        "completion",
        "generate",
    ]

    for pattern in patterns:
        for match in re.finditer(pattern, content, re.DOTALL):
            prompt_content = (
                match.group(2)
                if "?" in pattern and match.lastindex and match.lastindex >= 2
                else match.group(1)
            )

            if len(prompt_content) < 200:
                continue

            context_start = max(0, match.start() - 500)
            context_end = min(len(content), match.end() + 500)
            context = content[context_start:context_end].lower()

            if not any(kw in context for kw in llm_keywords):
                continue

            line_num = content[: match.start()].count("\n") + 1
            prompt_type = "unknown"
            if any(kw in context for kw in ("system", "system_prompt")):
                prompt_type = "system"
            elif any(kw in context for kw in ("developer", "developer_prompt")):
                prompt_type = "developer"
            elif any(kw in context for kw in ("user", "user_prompt")):
                prompt_type = "user"

            content_hash_val = hash_content(prompt_content)
            hash_short = hash_content_short(prompt_content, 12)
            bom_ref = generate_bom_ref("prompt", "inline", rel_path, str(line_num), hash_short)

            properties = [
                Property(name="ca9.ai.asset.kind", value="prompt"),
                Property(name="ca9.ai.prompt.type", value=prompt_type),
                Property(name="ca9.ai.prompt.source", value="inline"),
                Property(name="ca9.location.file", value=rel_path),
                Property(name="ca9.location.line_start", value=str(line_num)),
                Property(name="ca9.hash.content", value=f"sha256:{content_hash_val}"),
            ]

            risk_signals = _detect_risk_signals(prompt_content)
            if risk_signals:
                properties.append(
                    Property(name="ca9.ai.prompt.risk_signals", value=",".join(risk_signals))
                )

            components.append(
                Component(
                    type="data",
                    name=f"prompt:{rel_path}:{line_num}",
                    version="1",
                    bom_ref=bom_ref,
                    properties=properties,
                )
            )

    return components


def _determine_prompt_type(filename: str, content: str) -> str:
    filename_lower = filename.lower()
    content_lower = content.lower()
    if "system" in filename_lower or "system_prompt" in content_lower[:500]:
        return "system"
    if "developer" in filename_lower or "developer_prompt" in content_lower[:500]:
        return "developer"
    if "user" in filename_lower or "user_prompt" in content_lower[:500]:
        return "user"
    return "unknown"


def _detect_risk_signals(content: str) -> list[str]:
    signals: list[str] = []
    content_lower = content.lower()
    for pattern in RISK_PATTERNS:
        if re.search(pattern, content_lower):
            signals.append(pattern.replace(r"\s+", " ").replace("\\", ""))
    return signals
