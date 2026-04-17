from __future__ import annotations

import re
from pathlib import Path

from ca9.capabilities.models import Capability, Component, Property, generate_bom_ref

HTTP_PATTERNS = [
    r"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
    r"requests\.(get|post|put|delete|patch)\s*\(['\"]https?://([^'\"]+)",
    r"fetch\s*\(['\"]https?://([^'\"]+)",
    r"axios\.(get|post|put|delete|patch)\s*\(['\"]https?://([^'\"]+)",
    r"http\.get\(['\"]https?://([^'\"]+)",
    r"urllib\.request\.urlopen\(['\"]https?://([^'\"]+)",
]

INTERNAL_PATTERNS = [
    r"localhost",
    r"127\.0\.0\.1",
    r"0\.0\.0\.0",
    r".*\.local",
    r"example\.com",
    r"test\.com",
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}",
    r"192\.168\.\d{1,3}\.\d{1,3}",
]

_SKIP_DIRS = {"node_modules", ".git", "venv", "__pycache__", "dist", "build"}


def detect_egress(repo_path: Path) -> tuple[list[Component], list[Capability]]:
    components: list[Component] = []
    capabilities: list[Capability] = []

    code_files: list[Path] = []
    for pattern in ("*.py", "*.js", "*.ts", "*.jsx", "*.tsx", "*.go", "*.java"):
        code_files.extend(repo_path.rglob(pattern))

    detected_domains: set[str] = set()

    for code_file in code_files:
        if _SKIP_DIRS & set(code_file.parts):
            continue
        try:
            for domain, evidence in _detect_egress_in_file(code_file, repo_path):
                if domain not in detected_domains:
                    detected_domains.add(domain)
                    component, caps = _create_egress_component(domain, evidence)
                    components.append(component)
                    capabilities.extend(caps)
        except Exception:
            pass

    return components, capabilities


def _detect_egress_in_file(code_file: Path, repo_root: Path) -> list[tuple[str, str]]:
    detected: list[tuple[str, str]] = []
    try:
        content = code_file.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return detected

    rel_path = str(code_file.relative_to(repo_root))
    domains: set[str] = set()

    for pattern in HTTP_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            domain = match.group(match.lastindex if match.lastindex else 1)
            domain = domain.split("/")[0].split(":")[0]
            domains.add(domain)

    for domain in domains:
        if any(re.match(p, domain) for p in INTERNAL_PATTERNS):
            continue
        match = re.search(re.escape(domain), content)
        if match:
            line_num = content[: match.start()].count("\n") + 1
            detected.append((domain, f"{rel_path}:{line_num}"))

    return detected


def _create_egress_component(domain: str, evidence: str) -> tuple[Component, list[Capability]]:
    bom_ref = generate_bom_ref("egress_sink", domain)
    properties = [
        Property(name="ca9.ai.asset.kind", value="egress_sink"),
        Property(name="ca9.egress.domain", value=domain),
        Property(name="ca9.location.file", value=evidence.split(":")[0]),
    ]
    component = Component(
        type="service", name=f"egress:{domain}", version="1", bom_ref=bom_ref, properties=properties
    )
    capability = Capability(name="network.egress", scope=domain, asset=bom_ref, evidence=[evidence])
    return component, [capability]
