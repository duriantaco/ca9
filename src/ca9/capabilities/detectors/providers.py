from __future__ import annotations

import re
from pathlib import Path

from ca9.capabilities.models import Capability, Component, Property, generate_bom_ref

LLM_PROVIDERS = {
    "openai": {
        "domains": ["api.openai.com", "openai.azure.com"],
        "import_patterns": [r"import\s+openai", r"from\s+openai\s+import", r"OpenAI\("],
        "package_names": ["openai"],
    },
    "anthropic": {
        "domains": ["api.anthropic.com"],
        "import_patterns": [r"import\s+anthropic", r"from\s+anthropic\s+import", r"Anthropic\("],
        "package_names": ["anthropic"],
    },
    "bedrock": {
        "domains": ["bedrock-runtime.*.amazonaws.com"],
        "import_patterns": [r"boto3.*bedrock", r"bedrock-runtime"],
        "package_names": ["boto3"],
    },
    "azure": {
        "domains": ["openai.azure.com", "*.openai.azure.com"],
        "import_patterns": [r"AzureOpenAI\(", r"azure.*openai"],
        "package_names": [],
    },
    "cohere": {
        "domains": ["api.cohere.ai"],
        "import_patterns": [r"import\s+cohere", r"from\s+cohere\s+import"],
        "package_names": ["cohere"],
    },
}

_SKIP_DIRS = {"node_modules", ".git", "venv", "__pycache__", "dist", "build"}


def detect_providers(repo_path: Path) -> tuple[list[Component], list[Capability]]:
    components: list[Component] = []
    capabilities: list[Capability] = []

    code_files: list[Path] = []
    for pattern in ("*.py", "*.js", "*.ts", "*.jsx", "*.tsx", "*.go", "*.java"):
        code_files.extend(repo_path.rglob(pattern))

    detected: set[tuple[str, str]] = set()

    for code_file in code_files:
        if _SKIP_DIRS & set(code_file.parts):
            continue
        try:
            for provider, domain, evidence in _detect_providers_in_file(code_file, repo_path):
                key = (provider, domain)
                if key not in detected:
                    detected.add(key)
                    component, caps = _create_provider_component(provider, domain, evidence)
                    components.append(component)
                    capabilities.extend(caps)
        except Exception:
            pass

    return components, capabilities


def _detect_providers_in_file(code_file: Path, repo_root: Path) -> list[tuple[str, str, str]]:
    detected: list[tuple[str, str, str]] = []
    try:
        content = code_file.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return detected

    rel_path = str(code_file.relative_to(repo_root))

    for provider, config in LLM_PROVIDERS.items():
        for pattern in config["import_patterns"]:
            matches = list(re.finditer(pattern, content))
            if matches:
                line_num = content[: matches[0].start()].count("\n") + 1
                evidence = f"{rel_path}:{line_num}"
                domain = None
                for dom in config["domains"]:
                    if dom in content:
                        domain = dom
                        break
                if not domain:
                    domain = config["domains"][0] if config["domains"] else "unknown"
                detected.append((provider, domain, evidence))
                break

        for domain in config["domains"]:
            if "*" not in domain and domain in content:
                match = re.search(re.escape(domain), content)
                if match:
                    line_num = content[: match.start()].count("\n") + 1
                    evidence = f"{rel_path}:{line_num}"
                    detected.append((provider, domain, evidence))
                    break

    return detected


def _create_provider_component(
    provider: str, domain: str, evidence: str
) -> tuple[Component, list[Capability]]:
    bom_ref = generate_bom_ref("llm_provider", provider, domain)
    properties = [
        Property(name="ca9.ai.asset.kind", value="llm_provider"),
        Property(name="ca9.llm.provider", value=provider),
        Property(name="ca9.llm.endpoint", value=domain),
        Property(name="ca9.location.file", value=evidence.split(":")[0]),
    ]
    component = Component(
        type="service",
        name=f"llm-provider:{provider}:{domain}",
        version="1",
        bom_ref=bom_ref,
        properties=properties,
    )
    capability = Capability(name="network.egress", scope=domain, asset=bom_ref, evidence=[evidence])
    return component, [capability]
