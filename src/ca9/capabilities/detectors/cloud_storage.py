from __future__ import annotations

import re
from pathlib import Path

from ca9.capabilities.models import Capability, Component, Property, generate_bom_ref

CLOUD_STORAGE = {
    "s3": {
        "patterns": [
            r"import\s+boto3",
            r"from\s+boto3\s+import",
            r"boto3\.client\(['\"]s3['\"]\)",
            r"boto3\.resource\(['\"]s3['\"]\)",
            r"s3_client\s*=",
            r"s3_resource\s*=",
        ],
        "write_patterns": [
            r"\.put_object\(",
            r"\.upload_file\(",
            r"\.upload_fileobj\(",
            r"\.copy\(",
        ],
        "read_patterns": [
            r"\.get_object\(",
            r"\.download_file\(",
            r"\.download_fileobj\(",
            r"\.list_objects",
        ],
        "capability_prefix": "storage.s3",
    },
    "gcs": {
        "patterns": [
            r"from\s+google\.cloud\s+import\s+storage",
            r"google\.cloud\.storage",
            r"storage\.Client\(",
            r"storage\.Bucket\(",
        ],
        "write_patterns": [r"\.upload_from", r"\.upload_blob", r"blob\.upload"],
        "read_patterns": [
            r"\.download_to",
            r"\.download_as",
            r"blob\.download",
            r"bucket\.list_blobs",
        ],
        "capability_prefix": "storage.gcs",
    },
    "azure_blob": {
        "patterns": [
            r"from\s+azure\.storage\.blob\s+import",
            r"azure\.storage\.blob",
            r"BlobServiceClient",
            r"ContainerClient",
            r"BlobClient",
        ],
        "write_patterns": [r"\.upload_blob\(", r"\.upload_data\(", r"\.create_blob\("],
        "read_patterns": [r"\.download_blob\(", r"\.download_to_stream\(", r"\.list_blobs\("],
        "capability_prefix": "storage.azure",
    },
}

_SKIP_DIRS = {"node_modules", ".git", "venv", "__pycache__", "dist", "build"}


def detect_cloud_storage(repo_path: Path) -> tuple[list[Component], list[Capability]]:
    components: list[Component] = []
    capabilities: list[Capability] = []

    code_files: list[Path] = []
    for pattern in ("*.py", "*.js", "*.ts", "*.jsx", "*.tsx", "*.go", "*.java"):
        code_files.extend(repo_path.rglob(pattern))

    detected: dict[tuple[str, bool, bool], str] = {}

    for code_file in code_files:
        if _SKIP_DIRS & set(code_file.parts):
            continue
        try:
            for provider, has_read, has_write, evidence in _detect_in_file(code_file, repo_path):
                key = (provider, has_read, has_write)
                if key not in detected:
                    detected[key] = evidence
                    component, caps = _create_component(provider, has_read, has_write, evidence)
                    components.append(component)
                    capabilities.extend(caps)
        except Exception:
            pass

    return components, capabilities


def _detect_in_file(code_file: Path, repo_root: Path) -> list[tuple[str, bool, bool, str]]:
    detected: list[tuple[str, bool, bool, str]] = []
    try:
        content = code_file.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return detected

    rel_path = str(code_file.relative_to(repo_root))

    for provider, config in CLOUD_STORAGE.items():
        provider_found = False
        evidence_line = 0
        for pattern in config["patterns"]:
            matches = list(re.finditer(pattern, content))
            if matches:
                provider_found = True
                evidence_line = content[: matches[0].start()].count("\n") + 1
                break

        if not provider_found:
            continue

        has_read = any(re.search(p, content) for p in config["read_patterns"])
        has_write = any(re.search(p, content) for p in config["write_patterns"])
        if not has_read and not has_write:
            has_read = True
            has_write = True

        detected.append((provider, has_read, has_write, f"{rel_path}:{evidence_line}"))

    return detected


def _create_component(
    provider: str, has_read: bool, has_write: bool, evidence: str
) -> tuple[Component, list[Capability]]:
    bom_ref = generate_bom_ref("cloud_storage", provider)
    properties = [
        Property(name="ca9.ai.asset.kind", value="cloud_storage"),
        Property(name="ca9.cloud.provider", value=provider),
        Property(name="ca9.location.file", value=evidence.split(":")[0]),
    ]
    component = Component(
        type="service",
        name=f"cloud-storage:{provider}",
        version="1",
        bom_ref=bom_ref,
        properties=properties,
    )

    capabilities: list[Capability] = []
    cap_prefix = CLOUD_STORAGE[provider]["capability_prefix"]
    if has_read:
        capabilities.append(
            Capability(name=f"{cap_prefix}.read", scope="*", asset=bom_ref, evidence=[evidence])
        )
    if has_write:
        capabilities.append(
            Capability(name=f"{cap_prefix}.write", scope="*", asset=bom_ref, evidence=[evidence])
        )

    return component, capabilities
