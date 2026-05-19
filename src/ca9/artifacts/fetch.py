from __future__ import annotations

import base64
import binascii
import hashlib
import os
import shutil
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from ca9.artifacts.model import ArtifactSnapshot
from ca9.artifacts.unpack import UnpackConfig, unpack_artifact
from ca9.core.models import (
    Artifact,
    Evidence,
    Finding,
    Inventory,
    Package,
    RiskSignal,
    SourceEvidence,
)

DEFAULT_ARTIFACT_CACHE_DIR = Path(
    os.environ.get("CA9_ARTIFACT_CACHE_DIR", Path.home() / ".cache" / "ca9" / "artifacts")
)
DEFAULT_MAX_ARTIFACT_BYTES = 100 * 1024 * 1024
DEFAULT_MAX_EXTRACTED_BYTES = 250 * 1024 * 1024
DEFAULT_MAX_EXTRACTED_FILES = 5000
HASH_STRENGTH = {
    "md5": 0,
    "sha1": 1,
    "sha224": 2,
    "sha256": 3,
    "sha384": 4,
    "sha512": 5,
}


@dataclass(frozen=True)
class ArtifactScanConfig:
    cache_dir: Path = DEFAULT_ARTIFACT_CACHE_DIR
    allow_unhashed_downloads: bool = False
    max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES
    max_extracted_bytes: int = DEFAULT_MAX_EXTRACTED_BYTES
    max_extracted_files: int = DEFAULT_MAX_EXTRACTED_FILES


@dataclass(frozen=True)
class ArtifactCollectionResult:
    snapshots: tuple[ArtifactSnapshot, ...] = ()
    findings: tuple[Finding, ...] = ()
    warnings: tuple[str, ...] = ()
    scanned_artifacts: int = 0
    skipped_artifacts: int = 0


@dataclass
class _CollectionState:
    snapshots: list[ArtifactSnapshot] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    scanned_artifacts: int = 0
    skipped_artifacts: int = 0


def collect_artifact_snapshots(
    inventory: Inventory,
    config: ArtifactScanConfig | None = None,
) -> ArtifactCollectionResult:
    active_config = config or ArtifactScanConfig()
    state = _CollectionState()

    for package in inventory.packages:
        for artifact in package.artifacts:
            if artifact.kind not in {"wheel", "sdist", "npm-tarball"}:
                continue
            _collect_one(package, artifact, active_config, state)

    return ArtifactCollectionResult(
        snapshots=tuple(state.snapshots),
        findings=tuple(state.findings),
        warnings=tuple(state.warnings),
        scanned_artifacts=state.scanned_artifacts,
        skipped_artifacts=state.skipped_artifacts,
    )


def _collect_one(
    package: Package,
    artifact: Artifact,
    config: ArtifactScanConfig,
    state: _CollectionState,
) -> None:
    if not artifact.url:
        state.skipped_artifacts += 1
        state.warnings.append(f"skipped {package.key} {artifact.kind}: artifact has no URL")
        return

    if not artifact.hash and not config.allow_unhashed_downloads:
        state.skipped_artifacts += 1
        state.warnings.append(
            f"skipped {package.key} {artifact.kind}: artifact has no hash; "
            "pass --allow-unhashed-downloads to scan it"
        )
        return

    archive_path = _cache_path(package, artifact, config)
    try:
        _fetch_to_cache(artifact, archive_path, config)
    except ValueError as exc:
        state.skipped_artifacts += 1
        state.findings.append(
            _artifact_finding(
                package,
                artifact,
                signal_type="artifact_fetch_error",
                title=f"Could not fetch artifact for {package.name}",
                severity="medium",
                action="investigate",
                reason=str(exc),
            )
        )
        return

    if artifact.hash:
        hash_ok, reason = _verify_hash(archive_path, artifact.hash)
        if not hash_ok:
            state.skipped_artifacts += 1
            state.findings.append(
                _artifact_finding(
                    package,
                    artifact,
                    signal_type="artifact_hash_mismatch",
                    title=f"Artifact hash mismatch for {package.name}",
                    severity="critical",
                    action="block",
                    reason=reason,
                )
            )
            return

    unpack_dir = _unpack_dir(package, artifact, config)
    try:
        snapshot = unpack_artifact(
            package,
            artifact,
            archive_path,
            unpack_dir,
            UnpackConfig(
                max_files=config.max_extracted_files,
                max_total_bytes=config.max_extracted_bytes,
            ),
        )
    except ValueError as exc:
        state.skipped_artifacts += 1
        state.findings.append(
            _artifact_finding(
                package,
                artifact,
                signal_type="artifact_unpack_error",
                title=f"Unsafe or invalid artifact for {package.name}",
                severity="critical",
                action="block",
                reason=str(exc),
            )
        )
        return

    state.snapshots.append(snapshot)
    state.scanned_artifacts += 1


def _fetch_to_cache(artifact: Artifact, archive_path: Path, config: ArtifactScanConfig) -> None:
    if archive_path.is_file():
        if archive_path.stat().st_size <= config.max_artifact_bytes:
            return
        archive_path.unlink(missing_ok=True)

    archive_path.parent.mkdir(parents=True, exist_ok=True)
    source_path = _local_artifact_path(artifact.url or "")
    if source_path is not None:
        _copy_local_artifact(source_path, archive_path, config.max_artifact_bytes)
        return

    _download_artifact(artifact.url or "", archive_path, config.max_artifact_bytes)


def _copy_local_artifact(source_path: Path, archive_path: Path, max_bytes: int) -> None:
    try:
        size = source_path.stat().st_size
    except OSError as exc:
        raise ValueError(f"cannot read local artifact {source_path}: {exc}") from exc
    if size > max_bytes:
        raise ValueError(f"artifact is too large: {size} bytes exceeds {max_bytes}")
    shutil.copyfile(source_path, archive_path)


def _download_artifact(url: str, archive_path: Path, max_bytes: int) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "ca9-artifact-scanner"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > max_bytes:
                raise ValueError(
                    f"artifact is too large: {content_length} bytes exceeds {max_bytes}"
                )
            total = 0
            with archive_path.open("wb") as out:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError(f"artifact is too large: exceeds {max_bytes} bytes")
                    out.write(chunk)
    except (urllib.error.URLError, OSError) as exc:
        archive_path.unlink(missing_ok=True)
        raise ValueError(f"cannot download artifact {url}: {exc}") from exc


def _verify_hash(path: Path, expected: str) -> tuple[bool, str]:
    parsed_hashes = _parse_hashes(expected)
    supported_hashes = [item for item in parsed_hashes if item[0] in hashlib.algorithms_available]
    if not parsed_hashes:
        return False, "artifact hash is empty"
    if not supported_hashes:
        algorithms = ", ".join(sorted({algorithm for algorithm, _value in parsed_hashes}))
        return False, f"unsupported artifact hash algorithm: {algorithms}"

    algorithm, expected_value = max(
        supported_hashes,
        key=lambda item: HASH_STRENGTH.get(item[0], -1),
    )

    digest = hashlib.new(algorithm)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)

    actual = digest.hexdigest()
    if actual.lower() != expected_value.lower():
        return False, f"expected {algorithm}:{expected_value}, got {algorithm}:{actual}"
    return True, "hash verified"


def _parse_hashes(value: str) -> list[tuple[str, str]]:
    hashes: list[tuple[str, str]] = []
    for token in value.strip().split():
        parsed = _parse_hash_token(token)
        if parsed is not None:
            hashes.append(parsed)
    return hashes


def _parse_hash_token(token: str) -> tuple[str, str] | None:
    token = token.strip()
    if not token:
        return None
    if ":" in token:
        algorithm, digest = token.split(":", 1)
    elif "-" in token:
        algorithm, digest = token.split("-", 1)
        normalized_algorithm = algorithm.lower().replace("-", "")
        if normalized_algorithm in hashlib.algorithms_available:
            try:
                return normalized_algorithm, base64.b64decode(digest, validate=True).hex()
            except (binascii.Error, ValueError):
                pass
    elif "=" in token:
        algorithm, digest = token.split("=", 1)
    else:
        algorithm, digest = "sha256", token
    return algorithm.lower().replace("-", ""), digest.strip()


def _cache_path(package: Package, artifact: Artifact, config: ArtifactScanConfig) -> Path:
    suffix = _artifact_suffix(artifact)
    stable = artifact.hash or f"{package.key}:{artifact.kind}:{artifact.url}"
    digest = hashlib.sha256(stable.encode("utf-8")).hexdigest()
    return config.cache_dir / "downloads" / f"{digest}{suffix}"


def _unpack_dir(package: Package, artifact: Artifact, config: ArtifactScanConfig) -> Path:
    stable = artifact.hash or f"{package.key}:{artifact.kind}:{artifact.url}"
    digest = hashlib.sha256(stable.encode("utf-8")).hexdigest()
    return config.cache_dir / "unpacked" / digest


def _artifact_suffix(artifact: Artifact) -> str:
    url_path = urllib.parse.urlparse(artifact.url or "").path
    for suffix in (".tar.gz", ".tgz", ".zip", ".whl", ".tar.bz2", ".tar.xz"):
        if url_path.endswith(suffix):
            return suffix
    if artifact.kind == "wheel":
        return ".whl"
    return ".tar.gz"


def _local_artifact_path(url: str) -> Path | None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "file":
        return Path(urllib.parse.unquote(parsed.path))
    if parsed.scheme:
        return None
    path = Path(url)
    if path.exists():
        return path
    return None


def _artifact_finding(
    package: Package,
    artifact: Artifact,
    *,
    signal_type: str,
    title: str,
    severity: str,
    action: str,
    reason: str,
) -> Finding:
    source = SourceEvidence(
        source="artifact acquisition",
        path=artifact.url,
        reader="ca9 artifact scanner",
    )
    evidence = Evidence(
        kind="artifact_scan",
        description=reason,
        source=source,
        metadata={
            "artifact_kind": artifact.kind,
            "artifact_url": artifact.url,
            "artifact_hash": artifact.hash,
            "package": package.name,
            "version": package.version,
        },
    )
    signal = RiskSignal(
        signal_type=signal_type,
        package_key=package.key,
        severity=severity,
        confidence="high",
        evidence=(evidence,),
        metadata={"package": package.name, "version": package.version},
    )
    return Finding(
        title=title,
        signal_type=signal_type,
        package_key=package.key,
        severity=severity,
        signals=(signal,),
        evidence=(evidence,),
        metadata={
            "action": action,
            "reason": reason,
            "package": package.name,
            "version": package.version,
            "dependency_kind": package.dependency_kind,
            "policy_id": f"ca9.{signal_type}",
        },
    )
