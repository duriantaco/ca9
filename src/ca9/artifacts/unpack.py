from __future__ import annotations

import shutil
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from ca9.artifacts.model import ArtifactFile, ArtifactSnapshot
from ca9.core.models import Artifact, Package


@dataclass(frozen=True)
class UnpackConfig:
    max_files: int
    max_total_bytes: int


def unpack_artifact(
    package: Package,
    artifact: Artifact,
    archive_path: Path,
    extract_dir: Path,
    config: UnpackConfig,
) -> ArtifactSnapshot:
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_dir.mkdir(parents=True, exist_ok=True)

    if zipfile.is_zipfile(archive_path):
        files = _unpack_zip(archive_path, extract_dir, config)
    elif tarfile.is_tarfile(archive_path):
        files = _unpack_tar(archive_path, extract_dir, config)
    else:
        raise ValueError("unsupported artifact archive format")

    return ArtifactSnapshot(
        package=package,
        artifact=artifact,
        archive_path=archive_path,
        extract_dir=extract_dir,
        files=tuple(files),
    )


def _unpack_zip(
    archive_path: Path,
    extract_dir: Path,
    config: UnpackConfig,
) -> list[ArtifactFile]:
    files: list[ArtifactFile] = []
    total_size = 0

    with zipfile.ZipFile(archive_path) as zf:
        infos = [info for info in zf.infolist() if not info.is_dir()]
        if len(infos) > config.max_files:
            raise ValueError(
                f"artifact has too many files: {len(infos)} exceeds {config.max_files}"
            )

        for info in infos:
            rel = _safe_relative_path(info.filename)
            total_size += info.file_size
            if total_size > config.max_total_bytes:
                raise ValueError(
                    f"artifact expands too large: exceeds {config.max_total_bytes} bytes"
                )
            target = _safe_target(extract_dir, rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst)
            files.append(ArtifactFile(relative_path=rel, path=target, size=info.file_size))

    return files


def _unpack_tar(
    archive_path: Path,
    extract_dir: Path,
    config: UnpackConfig,
) -> list[ArtifactFile]:
    files: list[ArtifactFile] = []
    total_size = 0

    with tarfile.open(archive_path) as tf:
        members = tf.getmembers()
        regular_files = [member for member in members if member.isfile()]
        if len(regular_files) > config.max_files:
            raise ValueError(
                f"artifact has too many files: {len(regular_files)} exceeds {config.max_files}"
            )

        for member in members:
            if member.isdir():
                _safe_target(extract_dir, _safe_relative_path(member.name)).mkdir(
                    parents=True, exist_ok=True
                )
                continue
            if member.issym() or member.islnk():
                raise ValueError(f"artifact contains unsafe link: {member.name}")
            if not member.isfile():
                continue

            rel = _safe_relative_path(member.name)
            total_size += member.size
            if total_size > config.max_total_bytes:
                raise ValueError(
                    f"artifact expands too large: exceeds {config.max_total_bytes} bytes"
                )
            extracted = tf.extractfile(member)
            if extracted is None:
                continue
            target = _safe_target(extract_dir, rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            with extracted, target.open("wb") as dst:
                shutil.copyfileobj(extracted, dst)
            files.append(ArtifactFile(relative_path=rel, path=target, size=member.size))

    return files


def _safe_relative_path(value: str) -> str:
    path = Path(value)
    if path.is_absolute():
        raise ValueError(f"artifact contains absolute path: {value}")
    if any(part == ".." for part in path.parts):
        raise ValueError(f"artifact contains path traversal: {value}")
    normalized = path.as_posix().lstrip("/")
    if not normalized or normalized == ".":
        raise ValueError(f"artifact contains invalid path: {value}")
    return normalized


def _safe_target(root: Path, relative_path: str) -> Path:
    target = root / relative_path
    try:
        target.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"artifact escapes extraction root: {relative_path}") from exc
    return target
