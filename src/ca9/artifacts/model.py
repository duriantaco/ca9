from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ca9.core.models import Artifact, Package


@dataclass(frozen=True)
class ArtifactFile:
    relative_path: str
    path: Path
    size: int


@dataclass(frozen=True)
class ArtifactSnapshot:
    package: Package
    artifact: Artifact
    archive_path: Path
    extract_dir: Path
    files: tuple[ArtifactFile, ...]

    @property
    def package_key(self) -> str:
        return self.package.key
