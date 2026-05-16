from __future__ import annotations

from ca9.artifacts.fetch import (
    ArtifactCollectionResult,
    ArtifactScanConfig,
    collect_artifact_snapshots,
)
from ca9.artifacts.model import ArtifactFile, ArtifactSnapshot

__all__ = [
    "ArtifactCollectionResult",
    "ArtifactFile",
    "ArtifactScanConfig",
    "ArtifactSnapshot",
    "collect_artifact_snapshots",
]
