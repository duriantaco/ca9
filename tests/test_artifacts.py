from __future__ import annotations

import hashlib
import io
import tarfile
import urllib.error
import zipfile
from pathlib import Path

import pytest

from ca9.artifacts.fetch import (
    ArtifactScanConfig,
    _ValidatedRedirectHandler,
    collect_artifact_snapshots,
)
from ca9.core.models import Artifact, Inventory, Package, SourceEvidence


def test_collect_artifact_snapshots_extracts_wheel(tmp_path):
    wheel = tmp_path / "benign-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr("benign/__init__.py", "VALUE = 1\n")

    inventory = _inventory_for_artifact(wheel)

    result = collect_artifact_snapshots(
        inventory,
        ArtifactScanConfig(cache_dir=tmp_path / "cache"),
    )

    assert result.scanned_artifacts == 1
    assert result.skipped_artifacts == 0
    assert not result.findings
    assert result.snapshots[0].files[0].relative_path == "benign/__init__.py"


def test_collect_artifact_snapshots_extracts_sdist_tarball(tmp_path):
    sdist = tmp_path / "benign-1.0.0.tar.gz"
    with tarfile.open(sdist, "w:gz") as tf:
        payload = b"VALUE = 1\n"
        info = tarfile.TarInfo("benign-1.0.0/benign/__init__.py")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))

    inventory = _inventory_for_artifact(sdist, kind="sdist")

    result = collect_artifact_snapshots(
        inventory,
        ArtifactScanConfig(cache_dir=tmp_path / "cache"),
    )

    assert result.scanned_artifacts == 1
    assert not result.findings
    assert result.snapshots[0].files[0].relative_path == "benign-1.0.0/benign/__init__.py"


def test_collect_artifact_snapshots_rejects_zip_path_traversal(tmp_path):
    wheel = tmp_path / "bad-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr("../evil.py", "print('nope')\n")

    inventory = _inventory_for_artifact(wheel, package_name="bad")

    result = collect_artifact_snapshots(
        inventory,
        ArtifactScanConfig(cache_dir=tmp_path / "cache"),
    )

    assert result.scanned_artifacts == 0
    assert result.skipped_artifacts == 1
    assert result.findings[0].signal_type == "artifact_unpack_error"
    assert result.findings[0].metadata["action"] == "block"


def test_collect_artifact_snapshots_blocks_hash_mismatch(tmp_path):
    wheel = tmp_path / "bad-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr("bad/__init__.py", "VALUE = 1\n")

    inventory = _inventory_for_artifact(wheel, package_name="bad", artifact_hash="sha256:deadbeef")

    result = collect_artifact_snapshots(
        inventory,
        ArtifactScanConfig(cache_dir=tmp_path / "cache"),
    )

    assert result.scanned_artifacts == 0
    assert result.findings[0].signal_type == "artifact_hash_mismatch"
    assert result.findings[0].metadata["action"] == "block"


def test_collect_artifact_snapshots_refuses_unhashed_artifact_by_default(tmp_path):
    wheel = tmp_path / "bad-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr("bad/__init__.py", "VALUE = 1\n")

    inventory = _inventory_for_artifact(wheel, package_name="bad", artifact_hash=None)

    result = collect_artifact_snapshots(
        inventory,
        ArtifactScanConfig(cache_dir=tmp_path / "cache"),
    )

    assert result.scanned_artifacts == 0
    assert result.skipped_artifacts == 1
    assert "has no hash" in result.warnings[0]


def test_collect_artifact_snapshots_rejects_special_local_files(tmp_path):
    device = Path("/dev/zero")
    if not device.exists():
        pytest.skip("requires a Unix special file fixture")
    inventory = _inventory_for_artifact(
        device,
        package_name="special-file",
        artifact_hash=None,
    )

    result = collect_artifact_snapshots(
        inventory,
        ArtifactScanConfig(
            cache_dir=tmp_path / "cache",
            allow_unhashed_downloads=True,
        ),
    )

    assert result.scanned_artifacts == 0
    assert result.skipped_artifacts == 1
    assert result.findings[0].signal_type == "artifact_fetch_error"
    assert "not a regular file" in result.findings[0].metadata["reason"]


def test_collect_artifact_snapshots_enforces_local_artifact_roots(tmp_path):
    wheel = tmp_path / "outside.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr("package.py", "VALUE = 1\n")
    allowed = tmp_path / "allowed"
    allowed.mkdir()

    result = collect_artifact_snapshots(
        _inventory_for_artifact(wheel),
        ArtifactScanConfig(
            cache_dir=tmp_path / "cache",
            allowed_local_roots=(allowed,),
        ),
    )

    assert result.scanned_artifacts == 0
    assert result.findings[0].signal_type == "artifact_fetch_error"
    assert "outside the allowed roots" in result.findings[0].metadata["reason"]


def test_unpack_path_collision_is_a_block_finding(tmp_path):
    archive = tmp_path / "collision.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        payload = b"file first"
        file_info = tarfile.TarInfo("collision")
        file_info.size = len(payload)
        tf.addfile(file_info, io.BytesIO(payload))
        directory_info = tarfile.TarInfo("collision")
        directory_info.type = tarfile.DIRTYPE
        tf.addfile(directory_info)

    result = collect_artifact_snapshots(
        _inventory_for_artifact(archive, kind="sdist"),
        ArtifactScanConfig(cache_dir=tmp_path / "cache"),
    )

    assert result.scanned_artifacts == 0
    assert result.findings[0].signal_type == "artifact_unpack_error"
    assert result.findings[0].metadata["action"] == "block"


def test_redirect_handler_checks_destination_before_following():
    handler = _ValidatedRedirectHandler(lambda _url: False)

    with pytest.raises(urllib.error.URLError, match="redirect blocked"):
        handler.redirect_request(None, None, 302, "Found", {}, "https://blocked.example/x")


def _inventory_for_artifact(
    path,
    *,
    package_name: str = "benign",
    kind: str = "wheel",
    artifact_hash: str | None = "auto",
) -> Inventory:
    if artifact_hash == "auto":
        artifact_hash = f"sha256:{_sha256(path)}"
    evidence = SourceEvidence(source="test", path=str(path), reader="test")
    package = Package(
        name=package_name,
        version="1.0.0",
        dependency_kind="direct",
        artifacts=(
            Artifact(
                kind=kind,
                url=path.as_uri(),
                hash=artifact_hash,
                evidence=(evidence,),
            ),
        ),
        evidence=(evidence,),
    )
    return Inventory(repo_path=str(path.parent), packages=(package,))


def _sha256(path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
