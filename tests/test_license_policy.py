from __future__ import annotations

import hashlib
import io
import json
import tarfile
import zipfile

from click.testing import CliRunner

from ca9.cli import main


def test_vet_cli_blocks_denied_wheel_license(tmp_path):
    artifact = tmp_path / "badlib-1.0.0-py3-none-any.whl"
    _write_wheel_metadata(artifact, "License-Expression: AGPL-3.0-only\n")
    repo = _repo_with_artifact(tmp_path, artifact)

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["vet", "--repo", str(repo), "-f", "json", "--deny-license", "AGPL-3.0"],
    )

    assert result.exit_code == 1
    data = json.loads(result.output)
    finding = next(item for item in data["findings"] if item["signal_type"] == "denied_license")
    assert finding["metadata"]["action"] == "block"
    assert finding["evidence"][0]["metadata"]["normalized_license"] == "AGPL-3.0-ONLY"


def test_vet_cli_allows_non_denied_wheel_license(tmp_path):
    artifact = tmp_path / "goodlib-1.0.0-py3-none-any.whl"
    _write_wheel_metadata(artifact, "License-Expression: MIT\n")
    repo = _repo_with_artifact(tmp_path, artifact, package_name="goodlib")

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["vet", "--repo", str(repo), "-f", "json", "--deny-license", "AGPL-3.0"],
    )

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert not any(item["signal_type"] == "denied_license" for item in data["findings"])


def test_vet_cli_warns_on_unknown_license_when_required(tmp_path):
    artifact = tmp_path / "unknownlib-1.0.0-py3-none-any.whl"
    _write_wheel_metadata(artifact, "")
    repo = _repo_with_artifact(tmp_path, artifact, package_name="unknownlib")

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["vet", "--repo", str(repo), "-f", "json", "--require-known-license"],
    )

    assert result.exit_code == 0
    data = json.loads(result.output)
    finding = next(item for item in data["findings"] if item["signal_type"] == "unknown_license")
    assert finding["metadata"]["action"] == "warn"


def test_vet_cli_blocks_denied_sdist_license(tmp_path):
    artifact = tmp_path / "badlib-1.0.0.tar.gz"
    payload = b"Metadata-Version: 2.4\nName: badlib\nVersion: 1.0.0\nLicense: GPL-3.0-only\n"
    with tarfile.open(artifact, "w:gz") as tf:
        info = tarfile.TarInfo("badlib-1.0.0/PKG-INFO")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    repo = _repo_with_artifact(tmp_path, artifact, artifact_kind="sdist")

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["vet", "--repo", str(repo), "-f", "json", "--deny-license", "GPL-3.0"],
    )

    assert result.exit_code == 1
    data = json.loads(result.output)
    assert any(item["signal_type"] == "denied_license" for item in data["findings"])


def _write_wheel_metadata(path, extra_metadata: str) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("goodlib/__init__.py", "VALUE = 1\n")
        zf.writestr(
            "goodlib-1.0.0.dist-info/METADATA",
            "Metadata-Version: 2.4\nName: goodlib\nVersion: 1.0.0\n" + extra_metadata,
        )


def _repo_with_artifact(
    tmp_path,
    artifact,
    *,
    package_name: str = "badlib",
    artifact_kind: str = "wheel",
):
    repo = tmp_path / f"repo-{package_name}"
    repo.mkdir()
    artifact_table = "wheels" if artifact_kind == "wheel" else "sdist"
    artifact_value = (
        f'[{{ url = "{artifact.as_uri()}", hash = "sha256:{_sha256(artifact)}", size = 42 }}]'
        if artifact_kind == "wheel"
        else f'{{ url = "{artifact.as_uri()}", hash = "sha256:{_sha256(artifact)}", size = 42 }}'
    )
    (repo / "fyn.lock").write_text(
        f"""
version = 1

[[package]]
name = "demo"
version = "0.1.0"
source = {{ editable = "." }}
dependencies = [{{ name = "{package_name}" }}]

[[package]]
name = "{package_name}"
version = "1.0.0"
source = {{ registry = "https://pypi.org/simple" }}
{artifact_table} = {artifact_value}
"""
    )
    return repo


def _sha256(path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
