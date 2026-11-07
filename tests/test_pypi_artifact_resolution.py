from __future__ import annotations

import hashlib
import io
import json
import zipfile

import pytest

from ca9.artifacts import fetch
from ca9.artifacts.fetch import ArtifactScanConfig, collect_artifact_snapshots
from ca9.inventory import build_inventory


def _wheel_bytes(source: str = "VALUE = 1\n") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("six.py", source)
    return buffer.getvalue()


def _release(files: list[dict], name: str = "six", version: str = "1.16.0") -> bytes:
    return json.dumps({"info": {"name": name, "version": version}, "urls": files}).encode()


def _file(filename: str, data: bytes, packagetype: str = "bdist_wheel") -> dict:
    return {
        "filename": filename,
        "packagetype": packagetype,
        "url": f"https://files.pythonhosted.org/packages/xx/{filename}",
        "digests": {"sha256": hashlib.sha256(data).hexdigest()},
        "size": len(data),
    }


@pytest.fixture
def registry(monkeypatch):
    calls: dict[str, list[str]] = {"json": [], "download": []}
    served: dict[str, bytes] = {}
    documents: dict[str, bytes] = {}

    def fake_json(url, config):
        calls["json"].append(url)
        if url not in documents:
            raise ValueError("HTTP 404")
        return documents[url]

    def fake_download(url, destination, max_bytes, url_validator):
        calls["download"].append(url)
        destination.write_bytes(served[url])

    monkeypatch.setattr(fetch, "_fetch_registry_json", fake_json)
    monkeypatch.setattr(fetch, "_download_artifact", fake_download)
    return calls, served, documents


def _collect(repo, tmp_path, **overrides):
    config = ArtifactScanConfig(
        cache_dir=tmp_path / "cache", resolve_pypi_artifacts=True, **overrides
    )
    return collect_artifact_snapshots(build_inventory(repo), config)


def _serve_six(served, documents, wheel: bytes, *, extra_files=()):
    entry = _file("six-1.16.0-py2.py3-none-any.whl", wheel)
    sdist = b"sdist bytes"
    files = [_file("six-1.16.0.tar.gz", sdist, "sdist"), entry, *extra_files]
    documents["https://pypi.org/pypi/six/1.16.0/json"] = _release(files)
    served[entry["url"]] = wheel
    return entry


def test_hash_pinned_requirement_resolves_and_verifies_the_pure_wheel(tmp_path, registry):
    calls, served, documents = registry
    wheel = _wheel_bytes()
    entry = _serve_six(served, documents, wheel)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text(
        f"six==1.16.0 --hash=sha256:{entry['digests']['sha256']}\n"
    )

    result = _collect(repo, tmp_path)

    assert result.scanned_artifacts == 1
    assert calls["download"] == [entry["url"]]
    assert result.snapshots[0].artifact.kind == "wheel"


def test_unhashed_requirement_is_not_looked_up_without_opt_in(tmp_path, registry):
    calls, served, documents = registry
    _serve_six(served, documents, _wheel_bytes())
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("six==1.16.0\n")

    result = _collect(repo, tmp_path)

    assert result.scanned_artifacts == 0
    assert result.skipped_artifacts == 1
    assert calls["json"] == []
    assert "--allow-unhashed-downloads" in result.warnings[0]


def test_unhashed_opt_in_verifies_against_the_listed_digest(tmp_path, registry):
    calls, served, documents = registry
    entry = _serve_six(served, documents, _wheel_bytes())
    served[entry["url"]] = _wheel_bytes("TAMPERED = 1\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("six==1.16.0\n")

    result = _collect(repo, tmp_path, allow_unhashed_downloads=True)

    assert result.scanned_artifacts == 0
    assert result.findings[0].signal_type == "artifact_hash_mismatch"


def test_pins_that_match_no_pypi_file_download_nothing(tmp_path, registry):
    calls, served, documents = registry
    _serve_six(served, documents, _wheel_bytes())
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text(f"six==1.16.0 --hash=sha256:{'c' * 64}\n")

    result = _collect(repo, tmp_path)

    assert result.scanned_artifacts == 0
    assert calls["download"] == []
    assert not result.findings
    assert "another index" in result.warnings[0]


def test_only_a_pinned_platform_wheel_is_chosen_when_it_is_the_pinned_file(tmp_path, registry):
    calls, served, documents = registry
    platform = _wheel_bytes("NATIVE = 1\n")
    platform_entry = _file("six-1.16.0-cp312-cp312-manylinux_2_17_x86_64.whl", platform)
    _serve_six(served, documents, _wheel_bytes(), extra_files=(platform_entry,))
    served[platform_entry["url"]] = platform
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text(
        f"six==1.16.0 --hash=sha256:{platform_entry['digests']['sha256']}\n"
    )

    result = _collect(repo, tmp_path)

    assert calls["download"] == [platform_entry["url"]]
    assert result.scanned_artifacts == 1


@pytest.mark.parametrize(
    "requirements",
    [
        "--index-url https://pypi.acme-internal.example/simple\nsix==1.16.0 --hash=sha256:{d}\n",
        "--extra-index-url https://pypi.acme-internal.example/simple\nsix==1.16.0 --hash=sha256:{d}\n",
        "six>=1.16 --hash=sha256:{d}\n",
    ],
)
def test_private_merged_or_unpinned_requirements_are_not_looked_up(
    tmp_path, registry, requirements
):
    calls, served, documents = registry
    entry = _serve_six(served, documents, _wheel_bytes())
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text(requirements.format(d=entry["digests"]["sha256"]))

    _collect(repo, tmp_path)

    assert calls["json"] == []


def test_internal_package_names_are_never_sent_to_pypi(tmp_path, registry):
    calls, _served, _documents = registry
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text(f"ACME_billing==2.0.0 --hash=sha256:{'a' * 64}\n")

    _collect(repo, tmp_path, internal_package_patterns=("acme-*",))

    assert calls["json"] == []


def test_release_document_for_another_project_is_rejected(tmp_path, registry):
    calls, served, documents = registry
    wheel = _wheel_bytes()
    entry = _file("six-1.16.0-py2.py3-none-any.whl", wheel)
    documents["https://pypi.org/pypi/six/1.16.0/json"] = _release([entry], name="evil")
    served[entry["url"]] = wheel
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text(
        f"six==1.16.0 --hash=sha256:{entry['digests']['sha256']}\n"
    )

    result = _collect(repo, tmp_path)

    assert calls["download"] == []
    assert result.scanned_artifacts == 0
    assert "different project" in result.warnings[0]
