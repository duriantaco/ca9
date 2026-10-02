from __future__ import annotations

import bz2
import contextlib
import gzip
import lzma
import os
import shutil
import tarfile
import tempfile
import urllib.parse
import uuid
import zipfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from ca9.artifacts.model import ArtifactFile, ArtifactSnapshot
from ca9.core.models import Artifact, Package

DEFAULT_MAX_EXPANSION_RATIO = 200
# Archives that expand to less than this are never rejected for their compression ratio.
_EXPANSION_RATIO_FLOOR = 32 * 1024 * 1024
# Tar metadata (header, pax/long-name records, padding) allowed per permitted entry.
_TAR_ENTRY_OVERHEAD = 4 * tarfile.BLOCKSIZE
# tarfile reads pax and GNU long-name records into memory whole; real ones are tiny.
_MAX_TAR_SINGLE_READ = 16 * 1024 * 1024
_TAR_PROBE_LIMIT = 1024 * 1024
# Central-directory bytes allowed per permitted zip entry, checked before zipfile parses it.
_MAX_ZIP_DIRECTORY_BYTES_PER_ENTRY = 1024
_COPY_CHUNK = 1024 * 1024
_TAR_SUFFIXES = (".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar")
_ZIP_SUFFIXES = (".whl", ".zip", ".egg")
_DATA_FILTER = getattr(tarfile, "data_filter", None)


class AmbiguousArchiveError(ValueError):
    """The artifact parses both as the expected archive format and as another one."""


class _ExpansionLimitError(ValueError):
    pass


@dataclass(frozen=True)
class UnpackConfig:
    max_files: int
    max_total_bytes: int
    max_expansion_ratio: int = DEFAULT_MAX_EXPANSION_RATIO


def unpack_artifact(
    package: Package,
    artifact: Artifact,
    archive_path: Path,
    extract_dir: Path,
    config: UnpackConfig,
) -> ArtifactSnapshot:
    archive_format = _archive_format(artifact, archive_path)
    _reject_polyglot(archive_path, archive_format)

    extract_dir.parent.mkdir(parents=True, exist_ok=True)
    # Extract into a private staging directory and move it into place afterwards so a
    # concurrent run never observes a half-extracted tree.
    staging = Path(
        tempfile.mkdtemp(prefix=f".{extract_dir.name}.", suffix=".tmp", dir=extract_dir.parent)
    )
    try:
        unpack = _unpack_zip if archive_format == "zip" else _unpack_tar
        try:
            entries = unpack(archive_path, staging, config)
        except (EOFError, zlib.error, lzma.LZMAError, NotImplementedError, RuntimeError) as exc:
            raise ValueError(f"artifact archive is corrupt or unsupported: {exc}") from exc
        _install_tree(staging, extract_dir)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    return ArtifactSnapshot(
        package=package,
        artifact=artifact,
        archive_path=archive_path,
        extract_dir=extract_dir,
        files=tuple(
            ArtifactFile(relative_path=rel, path=extract_dir / rel, size=size)
            for rel, size in entries.items()
        ),
    )


def _archive_format(artifact: Artifact, archive_path: Path) -> str:
    # Choose the container the installer will use instead of sniffing the bytes: npm
    # extracts tarballs and wheel installers read zips.
    if artifact.kind == "npm-tarball":
        return "tar"
    if artifact.kind == "wheel":
        return "zip"
    for name in (urllib.parse.urlsplit(artifact.url or "").path, archive_path.name):
        lowered = name.lower()
        if lowered.endswith(_ZIP_SUFFIXES):
            return "zip"
        if lowered.endswith(_TAR_SUFFIXES):
            return "tar"
    raise ValueError("unsupported artifact archive format")


def _reject_polyglot(archive_path: Path, archive_format: str) -> None:
    # pip sniffs zip before tar for sdists while npm only reads tar, so bytes that parse
    # both ways can show the scanner different files from the ones that get installed.
    with archive_path.open("rb") as fp:
        zip_view = _zip_directory(fp) is not None
    if zip_view and _parses_as_tar(archive_path):
        other = "zip" if archive_format == "tar" else "tar"
        raise AmbiguousArchiveError(
            f"artifact should be a {archive_format} archive but also parses as {other}; "
            "refusing to pick one view of an ambiguous archive"
        )


def _unpack_zip(
    archive_path: Path,
    extract_dir: Path,
    config: UnpackConfig,
) -> dict[str, int]:
    files: dict[str, int] = {}
    archive_size = archive_path.stat().st_size

    with archive_path.open("rb") as fp:
        directory = _zip_directory(fp)
    if directory is not None:
        entries, directory_size = directory
        if (
            entries > config.max_files
            or directory_size > config.max_files * _MAX_ZIP_DIRECTORY_BYTES_PER_ENTRY
        ):
            raise ValueError(f"artifact has too many entries: exceeds {config.max_files}")

    with zipfile.ZipFile(archive_path) as zf:
        infos = zf.infolist()
        if len(infos) > config.max_files:
            raise ValueError(
                f"artifact has too many entries: {len(infos)} exceeds {config.max_files}"
            )
        _check_expansion(sum(info.file_size for info in infos), archive_size, config)

        seen: set[str] = set()
        for info in infos:
            rel = _safe_relative_path(info.filename)
            if rel in seen:
                raise ValueError(f"artifact contains duplicate entry: {rel}")
            seen.add(rel)
            target = _safe_target(extract_dir, rel)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if info.flag_bits & 0x1:
                raise ValueError(f"artifact contains encrypted entry: {rel}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as dst:
                written = _copy_bounded(src, dst, info.file_size)
            if written != info.file_size:
                raise ValueError(f"artifact entry size does not match its header: {rel}")
            files[rel] = info.file_size

    return files


def _unpack_tar(
    archive_path: Path,
    extract_dir: Path,
    config: UnpackConfig,
) -> dict[str, int]:
    files: dict[str, int] = {}
    archive_size = archive_path.stat().st_size
    entries = 0
    total_size = 0
    stream_limit = _expansion_limit(archive_size, config) + (
        config.max_files * _TAR_ENTRY_OVERHEAD + _COPY_CHUNK
    )

    with _open_tar(archive_path, stream_limit) as tf:
        # Iterate lazily: getmembers() would decompress and index the whole stream first.
        while (member := tf.next()) is not None:
            entries += 1
            if entries > config.max_files:
                raise ValueError(f"artifact has too many entries: exceeds {config.max_files}")
            total_size += max(member.size, 0)
            _check_expansion(total_size, archive_size, config)

            rel = _safe_relative_path(member.name)
            if member.issym() or member.islnk():
                raise ValueError(f"artifact contains unsafe link: {member.name}")
            if not (member.isdir() or member.isfile()):
                continue
            if _DATA_FILTER is not None:
                _DATA_FILTER(member, str(extract_dir))
            target = _safe_target(extract_dir, rel)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            extracted = tf.extractfile(member)
            if extracted is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with extracted, target.open("wb") as dst:
                written = _copy_bounded(extracted, dst, member.size)
            if written != member.size:
                raise ValueError(f"artifact entry size does not match its header: {rel}")
            # Later duplicates overwrite earlier ones, as they do for tar extractors.
            files.pop(rel, None)
            files[rel] = member.size

    return files


@contextlib.contextmanager
def _open_tar(archive_path: Path, limit: int) -> Iterator[tarfile.TarFile]:
    with contextlib.ExitStack() as stack:
        raw = stack.enter_context(archive_path.open("rb"))
        magic = raw.read(6)
        raw.seek(0)
        stream: BinaryIO = raw
        if magic.startswith(b"\x1f\x8b"):
            stream = stack.enter_context(gzip.GzipFile(fileobj=raw, mode="rb"))
        elif magic.startswith(b"BZh"):
            stream = stack.enter_context(bz2.BZ2File(raw))
        elif magic.startswith(b"\xfd7zXZ\x00"):
            stream = stack.enter_context(lzma.LZMAFile(raw))
        yield stack.enter_context(tarfile.open(fileobj=_BoundedReader(stream, limit), mode="r:"))


class _BoundedReader:
    """Read-only view of a decompressed tar stream that stops runaway expansion."""

    def __init__(self, stream: BinaryIO, limit: int) -> None:
        self._stream = stream
        self._limit = limit

    def tell(self) -> int:
        return self._stream.tell()

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        target = offset if whence == os.SEEK_SET else self._stream.tell() + offset
        if whence not in (os.SEEK_SET, os.SEEK_CUR) or target > self._limit:
            raise _ExpansionLimitError(f"artifact expands too large: exceeds {self._limit} bytes")
        return self._stream.seek(target)

    def read(self, size: int | None = -1) -> bytes:
        position = self._stream.tell()
        if size is not None and size > _MAX_TAR_SINGLE_READ:
            raise _ExpansionLimitError("artifact contains an oversized tar header")
        allowed = max(self._limit - position + 1, 0)
        data = self._stream.read(allowed if size is None or size < 0 else min(size, allowed))
        if position + len(data) > self._limit:
            raise _ExpansionLimitError(f"artifact expands too large: exceeds {self._limit} bytes")
        return data


def _parses_as_tar(archive_path: Path) -> bool:
    # An empty but well-formed tar still counts: its zip view is what pip would install.
    try:
        with _open_tar(archive_path, _TAR_PROBE_LIMIT):
            return True
    except _ExpansionLimitError:
        return True
    except (tarfile.TarError, OSError, EOFError, zlib.error, lzma.LZMAError, ValueError):
        return False


def _zip_directory(fp: BinaryIO) -> tuple[int, int] | None:
    """Return (entries, directory bytes) when fp ends with a non-empty zip directory.

    Locates the directory the way zipfile does (last end record, directory placed just
    before it) without parsing entries, and requires the directory signature so random
    compressed bytes are not mistaken for a zip.
    """
    fp.seek(0, os.SEEK_END)
    size = fp.tell()
    tail_start = max(size - (0xFFFF + 22), 0)
    fp.seek(tail_start)
    tail = fp.read()
    index = tail.rfind(b"PK\x05\x06")
    if index < 0 or len(tail) - index < 22:
        return None
    record = tail[index : index + 22]
    entries = int.from_bytes(record[10:12], "little")
    directory_size = int.from_bytes(record[12:16], "little")
    directory_end = tail_start + index
    locator = directory_end - 20
    if locator >= 56:
        fp.seek(locator)
        if fp.read(4) == b"PK\x06\x07":
            fp.seek(locator - 56)
            record64 = fp.read(56)
            if record64[:4] == b"PK\x06\x06":
                entries = int.from_bytes(record64[32:40], "little")
                directory_size = int.from_bytes(record64[40:48], "little")
                directory_end = locator - 56
    directory_start = directory_end - directory_size
    if directory_size == 0 or directory_start < 0:
        return None
    fp.seek(directory_start)
    if fp.read(4) != b"PK\x01\x02":
        return None
    return entries, directory_size


def _expansion_limit(archive_size: int, config: UnpackConfig) -> int:
    ratio_limit = max(_EXPANSION_RATIO_FLOOR, archive_size * config.max_expansion_ratio)
    return min(config.max_total_bytes, ratio_limit)


def _check_expansion(expanded: int, archive_size: int, config: UnpackConfig) -> None:
    if expanded > config.max_total_bytes:
        raise ValueError(f"artifact expands too large: exceeds {config.max_total_bytes} bytes")
    if expanded > _expansion_limit(archive_size, config):
        raise ValueError(
            f"artifact expands more than {config.max_expansion_ratio}x its compressed size"
        )


def _copy_bounded(source: BinaryIO, destination: BinaryIO, expected: int) -> int:
    written = 0
    while chunk := source.read(_COPY_CHUNK):
        written += len(chunk)
        if written > expected:
            break
        destination.write(chunk)
    return written


def _install_tree(staging: Path, final: Path) -> None:
    for _ in range(3):
        try:
            os.rename(staging, final)
            return
        except OSError:
            if not os.path.lexists(final):
                continue
        # Retire the previous tree; it holds the same verified artifact contents.
        retired = final.with_name(f".{final.name}.{uuid.uuid4().hex}.old")
        try:
            os.rename(final, retired)
        except FileNotFoundError:
            continue
        shutil.rmtree(retired, ignore_errors=True)
    os.rename(staging, final)


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
