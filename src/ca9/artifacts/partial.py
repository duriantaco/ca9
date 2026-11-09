"""Read part of a wheel: its zip directory, the members asked for, the first bytes of others.

A release's other wheels mostly repeat the code of the wheel already reviewed and differ
in compiled binaries, so they are read by byte ranges: every member except the native
binaries in full (to compare its bytes), the binaries only far enough to see their format.
The zip is parsed by ``zipfile``, as wheel installers do, with the same entry checks as a
full unpack. The registry digest covers the whole file, so it is not checked here.
"""

from __future__ import annotations

import bisect
import hashlib
import lzma
import zipfile
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ca9.artifacts import fetch
from ca9.artifacts.unpack import _safe_relative_path, _safe_target

_TAIL = 64 * 1024
_HEAD = 8 * 1024
_HEAD_BYTES = 16
_GAP = 16 * 1024
_MIN_FETCH = 64 * 1024
_COPY_CHUNK = 1024 * 1024


_UNREADABLE = (
    zipfile.BadZipFile,
    zipfile.LargeZipFile,
    EOFError,
    OSError,
    RuntimeError,
    NotImplementedError,
    zlib.error,
    lzma.LZMAError,
)


class PartialReadError(ValueError):
    """The wheel cannot be read in part; it has to be reviewed whole."""


class OverBudget(ValueError):
    """Reading the wheel would fetch more bytes than the budget left."""


@dataclass
class ByteBudget:
    """Bytes a review may still fetch; every range read is charged, including failed ones."""

    remaining: int


@dataclass
class PartialWheel:
    """Members of a wheel: sizes of all, bytes of those read in full, heads of the rest."""

    sizes: dict[str, int] = field(default_factory=dict)
    files: dict[str, Path] = field(default_factory=dict)
    digests: dict[str, str] = field(default_factory=dict)
    heads: dict[str, bytes] = field(default_factory=dict)


class _Ranges:
    """A seekable view of a remote artifact that fetches only the byte ranges read."""

    def __init__(
        self, url: str, size: int, config: fetch.ArtifactScanConfig, budget: ByteBudget
    ) -> None:
        self.url = url
        self.size = size
        self.config = config
        self.budget = budget
        self.position = 0
        self.starts: list[int] = []
        self.chunks: list[bytes] = []

    def seekable(self) -> bool:
        return True

    def readable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.position

    def seek(self, offset: int, whence: int = 0) -> int:
        base = {0: 0, 1: self.position, 2: self.size}[whence]
        self.position = max(base + offset, 0)
        return self.position

    def read(self, size: int | None = -1) -> bytes:
        end = self.size
        if size is not None and size >= 0:
            end = min(self.position + size, self.size)
        if end <= self.position:
            return b""
        data = self._slice(self.position, end)
        self.position = end
        return data

    def ensure(self, spans: list[tuple[int, int]]) -> None:
        """Fetch what ``spans`` need that is not held yet; spans a few bytes apart are
        fetched as one, and all of them in as few requests as the server allows."""
        merged: list[list[int]] = []
        for start, end in sorted(spans):
            start, end = max(start, 0), min(end, self.size)
            if end <= start:
                continue
            if merged and start - merged[-1][1] <= _GAP:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        gaps = [gap for start, end in merged for gap in self._missing(start, end)]
        if gaps:
            self._fetch(gaps)

    def _missing(self, start: int, end: int) -> list[tuple[int, int]]:
        gaps = []
        cursor = start
        index = max(bisect.bisect_right(self.starts, start) - 1, 0)
        while cursor < end and index < len(self.starts):
            chunk_start = self.starts[index]
            chunk_end = chunk_start + len(self.chunks[index])
            if chunk_end <= cursor:
                index += 1
                continue
            if chunk_start > cursor:
                gaps.append((cursor, min(chunk_start, end)))
            cursor = max(cursor, chunk_end)
            index += 1
        if cursor < end:
            gaps.append((cursor, end))
        return gaps

    def _fetch(self, gaps: list[tuple[int, int]]) -> None:
        needed = sum(end - start for start, end in gaps)
        if needed > self.budget.remaining:
            raise OverBudget(f"reading {self.url} needs more than the bytes left")
        self.budget.remaining -= needed
        pieces = fetch._read_artifact_ranges(self.url, gaps, self.size, self.config)
        for (start, end), data in zip(gaps, pieces, strict=True):
            if len(data) != end - start:
                raise PartialReadError(f"short read of {self.url}")
            index = bisect.bisect_left(self.starts, start)
            self.starts.insert(index, start)
            self.chunks.insert(index, data)

    def _slice(self, start: int, end: int) -> bytes:
        missing = self._missing(start, end)
        if missing:
            self.ensure(
                [
                    (gap_start, max(gap_end, gap_start + _MIN_FETCH))
                    for gap_start, gap_end in missing
                ]
            )
        parts = []
        cursor = start
        index = max(bisect.bisect_right(self.starts, start) - 1, 0)
        while cursor < end:
            chunk_start = self.starts[index]
            chunk = self.chunks[index]
            if chunk_start + len(chunk) <= cursor:
                index += 1
                continue
            piece = chunk[cursor - chunk_start : end - chunk_start]
            parts.append(piece)
            cursor += len(piece)
            index += 1
        return b"".join(parts)


def read_wheel(
    url: str,
    size: int,
    config: fetch.ArtifactScanConfig,
    out_dir: Path,
    *,
    partial: Callable[[str], bool],
    budget: ByteBudget,
    expected: dict[str, str] | None = None,
) -> PartialWheel:
    """Members of the wheel at ``url``: those ``partial`` names only up to their first
    bytes, every other one hashed (SHA-256) and written under ``out_dir`` unless its
    digest is the one ``expected`` lists for its path."""
    ranges = _Ranges(url, size, config, budget)
    result = PartialWheel()
    try:
        ranges.ensure([(size - _TAIL, size)])
        with zipfile.ZipFile(ranges) as archive:
            infos = _checked(archive, config)
            ordered = sorted(infos, key=lambda info: info.header_offset)
            ends = [info.header_offset for info in ordered[1:]] + [archive.start_dir]
            spans = []
            for info, end in zip(ordered, ends, strict=True):
                if end < info.header_offset:
                    raise PartialReadError("zip entries overlap")
                if info.is_dir():
                    continue
                if partial(info.filename):
                    end = min(end, info.header_offset + _HEAD)
                spans.append((info.header_offset, end))
            ranges.ensure(spans)
            total = 0
            for info in ordered:
                if info.is_dir():
                    continue
                relative = _safe_relative_path(info.filename)
                result.sizes[relative] = info.file_size
                if partial(info.filename):
                    with archive.open(info) as stream:
                        result.heads[relative] = stream.read(_HEAD_BYTES)
                    continue
                total += info.file_size
                if total > config.max_extracted_bytes:
                    raise PartialReadError("wheel expands beyond max_extracted_bytes")
                digest = _digest(archive, info)
                result.digests[relative] = digest
                if (expected or {}).get(relative) == digest:
                    continue
                target = _safe_target(out_dir, relative)
                target.parent.mkdir(parents=True, exist_ok=True)
                _extract(archive, info, target)
                result.files[relative] = target
    except _UNREADABLE as exc:
        raise PartialReadError(f"cannot read {url} in part: {exc}") from exc
    return result


def wheel_names(
    url: str, size: int, config: fetch.ArtifactScanConfig, *, budget: ByteBudget
) -> list[str]:
    """File names in the wheel at ``url``, read from its zip directory alone."""
    ranges = _Ranges(url, size, config, budget)
    try:
        ranges.ensure([(size - _TAIL, size)])
        with zipfile.ZipFile(ranges) as archive:
            return [info.filename for info in _checked(archive, config) if not info.is_dir()]
    except _UNREADABLE as exc:
        raise PartialReadError(f"cannot read the directory of {url}: {exc}") from exc


def _checked(archive: zipfile.ZipFile, config: fetch.ArtifactScanConfig) -> list[zipfile.ZipInfo]:
    infos = archive.infolist()
    if len(infos) > config.max_extracted_files:
        raise PartialReadError(f"wheel has more than {config.max_extracted_files} entries")
    seen: set[str] = set()
    for info in infos:
        relative = _safe_relative_path(info.filename)
        if relative in seen:
            raise PartialReadError(f"wheel contains duplicate entry: {relative}")
        seen.add(relative)
        if info.flag_bits & 0x1:
            raise PartialReadError(f"wheel contains encrypted entry: {relative}")
    return infos


def _digest(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
    digest = hashlib.sha256()
    _copy(archive, info, digest.update)
    return digest.hexdigest()


def _extract(archive: zipfile.ZipFile, info: zipfile.ZipInfo, target: Path) -> None:
    with target.open("wb") as destination:
        _copy(archive, info, destination.write)


def _copy(archive: zipfile.ZipFile, info: zipfile.ZipInfo, sink: Callable[[bytes], Any]) -> None:
    written = 0
    with archive.open(info) as source:
        while chunk := source.read(_COPY_CHUNK):
            written += len(chunk)
            if written > info.file_size:
                break
            sink(chunk)
    if written != info.file_size:
        raise PartialReadError(f"wheel entry size does not match its header: {info.filename}")
