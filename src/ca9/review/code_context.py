"""Code text for reviewers of an upgrade: diff excerpts around deltas and identity diffs.

Every line comes from the package files of the two releases. Control, bidi and other
invisible characters are removed (tabs stay; other whitespace becomes a space) and a line
break hidden inside a line (a lone CR, U+2028, U+2029) is shown as its escape, so that
code after it cannot pass for part of a comment. Nothing else is changed or added.
"""

from __future__ import annotations

import difflib
import re
import time
from bisect import bisect_left
from collections import Counter
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from itertools import islice
from pathlib import PurePosixPath
from typing import Any

from ca9.analyzers import package_code as pc
from ca9.artifacts.model import ArtifactFile

MAX_CONTEXT_LINES = 200
MAX_IDENTITY_DIFF_BYTES = 200_000
DELTA_CONTEXT_BYTES = 8 * 1024
RESULT_CONTEXT_BYTES = 64 * 1024
TRUNCATED = "... (truncated)"
IDENTITY_KINDS = frozenset({"publisher_change", "provenance_dropped"})
IDENTITY_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".py", ".pth", ".json", ".sh", ".toml", ".cfg")
IDENTITY_NAMES = frozenset({"setup.py", "package.json"})
LOCKFILES = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lock",
        "bun.lockb",
        "poetry.lock",
        "pipfile.lock",
        "pdm.lock",
        "uv.lock",
    }
)
IDENTITY_CONTEXT = 3
MAX_READ_BYTES = 32 * 1024 * 1024
MATCH_GAP_LINES = 2000
MATCH_WORK_LINES = 20000
_JS_SUFFIXES = (".js", ".cjs", ".mjs")
_HIDDEN_BREAKS = {"\r": "\\r", "\u2028": "\\u2028", "\u2029": "\\u2029"}
_HEADER = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_MARKER = "\n" + TRUNCATED


@dataclass(frozen=True)
class _Row:
    """One diff line: its sign, the old and new line indexes it sits at, and its cleaned
    text."""

    sign: str
    old: int
    new: int
    text: str


class FileDiff:
    """Line diff of one file between two releases; ``old`` is empty for a new file."""

    def __init__(self, old: Sequence[str] | None, new: Sequence[str]) -> None:
        self.old = list(old or [])
        self.new = list(new)
        self._opcodes: list[tuple[str, int, int, int, int]] | None = None

    def opcodes(self) -> list[tuple[str, int, int, int, int]]:
        if self._opcodes is None:
            self._opcodes = _opcodes(self.old, self.new)
        return self._opcodes


class _Scrub(dict):
    """``str.translate`` table filled in as characters are met: tabs and printable
    characters stay, hidden line breaks become their escapes, other whitespace a space,
    and every other character that does not print is removed."""

    def __missing__(self, code: int) -> str | None:
        char = chr(code)
        value: str | None = char
        if char in _HIDDEN_BREAKS:
            value = _HIDDEN_BREAKS[char]
        elif char != "\t" and not char.isprintable():
            value = None
            if char.isspace():
                value = " "
        self[code] = value
        return value


_SCRUB = _Scrub()


def clean(line: str) -> str:
    """The line (without its CR line end) with no control, bidi or invisible characters."""
    return _scrub(line.removesuffix("\r"))


def _scrub(text: str) -> str:
    if text.isprintable():
        return text
    return text.translate(_SCRUB)


def _shown(line: str, chars: int) -> str:
    """``clean(line)`` computed only until it is longer than ``chars`` characters, as no
    more than that of a line is ever shown."""
    line = line.removesuffix("\r")
    if len(line) <= chars:
        return _scrub(line)
    pieces = []
    size = 0
    for start in range(0, len(line), chars + 1):
        piece = _scrub(line[start : start + chars + 1])
        pieces.append(piece)
        size += len(piece)
        if size > chars:
            break
    return "".join(pieces)


def read_lines(file: ArtifactFile) -> list[str] | None:
    """The file's lines split on LF as the rules count them; None for a binary file or
    one over 32 MB. JavaScript with NUL bytes is text, as Node runs it."""
    if file.size > MAX_READ_BYTES:
        return None
    raw = pc._read_bytes(file, MAX_READ_BYTES + 1)
    if raw is None or len(raw) > MAX_READ_BYTES or pc._is_native_binary(raw):
        return None
    text = pc._decode_text(raw)
    if text is None and file.relative_path.lower().endswith(_JS_SUFFIXES):
        text = raw.decode("utf-8", errors="replace")
    if text is None:
        return None
    lines = text.removeprefix("\ufeff").split("\n")
    if lines[-1] == "":
        lines.pop()
    return lines


def excerpt(diff: FileDiff, line: int | None, around: int) -> str:
    """Unified-diff hunks of ``diff`` within ``around`` lines of ``line`` (1-based in the
    new file; the first change when None), at most 8 KB, cut around that line."""
    rows, anchor = _window(diff, line, max(around, 1), DELTA_CONTEXT_BYTES)
    return _fitted(rows, anchor, DELTA_CONTEXT_BYTES)


def cap_contexts(deltas: Iterable[dict[str, Any]]) -> None:
    """Keep the contexts of one result within 64 KB: contexts that fit an equal share stay
    whole and the others are cut around their delta line to share the rest."""
    present = [delta for delta in deltas if isinstance(delta.get("context"), str)]
    sizes = [len(delta["context"].encode()) for delta in present]
    if sum(sizes) <= RESULT_CONTEXT_BYTES:
        return
    remaining = RESULT_CONTEXT_BYTES
    order = sorted(range(len(present)), key=lambda index: sizes[index])
    for position, index in enumerate(order):
        share = max(remaining // (len(order) - position), len(TRUNCATED))
        delta = present[index]
        if sizes[index] > share:
            rows, anchor, cut = _parsed(delta["context"], delta.get("line"))
            delta["context"] = _fitted(rows, anchor, share, cut)
        remaining -= len(delta["context"].encode())


def identity_diff(
    files: Iterable[tuple[str, ArtifactFile | None, ArtifactFile | None]],
    limit: int,
    deadline: float | None = None,
) -> tuple[str, bool]:
    """Unified diff of every changed text code file, smallest change first, at most
    ``limit`` bytes, and whether anything was left out."""
    sized: list[tuple[int, str, ArtifactFile | None, ArtifactFile | None]] = []
    truncated = False
    for path, old, new in files:
        if not _identity_file(path):
            continue
        if deadline is not None and time.monotonic() >= deadline:
            truncated = True
            break
        lines = _file_block(path, old, new, limit + 1)
        if lines:
            size = len("\n".join(text for text, _header in lines).encode())
            sized.append((size, path, old, new))
    sized.sort(key=lambda item: (item[0], item[1]))
    shown: list[tuple[str, bool]] = []
    used = 0
    for size, path, old, new in sized:
        if used > limit:
            break
        shown.extend(_file_block(path, old, new, limit + 1))
        used += size + 1
    kept, cut = _fit(shown, limit)
    return "\n".join(kept), truncated or cut


def _identity_file(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    if name in LOCKFILES:
        return False
    return name in IDENTITY_NAMES or name.endswith(IDENTITY_SUFFIXES)


def _file_block(
    path: str, old_file: ArtifactFile | None, new_file: ArtifactFile | None, limit: int
) -> list[tuple[str, bool]]:
    """Header and hunks of one changed text file, built until ``limit`` bytes are exceeded;
    empty for an unchanged or binary file."""
    old = None
    new = None
    if old_file is not None:
        old = read_lines(old_file)
        if old is None:
            return []
    if new_file is not None:
        new = read_lines(new_file)
        if new is None:
            return []
    if old == new:
        return []
    source = f"a/{clean(path)}"
    target = f"b/{clean(path)}"
    if old is None:
        source = "/dev/null"
    if new is None:
        target = "/dev/null"
    lines = [(f"--- {source}", True), (f"+++ {target}", True)]
    size = len(source) + len(target) + 9
    rows = list(islice(_changes(FileDiff(old, new or []), limit), limit))
    for text in _render(rows):
        lines.append((text, text.startswith("@@ ")))
        size += len(text.encode()) + 1
        if size > limit:
            break
    return lines


def _opcodes(old: list[str], new: list[str]) -> list[tuple[str, int, int, int, int]]:
    """difflib-style opcodes from the matched blocks of the two files."""
    codes: list[tuple[str, int, int, int, int]] = []
    old_at = 0
    new_at = 0
    for start, other, size in [*_blocks(old, new), (len(old), len(new), 0)]:
        if start > old_at and other > new_at:
            codes.append(("replace", old_at, start, new_at, other))
        elif start > old_at:
            codes.append(("delete", old_at, start, new_at, new_at))
        elif other > new_at:
            codes.append(("insert", old_at, old_at, new_at, other))
        if size and codes and codes[-1][0] == "equal" and codes[-1][2] == start:
            codes[-1] = ("equal", codes[-1][1], start + size, codes[-1][3], other + size)
        elif size:
            codes.append(("equal", start, start + size, other, other + size))
        old_at = start + size
        new_at = other + size
    return codes


def _blocks(old: list[str], new: list[str]) -> list[tuple[int, int, int]]:
    """Equal runs (old start, new start, length) in order on both sides: the common head and
    tail, then, as patience diff does, the lines found once on each side in their longest
    common order, with difflib matching the small gaps between them. Gaps too large, or
    beyond the work allowance, stay unmatched, so large files are diffed in linear time."""
    blocks: list[tuple[int, int, int]] = []
    head, tail = _common_ends(old, new, 0, len(old), 0, len(new))
    if head:
        blocks.append((0, 0, head))
    old_end = len(old) - tail
    new_end = len(new) - tail
    work = MATCH_WORK_LINES
    old_at = head
    new_at = head
    anchors: list[tuple[int, int]] = []
    if max(old_end - head, new_end - head) > MATCH_GAP_LINES:
        anchors = _unique_anchors(old, new, head, old_end, head, new_end)
    for start, other in [*anchors, (old_end, new_end)]:
        work -= _gap_blocks(old, new, (old_at, start, new_at, other), work, blocks)
        if (start, other) != (old_end, new_end):
            blocks.append((start, other, 1))
        old_at = start + 1
        new_at = other + 1
    if tail:
        blocks.append((old_end, new_end, tail))
    return blocks


def _common_ends(
    old: list[str], new: list[str], old_start: int, old_end: int, new_start: int, new_end: int
) -> tuple[int, int]:
    shortest = min(old_end - old_start, new_end - new_start)
    head = 0
    while head < shortest and old[old_start + head] == new[new_start + head]:
        head += 1
    tail = 0
    while tail < shortest - head and old[old_end - 1 - tail] == new[new_end - 1 - tail]:
        tail += 1
    return head, tail


def _gap_blocks(
    old: list[str],
    new: list[str],
    gap: tuple[int, int, int, int],
    work: int,
    blocks: list[tuple[int, int, int]],
) -> int:
    """Append the equal runs of one gap; the lines given to difflib are returned."""
    old_start, old_end, new_start, new_end = gap
    if old_start >= old_end or new_start >= new_end:
        return 0
    head, tail = _common_ends(old, new, old_start, old_end, new_start, new_end)
    if head:
        blocks.append((old_start, new_start, head))
    old_start += head
    new_start += head
    old_end -= tail
    new_end -= tail
    used = 0
    sizes = (old_end - old_start, new_end - new_start)
    if min(sizes) > 0 and max(sizes) <= min(MATCH_GAP_LINES, work):
        used = sum(sizes)
        matcher = difflib.SequenceMatcher(None, old[old_start:old_end], new[new_start:new_end])
        for first, second, size in matcher.get_matching_blocks():
            if size:
                blocks.append((old_start + first, new_start + second, size))
    if tail:
        blocks.append((old_end, new_end, tail))
    return used


def _unique_anchors(
    old: list[str], new: list[str], old_start: int, old_end: int, new_start: int, new_end: int
) -> list[tuple[int, int]]:
    """Lines found exactly once on each side, in their longest common order."""
    old_counts = Counter(old[old_start:old_end])
    new_counts = Counter(new[new_start:new_end])
    where = {
        new[index]: index for index in range(new_start, new_end) if new_counts[new[index]] == 1
    }
    pairs = [
        (index, where[old[index]])
        for index in range(old_start, old_end)
        if old_counts[old[index]] == 1 and old[index] in where
    ]
    ends: list[int] = []
    owners: list[int] = []
    previous: list[int] = []
    for position, (_index, other) in enumerate(pairs):
        slot = bisect_left(ends, other)
        if slot == len(ends):
            ends.append(other)
            owners.append(position)
        else:
            ends[slot] = other
            owners[slot] = position
        previous.append(-1)
        if slot:
            previous[position] = owners[slot - 1]
    chain: list[tuple[int, int]] = []
    position = -1
    if owners:
        position = owners[-1]
    while position >= 0:
        chain.append(pairs[position])
        position = previous[position]
    chain.reverse()
    return chain


def _target(diff: FileDiff, line: int | None) -> int:
    last = len(diff.new) - 1
    if isinstance(line, int) and not isinstance(line, bool) and line >= 1:
        return min(line - 1, last)
    for tag, _i1, _i2, j1, _j2 in diff.opcodes():
        if tag != "equal":
            return min(j1, last)
    return 0


def _window(diff: FileDiff, line: int | None, around: int, chars: int) -> tuple[list[_Row], int]:
    """Rows within ``around`` new lines of the target line, with at most ``around`` lines
    of each removed run (those nearest the target), and the target row's index."""
    if not diff.new:
        return [], 0
    target = _target(diff, line)
    low = max(0, target - around)
    high = min(len(diff.new), target + around + 1)
    rows: list[_Row] = []
    anchor = 0
    for tag, i1, i2, j1, j2 in diff.opcodes():
        if j1 >= high:
            break
        if tag in {"delete", "replace"} and low <= j1:
            removed = range(i1, i2)
            if j1 <= target:
                removed = removed[-around:]
            else:
                removed = removed[:around]
            rows.extend(_Row("-", index, j1, _shown(diff.old[index], chars)) for index in removed)
        for index in range(max(j1, low), min(j2, high)):
            if index == target:
                anchor = len(rows)
            if tag == "equal":
                rows.append(_Row(" ", i1 + index - j1, index, _shown(diff.new[index], chars)))
            elif tag in {"insert", "replace"}:
                rows.append(_Row("+", i2, index, _shown(diff.new[index], chars)))
    return rows, anchor


def _changes(diff: FileDiff, chars: int) -> Iterator[_Row]:
    """Rows of every change with three lines of context, as ``diff -u`` shows them."""
    codes = diff.opcodes()
    for position, (tag, i1, i2, j1, j2) in enumerate(codes):
        if tag != "equal":
            for index in range(i1, i2):
                yield _Row("-", index, j1, _shown(diff.old[index], chars))
            for index in range(j1, j2):
                yield _Row("+", i2, index, _shown(diff.new[index], chars))
            continue
        span = j2 - j1
        keep: list[int] = []
        if position > 0:
            keep.extend(range(min(IDENTITY_CONTEXT, span)))
        if position < len(codes) - 1:
            keep.extend(range(max(span - IDENTITY_CONTEXT, 0), span))
        for offset in sorted(set(keep)):
            yield _Row(" ", i1 + offset, j1 + offset, _shown(diff.new[j1 + offset], chars))


def _render(rows: Sequence[_Row]) -> list[str]:
    """Hunk headers and lines; a new hunk starts wherever the rows are not contiguous."""
    lines: list[str] = []
    hunk: list[_Row] = []
    expected: tuple[int, int] | None = None
    for row in rows:
        if hunk and (row.old, row.new) != expected:
            lines.extend(_hunk(hunk))
            hunk = []
        hunk.append(row)
        expected = (row.old + (row.sign != "+"), row.new + (row.sign != "-"))
    if hunk:
        lines.extend(_hunk(hunk))
    return lines


def _hunk(rows: list[_Row]) -> list[str]:
    old_length = sum(row.sign != "+" for row in rows)
    new_length = sum(row.sign != "-" for row in rows)
    header = f"@@ -{_range(rows[0].old, old_length)} +{_range(rows[0].new, new_length)} @@"
    return [header, *(row.sign + row.text for row in rows)]


def _range(start: int, length: int) -> str:
    if length == 1:
        return str(start + 1)
    if not length:
        return f"{start},0"
    return f"{start + 1},{length}"


def _fitted(rows: list[_Row], anchor: int, limit: int, cut: bool = False) -> str:
    """The rows rendered within ``limit`` bytes; when they do not fit, the widest run of
    rows centred on the anchor row that does, ending with the truncation line."""
    whole = "\n".join(_render(rows))
    if not cut and len(whole.encode()) <= limit:
        return whole
    room = limit - len(_MARKER.encode())
    best = ""
    low, high = 0, len(rows)
    while low <= high and rows:
        width = (low + high) // 2
        text = "\n".join(_render(rows[max(0, anchor - width) : anchor + width + 1]))
        if len(text.encode()) <= room:
            best = text
            low = width + 1
        else:
            high = width - 1
    if not best and rows:
        header, line = _render([rows[anchor]])
        kept, _cut = _fit([(header, True), (line, False)], room)
        best = "\n".join(kept)
    if not best:
        return TRUNCATED
    return best + _MARKER


def _fit(lines: Iterable[tuple[str, bool]], limit: int) -> tuple[list[str], bool]:
    """Whole lines within ``limit`` bytes; a code line that does not fit is kept in part.
    Headers left with no line after them are dropped. True when anything was left out."""
    kept: list[tuple[str, bool]] = []
    used = 0
    cut = False
    for text, header in lines:
        size = len(text.encode()) + bool(kept)
        if used + size <= limit:
            kept.append((text, header))
            used += size
            continue
        room = limit - used - bool(kept)
        part = text.encode()[: max(room, 0)].decode("utf-8", errors="ignore")
        if not header and len(part) > 1:
            kept.append((part, False))
        cut = True
        break
    while kept and kept[-1][1]:
        kept.pop()
    return [text for text, _header in kept], cut


def _parsed(context: str, line: object) -> tuple[list[_Row], int, bool]:
    """Rows of a context this module rendered, the row of ``line`` and whether it was cut."""
    rows: list[_Row] = []
    lines = context.split("\n")
    cut = lines[-1] == TRUNCATED
    if cut:
        lines.pop()
    old = 0
    new = 0
    for text in lines:
        header = _HEADER.fullmatch(text)
        if header is not None:
            old = _start(header.group(1), header.group(2))
            new = _start(header.group(3), header.group(4))
            continue
        sign = text[:1]
        if sign not in {" ", "+", "-"}:
            continue
        rows.append(_Row(sign, old, new, text[1:]))
        old += sign != "+"
        new += sign != "-"
    anchor = 0
    target = None
    if isinstance(line, int) and not isinstance(line, bool):
        target = line - 1
    for index, row in enumerate(rows):
        if row.sign != "-" and row.new == target:
            anchor = index
            break
    else:
        changed = [index for index, row in enumerate(rows) if row.sign != " "]
        if changed:
            anchor = changed[0]
    return rows, anchor, cut


def _start(start: str, length: str | None) -> int:
    if length is not None and int(length) == 0:
        return int(start)
    return int(start) - 1
