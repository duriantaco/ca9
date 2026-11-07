"""Lenient JSON-with-comments parser that remembers where each value starts.

Accepts what VS Code, Cursor and Gemini accept (``//`` and ``/* */`` comments,
trailing commas, a byte-order mark, raw control characters inside strings) so a
file an editor would load is never skipped. Iterative, so deep nesting cannot
exhaust the Python stack. A duplicate key keeps only its last value, as
``JSON.parse`` does, and is recorded in ``Document.duplicates`` so callers can
report the ambiguity.
"""

from __future__ import annotations

import bisect
import json
import re
from typing import Any

_TOKEN = re.compile(
    r"""
    (?P<ws>[\s﻿]+)
    |(?P<line_comment>//[^\n]*)
    |(?P<block_comment>/\*.*?\*/)
    |(?P<string>"(?:[^"\\]|\\.)*")
    |(?P<number>-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)
    |(?P<literal>true|false|null)
    |(?P<punct>[{}\[\]:,])
    """,
    re.VERBOSE | re.DOTALL,
)
_LITERALS = {"true": True, "false": False, "null": None}


class JsoncError(ValueError):
    def __init__(self, message: str, offset: int) -> None:
        super().__init__(message)
        self.offset = offset


class LineDict(dict):
    """A JSON object; ``offsets[key]`` is where that key's value starts."""

    def __init__(self) -> None:
        super().__init__()
        self.offsets: dict[str, int] = {}


class LineList(list):
    """A JSON array; ``offsets[i]`` is where item ``i`` starts."""

    def __init__(self) -> None:
        super().__init__()
        self.offsets: list[int] = []


class Duplicate:
    def __init__(self, path: str, first: int, last: int) -> None:
        self.path = path
        self.first = first
        self.last = last


class Document:
    def __init__(self, text: str, value: Any, duplicates: list[Duplicate]) -> None:
        self.text = text
        self.value = value
        self.duplicates = duplicates
        self._newlines = [match.start() for match in re.finditer("\n", text)]

    def line(self, offset: int | None) -> int:
        if offset is None:
            return 1
        return bisect.bisect_left(self._newlines, offset) + 1

    def line_start(self, offset: int) -> int:
        index = bisect.bisect_left(self._newlines, offset)
        if index == 0:
            return 0
        return self._newlines[index - 1] + 1


def parse(text: str) -> Document:
    duplicates: list[Duplicate] = []
    return Document(text, _parse_value(text, duplicates), duplicates)


def _tokens(text: str):
    position = 0
    length = len(text)
    while position < length:
        match = _TOKEN.match(text, position)
        if match is None:
            raise JsoncError(f"unexpected character {text[position]!r}", position)
        kind = match.lastgroup
        if kind not in {"ws", "line_comment", "block_comment"}:
            yield kind, match.group(), position
        position = match.end()


def _scalar(kind: str, raw: str, offset: int) -> Any:
    if kind == "string":
        try:
            return json.loads(raw, strict=False)
        except ValueError as exc:
            raise JsoncError("invalid string escape", offset) from exc
    if kind == "number":
        return json.loads(raw)
    return _LITERALS[raw]


def _join(path: str, key: Any) -> str:
    if isinstance(key, int):
        return f"{path}[{key}]"
    if path:
        return f"{path}.{key}"
    return str(key)


def _child_path(stack: list[list[Any]]) -> str:
    if not stack:
        return ""
    frame = stack[-1]
    if isinstance(frame[0], LineDict):
        return _join(frame[4], frame[2])
    return _join(frame[4], len(frame[0]))


def _attach(stack: list[list[Any]], value: Any, offset: int, duplicates: list[Duplicate]) -> None:
    frame = stack[-1]
    container = frame[0]
    if isinstance(container, LineDict):
        key = frame[2]
        if key in container:
            duplicates.append(Duplicate(_join(frame[4], key), container.offsets[key], offset))
        container[key] = value
        container.offsets[key] = offset
        frame[1] = "comma"
        frame[2] = None
        return
    container.append(value)
    container.offsets.append(offset)
    frame[1] = "comma"


def _parse_value(text: str, duplicates: list[Duplicate]) -> Any:
    stack: list[list[Any]] = []
    root: Any = None
    have_root = False
    for kind, raw, offset in _tokens(text):
        if have_root and not stack:
            raise JsoncError("unexpected data after the document", offset)
        if stack:
            frame = stack[-1]
            container, state = frame[0], frame[1]
            if raw == "," and kind == "punct":
                if state != "comma":
                    raise JsoncError("unexpected comma", offset)
                frame[1] = "value"
                if isinstance(container, LineDict):
                    frame[1] = "key"
                continue
            if kind == "punct" and raw in "}]":
                expected = "]"
                if isinstance(container, LineDict):
                    expected = "}"
                if raw != expected or state not in {"comma", "key", "value", "first"}:
                    raise JsoncError(f"unexpected {raw}", offset)
                if isinstance(container, LineDict) and state == "value" and frame[2] is not None:
                    raise JsoncError("missing value", offset)
                stack.pop()
                if stack:
                    _attach(stack, container, frame[3], duplicates)
                else:
                    root, have_root = container, True
                continue
            if isinstance(container, LineDict):
                if state in {"key", "first"}:
                    if kind != "string":
                        raise JsoncError("expected a key", offset)
                    frame[2] = _scalar(kind, raw, offset)
                    frame[1] = "colon"
                    continue
                if state == "colon":
                    if raw != ":":
                        raise JsoncError("expected ':'", offset)
                    frame[1] = "value"
                    continue
            if state == "comma":
                raise JsoncError("expected ',' or a closing bracket", offset)
        if kind == "punct" and raw in "{[":
            container = LineList()
            if raw == "{":
                container = LineDict()
            stack.append([container, "first", None, offset, _child_path(stack)])
            continue
        if kind == "punct":
            raise JsoncError(f"unexpected {raw}", offset)
        value = _scalar(kind, raw, offset)
        if stack:
            _attach(stack, value, offset, duplicates)
        else:
            root, have_root = value, True
    if stack or not have_root:
        raise JsoncError("unexpected end of document", len(text))
    return root
