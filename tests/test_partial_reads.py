from __future__ import annotations

import io

import pytest

from ca9.artifacts import fetch


def _reader(body):
    return fetch._BoundedReader(io.BytesIO(body), fetch._URLPolicy(frozenset()), "https://x", 4096)


def _part(boundary, start, data, size):
    end = start + len(data) - 1
    head = f"--{boundary}\r\ncontent-type: application/octet-stream\r\n"
    return (head + f"content-range: bytes {start}-{end}/{size}\r\n\r\n").encode() + data + b"\r\n"


def test_multipart_byte_ranges_are_split_by_their_content_range():
    body = (
        _part("b1", 0, b"PK\x03\x04", 100) + _part("b1", 50, b"\r\n--b1\r\n", 100) + b"--b1--\r\n"
    )

    parts = fetch._byte_range_parts(_reader(body), b"b1", 100)

    assert parts == [(0, 4, b"PK\x03\x04"), (50, 58, b"\r\n--b1\r\n")]


def test_multipart_part_for_another_file_size_is_refused():
    body = _part("b1", 0, b"PK\x03\x04", 999) + b"--b1--\r\n"

    with pytest.raises(fetch.RangeNotServed):
        fetch._byte_range_parts(_reader(body), b"b1", 100)
