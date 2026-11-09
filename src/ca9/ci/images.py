"""Container images a CI job runs in or starts, and whether each reference is pinned.

A job image runs every step with the job's credentials, like any tool the job installs.
A digest is immutable. A Docker official image (``node:22``) at a version tag is
treated like a setup action given a version; a floating tag (latest, lts, edge...) or
no tag is not pinned, and a third-party image is pinned only by digest, because its
owner can move any tag.
"""

from __future__ import annotations

import re
from typing import Any

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_OFFICIAL_PREFIXES = ("docker.io/library/", "index.docker.io/library/", "library/")
_FLOATING_TAGS = (
    "latest",
    "stable",
    "lts",
    "edge",
    "current",
    "nightly",
    "rolling",
    "main",
    "master",
    "dev",
    "beta",
    "rc",
)


def image_reference(value: Any) -> str | None:
    """The image named by a ``container:``/``image:`` value (a string or a mapping)."""
    if isinstance(value, dict):
        value = value.get("image", value.get("name"))
    if not isinstance(value, str):
        return None
    reference = value.strip()
    if not reference or "$" in reference or any(char.isspace() for char in reference):
        return None
    return reference


def image_pinned(reference: str) -> bool:
    name, at, digest = reference.partition("@")
    if at:
        return bool(_DIGEST.fullmatch(digest))
    slash = name.rfind("/")
    colon = name.rfind(":")
    repository = name
    tag = ""
    if colon > slash:
        repository, tag = name[:colon], name[colon + 1 :]
    official = "/" not in repository or repository.lower().startswith(_OFFICIAL_PREFIXES)
    if not official or not tag:
        return False
    lowered = tag.lower()
    return not any(
        lowered == word or lowered.startswith((f"{word}-", f"{word}.", f"{word}_"))
        for word in _FLOATING_TAGS
    )
