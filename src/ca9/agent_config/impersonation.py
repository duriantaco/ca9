"""Package names that borrow an AI-vendor brand they do not belong to.

A small, explicit vendor list. A name is flagged when it carries a vendor brand
outside that vendor's own npm scopes / PyPI names (``openai-mcp``,
``@anthropic/claude-code``, unscoped ``claude-code``), or when one of its words
is one edit away from a brand (``claud-code``, ``cloude``, ``opneai``).
"""

from __future__ import annotations

import re

_VENDORS: dict[str, dict[str, frozenset[str]]] = {
    "anthropic": {
        "npm_scopes": frozenset({"@anthropic-ai"}),
        "npm": frozenset(),
        "pypi": frozenset({"anthropic", "anthropic-bedrock"}),
    },
    "claude": {
        "npm_scopes": frozenset({"@anthropic-ai"}),
        "npm": frozenset(),
        "pypi": frozenset({"claude-agent-sdk", "claude-code-sdk"}),
    },
    "openai": {
        "npm_scopes": frozenset({"@openai"}),
        "npm": frozenset({"openai"}),
        "pypi": frozenset({"openai", "openai-agents", "openai-harmony", "openai-guardrails"}),
    },
    "chatgpt": {
        "npm_scopes": frozenset({"@openai"}),
        "npm": frozenset(),
        "pypi": frozenset(),
    },
    "gemini": {
        "npm_scopes": frozenset({"@google", "@google-cloud", "@google-labs"}),
        "npm": frozenset(),
        "pypi": frozenset(),
    },
    "postmark": {
        "npm_scopes": frozenset({"@activecampaign"}),
        "npm": frozenset({"postmark"}),
        "pypi": frozenset(),
    },
    "modelcontextprotocol": {
        "npm_scopes": frozenset({"@modelcontextprotocol"}),
        "npm": frozenset(),
        "pypi": frozenset(),
    },
}
LONG_BRAND = 12
_DICTIONARY_WORDS = frozenset({"openapi", "openal", "openui", "clause"})


def check(ecosystem: str | None, package: str | None) -> dict[str, str] | None:
    if ecosystem not in {"npm", "pypi"} or not isinstance(package, str) or not package:
        return None
    name = package.strip().lower()
    scope = ""
    bare = name
    if ecosystem == "npm" and name.startswith("@") and "/" in name:
        scope, _, bare = name.partition("/")
    if ecosystem == "pypi":
        name = re.sub(r"[-_.]+", "-", name)
        bare = name
    words = [word for word in re.split(r"[^a-z0-9]+", f"{scope} {bare}") if word]
    compact = re.sub(r"[^a-z0-9]+", "", f"{scope}{bare}")
    for vendor, official in _VENDORS.items():
        if _official(ecosystem, scope, name, official):
            continue
        if vendor in compact:
            return {
                "vendor": vendor,
                "reason": "brand_outside_vendor_scope",
                "matched": vendor,
                "expected": _expected(ecosystem, official),
            }
    for vendor, official in _VENDORS.items():
        if _official(ecosystem, scope, name, official):
            continue
        for word in words:
            if word in _DICTIONARY_WORDS or len(word) < 5:
                continue
            if word != vendor and _within_one_edit(word, vendor):
                return {
                    "vendor": vendor,
                    "reason": "near_miss",
                    "matched": word,
                    "expected": _expected(ecosystem, official),
                }
        if len(vendor) >= LONG_BRAND:
            window = _near_window(compact, vendor)
            if window is not None:
                return {
                    "vendor": vendor,
                    "reason": "near_miss",
                    "matched": window,
                    "expected": _expected(ecosystem, official),
                }
    return None


def _near_window(compact: str, vendor: str) -> str | None:
    for size in (len(vendor) - 1, len(vendor), len(vendor) + 1):
        for start in range(len(compact) - size + 1):
            window = compact[start : start + size]
            if window != vendor and _within_one_edit(window, vendor):
                return window
    return None


def _official(ecosystem: str, scope: str, name: str, official: dict[str, frozenset[str]]) -> bool:
    if ecosystem == "npm":
        return scope in official["npm_scopes"] or (not scope and name in official["npm"])
    return name in official["pypi"]


def _expected(ecosystem: str, official: dict[str, frozenset[str]]) -> str:
    if ecosystem == "npm":
        names = sorted(official["npm_scopes"]) + sorted(official["npm"])
    else:
        names = sorted(official["pypi"])
    return ", ".join(names) or "the vendor's own publisher"


def _within_one_edit(left: str, right: str) -> bool:
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        diffs = [index for index, (a, b) in enumerate(zip(left, right, strict=True)) if a != b]
        if len(diffs) == 1:
            return True
        return (
            len(diffs) == 2
            and diffs[1] == diffs[0] + 1
            and left[diffs[0]] == right[diffs[1]]
            and left[diffs[1]] == right[diffs[0]]
        )
    longer, shorter = left, right
    if len(right) > len(left):
        longer, shorter = right, left
    return any(longer[:index] + longer[index + 1 :] == shorter for index in range(len(longer)))
