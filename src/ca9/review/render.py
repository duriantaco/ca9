"""Deterministic, presentation-safe dependency review reports."""

from __future__ import annotations

import html
import json
import unicodedata
from typing import Any, Protocol


class SerializableReview(Protocol):
    def to_dict(self) -> dict[str, Any]: ...


def write_json(report: SerializableReview) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True, ensure_ascii=True)


def _text(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, sort_keys=True, ensure_ascii=False)
    value = str(value)
    # Keep every field on one Markdown line and make invisible controls visible.
    value = "".join(
        " "
        if character in "\n\r\t"
        else f"\\u{ord(character):04x}"
        if unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
        else character
        for character in value
    )
    value = html.escape(value, quote=False)
    return "".join(
        "\\" + character if character in "\\`*_{}[]()#!|~" else character for character in value
    )


def _identity(package: dict[str, Any] | None) -> str:
    if package is None:
        return "absent"
    return _text(f"{package.get('name', '?')}@{package.get('version', '?')}")


def write_markdown(report: SerializableReview) -> str:
    data = report.to_dict()
    summary = data.get("summary", {})
    lines = [
        "# Dependency update review",
        "",
        f"Decision: **{_text(data['decision'])}** · Exit code: {_text(data['exit_code'])}",
        "",
        f"Base: {_text(data.get('base'))}",
        "",
        f"Head: {_text(data.get('head'))}",
        "",
        "Comparison coverage: **complete within the declared scope**."
        if data["complete"]
        else "Comparison coverage: **incomplete**. Uninspected behavior remains unknown.",
        "",
        "A pass means no new review or blocking observations within this scope; "
        "it does not establish that a package is safe or behaviorally equivalent.",
        "",
        "| Package occurrences | Count |",
        "|---|---:|",
    ]
    for key, label in (
        ("packages_added", "Added"),
        ("packages_removed", "Removed"),
        ("packages_changed", "Changed"),
        ("packages_unchanged", "Unchanged"),
        ("packages_reviewed", "Reviewed"),
    ):
        lines.append(f"| {label} | {_text(summary.get(key, 0))} |")

    scope = data.get("scope", {})
    if scope:
        lines.extend(["", "## Scope", ""])
        for key, value in sorted(scope.items()):
            lines.append(f"- {_text(key)}: {_text(value)}")

    if data.get("issues"):
        lines.extend(["", "## Incomplete evidence", ""])
        lines.extend(f"- {_text(issue)}" for issue in data["issues"])

    for package in data.get("packages", []):
        if package["status"] == "unchanged":
            continue
        lines.extend(
            [
                "",
                f"## {_text(package['path'])}",
                "",
                f"**{_text(package['status'])}**: "
                f"{_identity(package.get('base'))} → {_identity(package.get('head'))}",
            ]
        )
        for side in ("base", "head"):
            metadata = package.get(side)
            if metadata:
                for key in ("installed_name", "source", "integrity", "chains"):
                    if key in metadata:
                        lines.extend(["", f"{side.title()} {_text(key)}: {_text(metadata[key])}"])
            inspection = package.get(f"{side}_inspection", {})
            if inspection:
                lines.extend(
                    [
                        "",
                        f"{side.title()} inspection: {_text(inspection.get('status', 'unknown'))}.",
                    ]
                )
                issues = inspection.get("issues", [])
                if issues:
                    lines.append("")
                    lines.extend(f"- {_text(issue)}" for issue in issues)
        deltas = package.get("deltas", [])
        visible = [delta for delta in deltas if delta["status"] != "unchanged"]
        if visible:
            lines.extend(
                [
                    "",
                    "| Observation | Change | Before | After | Action | Reason |",
                    "|---|---|---|---|---|---|",
                ]
            )
            for delta in visible:
                observation = f"{delta['kind']}: {delta['key']}"
                values = (
                    observation,
                    delta["status"],
                    delta.get("base"),
                    delta.get("head"),
                    delta["action"],
                    delta.get("reason", ""),
                )
                lines.append("| " + " | ".join(_text(value) for value in values) + " |")
        unchanged = len(deltas) - len(visible)
        if unchanged:
            lines.extend(["", f"{unchanged} unchanged observation(s) omitted; available in JSON."])
    return "\n".join(lines) + "\n"
