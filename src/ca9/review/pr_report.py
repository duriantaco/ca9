"""Results and GitHub job summaries for a review spanning multiple npm lockfiles."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from itertools import islice
from typing import Any

from ca9.review.redaction import redact_text
from ca9.review.render import write_markdown
from ca9.review.service import ReviewReport


@dataclass(frozen=True)
class LockfileReview:
    path: str
    status: str
    report: ReviewReport | None = None
    reason: str | None = None

    @property
    def decision(self) -> str:
        return self.report.decision if self.report else "incomplete"

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": redact_text(self.path),
            "status": self.status,
            "decision": self.decision,
            "reason": redact_text(self.reason) if self.reason else None,
            "report": self.report.to_dict() if self.report else None,
        }


@dataclass(frozen=True)
class PullRequestReview:
    base: str
    head: str
    lockfiles: tuple[LockfileReview, ...] = ()
    issues: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        return not self.issues and all(
            lock.report and lock.report.complete for lock in self.lockfiles
        )

    @property
    def decision(self) -> str:
        decisions = {lock.decision for lock in self.lockfiles}
        if "block" in decisions:
            return "block"
        if not self.complete:
            return "incomplete"
        return "review" if "review" in decisions else "pass"

    @property
    def exit_code(self) -> int:
        return {"pass": 0, "review": 1, "block": 1, "incomplete": 2}[self.decision]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "ca9.pull-request-review.v1",
            "base": redact_text(self.base),
            "head": redact_text(self.head),
            "decision": self.decision,
            "complete": self.complete,
            "exit_code": self.exit_code,
            "issues": [redact_text(issue) for issue in self.issues],
            "lockfiles": [lock.to_dict() for lock in self.lockfiles],
        }


def _code(value: str, limit: int | None = None) -> str:
    """A single Markdown code span with visible controls and an optional byte limit."""
    safe = "".join(
        ch if ch.isprintable() and ch not in "`<>" else f"\\u{ord(ch):04x}"
        for ch in redact_text(value)
    )
    if limit is not None:
        encoded = safe.encode("utf-8")
        if len(encoded) > limit:
            safe = encoded[: limit - 3].decode("utf-8", errors="ignore") + "…"
    return f"` {safe} `"


def _overview(review: PullRequestReview) -> str:
    if not review.lockfiles and not review.issues:
        return "No npm package-lock.json changes to review."
    count = len(review.lockfiles)
    heading = f"npm dependency review — **{review.decision}** · {count} lockfile{'s' if count != 1 else ''}"
    if review.decision == "pass":
        reviewed = sum(
            lock.report.summary.get("packages_reviewed", 0)
            for lock in review.lockfiles
            if lock.report
        )
        heading += (
            f" · {reviewed} changed package occurrence{'s' if reviewed != 1 else ''} reviewed"
        )
        removed = sum(lock.status == "deleted" for lock in review.lockfiles)
        if removed:
            heading += f" · {removed} lockfile{'s' if removed != 1 else ''} deleted"
    return heading


def _observations(review: PullRequestReview) -> Iterator[str]:
    # Keep the most important changes visible even when an earlier lock has many warnings.
    # The summary takes at most seven distinct rows. Compare whole deltas (including
    # evidence digests), since two different changes may have the same short preview.
    seen = []
    for action in ("block", "review"):
        for lock in review.lockfiles:
            if lock.report is None:
                continue
            for pkg in lock.report.packages:
                base = pkg.get("base") or {}
                head = pkg.get("head") or {}
                has_hook_change = any(
                    d["kind"] == "lifecycle_script" and d["status"] in {"added", "changed"}
                    for d in pkg["deltas"]
                )
                for delta in pkg["deltas"]:
                    if delta["action"] != action or delta["status"] not in {"added", "changed"}:
                        continue
                    if has_hook_change and (delta["kind"], delta["key"]) == (
                        "lock_metadata",
                        "has_install_script",
                    ):
                        continue
                    identity_and_change = (
                        lock.path,
                        base.get("name"),
                        base.get("version"),
                        head.get("name"),
                        head.get("version"),
                        delta,
                    )
                    if identity_and_change in seen:
                        continue
                    seen.append(identity_and_change)
                    yield _observation_line(lock.path, head, delta)


def _observation_line(path: str, head: dict[str, Any], delta: dict[str, Any]) -> str:
    identity = f"{head.get('name', '?')}@{head.get('version', '?')}"
    kind = delta["kind"].replace("_", " ")
    observation = f"{kind} {delta['key']}"
    line = (
        f"- **{delta['action'].title()}** · {_code(path, 150)} · {_code(identity, 120)} "
        f"{delta['status']} {_code(observation, 160)}"
    )
    after = _observation_value(delta["kind"], delta.get("head"))
    if after:
        before = _observation_value(delta["kind"], delta.get("base"))
        if delta["status"] == "changed" and before and before != after:
            line += " · " + _code(before, 120) + " → " + _code(after, 120)
        else:
            line += " · " + _code(after, 180)
    if head.get("dependency_kind") == "transitive" and head.get("chains"):
        # Each node is an npm installation path. The empty root and
        # the occurrence named on this row need no repetition.
        chain = min(head["chains"], key=len)
        parents = [path.rsplit("node_modules/", 1)[-1] for path in chain[1:-1]]
        if parents:
            line += " · via " + _code(" → ".join(parents), 150)
    return line


def _observation_value(kind: str, value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if kind == "lifecycle_script" and isinstance(value, dict):
        return value.get("command")
    if kind == "code_observation" and isinstance(value, dict):
        return value.get("description")
    if kind in {"entrypoint", "dependency"} and isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return None


def _gaps(review: PullRequestReview) -> Iterator[str]:
    for issue in review.issues:
        yield f"- Comparison · {_code(issue, 240)}"
    for lock in review.lockfiles:
        if lock.report is None:
            yield f"- Lockfile {_code(lock.path, 150)} · {_code(lock.reason or 'Comparison unavailable', 240)}"
        else:
            for issue in lock.report.issues:
                yield f"- Lockfile {_code(lock.path, 150)} · {_code(issue, 240)}"


def write_job_summary(report: PullRequestReview) -> str:
    """Return a concise Markdown summary. Full per-occurrence evidence lives in the report."""
    lines = [_overview(report)]
    if report.decision != "pass":
        for title, rows, limit in (
            ("Package changes", _observations(report), 6),
            ("Inspection gaps", _gaps(report), 3),
        ):
            excerpt = list(islice(rows, limit + 1))
            if excerpt:
                lines.extend(["", f"### {title}", "", *excerpt[:limit]])
                if len(excerpt) > limit:
                    lines.append("- More in the full review.")
    return "\n".join(lines) + "\n"


def write_full_markdown(report: PullRequestReview) -> str:
    lines = [_overview(report)]
    for issue in report.issues:
        lines.extend(["", f"- Comparison · {_code(issue)}"])
    for lock in report.lockfiles:
        lines.extend(["", f"## Lockfile {_code(lock.path)} ({_code(lock.status)})"])
        if lock.reason:
            lines.extend(["", _code(lock.reason)])
        if lock.report is not None:
            lines.extend(["", write_markdown(lock.report).rstrip()])
    return "\n".join(lines) + "\n"
