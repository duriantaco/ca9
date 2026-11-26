"""Review committed npm lockfile changes introduced by a pull request."""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory

from ca9.review.locks import MAX_LOCK_BYTES, load_lock
from ca9.review.pr_report import LockfileReview, PullRequestReview
from ca9.review.service import (
    DEFAULT_TRUSTED_REGISTRIES,
    ReviewReport,
    review_lockfiles,
    trusted_registry_origins,
)

_OBJECT_ID = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")
_EMPTY_LOCK = b'{"lockfileVersion":3,"packages":{"":{}}}'
_HISTORY_HINT = "Check out the PR history with actions/checkout and fetch-depth: 0."


def _git(repo: Path, *args: str, error: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            env={
                **os.environ,
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_NO_LAZY_FETCH": "1",
                "GIT_ALLOW_PROTOCOL": "",
                "GIT_TERMINAL_PROMPT": "0",
            },
        )
    except OSError as exc:
        raise ValueError(error) from exc
    if result.returncode:
        raise ValueError(error)
    return result.stdout


def _commit(repo: Path, sha: str) -> str:
    if not isinstance(sha, str) or not _OBJECT_ID.fullmatch(sha):
        raise ValueError("The pull request must supply full base and head commit SHAs.")
    error = f"Commit {sha} is unavailable. {_HISTORY_HINT}"
    resolved = _git(repo, "rev-parse", "--verify", f"{sha}^{{commit}}", error=error).strip()
    if resolved != sha.lower().encode("ascii"):
        raise ValueError(error)
    return sha.lower()


def _manifest_present(root: Path, revision: str, lock_path: str) -> bool:
    manifest = PurePosixPath(lock_path).with_name("package.json")
    # A Git tree does not expose files inside a submodule or symlink. Treat
    # those transitions as unknown rather than concluding a project vanished.
    for path in (manifest, *manifest.parents):
        if not path.parts:
            break
        entry = _git(
            root,
            "--literal-pathspecs",
            "ls-tree",
            "-z",
            revision,
            "--",
            str(path),
            error=f"Cannot inspect the committed manifest. {_HISTORY_HINT}",
        )
        if entry:
            mode = entry.partition(b" ")[0]
            if mode in {b"160000", b"120000"}:
                raise ValueError(
                    "Cannot establish project history through a Git symlink or submodule."
                )
            return path == manifest and mode in {b"100644", b"100755"}
    return False


@dataclass(frozen=True)
class _TreeEntry:
    path: str
    oid: str
    mode: str

    def write_blob(self, root: Path, dest: Path) -> None:
        if self.mode not in {"100644", "100755"}:
            raise ValueError(
                "The lockfile must be a regular committed file. Symlinks and submodules cannot be reviewed."
            )
        error = f"A required lockfile blob is unavailable. {_HISTORY_HINT}"
        size = int(_git(root, "cat-file", "-s", self.oid, error=error))
        if size > MAX_LOCK_BYTES:
            raise ValueError(f"The lockfile exceeds the {MAX_LOCK_BYTES}-byte review limit.")
        dest.write_bytes(_git(root, "cat-file", "blob", self.oid, error=error))


def _lock_changes(
    raw: bytes, root: Path, ancestor: str, head: str
) -> Iterator[tuple[str, _TreeEntry, _TreeEntry]]:
    fields = iter(raw.split(b"\0")[:-1])
    for header in fields:
        old_mode, new_mode, old_oid, new_oid, change = header[1:].decode("ascii").split()
        old_path = os.fsdecode(next(fields))
        new_path = os.fsdecode(next(fields)) if change.startswith("R") else old_path
        old = _TreeEntry(old_path, old_oid, old_mode)
        new = _TreeEntry(new_path, new_oid, new_mode)
        status = {"A": "added", "D": "deleted", "R": "renamed"}.get(change[0], "modified")
        if status == "renamed":
            # Identical lockfiles can belong to separate existing projects.
            try:
                separate = _manifest_present(root, head, old_path) or _manifest_present(
                    root, ancestor, new_path
                )
            except ValueError:
                separate = True
            if separate:
                yield "deleted", old, old
                yield "added", new, new
                continue
        yield status, old, new


def review_pull_request(
    repo: Path,
    base_sha: str,
    head_sha: str,
    *,
    scan_artifacts: bool = True,
    cache_dir: Path | None = None,
    trusted_registries: tuple[str, ...] = DEFAULT_TRUSTED_REGISTRIES,
) -> PullRequestReview:
    """Compare PR head with its merge base, restricted to the given checkout directory."""
    trusted_registries = trusted_registry_origins(trusted_registries)
    top = _git(repo, "rev-parse", "--show-toplevel", error="PR review requires a Git checkout.")
    root = Path(os.fsdecode(top.removesuffix(b"\n")))
    base = _commit(root, base_sha)
    head = _commit(root, head_sha)
    ancestors = _git(
        root,
        "merge-base",
        "--all",
        base,
        head,
        error=f"No common PR ancestor is available. {_HISTORY_HINT}",
    ).splitlines()
    if len(ancestors) != 1:
        raise ValueError(
            "The PR has multiple merge bases. Update the branch to establish a single comparison base."
        )
    ancestor = ancestors[0].decode("ascii")
    # The pathspec is relative to the requested subdirectory. --no-relative
    # keeps the returned path labels relative to the repository root.
    changes = _git(
        repo,
        "diff",
        "--raw",
        "-z",
        "--no-abbrev",
        "--no-relative",
        # npm lockfiles share large amounts of identical registry metadata.
        # Similarity alone cannot establish a common project baseline.
        "--find-renames=100%",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-submodules=none",
        ancestor,
        head,
        "--",
        ":(glob)**/package-lock.json",
        error=f"Cannot compare the PR commit trees. {_HISTORY_HINT}",
    )
    reviewed = []
    for status, old, new in _lock_changes(changes, root, ancestor, head):
        before = f"{ancestor}:{old.path}"
        after = f"{head}:{new.path}"
        try:
            with TemporaryDirectory(prefix="ca9-pr-lock-") as staging:
                old_file, new_file = Path(staging) / "base", Path(staging) / "head"
                if status == "added":
                    if _manifest_present(root, ancestor, new.path):
                        raise ValueError(
                            "The project already had a package.json. Its previous resolved dependency versions are unknown."
                        )
                    old_file.write_bytes(_EMPTY_LOCK)
                    before = f"{ancestor}: (lockfile absent)"
                else:
                    old.write_blob(root, old_file)
                if status == "deleted":
                    if _manifest_present(root, head, old.path):
                        raise ValueError(
                            "The project still has a package.json. Its dependency behavior after lockfile removal is unknown."
                        )
                    if not _manifest_present(root, ancestor, old.path):
                        raise ValueError(
                            "The lockfile was removed without a project manifest to establish project removal."
                        )
                    # The project and lock were both removed. No new code from
                    # this installation needs an artifact comparison.
                    removed = load_lock(old_file)
                    report = ReviewReport(
                        base=before,
                        head=f"{head}: (project removed)",
                        complete=True,
                        decision="pass",
                        summary={
                            "packages_removed": len(removed.occurrences),
                            "packages_reviewed": 0,
                        },
                        packages=(),
                        trusted_registries=trusted_registries,
                    )
                else:
                    new.write_blob(root, new_file)
                    comparison = review_lockfiles(
                        old_file,
                        new_file,
                        scan_artifacts=scan_artifacts,
                        cache_dir=cache_dir,
                        trusted_registries=trusted_registries,
                    )
                    report = replace(comparison, base=before, head=after)
            reviewed.append(LockfileReview(new.path, status, report=report))
        except ValueError as exc:
            reviewed.append(LockfileReview(new.path, status, reason=str(exc)))
    return PullRequestReview(base=base, head=head, lockfiles=tuple(reviewed))
