"""Run dependency review for the pull request that triggered the GitHub Action."""

import argparse
import json
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from ca9.review.pr_git import review_pull_request
from ca9.review.pr_report import write_full_markdown, write_job_summary
from ca9.review.render import write_json
from ca9.review.service import DEFAULT_TRUSTED_REGISTRIES


def _event_commits() -> tuple[str, str]:
    if os.environ["GITHUB_EVENT_NAME"] != "pull_request":
        raise ValueError("command: review requires a pull_request event.")
    payload = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
    try:
        pr = payload["pull_request"]
        base, head = pr["base"]["sha"], pr["head"]["sha"]
    except (KeyError, TypeError) as exc:
        raise ValueError("The pull_request event is missing its base or head commit.") from exc
    if not isinstance(base, str) or not isinstance(head, str):
        raise ValueError("The pull_request event has invalid commit identifiers.")
    return base, head


def _output_path(workspace: Path, fmt: str) -> Path:
    filename = "ca9-review.json" if fmt == "json" else "ca9-review.md"
    raw = os.environ.get("CA9_OUTPUT") or filename
    if "://" in raw:
        raise ValueError("The review output must be a local file path.")
    path = workspace / raw
    # Only the parent is followed. Publishing atomically replaces a file symlink.
    path = path.parent.resolve() / path.name
    if not path.is_relative_to(workspace):
        raise ValueError("The review output must be a file inside the GitHub workspace.")
    relative = path.relative_to(workspace)
    if any(ord(c) < 32 for c in str(relative)) or any(
        p.casefold() == ".git" for p in relative.parts
    ):
        raise ValueError("Invalid review output path.")
    return path


def run() -> None:
    base, head = _event_commits()
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
    repo = (workspace / (os.environ.get("CA9_REPO") or ".")).resolve(strict=True)
    if not repo.is_dir() or not repo.is_relative_to(workspace):
        raise ValueError("The review repo must be a directory inside the GitHub workspace.")
    fmt = os.environ.get("CA9_FORMAT") or "json"
    if fmt not in {"json", "markdown"}:
        raise ValueError("command: review supports the json and markdown output formats.")
    output = _output_path(workspace, fmt)
    parser = argparse.ArgumentParser(prog="ca9 PR review", add_help=False, allow_abbrev=False)
    parser.add_argument("--no-scan-artifacts", action="store_true")
    parser.add_argument("--trusted-registry", action="append", default=[])
    args = parser.parse_args(os.environ.get("CA9_EXTRA_ARGS", "").split())
    report = review_pull_request(
        repo,
        base,
        head,
        scan_artifacts=not args.no_scan_artifacts,
        trusted_registries=(*DEFAULT_TRUSTED_REGISTRIES, *args.trusted_registry),
    )
    body = write_json(report) if fmt == "json" else write_full_markdown(report)
    summary = write_job_summary(report)
    output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=output.parent) as staging:
        staged = Path(staging) / "report"
        staged.write_text(body, encoding="utf-8")
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as step_summary:
            step_summary.write(summary.rstrip() + "\n")
        staged.replace(output)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as step_outputs:
        print(f"exit-code={report.exit_code}", file=step_outputs)
        print(f"output-path={output.relative_to(workspace)}", file=step_outputs)
        print("report-written=true", file=step_outputs)


if __name__ == "__main__":
    try:
        run()
    except (OSError, ValueError, KeyError) as exc:
        print(f"ca9 dependency review failed: {exc}", file=sys.stderr)
        sys.exit(1)
