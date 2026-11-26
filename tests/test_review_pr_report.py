import json
from dataclasses import replace

import pytest

from ca9.review.pr_report import (
    LockfileReview,
    PullRequestReview,
    write_full_markdown,
    write_job_summary,
)
from ca9.review.render import write_json
from ca9.review.service import ReviewReport


def _result(decision, *, complete=True):
    action = decision if decision in {"review", "block"} else "info"
    packages = (
        {
            "path": "node_modules/demo",
            "status": "changed",
            "base": {"name": "demo", "version": "1.0.0"},
            "head": {"name": "demo", "version": "1.0.1"},
            "deltas": [
                {
                    "kind": "lifecycle_script",
                    "key": "postinstall",
                    "status": "added",
                    "head": {"command": "node setup.js"},
                    "action": action,
                },
                {
                    "kind": "code_observation",
                    "key": "existing",
                    "status": "unchanged",
                    "head": "unchanged rule",
                    "action": "info",
                },
            ],
        },
    )
    return ReviewReport(
        "old",
        "new",
        decision,
        complete,
        {"packages_reviewed": 1},
        packages,
        () if complete else ("Head artifact unavailable.",),
    )


def test_no_changed_lockfiles_is_one_line_and_successful():
    review = PullRequestReview("old", "new")
    assert review.complete
    assert review.exit_code == 0
    assert review.decision == "pass"
    assert write_job_summary(review).splitlines() == ["No npm package-lock.json changes to review."]


def test_clean_review_summary_shows_count_without_individual_observations():
    clean = LockfileReview("package-lock.json", "modified", _result("pass"))
    review = PullRequestReview("old", "new", (clean,))
    assert len(write_job_summary(review).splitlines()) == 1
    assert "1 changed package occurrence reviewed" in write_job_summary(review)


@pytest.mark.parametrize(
    "decision,expected,code",
    [("pass", "incomplete", 2), ("review", "incomplete", 2), ("block", "block", 1)],
)
def test_incomplete_discovery_preserves_known_blocking_observations(decision, expected, code):
    lock = LockfileReview("a/package-lock.json", "modified", _result(decision))
    missing = LockfileReview("b/package-lock.json", "added", reason="No baseline")
    review = PullRequestReview("old", "new", (lock, missing), ("Other changes uninspected",))
    assert review.decision == expected
    assert review.exit_code == code
    assert not review.complete
    output = json.loads(write_json(review))
    assert output["issues"] == ["Other changes uninspected"]
    assert output["lockfiles"][0]["report"] == lock.report.to_dict()
    assert output["lockfiles"][1] == {
        "path": missing.path,
        "status": "added",
        "decision": "incomplete",
        "report": None,
        "reason": "No baseline",
    }
    markdown = write_full_markdown(review)
    for value in ("No baseline", lock.path, "node setup.js", "Other changes uninspected"):
        assert value in markdown
    assert "No baseline" in write_job_summary(review)


def test_single_lock_block_can_be_incomplete_and_include_both_in_summary():
    lock = LockfileReview("package-lock.json", "modified", _result("block", complete=False))
    review = PullRequestReview("old", "new", (lock,))
    assert review.decision == "block"
    assert review.exit_code == 1
    assert not review.complete
    summary = write_job_summary(review)
    for value in (
        "**Block**",
        "demo@1.0.1",
        "postinstall",
        "node setup.js",
        "Head artifact unavailable",
    ):
        assert value in summary
    assert "unchanged rule" not in summary


def test_bounded_summary_prioritizes_blocks_and_escapes_untrusted_values():
    hostile = "x`\n## title\x1b\u202e<img>" + "🙂" * 1000
    noisy = _result("review", complete=False)
    pkg = noisy.packages[0]
    delta = {**pkg["deltas"][0], "head": {"command": hostile}}
    noisy = replace(noisy, packages=({**pkg, "deltas": [delta] * 100},), issues=(hostile,) * 100)
    blocked = _result("block")
    locks = (
        LockfileReview(hostile, "modified", noisy),
        LockfileReview("last/package-lock.json", "modified", blocked),
    )
    summary = write_job_summary(PullRequestReview("base", "head", locks))
    assert summary.index("**Block**") < summary.index("**Review**")
    assert len(summary.encode()) < 8192
    assert "More in the full review." in summary
    for value in ("<img>", "\n## title", "\x1b", "\u202e", "x`"):
        assert value not in summary
    assert "\\u202e" in summary


def test_failure_discovering_changes_is_distinct_from_no_changes():
    review = PullRequestReview("base", "head", issues=("Unable to read comparison commit",))
    assert not review.complete
    assert review.exit_code == 2
    assert "Unable to read comparison commit" in write_job_summary(review)


def test_summary_folds_repeated_occurrences_but_retains_distinct_changes():
    report = _result("review")
    original = report.packages[0]
    hook = {**original["deltas"][0], "status": "changed", "base": {"command": "node before.js"}}
    flag = {
        "kind": "lock_metadata",
        "key": "has_install_script",
        "status": "added",
        "action": "review",
        "head": True,
    }
    repeated = [
        {**original, "path": f"node_modules/p{i}/node_modules/demo", "deltas": [flag, hook]}
        for i in range(8)
    ]
    distinct = {
        **original,
        "path": "node_modules/other/node_modules/demo",
        "deltas": [{**hook, "base": {"command": "node other-before.js"}}],
    }
    report = replace(report, packages=(*repeated, distinct))
    pr = PullRequestReview("old", "new", (LockfileReview("package-lock.json", "modified", report),))
    summary = write_job_summary(pr)
    assert summary.count("postinstall") == 2
    assert "node before.js" in summary and "node other-before.js" in summary
    assert summary.count(" → ") == 2
    assert "has_install_script" not in summary
    assert "More in the full review" not in summary
    assert len(pr.to_dict()["lockfiles"][0]["report"]["packages"]) == 9
    assert write_full_markdown(pr).count("postinstall") == 9


def test_summary_keeps_install_marker_when_hook_was_uninspectable():
    report = _result("incomplete", complete=False)
    original = report.packages[0]
    gaps = [
        {**original["deltas"][0], "status": "uninspectable", "action": "info"},
        {
            "kind": "lock_metadata",
            "key": "has_install_script",
            "status": "added",
            "action": "review",
            "head": True,
        },
    ]
    report = replace(report, packages=({**original, "deltas": gaps},))
    pr = PullRequestReview("old", "new", (LockfileReview("lock", "modified", report),))
    assert "has_install_script" in write_job_summary(pr)


@pytest.mark.parametrize("kind,show_chain", [("direct", False), ("transitive", True)])
def test_summary_shows_shortest_parent_chain_for_transitive_observation(kind, show_chain):
    report = _result("review")
    pkg = report.packages[0]
    head = {
        **pkg["head"],
        "dependency_kind": kind,
        "chains": [
            ["", "node_modules/long-path", "node_modules/indirect", "node_modules/demo"],
            ["", "node_modules/@org/parent", "node_modules/demo"],
        ],
    }
    if kind == "direct":
        head["chains"].append(["", "node_modules/demo"])
    lock = LockfileReview(
        "package-lock.json", "modified", replace(report, packages=({**pkg, "head": head},))
    )
    summary = write_job_summary(PullRequestReview("base", "head", (lock,)))
    assert ("via " in summary) == show_chain
    assert ("@org/parent" in summary) == show_chain
    assert "long-path" not in summary
