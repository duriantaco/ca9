import json
import subprocess
from pathlib import Path

import pytest

from ca9.review import pr_git
from ca9.review.pr_git import review_pull_request


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            *args,
        ],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q")
    return tmp_path


def commit(repo):
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "test", "--allow-empty")
    return git(repo, "rev-parse", "HEAD")


def lock(repo, project, version=None):
    path = repo / project / "package-lock.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    packages = {"": {}}
    if version:
        packages = {
            "": {"dependencies": {"widget": version}},
            "node_modules/widget": {"version": version},
        }
    path.write_text(json.dumps({"lockfileVersion": 3, "packages": packages}))
    return path


def test_review_uses_merge_base_commit_blobs_and_local_scope(repo):
    nested = "projects/feature[*] dir"
    old_path = lock(repo, nested, "1.0.0")
    common = commit(repo)
    git(repo, "checkout", "-qb", "base-tip")
    lock(repo, "base-only")
    base = commit(repo)
    git(repo, "checkout", "-qb", "topic", common)
    lock(repo, nested, "2.0.0")
    lock(repo, "outside")
    head = commit(repo)
    # The checkout has neither endpoint's contents.
    old_path.write_text("invalid working tree lock")
    result = review_pull_request(repo / nested, base, head, scan_artifacts=False)
    assert (result.base, result.head) == (base, head)
    (update,) = result.lockfiles
    assert (update.path, update.status) == (nested + "/package-lock.json", "modified")
    assert update.report.base == f"{common}:{update.path}"
    (change,) = update.report.packages
    assert (change["base"]["version"], change["head"]["version"]) == ("1.0.0", "2.0.0")
    paths = {
        item.path for item in review_pull_request(repo, base, head, scan_artifacts=False).lockfiles
    }
    assert paths == {"outside/package-lock.json", update.path}


def test_add_delete_baselines_and_project_removal(repo):
    for name in ("existing", "retired", "unlocked"):
        (repo / name).mkdir()
        (repo / name / "package.json").write_text("{}")
    lock(repo, "retired", "1.0.0")
    lock(repo, "unlocked", "2.0.0")
    base = commit(repo)
    lock(repo, "fresh", "3.0.0")
    (repo / "fresh/package.json").write_text("{}")
    lock(repo, "existing")
    for name in ("unlocked/package-lock.json", "retired/package-lock.json", "retired/package.json"):
        (repo / name).unlink()
    head = commit(repo)
    result = review_pull_request(repo, base, head, scan_artifacts=False)
    reviewed = {item.path.split("/")[0]: item for item in result.lockfiles}
    assert reviewed["fresh"].status == "added"
    assert reviewed["fresh"].report.summary["packages_added"] == 1
    assert "previous resolved dependency versions are unknown" in reviewed["existing"].reason
    assert "still has a package.json" in reviewed["unlocked"].reason
    assert reviewed["retired"].report.summary["packages_removed"] == 1
    assert reviewed["retired"].decision == "pass"
    assert not result.complete


def test_lock_rename_uses_old_path_and_has_no_new_behavior(repo):
    lock(repo, "before", "1.0.0")
    base = commit(repo)
    (repo / "before").rename(repo / "after")
    head = commit(repo)
    result = review_pull_request(repo, base, head, scan_artifacts=False)
    (moved,) = result.lockfiles
    assert (moved.path, moved.status) == ("after/package-lock.json", "renamed")
    assert moved.report.base == f"{base}:before/package-lock.json"
    assert moved.report.summary["packages_reviewed"] == 0


def test_moving_a_lock_between_existing_projects_leaves_both_baselines_unknown(repo):
    for path in ("one", "two"):
        (repo / path).mkdir()
        (repo / path / "package.json").write_text("{}")
    source = lock(repo, "one", "1.0")
    base = commit(repo)
    source.rename(repo / "two/package-lock.json")
    result = review_pull_request(repo, base, commit(repo), scan_artifacts=False)
    assert {(item.path, item.status, item.decision) for item in result.lockfiles} == {
        ("one/package-lock.json", "deleted", "incomplete"),
        ("two/package-lock.json", "added", "incomplete"),
    }


def test_opaque_project_directory_is_not_reported_as_removed(repo):
    lock(repo, "service", "1.0")
    (repo / "service/package.json").write_text("{}")
    base = commit(repo)
    git(repo, "rm", "-qr", "service")
    (repo / "service").symlink_to("other-service")
    git(repo, "add", "service")
    result = review_pull_request(repo, base, commit(repo), scan_artifacts=False)
    (removed,) = result.lockfiles
    assert removed.decision == "incomplete"
    assert "symlink or submodule" in removed.reason


def test_bad_blobs_are_incomplete_and_do_not_hide_other_locks(repo, monkeypatch):
    base = commit(repo)
    lock(repo, "healthy")
    (repo / "symlink").mkdir()
    (repo / "symlink/package-lock.json").symlink_to("../healthy/package-lock.json")
    for name, data in (("invalid", b"\x00\xffbad"), ("large", b"a" * 400)):
        (repo / name).mkdir()
        (repo / name / "package-lock.json").write_bytes(data)
    git(repo, "add", "-A")
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{base},module/package-lock.json")
    git(repo, "commit", "-qm", "mixed inputs")
    head = git(repo, "rev-parse", "HEAD")
    monkeypatch.setattr(pr_git, "MAX_LOCK_BYTES", 256)
    result = review_pull_request(repo, base, head, scan_artifacts=False)
    by_name = {entry.path.split("/")[0]: entry for entry in result.lockfiles}
    assert by_name["healthy"].decision == "pass"
    assert "regular committed file" in by_name["symlink"].reason
    assert "regular committed file" in by_name["module"].reason
    assert "lockfile" in by_name["invalid"].reason
    assert "256-byte" in by_name["large"].reason


def test_review_rejects_invalid_or_unavailable_commit_and_handles_no_op(repo):
    base = commit(repo)
    with pytest.raises(ValueError, match="full base and head commit"):
        review_pull_request(repo, "HEAD", base)
    with pytest.raises(ValueError, match="fetch-depth: 0"):
        review_pull_request(repo, base, "0" * 40)
    no_op = review_pull_request(repo, base, base)
    assert no_op.complete and not no_op.lockfiles
    with pytest.raises(ValueError, match="HTTPS origins"):
        review_pull_request(repo, base, base, trusted_registries=("invalid",))
