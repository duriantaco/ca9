from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone

import pytest
from click.testing import CliRunner
from scripts.build_feed import build_bundle_from_records

from ca9.cli import main
from ca9.package_feed import (
    FeedError,
    FeedMissingError,
    load_current_snapshot,
    update_feed_from_source,
    verify_feed_attestation,
)


def _bundle(tmp_path):
    bundle = build_bundle_from_records({}, now=datetime.now(timezone.utc))
    path = tmp_path / "latest.json"
    path.write_text(json.dumps(bundle))
    return path


class _FakeRun:
    def __init__(self, returncode=0, stderr=""):
        self.returncode = returncode
        self.stderr = stderr
        self.commands: list[list[str]] = []
        self.verified_bytes: list[bytes] = []

    def __call__(self, command, **kwargs):
        self.commands.append(command)
        with open(command[3], "rb") as handle:
            self.verified_bytes.append(handle.read())
        return subprocess.CompletedProcess(command, self.returncode, "", self.stderr)


def test_attested_update_verifies_the_exact_bytes_it_installs(tmp_path):
    source = _bundle(tmp_path)
    run = _FakeRun()

    update_feed_from_source(
        str(source),
        cache_dir=tmp_path / "feed",
        require_attestation=True,
        attestation_verifier=lambda path: verify_feed_attestation(path, gh="/usr/bin/gh", run=run),
    )

    assert run.verified_bytes == [source.read_bytes()]
    command = run.commands[0]
    assert command[:3] == ["/usr/bin/gh", "attestation", "verify"]
    assert command[command.index("--repo") + 1] == "duriantaco/ca9"
    assert (
        command[command.index("--cert-identity") + 1]
        == "https://github.com/duriantaco/ca9/.github/workflows/feed.yml@refs/heads/main"
    )
    assert command[command.index("--source-ref") + 1] == "refs/heads/main"
    assert "--deny-self-hosted-runners" in command
    assert "--signer-workflow" not in command
    assert load_current_snapshot(cache_dir=tmp_path / "feed").snapshot_id


def _install_with(tmp_path, verifier):
    update_feed_from_source(
        str(_bundle(tmp_path)),
        cache_dir=tmp_path / "feed",
        require_attestation=True,
        attestation_verifier=verifier,
    )


def test_failed_verification_installs_nothing(tmp_path):
    run = _FakeRun(1, "Error: no matching attestations found")

    with pytest.raises(FeedError, match="no matching attestations"):
        _install_with(tmp_path, lambda path: verify_feed_attestation(path, gh="gh", run=run))
    with pytest.raises(FeedMissingError):
        load_current_snapshot(cache_dir=tmp_path / "feed")


def test_missing_gh_installs_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr("ca9.package_feed.shutil.which", lambda name: None)
    run = _FakeRun()

    with pytest.raises(FeedError, match="not installed"):
        _install_with(tmp_path, lambda path: verify_feed_attestation(path, run=run))
    assert run.commands == []
    with pytest.raises(FeedMissingError):
        load_current_snapshot(cache_dir=tmp_path / "feed")


def test_directory_sources_cannot_satisfy_required_attestation(tmp_path):
    with pytest.raises(FeedError, match="single-file"):
        update_feed_from_source(
            str(tmp_path),
            cache_dir=tmp_path / "feed",
            require_attestation=True,
            attestation_verifier=lambda path: None,
        )


def test_cli_require_attestation_fails_closed_without_gh(tmp_path):
    source = _bundle(tmp_path)
    env = {"CA9_CACHE_DIR": str(tmp_path / "cache"), "PATH": str(tmp_path / "empty-bin")}

    required = CliRunner().invoke(
        main, ["feed", "update", "--from", str(source), "--require-attestation"], env=env
    )
    plain = CliRunner().invoke(main, ["feed", "update", "--from", str(source)], env=env)

    assert required.exit_code == 1
    assert "GitHub CLI (gh) is not installed" in required.output
    assert plain.exit_code == 0, plain.output
