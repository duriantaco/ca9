from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile

import pytest

from ca9.artifacts import fetch
from ca9.review.behavior import BehaviorFact
from ca9.review.service import (
    Inspection,
    _behavior_deltas,
    _permitted_url,
    _registry_origin,
    review_lockfiles,
)


class Registry:
    """In-memory registry transport; extraction, verification and analysis stay real."""

    def __init__(self, tmp_path, monkeypatch):
        self.root = tmp_path
        self.archives = {}
        self.downloads = []
        monkeypatch.setattr(fetch, "_download_artifact", self.download)

    def download(self, url, destination, max_bytes, url_validator):
        assert url_validator(url)
        self.downloads.append(url)
        if url not in self.archives:
            raise ValueError("fixture artifact unavailable")
        data = self.archives[url]
        assert len(data) <= max_bytes
        destination.write_bytes(data)

    def release(
        self,
        version,
        *,
        name="sample",
        manifest=None,
        files=None,
        origin="https://registry.npmjs.org",
        tag="",
    ):
        package = {"name": name, "version": version, "main": "index.js"}
        package.update(manifest or {})
        payloads = {
            "package/package.json": json.dumps(package).encode(),
            "package/index.js": b"module.exports = 1;\n",
        }
        payloads.update(
            {
                f"package/{path}": value.encode() if isinstance(value, str) else value
                for path, value in (files or {}).items()
            }
        )
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            for path, data in sorted(payloads.items()):
                info = tarfile.TarInfo(path)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        raw = stream.getvalue()
        url = f"{origin}/{name}/-/{name}-{version}{tag}.tgz"
        self.archives[url] = raw
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(raw).digest()).decode()
        return {"version": version, "resolved": url, "integrity": integrity}

    def lock(self, filename, entry=None, *, entries=None, root_dependencies=None):
        records = (
            entries if entries is not None else ({"node_modules/sample": entry} if entry else {})
        )
        root = {
            "name": "application",
            "version": "1.0.0",
            "dependencies": root_dependencies
            if root_dependencies is not None
            else {
                path.removeprefix("node_modules/"): record.get("version", "*")
                for path, record in records.items()
                if path.count("node_modules") == 1
            },
        }
        path = self.root / filename
        path.write_text(json.dumps({"lockfileVersion": 3, "packages": {"": root, **records}}))
        return path

    def review(self, old, new, **kwargs):
        return review_lockfiles(old, new, cache_dir=self.root / "cache", **kwargs)


@pytest.fixture
def registry(tmp_path, monkeypatch):
    return Registry(tmp_path, monkeypatch)


def _deltas(report, kind=None):
    return [
        item
        for package in report.packages
        for item in package["deltas"]
        if kind is None or item["kind"] == kind
    ]


def test_version_and_formatting_only_update_has_no_new_behavior(registry):
    old = registry.lock("base.json", registry.release("1.0.0"))
    new = registry.lock(
        "head.json",
        registry.release(
            "1.0.1",
            files={
                "index.js": "// formatting only\n\nmodule.exports   =   1 ;\n",
            },
        ),
    )

    report = registry.review(old, new)

    assert report.complete
    assert report.decision == "pass"
    assert report.exit_code == 0
    assert report.summary["packages_changed"] == 1
    assert len(registry.downloads) == 2
    assert not [item for item in _deltas(report) if item["action"] != "info"]
    assert report.packages[0]["base_inspection"]["status"] == "verified"
    assert report.packages[0]["head_inspection"]["status"] == "verified"


def test_added_install_hook_requests_review_without_executing(registry):
    old = registry.lock("base.json", registry.release("1.0.0"))
    new = registry.lock(
        "head.json",
        registry.release(
            "2.0.0",
            manifest={
                "scripts": {"postinstall": "node install.js"},
            },
            files={"install.js": "console.log('local fixture');\n"},
        ),
    )

    report = registry.review(old, new)

    assert report.complete
    assert report.decision in {"review", "block"}
    assert report.exit_code == 1
    delta = next(
        item for item in _deltas(report, "lifecycle_script") if item["key"] == "postinstall"
    )
    assert delta["status"] == "added"
    assert delta["action"] == "review"


def test_preexisting_install_hook_does_not_regate_version_bump(registry):
    manifest = {"scripts": {"postinstall": "node install.js"}}
    files = {"install.js": "console.log('fixture');\n"}
    old = registry.lock("base.json", registry.release("1.0.0", manifest=manifest, files=files))
    new = registry.lock("head.json", registry.release("1.0.1", manifest=manifest, files=files))

    report = registry.review(old, new)

    assert report.complete
    assert report.decision == "pass"
    assert all(item["status"] == "unchanged" for item in _deltas(report, "lifecycle_script"))
    assert all(item["action"] == "info" for item in _deltas(report, "code_observation"))


@pytest.mark.parametrize("missing_side", ["base", "head"])
def test_missing_artifact_leaves_behavior_change_unknown(registry, missing_side):
    manifest = {"scripts": {"postinstall": "node install.js"}}
    files = {"install.js": "console.log('fixture');\n"}
    left = registry.release("1.0.0", manifest=manifest, files=files)
    right = registry.release("2.0.0", manifest=manifest, files=files)
    del registry.archives[(left if missing_side == "base" else right)["resolved"]]

    report = registry.review(registry.lock("base.json", left), registry.lock("head.json", right))

    assert not report.complete
    assert report.decision == "incomplete"
    assert report.exit_code == 2
    assert all(item["status"] == "uninspectable" for item in _deltas(report, "lifecycle_script"))
    assert all(item["action"] == "info" for item in _deltas(report, "lifecycle_script"))


@pytest.mark.parametrize("integrity", [None, "", "sha1-YWJj", "sha512-YWJj", "sha512-!!!"])
def test_unverifiable_integrity_is_incomplete_without_fetching(registry, integrity):
    right = registry.release("2.0.0")
    if integrity is None:
        right.pop("integrity")
    else:
        right["integrity"] = integrity

    report = registry.review(registry.lock("base.json"), registry.lock("head.json", right))

    assert not report.complete
    assert report.exit_code == 2
    assert not registry.downloads


def test_strongest_sri_must_match_even_if_weaker_digest_matches(registry):
    right = registry.release("2.0.0")
    raw = registry.archives[right["resolved"]]
    valid_sha256 = base64.b64encode(hashlib.sha256(raw).digest()).decode()
    wrong_sha512 = base64.b64encode(b"\0" * 64).decode()
    right["integrity"] = f"sha256-{valid_sha256} sha512-{wrong_sha512}"

    report = registry.review(registry.lock("base.json"), registry.lock("head.json", right))

    assert not report.complete
    assert report.decision == "block"
    assert report.exit_code == 1
    assert any(
        item["key"] == "artifact_hash_mismatch" for item in _deltas(report, "artifact_verification")
    )


def test_base_integrity_failure_does_not_label_head_as_blocked(registry):
    left = registry.release("1.0.0")
    left["integrity"] = "sha512-" + base64.b64encode(b"\0" * 64).decode()
    right = registry.release("2.0.0")

    report = registry.review(registry.lock("base.json", left), registry.lock("head.json", right))

    assert report.decision == "incomplete"
    assert report.exit_code == 2
    assert not _deltas(report, "artifact_verification")


def test_same_version_artifact_replacement_requests_review(registry):
    left = registry.release("1.0.0", tag="-old")
    right = registry.release("1.0.0", tag="-new", files={"index.js": "module.exports = 2;\n"})

    report = registry.review(registry.lock("base.json", left), registry.lock("head.json", right))

    assert report.complete
    assert report.decision == "review"
    assert any(
        item["key"] == "integrity" and item["action"] == "review"
        for item in _deltas(report, "lock_metadata")
    )


def test_registry_change_is_reviewed_only_when_explicitly_trusted(registry):
    left = registry.release("1.0.0")
    right = registry.release("2.0.0", origin="https://packages.example")
    base, head = registry.lock("base.json", left), registry.lock("head.json", right)

    untrusted = registry.review(base, head)
    trusted = registry.review(
        base,
        head,
        trusted_registries=(
            "https://registry.npmjs.org",
            "https://packages.example",
        ),
    )

    assert untrusted.decision == "incomplete"
    assert trusted.complete
    assert trusted.decision == "review"
    assert any(
        item["key"] == "source" and item["action"] == "review"
        for item in _deltas(trusted, "lock_metadata")
    )


def test_native_code_remains_an_explicit_gap(registry):
    old = registry.lock("base.json", registry.release("1.0.0"))
    new = registry.lock(
        "head.json", registry.release("2.0.0", files={"native.node": b"\x00native"})
    )

    report = registry.review(old, new)

    assert not report.complete
    assert report.exit_code == 2
    assert any("native.node" in issue for issue in report.issues)


def test_manifest_identity_mismatch_cannot_pass(registry):
    old = registry.lock("base.json", registry.release("1.0.0"))
    new = registry.lock("head.json", registry.release("2.0.0", manifest={"name": "other"}))

    report = registry.review(old, new)

    assert not report.complete
    assert report.exit_code == 2
    assert report.packages[0]["head_inspection"]["status"] == "incomplete"


def test_unchanged_occurrences_are_counted_and_not_fetched(registry):
    entry = registry.release("1.0.0")
    old, new = registry.lock("base.json", entry), registry.lock("head.json", entry)

    report = registry.review(old, new)

    assert report.complete
    assert report.summary["packages_unchanged"] == 1
    assert report.packages == ()
    assert not registry.downloads
    assert "Unchanged occurrences are not scanned" in report.to_dict()["scope"]["limitations"]


def test_cache_reused_with_deterministic_report(registry):
    old = registry.lock("base.json", registry.release("1.0.0"))
    new = registry.lock("head.json", registry.release("2.0.0"))

    first = registry.review(old, new)
    second = registry.review(old, new)

    assert first.to_dict() == second.to_dict()
    assert len(registry.downloads) == 2


def test_disabled_artifact_scan_cannot_produce_a_pass(registry):
    old = registry.lock("base.json", registry.release("1.0.0"))
    new = registry.lock("head.json", registry.release("2.0.0"))

    report = registry.review(old, new, scan_artifacts=False)

    assert report.decision == "incomplete"
    assert report.exit_code == 2
    assert not registry.downloads


def test_removed_package_has_verified_removals(registry):
    old = registry.lock("base.json", registry.release("1.0.0"))
    new = registry.lock("head.json")

    report = registry.review(old, new)

    assert report.complete
    assert report.decision == "pass"
    assert report.summary["packages_removed"] == 1
    assert all(item["status"] == "removed" for item in _deltas(report))


def test_known_observations_still_compare_when_unrelated_files_are_unknown():
    old = Inspection(
        "incomplete",
        facts=(BehaviorFact("lifecycle_script", "install", "old", "review"),),
        issues=("unrelated native code",),
    )
    new = Inspection(
        "verified", facts=(BehaviorFact("lifecycle_script", "install", "new", "review"),)
    )

    delta = _behavior_deltas(old, new)[0]

    assert delta["status"] == "changed"
    assert delta["action"] == "review"


def test_removing_a_dependency_does_not_trigger_new_risk(registry):
    alpha = registry.release("1.0.0", name="alpha")
    beta = registry.release("1.0.0", name="beta")
    left = registry.release(
        "1.0.0",
        manifest={
            "optionalDependencies": {"alpha": "1.0.0", "beta": "1.0.0"},
        },
    )
    right = registry.release("2.0.0", manifest={"optionalDependencies": {"alpha": "1.0.0"}})
    left["optionalDependencies"] = {"alpha": "1.0.0", "beta": "1.0.0"}
    right["optionalDependencies"] = {"alpha": "1.0.0"}
    base = registry.lock(
        "base.json",
        entries={
            "node_modules/sample": left,
            "node_modules/alpha": alpha,
            "node_modules/beta": beta,
        },
        root_dependencies={"sample": "1.0.0"},
    )
    head = registry.lock(
        "head.json",
        entries={
            "node_modules/sample": right,
            "node_modules/alpha": alpha,
        },
        root_dependencies={"sample": "2.0.0"},
    )

    report = registry.review(base, head)

    assert report.complete
    assert report.decision == "pass"
    assert all(item["action"] == "info" for item in _deltas(report))


def test_mutated_cached_archive_is_reverified(registry):
    base = registry.lock("base.json")
    head = registry.lock("head.json", registry.release("1.0.0"))
    assert registry.review(base, head).complete
    cached = next((registry.root / "cache" / "downloads").iterdir())
    cached.write_bytes(b"unexpected cached bytes")

    report = registry.review(base, head)

    assert report.decision == "block"
    assert report.exit_code == 1
    assert len(registry.downloads) == 1


def test_failed_fetch_does_not_copy_redirect_credentials_to_report(registry, monkeypatch):
    def unavailable(*args):
        raise ValueError(
            "redirect failed https://account:private-password@example.org/a?token=secret"
        )

    monkeypatch.setattr(fetch, "_download_artifact", unavailable)
    base = registry.lock("base.json")
    head = registry.lock("head.json", registry.release("1.0.0"))

    report = registry.review(base, head)

    assert report.decision == "incomplete"
    rendered = json.dumps(report.to_dict())
    assert "private-password" not in rendered
    assert "token=secret" not in rendered


@pytest.mark.parametrize(
    "url",
    [
        "http://registry.npmjs.org/sample.tgz",
        "file:///tmp/sample.tgz",
        "https://registry.npmjs.org.other.example/sample.tgz",
        "https://user:password@registry.npmjs.org/sample.tgz",
        "https://registry.npmjs.org/sample.tgz?token=secret",
        "https://registry.npmjs.org/sample.tgz#fragment",
        "https://registry.npmjs.org:8443/sample.tgz",
        "https://[invalid/sample.tgz",
        "https://registry.npmjs.org\\other.example/sample.tgz",
    ],
)
def test_artifact_origin_validation_rejects_untrusted_sources(url):
    assert not _permitted_url(url, ("https://registry.npmjs.org",))


@pytest.mark.parametrize(
    "origin",
    [
        "http://example.org",
        "https://example.org/path",
        "https://name:secret@example.org",
        "file:///tmp",
    ],
)
def test_invalid_registry_configuration_is_an_input_error(origin):
    with pytest.raises(ValueError, match="HTTPS origins"):
        _registry_origin(origin)


def test_default_https_port_is_equivalent():
    assert _registry_origin("https://REGISTRY.NPMJS.ORG:443/") == "https://registry.npmjs.org"
    assert _permitted_url("https://registry.npmjs.org:443/pkg.tgz", ("https://registry.npmjs.org",))
