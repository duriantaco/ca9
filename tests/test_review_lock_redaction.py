from __future__ import annotations

import json

import pytest

from ca9.review.locks import compare_locks, load_lock
from ca9.review.service import _metadata_deltas, review_lockfiles


def _url(secret):
    return f"https://qa-user:{secret}@registry.npmjs.org/sample.tgz?token={secret}#private"


def _record(name="sample", version="1.0.0", **values):
    return {
        "version": version,
        "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
        "integrity": "sha512-" + "A" * 86 + "==",
        **values,
    }


def _lock(tmp_path, name, *, resolved=None, requested="1.0.0", dependencies=None, version="1.0.0"):
    sample = _record(version=version)
    if resolved is not None:
        sample["resolved"] = resolved
    if dependencies is not None:
        sample["dependencies"] = dependencies
    path = tmp_path / name
    path.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"sample": requested}},
                    "node_modules/sample": sample,
                    **{
                        f"node_modules/{package}": _record(package)
                        for package in dependencies or {}
                    },
                },
            }
        )
    )
    return path


@pytest.mark.parametrize(
    "field,kwargs,action",
    [
        ("source", lambda value: {"resolved": value}, "review"),
        ("source_registry", lambda value: {"resolved": value}, "info"),
        ("requested_specifiers", lambda value: {"requested": value}, "info"),
        ("dependencies", lambda value: {"dependencies": {"helper": value}}, "review"),
    ],
)
def test_hidden_lock_metadata_changes_retain_status_and_identity(tmp_path, field, kwargs, action):
    base = _lock(tmp_path, "base.json", **kwargs(_url("QA_SECRET_A")))
    head = _lock(tmp_path, "head.json", **kwargs(_url("QA_SECRET_B")))

    report = review_lockfiles(base, head, scan_artifacts=False)
    occurrence = next(item for item in report.packages if item["path"] == "node_modules/sample")
    delta = next(item for item in occurrence["deltas"] if item["key"] == field)

    assert occurrence["status"] == "changed"
    assert delta["status"] == "changed"
    assert delta["action"] == action
    assert delta["base"] == delta["head"]
    assert delta["base_identity_sha256"] != delta["head_identity_sha256"]
    display = json.dumps(report.to_dict())
    metadata = json.dumps(load_lock(head).occurrences["node_modules/sample"].metadata)
    for output in (display, metadata):
        assert "QA_SECRET_A" not in output
        assert "QA_SECRET_B" not in output
        assert "qa-user" not in output
        assert "#private" not in output
    assert report.to_dict() == report.to_dict()


def test_removal_with_hidden_change_to_remaining_dependency_requires_review(tmp_path):
    base = _lock(
        tmp_path,
        "base.json",
        dependencies={"helper": _url("QA_SECRET_A"), "removed": "1.0.0"},
    )
    head = _lock(tmp_path, "head.json", dependencies={"helper": _url("QA_SECRET_B")})
    report = review_lockfiles(base, head, scan_artifacts=False)
    occurrence = next(item for item in report.packages if item["path"] == "node_modules/sample")
    delta = next(item for item in occurrence["deltas"] if item["key"] == "dependencies")
    assert delta["status"] == "changed"
    assert delta["action"] == "review"
    assert delta["base_identity_sha256"] != delta["head_identity_sha256"]


def test_removing_dependency_with_unchanged_sensitive_remaining_specifier_is_info(tmp_path):
    base = _lock(
        tmp_path,
        "base.json",
        dependencies={"helper": _url("QA_SECRET_A"), "removed": "1.0.0"},
    )
    head = _lock(tmp_path, "head.json", dependencies={"helper": _url("QA_SECRET_A")})
    change = next(
        item
        for item in compare_locks(load_lock(base), load_lock(head))
        if item.path == "node_modules/sample"
    )
    delta = next(item for item in _metadata_deltas(change) if item["key"] == "dependencies")
    assert delta["status"] == "changed"
    assert delta["action"] == "info"


def test_identical_sensitive_lock_values_stay_unchanged(tmp_path):
    base = _lock(tmp_path, "base.json", resolved=_url("QA_SECRET_A"))
    head = _lock(tmp_path, "head.json", resolved=_url("QA_SECRET_A"))
    change = compare_locks(load_lock(base), load_lock(head))[0]
    delta = next(item for item in _metadata_deltas(change) if item["key"] == "source")
    assert change.status == "unchanged"
    assert delta["status"] == "unchanged"
    assert delta["action"] == "info"
    assert delta["base_identity_sha256"] == delta["head_identity_sha256"]


def test_version_only_tarball_path_update_keeps_informational_policy(tmp_path):
    base = _lock(tmp_path, "base.json", version="1.0.0")
    head = _lock(tmp_path, "head.json", version="2.0.0")
    change = compare_locks(load_lock(base), load_lock(head))[0]
    delta = next(item for item in _metadata_deltas(change) if item["key"] == "source")
    assert delta["status"] == "changed"
    assert delta["action"] == "info"
