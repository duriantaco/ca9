from __future__ import annotations

import json

import pytest

from ca9.review.locks import compare_locks, load_lock
from ca9.review.service import review_lockfiles


def _lock(tmp_path, name, record):
    path = tmp_path / name
    path.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"sample": "*"}},
                    "node_modules/sample": record,
                },
            }
        )
    )
    return path


@pytest.mark.parametrize(
    "before,after",
    [
        (["old metadata"], ["new metadata"]),
        ([], False),
        ({"version": []}, {"version": {}}),
        ({"cpu": [1]}, {"cpu": [2]}),
    ],
)
def test_changed_malformed_record_retains_distinct_identity(tmp_path, before, after):
    base = _lock(tmp_path, "base.json", before)
    head = _lock(tmp_path, "head.json", after)

    change = compare_locks(load_lock(base), load_lock(head))[0]
    report = review_lockfiles(base, head, scan_artifacts=False)

    assert change.status == "changed"
    assert report.summary["packages_changed"] == 1
    assert report.decision == "incomplete"
    assert report.exit_code == 2
    assert report.issues


@pytest.mark.parametrize("record", [[], False, {"version": []}, {"dependencies": []}])
def test_unchanged_structural_error_remains_invalid(tmp_path, record):
    base = _lock(tmp_path, "base.json", record)
    head = _lock(tmp_path, "head.json", record)

    report = review_lockfiles(base, head, scan_artifacts=False)

    assert report.summary["packages_unchanged"] == 1
    assert not report.complete
    assert report.exit_code == 2
    assert report.issues


def test_unchanged_unavailable_artifact_remains_outside_update_scope(tmp_path):
    # Valid metadata with absent artifact evidence is distinct from bad schema.
    record = {"version": "1.0.0"}
    base = _lock(tmp_path, "base.json", record)
    head = _lock(tmp_path, "head.json", record)

    report = review_lockfiles(base, head, scan_artifacts=False)

    assert report.complete
    assert report.exit_code == 0
    assert report.summary["packages_reviewed"] == 0
