from __future__ import annotations

import json

import pytest

from ca9.review.behavior import BehaviorFact
from ca9.review.render import write_json, write_markdown
from ca9.review.service import Inspection, _behavior_deltas
from test_dependency_review import Registry


def _url(secret):
    return f"https://qa-user:{secret}@packages.invalid/helper.tgz?token={secret}#private"


@pytest.mark.parametrize(
    "kind,key,make_value",
    [
        ("dependency", "dependencies:helper", lambda url: url),
        ("lifecycle_script", "postinstall", lambda url: {"command": f"echo '{url}'"}),
        ("code_observation", "rule:file.js", lambda url: {"evidence_preview": json.dumps(url)}),
    ],
)
def test_sensitive_value_changes_stay_comparable_without_exposing_values(kind, key, make_value):
    before = Inspection(
        "verified", (BehaviorFact(kind, key, make_value(_url("QA_SECRET_A")), "review"),)
    )
    after = Inspection(
        "verified", (BehaviorFact(kind, key, make_value(_url("QA_SECRET_B")), "review"),)
    )

    delta = _behavior_deltas(before, after)[0]

    assert delta["status"] == "changed"
    assert delta["action"] == "review"
    assert delta["base"] == delta["head"]
    assert delta["base_identity_sha256"] != delta["head_identity_sha256"]
    output = json.dumps(delta)
    assert "QA_SECRET_A" not in output
    assert "QA_SECRET_B" not in output
    assert "qa-user" not in output
    assert "private" not in output
    assert "packages.invalid" in output


def test_identical_sensitive_values_do_not_create_a_change():
    value = _url("QA_SECRET_A")
    inspection = Inspection("verified", (BehaviorFact("dependency", "helper", value, "review"),))

    delta = _behavior_deltas(inspection, inspection)[0]

    assert delta["status"] == "unchanged"
    assert delta["action"] == "info"
    assert "QA_SECRET_A" not in json.dumps(delta)
    assert delta["base_identity_sha256"] == delta["head_identity_sha256"]


def test_verified_artifact_dependency_urls_are_redacted_in_both_reports(tmp_path, monkeypatch):
    registry = Registry(tmp_path, monkeypatch)
    base = registry.lock("base.json", registry.release("1.0.0"))
    head = registry.lock(
        "head.json",
        registry.release(
            "2.0.0",
            manifest={
                "dependencies": {"helper": _url("QA_SECRET_MANIFEST")},
            },
        ),
    )

    report = registry.review(base, head)

    assert report.decision == "review"
    assert report.complete
    for output in (write_json(report), write_markdown(report)):
        assert "QA_SECRET_MANIFEST" not in output
        assert "qa-user" not in output
        assert "#private" not in output
        assert "packages.invalid" in output
