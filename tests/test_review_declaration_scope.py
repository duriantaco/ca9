from __future__ import annotations

import pytest

from test_dependency_review import Registry


@pytest.mark.parametrize(
    "before_enabled,after_enabled,expected",
    [
        (False, True, "added"),
        (True, False, "removed"),
    ],
)
def test_known_native_install_declaration_compares_despite_native_code_gap(
    tmp_path, monkeypatch, before_enabled, after_enabled, expected
):
    registry = Registry(tmp_path, monkeypatch)
    before = registry.release(
        "1.0.0", manifest={"gypfile": before_enabled}, files={"binding.gyp": "{}"}
    )
    after = registry.release(
        "2.0.0", manifest={"gypfile": after_enabled}, files={"binding.gyp": "{}"}
    )

    report = registry.review(registry.lock("base.json", before), registry.lock("head.json", after))

    assert not report.complete
    assert report.decision == "incomplete"
    hook = next(
        delta
        for delta in report.packages[0]["deltas"]
        if delta["kind"] == "lifecycle_script" and delta["key"] == "install"
    )
    assert hook["status"] == expected
    assert hook["action"] == ("review" if after_enabled else "info")


def test_invalid_script_metadata_still_prevents_an_added_declaration_claim(tmp_path, monkeypatch):
    registry = Registry(tmp_path, monkeypatch)
    before = registry.release("1.0.0", manifest={"scripts": []})
    after = registry.release(
        "2.0.0",
        manifest={"scripts": {"install": "node setup.js"}},
        files={"setup.js": "console.log('fixture');"},
    )

    report = registry.review(registry.lock("base.json", before), registry.lock("head.json", after))

    assert not report.complete
    hook = next(
        delta
        for delta in report.packages[0]["deltas"]
        if delta["kind"] == "lifecycle_script" and delta["key"] == "install"
    )
    assert hook["status"] == "uninspectable"
