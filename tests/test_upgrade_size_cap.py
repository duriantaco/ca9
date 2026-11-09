from __future__ import annotations

import json

from packaging.tags import sys_tags
from tests.test_upgrade_review import _kinds, _one, registry

__all__ = ["registry"]

HERE = str(next(iter(sys_tags())))
MB = 1024 * 1024


def _declare_sizes(registry, name, version, size, kinds):
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    document = json.loads(registry.documents[url])
    for item in document["urls"]:
        if item["packagetype"] in kinds:
            item["size"] = size
    registry.documents[url] = json.dumps(document).encode()


def test_oversized_secondary_comparison_still_reviews_the_primary(registry):
    base = {"pkg/__init__.py": "X = 1\n"}
    registry.pypi("bigsdist", "1.0", wheel=base, sdist=base)
    registry.pypi(
        "bigsdist",
        "1.1",
        wheel={**base, "bigsdist-boot.pth": "import os; os.system('id')\n"},
        sdist=base,
        wheel_tag=HERE,
    )
    for version in ("1.0", "1.1"):
        _declare_sizes(registry, "bigsdist", version, 900 * MB, {"sdist"})

    result, receipt = _one("pypi", "bigsdist", "1.0", "1.1")

    assert result["status"] == "reviewed"
    assert _kinds(result, "block") == ["new_pth_code"]
    assert result["complete"] is False
    assert any("bigsdist-1.1.tar.gz" in item for item in result["limitations"])
    assert receipt["complete"] is False


def test_a_sixty_megabyte_release_is_reviewed_by_default(registry):
    base = {"pkg/__init__.py": "X = 1\n"}
    registry.pypi("midsize", "1.0", wheel=base)
    registry.pypi("midsize", "1.1", wheel={**base, "pkg/extra.py": "Y = 2\n"})
    for version in ("1.0", "1.1"):
        _declare_sizes(registry, "midsize", version, 62 * MB, {"bdist_wheel"})

    result, _ = _one("pypi", "midsize", "1.0", "1.1")

    assert result["status"] == "reviewed"


def test_an_oversized_primary_artifact_is_still_skipped(registry):
    base = {"pkg/__init__.py": "X = 1\n"}
    registry.pypi("huge", "1.0", wheel=base)
    registry.pypi("huge", "1.1", wheel=base)
    _declare_sizes(registry, "huge", "1.1", 900 * MB, {"bdist_wheel"})

    result, receipt = _one("pypi", "huge", "1.0", "1.1")

    assert result["reason"] == "artifact_too_large"
    assert receipt["complete"] is False
