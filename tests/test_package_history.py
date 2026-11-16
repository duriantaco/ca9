from __future__ import annotations

import urllib.error
from datetime import datetime, timedelta, timezone

import pytest

from ca9 import api
from ca9.package_history import package_history

NOW = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)
PYPI_URL = "https://pypi.org/pypi/{name}/json"
NPM_URL = "https://registry.npmjs.org/{name}"


def _ago(days: float) -> str:
    return (NOW - timedelta(days=days)).isoformat().replace("+00:00", "Z")


def _pypi(release_days: list[float], **info) -> dict:
    releases = {
        f"0.{index}.0": [{"upload_time_iso_8601": _ago(days), "yanked": False}]
        for index, days in enumerate(release_days)
    }
    return {"info": info, "releases": releases, "ownership": info.pop("ownership", None)}


def _npm(release_days: list[float], **extra) -> dict:
    versions = {f"1.{index}.0": {} for index in range(len(release_days))}
    time = {f"1.{index}.0": _ago(days) for index, days in enumerate(release_days)}
    time["created"] = _ago(max(release_days))
    time["modified"] = _ago(min(release_days))
    return {"name": "pkg", "versions": versions, "time": time, **extra}


class _Registry:
    def __init__(self, documents: dict[str, object]) -> None:
        self.documents = documents
        self.calls: list[str] = []

    def __call__(self, url: str):
        self.calls.append(url)
        document = self.documents.get(url)
        if document is None:
            raise urllib.error.HTTPError(url, 404, "Not Found", None, None)
        if isinstance(document, Exception):
            raise document
        return document


def _check(registry, ecosystem, name, tmp_path, **kwargs):
    return package_history(ecosystem, name, fetch=registry, cache_dir=tmp_path, now=NOW, **kwargs)


@pytest.mark.parametrize(
    "release_days, status",
    [
        ([4], "new"),
        ([29, 2, 1], "new"),
        ([82], "thin_history"),
        ([120, 100], "thin_history"),
        ([120, 100, 90], "established"),
        ([181], "established"),
        ([2000, 1500, 3], "established"),
    ],
)
def test_pypi_status_follows_first_publish_and_release_count(tmp_path, release_days, status):
    registry = _Registry({PYPI_URL.format(name="pkg"): _pypi(release_days)})
    result = _check(registry, "pypi", "pkg", tmp_path)
    assert result["status"] == status
    assert result["age_days"] == int(max(release_days))
    assert result["release_count"] == len(release_days)
    assert result["first_published_at"] == _ago(max(release_days)).split(".")[0].rstrip("Z") + "Z"
    assert result["registry_url"] == "https://pypi.org/project/pkg/"
    assert result["report_url"] == "https://pypi.org/project/pkg/submit-malware-report/"
    assert result["reason"] is None


def test_first_publish_is_the_earliest_file_not_the_newest_file_of_a_release(tmp_path):
    document = _pypi([400])
    document["releases"]["0.0.0"].append({"upload_time_iso_8601": _ago(1), "yanked": False})
    registry = _Registry({PYPI_URL.format(name="pkg"): document})
    result = _check(registry, "pypi", "pkg", tmp_path)
    assert result["status"] == "established"
    assert result["age_days"] == 400


def test_links_and_owners_are_reported_but_do_not_change_the_status(tmp_path):
    plain = _Registry({PYPI_URL.format(name="pkg"): _pypi([3])})
    dressed = _Registry(
        {
            PYPI_URL.format(name="pkg"): _pypi(
                [3],
                project_urls={
                    "Docs": "https://example.test",
                    "Source": "https://github.com/a/b.git",
                },
                ownership={"organization": None, "roles": [{"role": "Owner", "user": "someone"}]},
            )
        }
    )
    bare = _check(plain, "pypi", "pkg", tmp_path / "a")
    linked = _check(dressed, "pypi", "pkg", tmp_path / "b")
    assert bare["status"] == linked["status"] == "new"
    assert bare["source_url"] is None and bare["owners"] == []
    assert linked["source_url"] == "https://github.com/a/b"
    assert linked["owners"] == ["someone"]


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/a/b",
        "https://user:secret@github.com/a/b",
        "https://github.com.evil.test/a/b",
        "javascript:alert(1)",
    ],
)
def test_untrustworthy_source_links_are_dropped(tmp_path, url):
    registry = _Registry({PYPI_URL.format(name="pkg"): _pypi([3], home_page=url)})
    assert _check(registry, "pypi", "pkg", tmp_path)["source_url"] is None


def test_missing_project_and_project_without_files(tmp_path):
    registry = _Registry({PYPI_URL.format(name="empty"): {"info": {}, "releases": {"1.0": []}}})
    assert _check(registry, "pypi", "nope", tmp_path)["status"] == "missing"
    assert _check(registry, "pypi", "empty", tmp_path)["status"] == "missing"


@pytest.mark.parametrize(
    "document",
    [
        urllib.error.HTTPError("u", 503, "down", None, None),
        OSError("offline"),
        ["not", "a", "dict"],
        {},
    ],
)
def test_unreadable_registry_is_unknown_not_safe(tmp_path, document):
    registry = _Registry({PYPI_URL.format(name="pkg"): document})
    result = _check(registry, "pypi", "pkg", tmp_path)
    assert result["status"] == "unknown"
    assert result["reason"]


def test_established_answer_is_served_from_cache_without_a_lookup(tmp_path):
    registry = _Registry({PYPI_URL.format(name="pkg"): _pypi([900, 700, 30])})
    first = _check(registry, "pypi", "pkg", tmp_path)
    second = _check(registry, "pypi", "pkg", tmp_path)
    assert first["status"] == second["status"] == "established"
    assert first["source"] == "pypi" and second["source"] == "cache"
    assert len(registry.calls) == 1


def test_young_answer_is_looked_up_again_every_time(tmp_path):
    registry = _Registry({PYPI_URL.format(name="pkg"): _pypi([5])})
    _check(registry, "pypi", "pkg", tmp_path)
    _check(registry, "pypi", "pkg", tmp_path)
    assert len(registry.calls) == 2


def test_npm_uses_created_time_maintainers_and_repository(tmp_path):
    document = _npm(
        [10, 2],
        maintainers=[{"name": "alice", "email": "a@example.test"}],
        repository={"type": "git", "url": "git+https://github.com/a/b.git"},
    )
    registry = _Registry({NPM_URL.format(name="pkg"): document})
    result = _check(registry, "npm", "pkg", tmp_path)
    assert result["status"] == "new"
    assert result["age_days"] == 10
    assert result["release_count"] == 2
    assert result["owners"] == ["alice"]
    assert result["source_url"] == "https://github.com/a/b"
    assert result["registry_url"] == "https://www.npmjs.com/package/pkg"


def test_scoped_npm_name_is_looked_up_and_linked(tmp_path):
    registry = _Registry({NPM_URL.format(name="@scope%2Fpkg"): _npm([500, 400, 300])})
    result = _check(registry, "npm", "@scope/pkg", tmp_path)
    assert result["status"] == "established"
    assert result["registry_url"] == "https://www.npmjs.com/package/@scope/pkg"


def test_thresholds_are_configurable_and_validated(tmp_path):
    registry = _Registry({PYPI_URL.format(name="pkg"): _pypi([45, 40, 35])})
    assert _check(registry, "pypi", "pkg", tmp_path, new_days=60)["status"] == "new"
    for bad in (
        {"new_days": -1},
        {"new_days": 200},
        {"max_thin_releases": True},
        {"young_days": 1.5},
    ):
        result = _check(registry, "pypi", "pkg", tmp_path, **bad)
        assert result["status"] == "unknown" and result["source"] == "policy"


@pytest.mark.parametrize("ecosystem, name", [("cargo", "pkg"), ("pypi", ""), ("", "pkg")])
def test_unsupported_input_is_unknown(tmp_path, ecosystem, name):
    result = _check(_Registry({}), ecosystem, name, tmp_path)
    assert result["status"] == "unknown" and result["source"] == "unsupported"


def test_api_wrapper_returns_unknown_instead_of_raising(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("broken")

    monkeypatch.setattr(api, "_optional_function", lambda module, name: boom)
    result = api.package_history("pypi", "pkg")
    assert result["status"] == "unknown"
    assert "broken" in result["reason"]
    monkeypatch.setattr(api, "_optional_function", lambda module, name: None)
    assert api.package_history("pypi", "pkg")["status"] == "unknown"
    monkeypatch.setattr(
        api, "_optional_function", lambda module, name: lambda *a, **k: {"status": "?"}
    )
    assert api.package_history("pypi", "pkg")["status"] == "unknown"
