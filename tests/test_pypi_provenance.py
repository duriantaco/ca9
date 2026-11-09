"""PyPI provenance regressions, with documents shaped like the live PyPI responses.

Shapes checked on 2026-11-07 with read-only GETs:
https://pypi.org/simple/sampleproject/ (Accept: application/vnd.pypi.simple.v1+json)
lists files with ``provenance`` (an integrity URL or null), ``upload-time`` and ``yanked``;
https://pypi.org/integrity/sampleproject/4.0.0/sampleproject-4.0.0-py3-none-any.whl/provenance
returns ``{"version": 1, "attestation_bundles": [{"publisher": {"kind": "GitHub",
"repository": "pypa/sampleproject", "workflow": "release.yml", "environment": "",
"claims": null}, "attestations": [...]}]}``; the 3.0.0 wheel's provenance URL is a 404.
"""

from __future__ import annotations

import pytest

from ca9 import api, pypi_provenance

SIMPLE = "https://pypi.org/simple/demo/"
ORIGINAL = {"kind": "GitHub", "repository": "acme/demo", "workflow": "release.yml"}


class FakePyPI:
    def __init__(self, monkeypatch):
        self.documents: dict[str, object] = {}
        self.requests: list[str] = []
        self.files: list[dict] = []
        monkeypatch.setattr(pypi_provenance, "_fetch_json", self.fetch)

    def fetch(self, url, *, max_bytes, accept="application/json"):
        self.requests.append(url)
        if url == SIMPLE:
            return {"meta": {"api-version": "1.4"}, "name": "demo", "files": self.files}
        document = self.documents.get(url)
        if isinstance(document, Exception):
            raise document
        if document is None:
            raise pypi_provenance.NotFound(f"HTTP 404 from {url}")
        return document

    def release(self, version, day, *, publisher=ORIGINAL, sdist_publisher=None, yanked=False):
        for filename, who in (
            (f"demo-{version}-py3-none-any.whl", publisher),
            (f"demo-{version}.tar.gz", sdist_publisher or publisher),
        ):
            provenance = None
            if who is not None:
                provenance = f"https://pypi.org/integrity/demo/{version}/{filename}/provenance"
                self.documents[provenance] = {
                    "version": 1,
                    "attestation_bundles": [
                        {
                            "publisher": {"environment": "", "claims": None, **who},
                            "attestations": [{"version": 1}],
                        }
                    ],
                }
            self.files.append(
                {
                    "filename": filename,
                    "hashes": {"sha256": "0" * 64},
                    "provenance": provenance,
                    "upload-time": f"2026-10-{day:02d}T10:00:00.000000Z",
                    "url": f"https://files.pythonhosted.org/packages/xx/{filename}",
                    "yanked": yanked,
                }
            )


@pytest.fixture
def pypi(monkeypatch):
    return FakePyPI(monkeypatch)


def _history(pypi):
    for index, version in enumerate(("1.0.0", "1.1.0", "1.2.0")):
        pypi.release(version, index + 1)


def test_release_without_attestations_after_attested_history_regresses(pypi):
    _history(pypi)
    pypi.release("1.3.0", 10, publisher=None)

    result = api.check_provenance("pypi", "demo", "1.3.0")

    assert result["status"] == "regressed"
    evidence = result["evidence"]
    assert evidence["previous_with_provenance"] == ["1.2.0", "1.1.0", "1.0.0"]
    assert evidence["this_version"]["attested_files"] == 0
    assert evidence["previous_publishers"] == [ORIGINAL]
    assert "1.2.0" in result["reason"]


@pytest.mark.parametrize(
    "publisher",
    [
        {"kind": "GitHub", "repository": "evil/demo", "workflow": "release.yml"},
        {"kind": "GitHub", "repository": "acme/demo", "workflow": "pwn.yml"},
        {"kind": "GitLab", "repository": "acme/demo", "workflow_filepath": ".gitlab-ci.yml"},
    ],
)
def test_release_from_a_different_trusted_publisher_regresses(pypi, publisher):
    _history(pypi)
    pypi.release("1.3.0", 10, publisher=publisher)

    result = api.check_provenance("pypi", "demo", "1.3.0")

    assert result["status"] == "regressed"
    assert result["evidence"]["this_version"]["publishers"] == [publisher]
    assert result["evidence"]["previous_publishers"] == [ORIGINAL]


def test_files_uploaded_without_attestations_into_a_fully_attested_line_regress(pypi):
    _history(pypi)
    pypi.release("1.3.0", 10, sdist_publisher=None)
    pypi.files[-1]["provenance"] = None

    result = api.check_provenance("pypi", "demo", "1.3.0")

    assert result["status"] == "regressed"
    assert result["evidence"]["files_without_provenance"] == ["demo-1.3.0.tar.gz"]


def test_same_publisher_new_environment_or_partly_attested_history_is_ok(pypi):
    for index, version in enumerate(("1.0.0", "1.1.0", "1.2.0")):
        pypi.release(version, index + 1)
        pypi.files[-1]["provenance"] = None
    pypi.release("1.3.0", 10, publisher={**ORIGINAL, "environment": "pypi"})
    pypi.files[-1]["provenance"] = None

    result = api.check_provenance("pypi", "demo", "1.3.0")

    assert result["status"] == "ok"
    assert result["evidence"]["previous_with_provenance"] == ["1.2.0", "1.1.0", "1.0.0"]


def test_projects_that_never_attested_are_ok(pypi):
    for index, version in enumerate(("1.0.0", "1.1.0", "1.3.0")):
        pypi.release(version, index + 1, publisher=None)

    result = api.check_provenance("pypi", "demo", "1.3.0")

    assert result["status"] == "ok"
    assert result["evidence"]["previous_with_provenance"] == []


def test_prereleases_and_later_uploads_are_not_history(pypi):
    pypi.release("0.9.0", 1, publisher=None)
    pypi.release("1.0.0rc1", 2)
    pypi.release("1.1.0", 20)
    pypi.release("1.0.1", 10, publisher=None)

    result = api.check_provenance("pypi", "demo", "1.0.1")

    assert result["status"] == "ok"
    assert result["evidence"]["previous_versions_checked"] == ["0.9.0"]


def test_yanking_the_attested_releases_does_not_hide_them(pypi):
    pypi.release("1.0.0", 1, yanked=True)
    pypi.release("1.1.0", 2, yanked="compromised account cleanup")
    pypi.release("1.2.0", 10, publisher=None)

    result = api.check_provenance("pypi", "demo", "1.2.0")

    assert result["status"] == "regressed"
    assert result["evidence"]["previous_with_provenance"] == ["1.1.0", "1.0.0"]


def test_backport_on_a_line_that_never_attested_after_newer_attested_lines(pypi):
    pypi.release("1.4.0", 1, publisher=None)
    pypi.release("2.0.0", 2)
    pypi.release("2.1.0", 3)
    pypi.release("1.4.1", 10, publisher=None)

    result = api.check_provenance("pypi", "demo", "1.4.1")

    assert result["status"] == "regressed"
    assert result["evidence"]["line"] == "newer"


@pytest.mark.parametrize(
    ("setup", "reason"),
    [
        (lambda pypi: pypi.release("1.0.0", 1), "no earlier stable release"),
        (lambda pypi: (_history(pypi), pypi.release("1.3.0", 10)), "not in registry metadata"),
    ],
)
def test_first_release_or_unknown_version_is_unknown(pypi, setup, reason):
    setup(pypi)

    result = api.check_provenance("pypi", "demo", "1.0.0" if "earlier" in reason else "9.9.9")

    assert result["status"] == "unknown"
    assert reason in result["reason"]


def test_network_errors_are_unknown(pypi, monkeypatch):
    _history(pypi)
    pypi.release(
        "1.3.0", 10, publisher={"kind": "GitHub", "repository": "evil/demo", "workflow": "x.yml"}
    )
    url = "https://pypi.org/integrity/demo/1.2.0/demo-1.2.0-py3-none-any.whl/provenance"
    pypi.documents[url] = OSError("connection reset")

    broken_history = api.check_provenance("pypi", "demo", "1.3.0")

    def offline(url, *, max_bytes, accept="application/json"):
        raise OSError("network down")

    monkeypatch.setattr(pypi_provenance, "_fetch_json", offline)
    offline_result = api.check_provenance("pypi", "demo", "1.3.0")

    assert broken_history["status"] == "unknown"
    assert offline_result["status"] == "unknown"
    assert "network down" in offline_result["reason"]


def test_results_are_cached_and_only_pypi_and_npm_are_checked(pypi, tmp_path):
    _history(pypi)
    pypi.release("1.3.0", 10, publisher=None)

    first = api.check_provenance("pypi", "Demo", "1.3.0", cache_dir=tmp_path)
    count = len(pypi.requests)
    second = api.check_provenance("pypi", "demo", "1.3.0", cache_dir=tmp_path)

    assert first["status"] == second["status"] == "regressed"
    assert second["source"] == "cache"
    assert len(pypi.requests) == count
    assert api.check_provenance("cargo", "serde", "1.0.0")["status"] == "not_applicable"
    assert api.check_provenance("pypi", "../x", "1.0")["status"] == "unknown"


def test_only_pypi_org_integrity_urls_are_fetched(pypi):
    _history(pypi)
    pypi.release("1.3.0", 10)
    pypi.files[-2]["provenance"] = "https://evil.example/integrity/demo/1.3.0/x/provenance"

    result = api.check_provenance("pypi", "demo", "1.3.0")

    assert result["status"] == "ok"
    assert all(url.startswith("https://pypi.org/") for url in pypi.requests)
