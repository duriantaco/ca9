from __future__ import annotations

import json
import urllib.error
from datetime import datetime, timezone

import pytest

from ca9 import npm_publisher
from ca9.core.models import Package, SourceEvidence

NOW = datetime(2018, 11, 26, tzinfo=timezone.utc)


def _package(name="event-stream", version="3.3.5", **overrides):
    metadata = {
        "source_kind": "registry",
        "lock_path": f"node_modules/{name}",
        "installed_names": [name],
        "requested_specifiers": [version],
    }
    metadata.update(overrides.pop("metadata", {}))
    return Package(
        name=name,
        version=version,
        ecosystem=overrides.pop("ecosystem", "npm"),
        dependency_kind=overrides.pop("dependency_kind", "direct"),
        source_registry=overrides.pop("source_registry", npm_publisher.REGISTRY_ORIGIN),
        evidence=overrides.pop(
            "evidence",
            (SourceEvidence(source="package-lock.json", reader="package-lock.json"),),
        ),
        metadata=metadata,
        **overrides,
    )


def _document(name="event-stream", *, new_version="3.3.5", new_publisher="right9ctrl"):
    return {
        "name": name,
        "time": {
            "3.3.4": "2016-07-17T07:24:09.767Z",
            new_version: "2018-09-05T02:00:00.000Z",
            # npm has since removed this version's metadata, but its time
            # remains. It should not erase the replay of locked 3.3.5.
            "3.3.6": "2018-09-09T08:28:59.503Z",
        },
        "versions": {
            "3.3.4": {"_npmUser": {"name": "dominictarr"}},
            new_version: {"_npmUser": {"name": new_publisher}},
        },
    }


def _fetcher(monkeypatch, document, search=None):
    calls = []

    def fake_fetch(url, *, max_bytes):
        calls.append((url, max_bytes))
        if "/-/v1/search?" in url:
            return {"objects": []} if search is None else search
        return document

    monkeypatch.setattr(npm_publisher, "_fetch_json", fake_fetch)
    return calls


def _search_result(name, maintainer, weekly):
    return {
        "package": {
            "name": name,
            "maintainers": [{"username": maintainer}],
        },
        "downloads": {"weekly": weekly},
    }


def test_event_stream_replay_is_a_warning_with_publisher_evidence(monkeypatch):
    calls = _fetcher(monkeypatch, _document())

    findings, warnings = npm_publisher.scan_npm_publisher_changes([_package(), _package()], now=NOW)

    assert warnings == []
    assert len(findings) == 1
    finding = findings[0]
    assert finding.signal_type == "npm_publisher_change"
    assert finding.severity == "medium"
    assert finding.metadata["action"] == "warn"
    assert finding.signals[0].confidence == "medium"
    assert finding.metadata["new_publisher"] == "right9ctrl"
    assert finding.metadata["previous_publisher"] == "dominictarr"
    assert finding.metadata["handover_version"] == "3.3.5"
    assert finding.metadata["release_gap_days"] >= 180
    assert finding.evidence[0].source.path == "https://registry.npmjs.org/event-stream"
    assert "malware" not in finding.title.lower()
    assert sum("/-/v1/search" not in url for url, _ in calls) == 1


def test_old_unknown_publishers_do_not_hide_event_stream_handover(monkeypatch):
    document = _document()
    document["time"]["2.0.0"] = "2013-01-01T00:00:00Z"
    document["versions"]["2.0.0"] = {"version": "2.0.0"}
    _fetcher(monkeypatch, document)

    findings, warnings = npm_publisher.scan_npm_publisher_changes([_package()], now=NOW)

    assert len(findings) == 1
    assert len(warnings) == 1
    assert "first observed, not proven first ever" in warnings[0]
    assert findings[0].metadata["earlier_publisher_history_complete"] is False
    assert "first observed" in findings[0].metadata["publisher_history_caveat"]
    assert findings[0].evidence[0].metadata["previous_publisher"] == "dominictarr"


def test_established_publisher_on_another_package_suppresses(monkeypatch):
    search = {
        "objects": [
            _search_result("event-stream", "right9ctrl", 500_000),
            _search_result("unrelated-owner", "not-right9ctrl", 500_000),
            _search_result("established", "right9ctrl", 100_000),
        ],
        "total": 1000,
    }
    calls = _fetcher(monkeypatch, _document(), search)

    findings, warnings = npm_publisher.scan_npm_publisher_changes([_package()], now=NOW)

    assert findings == []
    assert warnings == []
    assert len(calls) == 2  # one packument and one search; no download API


@pytest.mark.parametrize(
    "search",
    [
        {"objects": [_search_result("event-stream", "right9ctrl", 500_000)]},
        {"objects": [_search_result("other", "someone-else", 500_000)]},
        {"objects": [_search_result("other", "right9ctrl", True)]},
        {"objects": [_search_result("other", "right9ctrl", "500000")]},
        {"objects": [_search_result("other", "right9ctrl", 99_999)]},
    ],
)
def test_search_result_must_prove_another_established_maintained_package(monkeypatch, search):
    _fetcher(monkeypatch, _document(), search)

    findings, _ = npm_publisher.scan_npm_publisher_changes([_package()], now=NOW)

    assert len(findings) == 1


def test_missing_weekly_downloads_keeps_finding_and_warns(monkeypatch):
    _fetcher(
        monkeypatch,
        _document(),
        {"objects": [{"package": {"name": "other", "maintainers": [{"username": "right9ctrl"}]}}]},
    )

    findings, warnings = npm_publisher.scan_npm_publisher_changes([_package()], now=NOW)

    assert len(findings) == 1
    assert "weekly download counts" in warnings[0]


def test_prerelease_does_not_create_handover(monkeypatch):
    document = _document(new_version="3.3.5-beta.1")
    document["time"]["3.3.5"] = "2018-09-06T02:00:00Z"
    document["versions"]["3.3.5"] = {"_npmUser": {"name": "right9ctrl"}}
    _fetcher(monkeypatch, document)

    findings, warnings = npm_publisher.scan_npm_publisher_changes([_package()], now=NOW)

    assert findings == []
    assert warnings == []


def test_trusted_publisher_does_not_create_handover(monkeypatch):
    document = _document()
    document["versions"]["3.3.5"]["_npmUser"]["trustedPublisher"] = {"id": "github:user/repo"}
    calls = _fetcher(monkeypatch, document)

    findings, warnings = npm_publisher.scan_npm_publisher_changes([_package()], now=NOW)

    assert findings == []
    assert warnings == []
    assert len(calls) == 1


def test_later_locked_trusted_release_does_not_hide_untrusted_handover(monkeypatch):
    document = _document()
    document["versions"]["3.3.6"] = {"_npmUser": {"name": "right9ctrl"}}
    document["time"]["3.3.7"] = "2018-10-01T00:00:00Z"
    document["versions"]["3.3.7"] = {
        "_npmUser": {"name": "right9ctrl", "trustedPublisher": {"id": "github:user/repo"}}
    }
    _fetcher(monkeypatch, document)

    findings, warnings = npm_publisher.scan_npm_publisher_changes(
        [_package(version="3.3.7")], now=NOW
    )

    assert len(findings) == 1
    assert warnings == []
    assert findings[0].metadata["handover_version"] == "3.3.5"


def test_old_locked_version_and_different_later_publisher_are_not_flagged(monkeypatch):
    document = _document()
    document["versions"]["3.3.6"] = {"_npmUser": {"name": "right9ctrl"}}
    document["time"]["3.3.7"] = "2018-10-01T00:00:00Z"
    document["versions"]["3.3.7"] = {"_npmUser": {"name": "another"}}
    _fetcher(monkeypatch, document)

    findings, warnings = npm_publisher.scan_npm_publisher_changes(
        [_package(version="3.3.4"), _package(version="3.3.7")], now=NOW
    )

    assert findings == []
    assert warnings == []


def test_missing_prior_publisher_cannot_prove_handover(monkeypatch):
    document = _document()
    del document["versions"]["3.3.4"]["_npmUser"]
    calls = _fetcher(monkeypatch, document)

    findings, warnings = npm_publisher.scan_npm_publisher_changes([_package()], now=NOW)

    assert findings == []
    assert "publisher history before locked release is incomplete" in warnings[0]
    assert len(calls) == 1


def test_unknown_intervening_release_breaks_dormancy_gap(monkeypatch):
    document = _document()
    document["time"]["3.3.4-unknown"] = "2018-08-01T00:00:00Z"
    _fetcher(monkeypatch, document)

    findings, warnings = npm_publisher.scan_npm_publisher_changes([_package()], now=NOW)

    assert findings == []
    assert "publisher history before locked release is incomplete" in warnings[0]


def test_429_search_retains_review_finding(monkeypatch):
    def fake_fetch(url, *, max_bytes):
        if "/-/v1/search?" in url:
            raise npm_publisher.RegistryFetchError("HTTP 429")
        return _document()

    monkeypatch.setattr(npm_publisher, "_fetch_json", fake_fetch)

    findings, warnings = npm_publisher.scan_npm_publisher_changes([_package()], now=NOW)

    assert len(findings) == 1
    assert "429" in " ".join(warnings)
    assert "review finding kept" in warnings[0]


@pytest.mark.parametrize(
    "document",
    [
        {"name": "event-stream", "versions": {}},
        {"name": "other", "time": {}, "versions": {}},
        {
            "name": "event-stream",
            "time": {"3.3.5": "not-a-date"},
            "versions": {"3.3.5": {"_npmUser": {"name": "new"}}},
        },
    ],
)
def test_bad_registry_metadata_warns_without_finding(monkeypatch, document):
    _fetcher(monkeypatch, document)

    findings, warnings = npm_publisher.scan_npm_publisher_changes([_package()], now=NOW)

    assert findings == []
    assert len(warnings) == 1
    assert "skipped event-stream@3.3.5" in warnings[0]


def test_source_and_alias_filters_make_no_network_requests(monkeypatch):
    calls = _fetcher(monkeypatch, _document())
    base = _package()
    filtered = [
        _package(dependency_kind="transitive"),
        _package(source_registry="https://registry.npmjs.org.evil.example"),
        _package(source_registry="https://private.example"),
        _package(metadata={"requested_specifiers": ["npm:other@3.3.5"]}),
        _package(metadata={"source_kind": "remote"}),
        _package(metadata={"identity_ambiguous": True}),
        _package(metadata={"identity_unverified": True}),
        _package(metadata={"self_name": "other"}),
        _package(metadata={"installed_names": ["other"]}),
        _package(evidence=()),
        _package(ecosystem="pypi"),
        _package(version="3.3.5-beta.1"),
    ]

    findings, warnings = npm_publisher.scan_npm_publisher_changes(filtered, now=NOW)

    assert findings == []
    assert warnings == []
    assert calls == []
    assert base.metadata["source_kind"] == "registry"


def test_scoped_package_name_is_encoded_for_fixed_registry_url(monkeypatch):
    document = _document(name="@scope/widget")
    calls = _fetcher(monkeypatch, document)

    findings, warnings = npm_publisher.scan_npm_publisher_changes(
        [_package(name="@scope/widget")], now=NOW
    )

    assert len(findings) == 1
    assert warnings == []
    assert calls[0] == (
        "https://registry.npmjs.org/%40scope%2Fwidget",
        npm_publisher.MAX_PACKUMENT_BYTES,
    )


class _Response:
    def __init__(
        self, body=b"{}", *, url="https://registry.npmjs.org/example", headers=None, status=200
    ):
        self.body = body
        self.url = url
        self.headers = headers or {}
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def getcode(self):
        return self.status

    def geturl(self):
        return self.url

    def read(self, size):
        return self.body[:size]


def test_http_fetch_rejects_off_origin_redirect_and_oversize(monkeypatch):
    url = "https://registry.npmjs.org/example"
    responses = iter(
        [
            _Response(url="https://evil.example/example"),
            _Response(headers={"Content-Length": "100"}),
            _Response(body=b"0123456789"),
            _Response(body=json.dumps({"ok": True}).encode()),
        ]
    )

    class _Opener:
        def open(self, request, timeout):
            assert timeout == npm_publisher.HTTP_TIMEOUT_SECONDS
            return next(responses)

    monkeypatch.setattr(npm_publisher.urllib.request, "build_opener", lambda *_: _Opener())
    with pytest.raises(npm_publisher.RegistryFetchError, match="off-origin"):
        npm_publisher._fetch_json("https://registry.npmjs.org.evil.example/x", max_bytes=10)
    with pytest.raises(npm_publisher.RegistryFetchError, match="redirect"):
        npm_publisher._fetch_json(url, max_bytes=10)
    with pytest.raises(npm_publisher.RegistryFetchError, match="exceeds"):
        npm_publisher._fetch_json(url, max_bytes=10)
    with pytest.raises(npm_publisher.RegistryFetchError, match="exceeds"):
        npm_publisher._fetch_json(url, max_bytes=5)
    assert npm_publisher._fetch_json(url, max_bytes=20) == {"ok": True}


def test_http_fetch_disables_redirects_and_rejects_302(monkeypatch):
    url = "https://registry.npmjs.org/example"

    class _Opener:
        def open(self, request, timeout):
            raise urllib.error.HTTPError(url, 302, "Found", {}, None)

    def fake_build_opener(handler):
        assert isinstance(handler, npm_publisher._NoRedirect)
        return _Opener()

    monkeypatch.setattr(npm_publisher.urllib.request, "build_opener", fake_build_opener)
    with pytest.raises(npm_publisher.RegistryFetchError, match="HTTP 302"):
        npm_publisher._fetch_json(url, max_bytes=100)
