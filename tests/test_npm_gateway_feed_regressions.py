from __future__ import annotations

import io
import json
from datetime import datetime, timezone

import pytest

import ca9.runtime.npm_gateway as gateway_module
from ca9.cli import _gateway_ledger_events
from ca9.package_feed import FeedStatus, feed_status, update_feed_from_source
from ca9.package_policy import MalwarePolicy, ModePolicy, PackageAgePolicy, PackagePolicy
from ca9.runtime.npm_gateway import NpmGatewayState, NpmMetadataGateway

NOW = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
PACKUMENT = b'{"name":"fixture-package","versions":{"1.0.0":{}},"dist-tags":{"latest":"1.0.0"}}'


def _status(tmp_path, state, action, snapshot=None):
    return FeedStatus(
        cache_dir=tmp_path,
        state=state,
        action=action,
        reason="Local fixture feed status",
        snapshot=snapshot,
    )


def _snapshot(tmp_path, *, expired=False):
    path = tmp_path / "fixture-feed.json"
    path.write_text(
        json.dumps(
            {
                "schema": "ca9.feed.v1",
                "created_at": "2026-09-06T00:00:00Z",
                "expires_at": "2026-09-07T00:00:00Z" if expired else "2026-09-09T00:00:00Z",
                "datasets": {
                    "npm-malware": {"packages": []},
                    "pypi-malware": {"packages": []},
                    "npm-releases": {"packages": {}},
                    "pypi-releases": {"packages": {}},
                },
            }
        )
    )
    return update_feed_from_source(path, cache_dir=tmp_path / "cache")


def _request(state, monkeypatch):
    """Run the real handler's response path with in-memory transport only."""
    monkeypatch.setattr(
        gateway_module,
        "_fetch_upstream",
        lambda url: (200, {"Content-Type": "application/json"}, PACKUMENT),
    )
    handler = object.__new__(gateway_module._handler_for_state(state))
    handler.client_address = ("127.0.0.1", 12345)
    handler.path = "/fixture-package"
    handler.wfile = io.BytesIO()
    response = {"headers": {}}
    handler.send_response = lambda status: response.update(status=status)
    handler.send_header = lambda name, value: response["headers"].update({name: value})
    handler.end_headers = lambda: None
    handler.do_GET()
    return response, handler.wfile.getvalue()


def test_missing_feed_does_not_return_no_rewrite_under_block_policy(tmp_path):
    state = NpmGatewayState(
        upstream_registry="https://registry.npmjs.org",
        policy=PackagePolicy(mode=ModePolicy(offline="block")),
        feed_cache_dir=tmp_path / "missing",
    )

    with pytest.raises(ValueError, match="npm policy feed is missing") as caught:
        gateway_module._rewrite_metadata(PACKUMENT, state)

    assert caught.value.package == "fixture-package"
    assert caught.value.failure_kind == "feed_missing"


@pytest.mark.parametrize("state_name", ["missing", "stale"])
@pytest.mark.parametrize("offline_mode", ["warn", "block"])
def test_fail_closed_malware_blocks_unavailable_feed(tmp_path, state_name, offline_mode):
    cache_dir = tmp_path / "missing"
    if state_name == "stale":
        cache_dir = _snapshot(tmp_path, expired=True).cache_dir
    state = NpmGatewayState(
        upstream_registry="https://registry.npmjs.org",
        policy=PackagePolicy(
            malware=MalwarePolicy(enabled=True, fail_closed=True),
            mode=ModePolicy(offline=offline_mode),
        ),
        feed_cache_dir=cache_dir,
        now=NOW,
    )

    with pytest.raises(ValueError, match=f"npm policy feed is {state_name}"):
        gateway_module._rewrite_metadata(PACKUMENT, state)


def test_stale_feed_honors_block_action_without_fail_closed(tmp_path):
    snapshot = _snapshot(tmp_path, expired=True)
    state = NpmGatewayState(
        upstream_registry="https://registry.npmjs.org",
        policy=PackagePolicy(mode=ModePolicy(offline="block")),
        feed_cache_dir=snapshot.cache_dir,
        now=NOW,
    )

    with pytest.raises(ValueError, match="npm policy feed is stale"):
        gateway_module._rewrite_metadata(PACKUMENT, state)


@pytest.mark.parametrize("state_name", ["missing", "stale"])
def test_permissive_offline_policy_preserves_no_rewrite(tmp_path, state_name):
    cache_dir = tmp_path / "missing"
    if state_name == "stale":
        cache_dir = _snapshot(tmp_path, expired=True).cache_dir
    state = NpmGatewayState(
        upstream_registry="https://registry.npmjs.org",
        policy=PackagePolicy(mode=ModePolicy(offline="warn")),
        feed_cache_dir=cache_dir,
        now=NOW,
    )

    assert gateway_module._rewrite_metadata(PACKUMENT, state) is None
    assert state.feed.state == state_name


def test_disabled_feed_checks_do_not_require_feed(tmp_path, monkeypatch):
    def unexpected_feed_load(**kwargs):
        pytest.fail("Disabled feed checks must not load feed data")

    monkeypatch.setattr(gateway_module, "feed_status", unexpected_feed_load)
    state = NpmGatewayState(
        upstream_registry="https://registry.npmjs.org",
        policy=PackagePolicy(
            malware=MalwarePolicy(enabled=False, fail_closed=True),
            package_age=PackageAgePolicy(enabled=False),
            mode=ModePolicy(offline="block"),
        ),
        feed_cache_dir=tmp_path,
    )

    assert gateway_module._rewrite_metadata(PACKUMENT, state) is None


@pytest.mark.parametrize("feed_state", ["missing", "tampered"])
def test_denied_feed_is_structured_http_failure_and_ledger_event(tmp_path, monkeypatch, feed_state):
    gateway = NpmMetadataGateway(policy=PackagePolicy(), feed_cache_dir=tmp_path)
    status = _status(tmp_path, feed_state, "block")
    monkeypatch.setattr(gateway_module, "feed_status", lambda **kwargs: status)

    response, body = _request(gateway.state, monkeypatch)
    _request(gateway.state, monkeypatch)

    assert response["status"] == 403
    assert response["headers"]["Content-Type"] == "text/plain; charset=utf-8"
    assert int(response["headers"]["Content-Length"]) == len(body)
    assert PACKUMENT not in body
    payload = gateway.to_dict()
    assert payload["rewrite_count"] == 0
    assert payload["removed_versions"] == []
    assert payload["feed_state"] == feed_state
    assert len(payload["evaluation_failures"]) == 1
    failure = payload["evaluation_failures"][0]
    assert failure["policy_id"] == "ca9.npm_gateway_evaluation_failed"
    assert failure["package"] == "fixture-package"
    assert failure["evidence"] == {"ecosystem": "npm", "failure_kind": f"feed_{feed_state}"}
    events = _gateway_ledger_events(payload, session_id="fixture-session")
    emitted = [event for event in events if event.event_kind == "decision_emitted"]
    assert len(emitted) == 1
    assert emitted[0].payload["action"] == "block"
    assert emitted[0].payload["policy_id"] == failure["policy_id"]


@pytest.mark.parametrize("new_state", ["missing", "tampered"])
def test_each_packument_revalidates_previously_ready_feed(tmp_path, monkeypatch, new_state):
    snapshot = _snapshot(tmp_path)
    ready = feed_status(cache_dir=snapshot.cache_dir, now=NOW)
    assert ready.state == "ready"
    statuses = iter((ready, _status(tmp_path, new_state, "block")))
    monkeypatch.setattr(gateway_module, "feed_status", lambda **kwargs: next(statuses))
    state = NpmGatewayState(
        upstream_registry="https://registry.npmjs.org",
        policy=PackagePolicy(),
        feed_cache_dir=snapshot.cache_dir,
        now=NOW,
    )

    first, body = _request(state, monkeypatch)
    second, _ = _request(state, monkeypatch)

    assert first["status"] == 200
    assert body == PACKUMENT
    assert second["status"] == 403
    assert state.feed.state == new_state


def test_corrupt_local_feed_is_not_silently_forwarded(tmp_path):
    snapshot = _snapshot(tmp_path)
    # Damage only this test's local fixture data; no dependency is fetched or run.
    (snapshot.snapshot_dir / "npm-malware.json").write_text("incomplete fixture data")
    state = NpmGatewayState(
        upstream_registry="https://registry.npmjs.org",
        policy=PackagePolicy(),
        feed_cache_dir=snapshot.cache_dir,
        now=NOW,
    )

    with pytest.raises(ValueError, match="npm policy feed is tampered"):
        gateway_module._rewrite_metadata(PACKUMENT, state)

    assert state.feed.state == "tampered"
