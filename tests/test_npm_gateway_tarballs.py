from __future__ import annotations

import json
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from ca9.cli import _gateway_ledger_events
from ca9.package_feed import update_feed_from_source
from ca9.package_policy import MalwarePolicy, PackageAgePolicy, PackagePolicy
from ca9.runtime.npm_gateway import NpmMetadataGateway

TARBALL = b"TARBALL-BYTES"


class _RoutedServer:
    """Loopback HTTP server that serves fixed routes and records request paths."""

    def __init__(self, routes=None):
        self.routes = routes or {}
        self.requests: list[str] = []
        self._server: ThreadingHTTPServer | None = None

    @property
    def url(self) -> str:
        host, port = self._server.server_address
        return f"http://{host}:{port}"

    def __enter__(self):
        routes = self.routes
        requests = self.requests

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                requests.append(self.path)
                route = routes.get(self.path)
                if route is None:
                    route = (200, "application/octet-stream", TARBALL)
                status, content_type, body = route
                if isinstance(body, (dict, list)):
                    body = json.dumps(body).encode()
                self.send_response(status)
                if status in {301, 302, 307, 308}:
                    self.send_header("Location", content_type)
                    body = b""
                else:
                    self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt: str, *args) -> None:
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._server.shutdown()
        self._server.server_close()


def _feed(tmp_path, *, malware=(), releases=None):
    expires = (datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=1)).isoformat()
    bundle = {
        "schema": "ca9.feed.v1",
        "created_at": "2026-06-26T00:00:00Z",
        "expires_at": expires,
        "datasets": {
            "npm-malware": {"packages": list(malware)},
            "pypi-malware": {"packages": []},
            "npm-releases": {"packages": releases or {}},
            "pypi-releases": {"packages": {}},
        },
    }
    path = tmp_path / "feed.json"
    path.write_text(json.dumps(bundle))
    cache = tmp_path / "cache" / "feed"
    update_feed_from_source(path, cache_dir=cache)
    return cache


MALWARE = (
    {"name": "evil-pkg", "version": "1.0.0", "id": "MAL-1"},
    {"name": "@evil/pkg", "version": "2.0.0", "id": "MAL-2"},
)


def _get(url):
    try:
        with urllib.request.urlopen(url) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


@pytest.mark.parametrize(
    ("path", "package", "version"),
    [
        ("evil-pkg/-/evil-pkg-1.0.0.tgz", "evil-pkg", "1.0.0"),
        ("Evil-Pkg/-/Evil-Pkg-1.0.0.tgz", "Evil-Pkg", "1.0.0"),
        ("@evil/pkg/-/pkg-2.0.0.tgz", "@evil/pkg", "2.0.0"),
        ("@evil%2fpkg/-/pkg-2.0.0.tgz", "@evil/pkg", "2.0.0"),
        ("@evil/pkg/-/@evil/pkg-2.0.0.tgz", "@evil/pkg", "2.0.0"),
        ("evil-pkg/-/evil-pkg-1.0.0.tgz?cache=1", "evil-pkg", "1.0.0"),
    ],
)
def test_npm_gateway_denies_feed_listed_tarballs(path, package, version, tmp_path):
    cache = _feed(tmp_path, malware=MALWARE)

    with (
        _RoutedServer() as upstream,
        NpmMetadataGateway(
            upstream_registry=upstream.url, policy=PackagePolicy(), feed_cache_dir=cache
        ) as gateway,
    ):
        status, body = _get(gateway.registry_url + path)
        payload = gateway.to_dict()

    assert status == 403
    assert TARBALL not in body
    assert upstream.requests == []
    (decision,) = payload["removed_versions"]
    assert (decision["package"], decision["version"]) == (package, version)
    assert decision["policy_id"] == "ca9.malware"
    events = _gateway_ledger_events(payload, session_id="session")
    assert any(
        event.event_kind == "decision_emitted"
        and event.payload["action"] == "block"
        and event.payload["package"] == package
        for event in events
    )


def test_npm_gateway_passes_through_clean_tarballs(tmp_path):
    cache = _feed(tmp_path, malware=MALWARE)

    with (
        _RoutedServer() as upstream,
        NpmMetadataGateway(
            upstream_registry=upstream.url, policy=PackagePolicy(), feed_cache_dir=cache
        ) as gateway,
    ):
        status, body = _get(gateway.registry_url + "evil-pkg/-/evil-pkg-1.0.1.tgz")
        scoped_status, _ = _get(gateway.registry_url + "@scope/left-pad/-/left-pad-1.2.0.tgz")

    assert (status, body) == (200, TARBALL)
    assert scoped_status == 200
    assert gateway.state.removed_versions == []


@pytest.mark.parametrize(
    "path",
    [
        "lodash/-/evil-pkg-1.0.0.tgz",
        "lodash/-/lodash-.tgz",
        "nested/path/-/path-1.0.0.tgz",
        "@scope/-/scope-1.0.0.tgz",
        "-/evil-pkg-1.0.0.tgz",
    ],
)
def test_npm_gateway_denies_tarball_paths_that_do_not_name_their_package(path, tmp_path):
    cache = _feed(tmp_path, malware=MALWARE)

    with (
        _RoutedServer() as upstream,
        NpmMetadataGateway(
            upstream_registry=upstream.url, policy=PackagePolicy(), feed_cache_dir=cache
        ) as gateway,
    ):
        status, _ = _get(gateway.registry_url + path)

    assert status == 403
    assert upstream.requests == []
    assert gateway.state.evaluation_failures[0].failure_kind == "unparseable_tarball_path"


def test_npm_gateway_denies_tarballs_when_fail_closed_feed_is_missing(tmp_path):
    with (
        _RoutedServer() as upstream,
        NpmMetadataGateway(
            upstream_registry=upstream.url,
            policy=PackagePolicy(malware=MalwarePolicy(fail_closed=True)),
            feed_cache_dir=tmp_path / "missing",
        ) as gateway,
    ):
        status, _ = _get(gateway.registry_url + "left-pad/-/left-pad-1.3.0.tgz")

    assert status == 403
    assert upstream.requests == []
    assert gateway.state.evaluation_failures[0].failure_kind == "feed_missing"


def test_npm_gateway_applies_package_age_to_tarballs(tmp_path):
    fresh = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    cache = _feed(tmp_path, releases={"fresh-lib": {"2.0.0": fresh}})

    with (
        _RoutedServer() as upstream,
        NpmMetadataGateway(
            upstream_registry=upstream.url,
            policy=PackagePolicy(package_age=PackageAgePolicy(enabled=True, minimum_hours=48)),
            feed_cache_dir=cache,
        ) as gateway,
    ):
        status, _ = _get(gateway.registry_url + "fresh-lib/-/fresh-lib-2.0.0.tgz")

    assert status == 403
    assert gateway.state.removed_versions[0].policy_id == "ca9.package_age"


def test_npm_gateway_uses_registry_time_for_tarballs_without_feed_release(tmp_path):
    # npm ci fetches tarballs straight from the lockfile without a packument, so
    # the gateway looks up the registry's own release time.
    fresh = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    packument = {
        "name": "fresh-lib",
        "versions": {"1.0.0": {}, "2.0.0": {}},
        "time": {"1.0.0": "2020-01-01T00:00:00Z", "2.0.0": fresh},
        "dist-tags": {"latest": "2.0.0"},
    }
    cache = _feed(tmp_path)

    with (
        _RoutedServer({"/fresh-lib": (200, "application/json", packument)}) as upstream,
        NpmMetadataGateway(
            upstream_registry=upstream.url,
            policy=PackagePolicy(package_age=PackageAgePolicy(enabled=True, minimum_hours=48)),
            feed_cache_dir=cache,
        ) as gateway,
    ):
        old_status, _ = _get(gateway.registry_url + "fresh-lib/-/fresh-lib-1.0.0.tgz")
        new_status, _ = _get(gateway.registry_url + "fresh-lib/-/fresh-lib-2.0.0.tgz")

    assert old_status == 200
    assert new_status == 403
    assert upstream.requests.count("/fresh-lib") == 1
    assert gateway.state.removed_versions[0].policy_id == "ca9.package_age"


def test_npm_gateway_latest_tag_skips_prereleases_after_removal(tmp_path):
    packument = {
        "name": "react",
        "versions": {
            "1.0.0": {},
            "1.10.0": {},
            "1.9.0": {},
            "2.0.0": {},
            "0.0.0-experimental-1": {},
            "3.0.0-rc.1": {},
        },
        "dist-tags": {"latest": "2.0.0", "next": "3.0.0-rc.1"},
    }
    cache = _feed(tmp_path, malware=({"name": "react", "version": "2.0.0", "id": "MAL-3"},))

    with (
        _RoutedServer({"/react": (200, "application/json", packument)}) as upstream,
        NpmMetadataGateway(
            upstream_registry=upstream.url, policy=PackagePolicy(), feed_cache_dir=cache
        ) as gateway,
    ):
        data = json.loads(urllib.request.urlopen(gateway.registry_url + "react").read())

    assert "2.0.0" not in data["versions"]
    assert data["dist-tags"] == {"latest": "1.10.0", "next": "3.0.0-rc.1"}


def test_npm_gateway_drops_latest_when_only_prereleases_remain(tmp_path):
    packument = {
        "name": "react",
        "versions": {"2.0.0": {}, "0.0.0-experimental-1": {}},
        "dist-tags": {"latest": "2.0.0"},
    }
    cache = _feed(tmp_path, malware=({"name": "react", "version": "2.0.0", "id": "MAL-3"},))

    with (
        _RoutedServer({"/react": (200, "application/json", packument)}) as upstream,
        NpmMetadataGateway(
            upstream_registry=upstream.url, policy=PackagePolicy(), feed_cache_dir=cache
        ) as gateway,
    ):
        data = json.loads(urllib.request.urlopen(gateway.registry_url + "react").read())

    assert data["dist-tags"] == {}


@pytest.mark.parametrize("raw_path", [".attacker.example/", "@{internal}/admin", "x/admin"])
def test_npm_gateway_rejects_paths_that_change_the_upstream_host(raw_path, tmp_path):
    with (
        _RoutedServer() as internal,
        _RoutedServer() as upstream,
        NpmMetadataGateway(upstream_registry=upstream.url, policy=PackagePolicy()) as gateway,
    ):
        internal_host = internal.url.removeprefix("http://")
        gateway_url = urllib.parse.urlsplit(gateway.registry_url)
        with socket.create_connection((gateway_url.hostname, gateway_url.port)) as connection:
            request_path = raw_path.format(internal=internal_host)
            connection.sendall(f"GET {request_path} HTTP/1.0\r\n\r\n".encode())
            response = connection.recv(4096)

    assert response.startswith(b"HTTP/1.0 403")
    assert internal.requests == []
    assert upstream.requests == []


def test_npm_gateway_does_not_follow_cross_host_redirects(tmp_path):
    with _RoutedServer() as other:
        redirect = (302, other.url + "/left-pad", b"")
        with (
            _RoutedServer({"/left-pad": redirect}) as upstream,
            NpmMetadataGateway(upstream_registry=upstream.url, policy=PackagePolicy()) as gateway,
        ):
            status, _ = _get(gateway.registry_url + "left-pad")

    assert status == 502
    assert other.requests == []


def test_npm_gateway_follows_same_host_redirects(tmp_path):
    packument = {"name": "left-pad", "versions": {"1.2.0": {}}, "dist-tags": {"latest": "1.2.0"}}
    with _RoutedServer() as upstream:
        upstream.routes["/left-pad"] = (302, upstream.url + "/left-pad-moved", b"")
        upstream.routes["/left-pad-moved"] = (200, "application/json", packument)
        with NpmMetadataGateway(upstream_registry=upstream.url, policy=PackagePolicy()) as gateway:
            status, body = _get(gateway.registry_url + "left-pad")

    assert status == 200
    assert json.loads(body)["name"] == "left-pad"
