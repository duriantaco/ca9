from __future__ import annotations

import json
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ca9.package_feed import update_feed_from_source
from ca9.package_policy import PackagePolicy
from ca9.runtime.pypi_gateway import PyPISimpleGateway


class _RoutedServer:
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
                status, value, body = routes.get(self.path, (200, "text/html", b"<html></html>"))
                self.send_response(status)
                if status in {301, 302, 307, 308}:
                    self.send_header("Location", value)
                    body = b""
                else:
                    self.send_header("Content-Type", value)
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


def _feed(tmp_path, malware):
    expires = (datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=1)).isoformat()
    bundle = {
        "schema": "ca9.feed.v1",
        "created_at": "2026-06-26T00:00:00Z",
        "expires_at": expires,
        "datasets": {
            "npm-malware": {"packages": []},
            "pypi-malware": {"packages": malware},
            "npm-releases": {"packages": {}},
            "pypi-releases": {"packages": {}},
        },
    }
    path = tmp_path / "feed.json"
    path.write_text(json.dumps(bundle))
    cache = tmp_path / "cache" / "feed"
    update_feed_from_source(path, cache_dir=cache)
    return cache


def _page(*filenames: str) -> bytes:
    links = "\n".join(f'<a href="https://files.example/{name}">{name}</a>' for name in filenames)
    return f"<!DOCTYPE html><html><body>\n{links}\n</body></html>\n".encode()


def _get(url):
    try:
        with urllib.request.urlopen(url) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def test_pypi_gateway_serves_pages_with_links_pip_ignores(tmp_path):
    cache = _feed(tmp_path, [{"name": "setuptools", "version": "1.0", "id": "MAL-1"}])
    page = _page(
        "setuptools-0.6c11-py2.7.egg",
        "setuptools-0.6c11.win32-py2.7.exe",
        "setuptools-0.6c11.tar.gz",
        "setuptools-68.0.0.tar.gz",
        "setuptools-68.0.0-py3-none-any.whl",
        "setuptools-68.0.0.zip",
        "setuptools-1.0.tar.bz2",
        "setuptools-0.9.tgz",
        "other_project-1.0.tar.gz",
        "setuptools-notaversion!.tar.gz",
        "README",
    )

    with (
        _RoutedServer({"/simple/setuptools/": (200, "text/html", page)}) as upstream,
        PyPISimpleGateway(
            upstream_base=upstream.url, policy=PackagePolicy(), feed_cache_dir=cache
        ) as gateway,
    ):
        status, body = _get(gateway.index_url + "/setuptools/")

    assert status == 200
    for kept in (
        "setuptools-0.6c11.tar.gz",
        "setuptools-68.0.0.tar.gz",
        "setuptools-68.0.0-py3-none-any.whl",
        "setuptools-68.0.0.zip",
        "setuptools-0.9.tgz",
    ):
        assert kept in body
    for dropped in (
        ".egg",
        ".exe",
        "setuptools-1.0.tar.bz2",
        "other_project",
        "notaversion",
        "README",
    ):
        assert dropped not in body
    assert gateway.state.evaluation_failures == []
    assert [(item.version, item.policy_id) for item in gateway.state.removed_links] == [
        ("1.0", "ca9.malware")
    ]


def test_pypi_gateway_matches_legacy_sdist_versions_like_pip(tmp_path):
    cache = _feed(
        tmp_path,
        [
            {"name": "pyyaml", "version": "5.1", "id": "MAL-1"},
            {"name": "foo-bar", "version": "1.0.post1", "id": "MAL-2"},
        ],
    )
    pyyaml = _page("PyYAML-5.1.tar.bz2", "PyYAML-5.2.tar.bz2")
    foo_bar = _page("foo-bar-1.0-1.tar.xz", "foo_bar-2.0.tar.lzma")

    with (
        _RoutedServer(
            {
                "/simple/pyyaml/": (200, "text/html", pyyaml),
                "/simple/foo-bar/": (200, "text/html", foo_bar),
            }
        ) as upstream,
        PyPISimpleGateway(
            upstream_base=upstream.url, policy=PackagePolicy(), feed_cache_dir=cache
        ) as gateway,
    ):
        _, pyyaml_body = _get(gateway.index_url + "/pyyaml/")
        _, foo_bar_body = _get(gateway.index_url + "/foo-bar/")

    assert "PyYAML-5.1.tar.bz2" not in pyyaml_body
    assert "PyYAML-5.2.tar.bz2" in pyyaml_body
    assert "foo-bar-1.0-1.tar.xz" not in foo_bar_body
    assert "foo_bar-2.0.tar.lzma" in foo_bar_body


def test_pypi_gateway_rejects_paths_that_change_the_upstream_host(tmp_path):
    with (
        _RoutedServer() as internal,
        _RoutedServer() as upstream,
        PyPISimpleGateway(upstream_base=upstream.url, policy=PackagePolicy()) as gateway,
    ):
        gateway_url = urllib.parse.urlsplit(gateway.index_url)
        internal_host = internal.url.removeprefix("http://")
        responses = []
        for raw_path in (f"@{internal_host}/simple/", ".attacker.example/simple/"):
            with socket.create_connection((gateway_url.hostname, gateway_url.port)) as conn:
                conn.sendall(f"GET {raw_path} HTTP/1.0\r\n\r\n".encode())
                responses.append(conn.recv(4096))

    assert all(response.startswith(b"HTTP/1.0 403") for response in responses)
    assert internal.requests == []
    assert upstream.requests == []


def test_pypi_gateway_does_not_follow_cross_host_redirects(tmp_path):
    with _RoutedServer() as other:
        redirect = (302, other.url + "/simple/requests/", b"")
        with (
            _RoutedServer({"/simple/requests/": redirect}) as upstream,
            PyPISimpleGateway(upstream_base=upstream.url, policy=PackagePolicy()) as gateway,
        ):
            status, _ = _get(gateway.index_url + "/requests/")

    assert status == 502
    assert other.requests == []
