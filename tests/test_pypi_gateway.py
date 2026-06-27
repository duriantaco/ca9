from __future__ import annotations

import http.client
import json
import os
import sys
import threading
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from click.testing import CliRunner

from ca9.cli import main
from ca9.package_feed import update_feed_from_source
from ca9.package_policy import ModePolicy, PackageAgePolicy, PackagePolicy
from ca9.runtime.pypi_gateway import PyPISimpleGateway, pypi_gateway_child_env


def test_pypi_gateway_removes_malware_wheel_link(tmp_path):
    html = b"""
<!doctype html>
<html><body>
<a href="https://files.example/badlib-0.9.0-py3-none-any.whl#sha256=abc">badlib-0.9.0-py3-none-any.whl</a>
<a href="https://files.example/badlib-1.0.0-py3-none-any.whl#sha256=def" data-requires-python=">=3.10">badlib-1.0.0-py3-none-any.whl</a>
</body></html>
"""
    upstream = _FakePyPIRegistry(html)
    cache_root = tmp_path / "cache"
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_root / "feed")

    with (
        upstream,
        PyPISimpleGateway(
            upstream_base=upstream.url,
            policy=PackagePolicy(),
            feed_cache_dir=cache_root / "feed",
        ) as gateway,
    ):
        assert gateway.index_url.startswith("http://127.0.0.1:")
        body = urllib.request.urlopen(gateway.index_url + "/badlib/").read().decode()

    assert "badlib-0.9.0-py3-none-any.whl" in body
    assert "badlib-1.0.0-py3-none-any.whl" not in body
    assert gateway.state.rewrite_count == 1
    assert gateway.state.removed_links[0].policy_id == "ca9.malware"


def test_pypi_gateway_preserves_upstream_bytes_when_no_rewrite(tmp_path):
    html = b'<html><body><a href="badlib-1.0.0-py3-none-any.whl">badlib</a></body></html>'
    upstream = _FakePyPIRegistry(html)
    cache_root = tmp_path / "cache"
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_root / "feed")

    with (
        upstream,
        PyPISimpleGateway(
            upstream_base=upstream.url,
            policy=PackagePolicy(mode=ModePolicy(default="warn")),
            feed_cache_dir=cache_root / "feed",
        ) as gateway,
    ):
        body = urllib.request.urlopen(gateway.index_url + "/badlib/").read()

    assert body == html
    assert gateway.state.rewrite_count == 0


def test_pypi_gateway_hides_too_new_sdist_link(tmp_path):
    released_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    html = b"""
<html><body>
<a href="fresh-lib-1.0.0.tar.gz">fresh-lib-1.0.0.tar.gz</a>
<a href="fresh-lib-2.0.0.tar.gz">fresh-lib-2.0.0.tar.gz</a>
</body></html>
"""
    upstream = _FakePyPIRegistry(html)
    cache_root = tmp_path / "cache"
    update_feed_from_source(
        _write_feed_bundle(
            tmp_path,
            pypi_releases={"packages": {"fresh-lib": {"2.0.0": released_at}}},
        ),
        cache_dir=cache_root / "feed",
    )

    with (
        upstream,
        PyPISimpleGateway(
            upstream_base=upstream.url,
            policy=PackagePolicy(package_age=PackageAgePolicy(enabled=True, minimum_hours=48)),
            feed_cache_dir=cache_root / "feed",
        ) as gateway,
    ):
        body = urllib.request.urlopen(gateway.index_url + "/fresh-lib/").read().decode()

    assert "fresh-lib-1.0.0.tar.gz" in body
    assert "fresh-lib-2.0.0.tar.gz" not in body
    assert gateway.state.removed_links[0].policy_id == "ca9.package_age"


def test_pypi_gateway_hides_unknown_release_links_when_offline_blocks(tmp_path):
    html = b"""
<html><body>
<a href="unknown-lib-1.0.0.tar.gz">unknown-lib-1.0.0.tar.gz</a>
<a href="unknown-lib-2.0.0.tar.gz">unknown-lib-2.0.0.tar.gz</a>
</body></html>
"""
    upstream = _FakePyPIRegistry(html)
    cache_root = tmp_path / "cache"
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_root / "feed")

    with (
        upstream,
        PyPISimpleGateway(
            upstream_base=upstream.url,
            policy=PackagePolicy(
                mode=ModePolicy(offline="block"),
                package_age=PackageAgePolicy(enabled=True, minimum_hours=48),
            ),
            feed_cache_dir=cache_root / "feed",
        ) as gateway,
    ):
        body = urllib.request.urlopen(gateway.index_url + "/unknown-lib/").read().decode()

    assert "unknown-lib-1.0.0.tar.gz" not in body
    assert "unknown-lib-2.0.0.tar.gz" not in body
    assert gateway.state.removed_links[0].policy_id == "ca9.package_age_unknown"


def test_pypi_gateway_rejects_absolute_proxy_urls(tmp_path):
    upstream = _FakePyPIRegistry(b"<html></html>")

    with (
        upstream,
        PyPISimpleGateway(
            upstream_base=upstream.url,
            policy=PackagePolicy(),
        ) as gateway,
    ):
        url = urllib.parse.urlparse(gateway.index_url)
        conn = http.client.HTTPConnection(url.hostname, url.port)
        conn.request("GET", "http://pypi.org/simple/badlib/")
        response = conn.getresponse()

    assert response.status == 403


def test_pypi_gateway_child_env_clears_alternate_sources():
    child_env = pypi_gateway_child_env(
        {
            "PIP_INDEX_URL": "https://packages.example/simple",
            "PIP_EXTRA_INDEX_URL": "https://extra.example/simple",
            "PIP_FIND_LINKS": "https://files.example",
            "PIP_CONFIG_FILE": "/tmp/pip.conf",
        },
        "http://127.0.0.1:12345/simple",
    )

    assert child_env["PIP_INDEX_URL"] == "http://127.0.0.1:12345/simple"
    assert child_env["PIP_CONFIG_FILE"] == os.devnull
    assert "PIP_EXTRA_INDEX_URL" not in child_env
    assert "PIP_FIND_LINKS" not in child_env


def test_ca9_run_pip_uses_gateway_for_child_install(tmp_path):
    html = b"""
<html><body>
<a href="badlib-0.9.0-py3-none-any.whl">badlib-0.9.0-py3-none-any.whl</a>
<a href="badlib-1.0.0-py3-none-any.whl">badlib-1.0.0-py3-none-any.whl</a>
</body></html>
"""
    upstream = _FakePyPIRegistry(html)
    cache_root = tmp_path / "cache"
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_root / "feed")
    bin_dir = tmp_path / "bin"
    index_path = tmp_path / "simple.html"
    argv_path = tmp_path / "argv.txt"
    policy_path = tmp_path / "ca9.toml"
    policy_path.write_text(
        """
[registries]
allow = ["127.0.0.1", "pypi.org", "files.pythonhosted.org"]

[install_scripts]
block_when_secrets_present = false

[ci]
strip_secret_env_for_installs = false
"""
    )
    _write_fake_command(
        bin_dir,
        "pip",
        "#!/bin/sh\n"
        f'{sys.executable} -c "import os, pathlib, urllib.request; '
        f"pathlib.Path({str(argv_path)!r}).write_text(' '.join(__import__('sys').argv[1:])); "
        "url=os.environ['PIP_INDEX_URL'].rstrip('/') + '/badlib/'; "
        f'pathlib.Path({str(index_path)!r}).write_bytes(urllib.request.urlopen(url).read())" '
        '"$@"\n'
        "exit 0\n",
    )

    runner = CliRunner()
    with upstream:
        result = runner.invoke(
            main,
            [
                "run",
                "--policy",
                str(policy_path),
                "--",
                "pip",
                "install",
                "--index-url",
                upstream.url + "/simple",
                "badlib",
            ],
            env={
                "CA9_CACHE_DIR": str(cache_root),
                "PATH": str(bin_dir),
            },
        )

    assert result.exit_code == 0
    assert "--index-url" not in argv_path.read_text()
    body = index_path.read_text()
    assert "badlib-0.9.0-py3-none-any.whl" in body
    assert "badlib-1.0.0-py3-none-any.whl" not in body


class _FakePyPIRegistry:
    def __init__(self, payload: bytes):
        self.payload = payload
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        if self._server is None:
            raise RuntimeError("fake registry is not started")
        host, port = self._server.server_address
        return f"http://{host}:{port}"

    def __enter__(self):
        payload = self.payload

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, fmt: str, *args) -> None:
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)


def _write_feed_bundle(
    tmp_path,
    *,
    pypi_releases: dict | None = None,
):
    expires = (datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=1)).isoformat()
    bundle = {
        "schema": "ca9.feed.v1",
        "created_at": "2026-06-26T00:00:00Z",
        "expires_at": expires,
        "datasets": {
            "pypi-malware": {
                "packages": [
                    {
                        "name": "badlib",
                        "version": "1.0.0",
                        "id": "MAL-PYPI-1",
                    }
                ]
            },
            "npm-malware": {"packages": []},
            "pypi-releases": pypi_releases or {"packages": {}},
            "npm-releases": {"packages": {}},
        },
    }
    path = tmp_path / "feed.json"
    path.write_text(json.dumps(bundle))
    return path


def _write_fake_command(bin_dir, name: str, content: str):
    bin_dir.mkdir(parents=True, exist_ok=True)
    path = bin_dir / name
    path.write_text(content)
    path.chmod(0o755)
    return path
