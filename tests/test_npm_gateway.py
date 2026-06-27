from __future__ import annotations

import http.client
import json
import os
import sys
import threading
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from click.testing import CliRunner

from ca9.cli import main
from ca9.package_feed import update_feed_from_source
from ca9.package_policy import ModePolicy, PackageAgePolicy, PackagePolicy
from ca9.runtime.npm_gateway import NpmMetadataGateway, npm_gateway_child_env


def test_npm_gateway_removes_malware_version_and_recomputes_latest(tmp_path):
    upstream = _FakeNpmRegistry(
        {
            "name": "left-pad",
            "versions": {
                "1.2.0": {"name": "left-pad", "version": "1.2.0"},
                "1.3.0": {"name": "left-pad", "version": "1.3.0"},
            },
            "dist-tags": {"latest": "1.3.0"},
        }
    )
    cache_root = tmp_path / "cache"
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_root / "feed")

    with (
        upstream,
        NpmMetadataGateway(
            upstream_registry=upstream.url,
            policy=PackagePolicy(),
            feed_cache_dir=cache_root / "feed",
        ) as gateway,
    ):
        assert gateway.registry_url.startswith("http://127.0.0.1:")
        body = urllib.request.urlopen(gateway.registry_url + "left-pad").read()

    data = json.loads(body)
    assert set(data["versions"]) == {"1.2.0"}
    assert data["dist-tags"]["latest"] == "1.2.0"
    assert gateway.state.rewrite_count == 1
    assert gateway.state.removed_versions[0].policy_id == "ca9.malware"


def test_npm_gateway_preserves_upstream_bytes_when_no_rewrite(tmp_path):
    raw = (
        b'{"name":"left-pad","versions":{"1.2.0":{"version":"1.2.0"}},'
        b'"dist-tags":{"latest":"1.2.0"}}'
    )
    upstream = _FakeNpmRegistry(raw)
    cache_root = tmp_path / "cache"
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_root / "feed")

    with (
        upstream,
        NpmMetadataGateway(
            upstream_registry=upstream.url,
            policy=PackagePolicy(mode=ModePolicy(default="warn")),
            feed_cache_dir=cache_root / "feed",
        ) as gateway,
    ):
        body = urllib.request.urlopen(gateway.registry_url + "left-pad").read()

    assert body == raw
    assert gateway.state.rewrite_count == 0


def test_npm_gateway_hides_too_new_versions(tmp_path):
    released_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    upstream = _FakeNpmRegistry(
        {
            "name": "fresh-lib",
            "versions": {
                "1.0.0": {"name": "fresh-lib", "version": "1.0.0"},
                "2.0.0": {"name": "fresh-lib", "version": "2.0.0"},
            },
            "dist-tags": {"latest": "2.0.0"},
        }
    )
    cache_root = tmp_path / "cache"
    update_feed_from_source(
        _write_feed_bundle(
            tmp_path,
            npm_releases={"packages": {"fresh-lib": {"2.0.0": released_at}}},
        ),
        cache_dir=cache_root / "feed",
    )

    with (
        upstream,
        NpmMetadataGateway(
            upstream_registry=upstream.url,
            policy=PackagePolicy(package_age=PackageAgePolicy(enabled=True, minimum_hours=48)),
            feed_cache_dir=cache_root / "feed",
        ) as gateway,
    ):
        body = urllib.request.urlopen(gateway.registry_url + "fresh-lib").read()

    data = json.loads(body)
    assert set(data["versions"]) == {"1.0.0"}
    assert data["dist-tags"]["latest"] == "1.0.0"
    assert gateway.state.removed_versions[0].policy_id == "ca9.package_age"


def test_npm_gateway_hides_unknown_release_versions_when_offline_blocks(tmp_path):
    upstream = _FakeNpmRegistry(
        {
            "name": "unknown-lib",
            "versions": {
                "1.0.0": {"name": "unknown-lib", "version": "1.0.0"},
                "2.0.0": {"name": "unknown-lib", "version": "2.0.0"},
            },
            "dist-tags": {"latest": "2.0.0"},
        }
    )
    cache_root = tmp_path / "cache"
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_root / "feed")

    with (
        upstream,
        NpmMetadataGateway(
            upstream_registry=upstream.url,
            policy=PackagePolicy(
                mode=ModePolicy(offline="block"),
                package_age=PackageAgePolicy(enabled=True, minimum_hours=48),
            ),
            feed_cache_dir=cache_root / "feed",
        ) as gateway,
    ):
        body = urllib.request.urlopen(gateway.registry_url + "unknown-lib").read()

    data = json.loads(body)
    assert data["versions"] == {}
    assert data["dist-tags"] == {}
    assert gateway.state.removed_versions[0].policy_id == "ca9.package_age_unknown"


def test_npm_gateway_uses_metadata_time_for_age_without_feed_release(tmp_path):
    fresh = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    upstream = _FakeNpmRegistry(
        {
            "name": "fresh-lib",
            "versions": {
                "1.0.0": {"name": "fresh-lib", "version": "1.0.0"},
                "2.0.0": {"name": "fresh-lib", "version": "2.0.0"},
            },
            "time": {"2.0.0": fresh},
            "dist-tags": {"latest": "2.0.0"},
        }
    )
    cache_root = tmp_path / "cache"
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_root / "feed")

    with (
        upstream,
        NpmMetadataGateway(
            upstream_registry=upstream.url,
            policy=PackagePolicy(package_age=PackageAgePolicy(enabled=True, minimum_hours=48)),
            feed_cache_dir=cache_root / "feed",
        ) as gateway,
    ):
        body = urllib.request.urlopen(gateway.registry_url + "fresh-lib").read()

    data = json.loads(body)
    # 2.0.0 is hidden using the registry's own `time` field, with no feed release data.
    assert "2.0.0" not in data["versions"]
    assert data["dist-tags"]["latest"] == "1.0.0"
    assert gateway.state.removed_versions[0].policy_id == "ca9.package_age"


def test_npm_gateway_rejects_absolute_proxy_urls(tmp_path):
    upstream = _FakeNpmRegistry({"name": "left-pad", "versions": {}, "dist-tags": {}})

    with (
        upstream,
        NpmMetadataGateway(
            upstream_registry=upstream.url,
            policy=PackagePolicy(),
        ) as gateway,
    ):
        url = urllib.parse.urlparse(gateway.registry_url)
        conn = http.client.HTTPConnection(url.hostname, url.port)
        conn.request("GET", "http://registry.npmjs.org/left-pad")
        response = conn.getresponse()

    assert response.status == 403


def test_npm_gateway_child_env_overrides_registry_and_config_sources():
    child_env = npm_gateway_child_env(
        {
            "NPM_CONFIG_REGISTRY": "https://packages.example",
            "npm_config_@scope:registry": "https://scope.example",
            "NPM_CONFIG_USERCONFIG": "/tmp/npmrc",
        },
        "http://127.0.0.1:12345/",
    )

    assert child_env["NPM_CONFIG_REGISTRY"] == "http://127.0.0.1:12345/"
    assert child_env["npm_config_registry"] == "http://127.0.0.1:12345/"
    assert child_env["npm_config_@scope:registry"] == "http://127.0.0.1:12345/"
    assert child_env["NPM_CONFIG_USERCONFIG"] == os.devnull
    assert child_env["npm_config_userconfig"] == os.devnull


def test_ca9_run_npm_uses_gateway_for_child_install(tmp_path):
    upstream = _FakeNpmRegistry(
        {
            "name": "left-pad",
            "versions": {
                "1.2.0": {"name": "left-pad", "version": "1.2.0"},
                "1.3.0": {"name": "left-pad", "version": "1.3.0"},
            },
            "dist-tags": {"latest": "1.3.0"},
        }
    )
    cache_root = tmp_path / "cache"
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_root / "feed")
    bin_dir = tmp_path / "bin"
    metadata_path = tmp_path / "metadata.json"
    argv_path = tmp_path / "argv.txt"
    audit_log = tmp_path / "audit.jsonl"
    policy_path = tmp_path / "ca9.toml"
    policy_path.write_text(
        """
[registries]
allow = ["127.0.0.1", "registry.npmjs.org"]

[install_scripts]
block_when_secrets_present = false

[ci]
strip_secret_env_for_installs = false
"""
    )
    _write_fake_command(
        bin_dir,
        "npm",
        "#!/bin/sh\n"
        f'{sys.executable} -c "import os, pathlib, urllib.request; '
        f"pathlib.Path({str(argv_path)!r}).write_text(' '.join(__import__('sys').argv[1:])); "
        "url=os.environ['NPM_CONFIG_REGISTRY'] + 'left-pad'; "
        f'pathlib.Path({str(metadata_path)!r}).write_bytes(urllib.request.urlopen(url).read())" '
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
                "--audit-log",
                str(audit_log),
                "--",
                "npm",
                "install",
                "--registry",
                upstream.url,
                "left-pad",
            ],
            env={
                "CA9_CACHE_DIR": str(cache_root),
                "PATH": str(bin_dir),
            },
        )

    assert result.exit_code == 0
    assert "--registry" not in argv_path.read_text()
    metadata = json.loads(metadata_path.read_text())
    assert set(metadata["versions"]) == {"1.2.0"}
    assert metadata["dist-tags"]["latest"] == "1.2.0"
    events = [json.loads(line) for line in audit_log.read_text().splitlines()]
    assert any(event["event_kind"] == "gateway_used" for event in events)
    assert any(
        event["event_kind"] == "decision_emitted"
        and event["payload"]["policy_id"] == "ca9.malware"
        and event["payload"]["package"] == "left-pad"
        and event["payload"]["version"] == "1.3.0"
        for event in events
    )


class _FakeNpmRegistry:
    def __init__(self, payload):
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
                body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

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
    npm_releases: dict | None = None,
):
    expires = (datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=1)).isoformat()
    bundle = {
        "schema": "ca9.feed.v1",
        "created_at": "2026-06-26T00:00:00Z",
        "expires_at": expires,
        "datasets": {
            "pypi-malware": {"packages": []},
            "npm-malware": {
                "packages": [
                    {
                        "name": "left-pad",
                        "version": "1.3.0",
                        "id": "MAL-NPM-1",
                    }
                ]
            },
            "pypi-releases": {"packages": {}},
            "npm-releases": npm_releases or {"packages": {}},
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
