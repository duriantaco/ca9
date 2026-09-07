from __future__ import annotations

import http.client
import json
import os
import shutil
import subprocess
import sys
import threading
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from click.testing import CliRunner

import ca9.runtime.npm_gateway as npm_gateway_module
from ca9.cli import main
from ca9.package_feed import update_feed_from_source
from ca9.package_policy import (
    ModePolicy,
    PackageAgePolicy,
    PackagePolicy,
    PolicyException,
)
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


def test_npm_gateway_evaluates_300_packument(tmp_path):
    upstream = _FakeNpmRegistry(
        {
            "name": "left-pad",
            "versions": {
                "1.2.0": {"name": "left-pad", "version": "1.2.0"},
                "1.3.0": {"name": "left-pad", "version": "1.3.0"},
            },
            "dist-tags": {"latest": "1.3.0"},
        },
        status=300,
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
        url = urllib.parse.urlparse(gateway.registry_url)
        connection = http.client.HTTPConnection(url.hostname, url.port)
        connection.request("GET", "/left-pad")
        response = connection.getresponse()
        body = json.loads(response.read())

    assert response.status == 300
    assert set(body["versions"]) == {"1.2.0"}
    assert body["dist-tags"]["latest"] == "1.2.0"


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


def test_npm_gateway_allows_scoped_package_age_exception(tmp_path):
    now = datetime(2026, 6, 26, 12, 0, tzinfo=timezone.utc)
    upstream = _FakeNpmRegistry(
        {
            "name": "fresh-lib",
            "versions": {
                "2.0.0": {"name": "fresh-lib", "version": "2.0.0"},
            },
            "dist-tags": {"latest": "2.0.0"},
        }
    )
    cache_root = tmp_path / "cache"
    update_feed_from_source(
        _write_feed_bundle(
            tmp_path,
            npm_releases={"packages": {"fresh-lib": {"2.0.0": "2026-06-26T11:00:00+00:00"}}},
        ),
        cache_dir=cache_root / "feed",
    )
    policy = PackagePolicy(
        package_age=PackageAgePolicy(enabled=True, minimum_hours=48),
        exceptions=(
            PolicyException(
                policy_id="ca9.package_age",
                ecosystem="npm",
                package="fresh-*",
                version="2.*",
                owner="release-security",
                reason="Emergency release",
                expires="2026-06-27",
            ),
        ),
    )

    with (
        upstream,
        NpmMetadataGateway(
            upstream_registry=upstream.url,
            policy=policy,
            feed_cache_dir=cache_root / "feed",
            now=now,
        ) as gateway,
    ):
        body = urllib.request.urlopen(gateway.registry_url + "fresh-lib").read()

    data = json.loads(body)
    assert set(data["versions"]) == {"2.0.0"}
    assert gateway.state.removed_versions == []
    assert gateway.state.applied_exceptions[0]["action"] == "warn"
    assert (
        gateway.state.applied_exceptions[0]["evidence"]["policy_exception"]["owner"]
        == "release-security"
    )


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


def test_npm_gateway_child_env_uses_distinct_owned_config_files():
    gateway = NpmMetadataGateway(policy=PackagePolicy())

    with gateway:
        user_config = gateway.user_config_path
        global_config = gateway.global_config_path
        child_env = npm_gateway_child_env(
            {
                "NPM_CONFIG_REGISTRY": "https://packages.example",
                "npm_config_@scope:registry": "https://scope.example",
                "NPM_CONFIG_USERCONFIG": "/tmp/npmrc",
                "npm_config_proxy": "http://proxy.example",
                "NPM_CONFIG_HTTPS_PROXY": "http://secure-proxy.example",
                "NO_PROXY": "metadata.internal",
            },
            "http://127.0.0.1:12345/",
            user_config_path=user_config,
            global_config_path=global_config,
        )

        assert user_config != global_config
        assert user_config.is_file()
        assert global_config.is_file()
        assert user_config.read_bytes() == b""
        assert global_config.read_bytes() == b""
        assert child_env["NPM_CONFIG_REGISTRY"] == "http://127.0.0.1:12345/"
        assert child_env["npm_config_registry"] == "http://127.0.0.1:12345/"
        assert child_env["npm_config_@scope:registry"] == "http://127.0.0.1:12345/"
        assert child_env["NPM_CONFIG_USERCONFIG"] == str(user_config.resolve())
        assert child_env["npm_config_userconfig"] == str(user_config.resolve())
        assert child_env["NPM_CONFIG_GLOBALCONFIG"] == str(global_config.resolve())
        assert child_env["npm_config_globalconfig"] == str(global_config.resolve())
        assert child_env["npm_config_proxy"] == "false"
        assert child_env["NPM_CONFIG_PROXY"] == "false"
        assert child_env["npm_config_https_proxy"] == "false"
        assert child_env["NPM_CONFIG_HTTPS_PROXY"] == "false"
        assert "metadata.internal" in child_env["NO_PROXY"]
        assert "127.0.0.1" in child_env["NO_PROXY"]
        assert child_env["NO_PROXY"] == child_env["no_proxy"]
        assert child_env["npm_config_noproxy"] == child_env["NO_PROXY"]

    assert not user_config.exists()
    assert not global_config.exists()


def test_npm_gateway_sanitizes_upstream_url_evidence():
    gateway = NpmMetadataGateway(
        upstream_registry="https://user:secret@registry.example/path?token=do-not-log",
        policy=PackagePolicy(),
    )

    assert gateway.to_dict()["upstream_registry"] == "https://registry.example/path"


def test_npm_gateway_child_env_rejects_shared_or_devnull_config(tmp_path):
    empty_config = tmp_path / "empty.npmrc"
    other_config = tmp_path / "other.npmrc"
    empty_config.touch()
    other_config.touch()

    with pytest.raises(ValueError, match="must be distinct"):
        npm_gateway_child_env(
            {},
            "http://127.0.0.1:12345/",
            user_config_path=empty_config,
            global_config_path=empty_config,
        )
    with pytest.raises(ValueError, match="must not be"):
        npm_gateway_child_env(
            {},
            "http://127.0.0.1:12345/",
            user_config_path=os.devnull,
            global_config_path=other_config,
        )


def test_npm_gateway_cleans_config_files_when_server_start_fails(tmp_path, monkeypatch):
    config_root = tmp_path / "gateway-config"
    created_paths = []

    class ControlledTemporaryDirectory:
        def __init__(self, *, prefix):
            config_root.mkdir()
            self.name = str(config_root)

        def cleanup(self):
            for child in config_root.iterdir():
                child.unlink()
            config_root.rmdir()

    def fail_to_start_server(*args, **kwargs):
        created_paths.extend(config_root.iterdir())
        raise OSError("cannot bind")

    monkeypatch.setattr(npm_gateway_module, "TemporaryDirectory", ControlledTemporaryDirectory)
    monkeypatch.setattr(npm_gateway_module, "ThreadingHTTPServer", fail_to_start_server)
    gateway = NpmMetadataGateway(policy=PackagePolicy())

    with pytest.raises(OSError, match="cannot bind"):
        gateway.start()

    assert {path.name for path in created_paths} == {"user.npmrc", "global.npmrc"}
    assert not config_root.exists()
    with pytest.raises(RuntimeError, match="not started"):
        _ = gateway.user_config_path


def test_npm_gateway_config_files_are_accepted_by_npm(tmp_path):
    npm = shutil.which("npm")
    if npm is None:
        pytest.skip("npm is not installed")

    gateway = NpmMetadataGateway(policy=PackagePolicy())
    with gateway:
        registry_url = gateway.registry_url
        child_env = npm_gateway_child_env(
            dict(os.environ),
            registry_url,
            user_config_path=gateway.user_config_path,
            global_config_path=gateway.global_config_path,
        )
        completed = subprocess.run(
            [npm, "config", "get", "registry"],
            cwd=tmp_path,
            env=child_env,
            capture_output=True,
            text=True,
            check=False,
        )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == registry_url


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
    def __init__(self, payload, *, status=200):
        self.payload = payload
        self.status = status
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
        status = self.status

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
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
