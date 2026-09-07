from __future__ import annotations

import http.client
import json
import os
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from click.testing import CliRunner

from ca9.cli import main
from ca9.package_feed import update_feed_from_source
from ca9.package_policy import (
    ModePolicy,
    PackageAgePolicy,
    PackagePolicy,
    PolicyException,
)
from ca9.runtime.pypi_gateway import PyPISimpleGateway, pypi_gateway_child_env


def test_pypi_gateway_removes_malware_wheel_link(tmp_path):
    html = b"""
<!doctype html>
<html><body>
<a href="https://files.example/badlib-0.9.0-py3-none-any.whl#sha256=abc">badlib-0.9.0-py3-none-any.whl</a>
<a href="https://files.example/badlib-1.0.0-py3-none-any.whl?X-Amz-Signature=do-not-log#sha256=def" data-requires-python=">=3.10">badlib-1.0.0-py3-none-any.whl</a>
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
    payload = gateway.to_dict()
    assert "do-not-log" not in json.dumps(payload)
    assert payload["removed_links"][0]["href"] == (
        "https://files.example/badlib-1.0.0-py3-none-any.whl"
    )


def test_pypi_gateway_sanitizes_upstream_url_evidence():
    gateway = PyPISimpleGateway(
        upstream_base="https://user:secret@packages.example/simple?token=do-not-log",
        policy=PackagePolicy(),
    )

    assert gateway.to_dict()["upstream_base"] == "https://packages.example/simple"


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


def test_pypi_gateway_rejects_unparseable_distribution_link(tmp_path):
    html = b"""
<html><body>
<a href="badlib-1.0.0.tar.bz2?credential=do-not-log">badlib-1.0.0.tar.bz2</a>
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
        pytest.raises(urllib.error.HTTPError) as caught,
    ):
        urllib.request.urlopen(gateway.index_url + "/badlib/")

    assert caught.value.code == 403
    payload = gateway.to_dict()
    assert payload["evaluation_failures"] == [
        {
            "package": "badlib",
            "policy_id": "ca9.pypi_gateway_evaluation_failed",
            "reason": (
                "PyPI project page contains a distribution link with an unparseable "
                "filename or version"
            ),
            "evidence": {
                "ecosystem": "pypi",
                "failure_kind": "unparseable_distribution_link",
            },
        }
    ]
    assert "do-not-log" not in json.dumps(payload)


def test_pypi_gateway_rejects_unclosed_distribution_anchor(tmp_path):
    html = b'<html><body><a href="badlib-1.0.0.tar.bz2">'
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
        pytest.raises(urllib.error.HTTPError) as caught,
    ):
        urllib.request.urlopen(gateway.index_url + "/badlib/")

    assert caught.value.code == 403
    assert gateway.state.evaluation_failures[0].failure_kind == "invalid_anchor_structure"


def test_pypi_gateway_rejects_duplicate_href_attributes(tmp_path):
    html = (
        b'<html><body><a href="badlib-0.9.0.tar.gz" '
        b'href="badlib-1.0.0.tar.bz2">badlib</a></body></html>'
    )
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
        pytest.raises(urllib.error.HTTPError) as caught,
    ):
        urllib.request.urlopen(gateway.index_url + "/badlib/")

    assert caught.value.code == 403
    assert gateway.state.evaluation_failures[0].failure_kind == "duplicate_href"


def test_pypi_gateway_evaluates_non_200_success_response(tmp_path):
    upstream = _FakePyPIRegistry(
        b'<html><body><a href="badlib-1.0.0.tar.bz2">badlib</a></body></html>',
        status=203,
    )
    cache_root = tmp_path / "cache"
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_root / "feed")

    with (
        upstream,
        PyPISimpleGateway(
            upstream_base=upstream.url,
            policy=PackagePolicy(),
            feed_cache_dir=cache_root / "feed",
        ) as gateway,
        pytest.raises(urllib.error.HTTPError) as caught,
    ):
        urllib.request.urlopen(gateway.index_url + "/badlib/")

    assert caught.value.code == 403
    assert gateway.state.evaluation_failures[0].failure_kind == "unparseable_distribution_link"


def test_pypi_gateway_evaluates_300_project_response(tmp_path):
    upstream = _FakePyPIRegistry(
        b'<html><body><a href="badlib-1.0.0.tar.bz2">badlib</a></body></html>',
        status=300,
    )
    cache_root = tmp_path / "cache"
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_root / "feed")

    with (
        upstream,
        PyPISimpleGateway(
            upstream_base=upstream.url,
            policy=PackagePolicy(),
            feed_cache_dir=cache_root / "feed",
        ) as gateway,
        pytest.raises(urllib.error.HTTPError) as caught,
    ):
        urllib.request.urlopen(gateway.index_url + "/badlib/")

    assert caught.value.code == 403
    assert gateway.state.evaluation_failures[0].failure_kind == "unparseable_distribution_link"


def test_pypi_gateway_does_not_treat_relative_artifact_as_project_page(tmp_path):
    artifact = b"not-html-wheel-content"
    upstream = _FakePyPIRegistry(artifact, content_type="application/octet-stream")

    with (
        upstream,
        PyPISimpleGateway(
            upstream_base=upstream.url,
            policy=PackagePolicy(),
        ) as gateway,
    ):
        body = urllib.request.urlopen(
            gateway.index_url + "/badlib/badlib-1.0.0-py3-none-any.whl"
        ).read()

    assert body == artifact
    assert gateway.state.evaluation_failures == []


def test_pypi_gateway_rejects_non_html_project_page_but_preserves_simple_root(tmp_path):
    payload = b'{"meta":{"api-version":"1.0"},"files":[]}'
    upstream = _FakePyPIRegistry(
        payload,
        content_type="application/vnd.pypi.simple.v1+json",
    )
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
        assert urllib.request.urlopen(gateway.index_url).read() == payload
        with pytest.raises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(gateway.index_url + "/badlib/")

    assert caught.value.code == 403
    assert gateway.state.evaluation_failures[0].failure_kind == "unsupported_content_type"


def test_pypi_gateway_rejects_non_utf8_project_page(tmp_path):
    upstream = _FakePyPIRegistry(b"<html><body>\xff</body></html>")
    cache_root = tmp_path / "cache"
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_root / "feed")

    with (
        upstream,
        PyPISimpleGateway(
            upstream_base=upstream.url,
            policy=PackagePolicy(),
            feed_cache_dir=cache_root / "feed",
        ) as gateway,
        pytest.raises(urllib.error.HTTPError) as caught,
    ):
        urllib.request.urlopen(gateway.index_url + "/badlib/")

    assert caught.value.code == 403
    assert gateway.state.evaluation_failures[0].failure_kind == "invalid_utf8"


def test_pypi_gateway_preserves_non_200_project_response(tmp_path):
    payload = b"project not found"
    upstream = _FakePyPIRegistry(payload, content_type="text/plain", status=404)

    with (
        upstream,
        PyPISimpleGateway(
            upstream_base=upstream.url,
            policy=PackagePolicy(),
        ) as gateway,
        pytest.raises(urllib.error.HTTPError) as caught,
    ):
        urllib.request.urlopen(gateway.index_url + "/badlib/")

    assert caught.value.code == 404
    assert caught.value.read() == payload
    assert gateway.state.evaluation_failures == []


@pytest.mark.parametrize("feed_state", ["missing", "tampered"])
def test_pypi_gateway_rejects_project_page_when_feed_cannot_be_loaded(
    tmp_path,
    feed_state,
):
    html = b'<html><body><a href="badlib-0.9.0.tar.gz">badlib</a></body></html>'
    upstream = _FakePyPIRegistry(html)
    cache_root = tmp_path / "cache"
    if feed_state == "tampered":
        snapshot = update_feed_from_source(
            _write_feed_bundle(tmp_path),
            cache_dir=cache_root / "feed",
        )
        (snapshot.snapshot_dir / "pypi-malware.json").write_text('{"packages": []}\n')

    with (
        upstream,
        PyPISimpleGateway(
            upstream_base=upstream.url,
            policy=PackagePolicy(),
            feed_cache_dir=cache_root / "feed",
        ) as gateway,
        pytest.raises(urllib.error.HTTPError) as caught,
    ):
        urllib.request.urlopen(gateway.index_url + "/badlib/")

    assert caught.value.code == 403
    assert gateway.state.evaluation_failures[0].failure_kind == f"feed_{feed_state}"
    assert gateway.to_dict()["feed_state"] == feed_state


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


def test_pypi_gateway_allows_scoped_package_age_exception(tmp_path):
    now = datetime(2026, 6, 26, 12, 0, tzinfo=timezone.utc)
    html = b"""
<html><body>
<a href="fresh-lib-2.0.0.tar.gz">fresh-lib-2.0.0.tar.gz</a>
</body></html>
"""
    upstream = _FakePyPIRegistry(html)
    cache_root = tmp_path / "cache"
    update_feed_from_source(
        _write_feed_bundle(
            tmp_path,
            pypi_releases={"packages": {"fresh-lib": {"2.0.0": "2026-06-26T11:00:00+00:00"}}},
        ),
        cache_dir=cache_root / "feed",
    )
    policy = PackagePolicy(
        package_age=PackageAgePolicy(enabled=True, minimum_hours=48),
        exceptions=(
            PolicyException(
                policy_id="ca9.package_age",
                ecosystem="pypi",
                package="fresh-lib",
                version="2.*",
                owner="release-security",
                reason="Emergency release",
                expires="2026-06-27",
            ),
        ),
    )

    with (
        upstream,
        PyPISimpleGateway(
            upstream_base=upstream.url,
            policy=policy,
            feed_cache_dir=cache_root / "feed",
            now=now,
        ) as gateway,
    ):
        body = urllib.request.urlopen(gateway.index_url + "/fresh-lib/").read().decode()

    assert "fresh-lib-2.0.0.tar.gz" in body
    assert gateway.state.removed_links == []
    assert gateway.state.applied_exceptions[0]["action"] == "warn"
    assert (
        gateway.state.applied_exceptions[0]["evidence"]["policy_exception"]["owner"]
        == "release-security"
    )


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
            "PIP_PYPI_URL": "https://alias.example/simple",
            "PIP_EXTRA_INDEX_URL": "https://extra.example/simple",
            "PIP_FIND_LINKS": "https://files.example",
            "PIP_CONFIG_FILE": "/tmp/pip.conf",
            "PIP_REQUIREMENT": "requirements.txt",
            "PIP_CONSTRAINT": "constraints.txt",
            "PIP_BUILD_CONSTRAINT": "build-constraints.txt",
            "PIP_REQUIREMENTS_FROM_SCRIPT": "script.py",
            "PIP_EDITABLE": "git+https://example.invalid/project.git",
            "PIP_GROUP": "project:dev",
            "PIP_PROXY": "http://proxy.example",
            "NO_PROXY": "metadata.internal",
        },
        "http://127.0.0.1:12345/simple",
    )

    assert child_env["PIP_INDEX_URL"] == "http://127.0.0.1:12345/simple"
    assert child_env["PIP_PYPI_URL"] == "http://127.0.0.1:12345/simple"
    assert child_env["PIP_CONFIG_FILE"] == os.devnull
    assert "PIP_EXTRA_INDEX_URL" not in child_env
    assert "PIP_FIND_LINKS" not in child_env
    assert "PIP_REQUIREMENT" not in child_env
    assert "PIP_CONSTRAINT" not in child_env
    assert "PIP_BUILD_CONSTRAINT" not in child_env
    assert "PIP_REQUIREMENTS_FROM_SCRIPT" not in child_env
    assert "PIP_EDITABLE" not in child_env
    assert "PIP_GROUP" not in child_env
    assert "PIP_PROXY" not in child_env
    assert "metadata.internal" in child_env["NO_PROXY"]
    assert "127.0.0.1" in child_env["NO_PROXY"]
    assert child_env["NO_PROXY"] == child_env["no_proxy"]


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
    child_args = argv_path.read_text()
    assert child_args.count("--index-url") == 1
    assert upstream.url not in child_args
    assert "--index-url http://127.0.0.1:" in child_args
    body = index_path.read_text()
    assert "badlib-0.9.0-py3-none-any.whl" in body
    assert "badlib-1.0.0-py3-none-any.whl" not in body


def test_ca9_run_pip_records_gateway_evaluation_failure_in_ledger(tmp_path):
    upstream = _FakePyPIRegistry(
        b'{"meta":{"api-version":"1.0"},"files":[]}',
        content_type="application/vnd.pypi.simple.v1+json",
    )
    cache_root = tmp_path / "cache"
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_root / "feed")
    bin_dir = tmp_path / "bin"
    audit_log = tmp_path / "audit.jsonl"
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
        f'{sys.executable} -c "import os, urllib.request; '
        "url=os.environ['PIP_INDEX_URL'].rstrip('/') + '/safe-lib/'; "
        'urllib.request.urlopen(url).read()"\n',
    )

    with upstream:
        result = CliRunner().invoke(
            main,
            [
                "run",
                "--policy",
                str(policy_path),
                "--audit-log",
                str(audit_log),
                "--",
                "pip",
                "install",
                "--index-url",
                upstream.url + "/simple",
                "safe-lib",
            ],
            env={"CA9_CACHE_DIR": str(cache_root), "PATH": str(bin_dir)},
        )

    assert result.exit_code == 1
    events = [json.loads(line) for line in audit_log.read_text().splitlines()]
    failure = next(
        event
        for event in events
        if event["event_kind"] == "decision_emitted"
        and event["payload"]["policy_id"] == "ca9.pypi_gateway_evaluation_failed"
    )
    assert failure["payload"]["action"] == "block"
    assert failure["payload"]["package"] == "safe-lib"
    assert failure["payload"]["evidence"]["failure_kind"] == "unsupported_content_type"


def test_ca9_run_pip_rejects_requirement_file_index_before_child_install(
    tmp_path,
    monkeypatch,
):
    html = b"""
<html><body>
<a href="badlib-0.9.0-py3-none-any.whl">badlib-0.9.0-py3-none-any.whl</a>
<a href="badlib-1.0.0-py3-none-any.whl">badlib-1.0.0-py3-none-any.whl</a>
</body></html>
"""
    upstream = _FakePyPIRegistry(html)
    cache_root = tmp_path / "cache"
    update_feed_from_source(_write_feed_bundle(tmp_path), cache_dir=cache_root / "feed")
    repo = tmp_path / "repo"
    repo.mkdir()
    bin_dir = tmp_path / "bin"
    index_path = tmp_path / "simple.html"
    argv_path = tmp_path / "argv.txt"
    policy_path = repo / "ca9.toml"
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
    monkeypatch.chdir(repo)

    runner = CliRunner()
    with upstream:
        (repo / "requirements.txt").write_text(f"--index-url {upstream.url}/simple\nbadlib\n")
        result = runner.invoke(
            main,
            [
                "run",
                "--policy",
                str(policy_path),
                "--",
                "pip",
                "install",
                "-r",
                "requirements.txt",
            ],
            env={
                "CA9_CACHE_DIR": str(cache_root),
                "PATH": str(bin_dir),
            },
        )

    assert result.exit_code == 1
    assert "ca9.runtime.requirements_unavailable" in result.output
    assert "--index-url" in result.output
    assert not argv_path.exists()
    assert not index_path.exists()


class _FakePyPIRegistry:
    def __init__(self, payload: bytes, *, content_type: str = "text/html", status: int = 200):
        self.payload = payload
        self.content_type = content_type
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
        content_type = self.content_type
        status = self.status

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
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
