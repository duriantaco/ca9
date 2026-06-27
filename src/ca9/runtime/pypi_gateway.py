from __future__ import annotations

import html
import os
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from fnmatch import fnmatch
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any

from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)

from ca9.package_feed import (
    FeedSnapshot,
    FeedStatus,
    feed_status,
    lookup_malware,
    lookup_release_time,
    release_window_covers,
)
from ca9.package_policy import PackagePolicy, action_for_mode

DEFAULT_PYPI_UPSTREAM = "https://pypi.org"
GATEWAY_SCHEMA = "ca9.pypi.gateway.v1"


@dataclass(frozen=True)
class PyPIGatewayDecision:
    package: str
    version: str
    policy_id: str
    reason: str
    href: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "version": self.version,
            "policy_id": self.policy_id,
            "reason": self.reason,
            "href": self.href,
        }


@dataclass
class PyPIGatewayState:
    upstream_base: str
    policy: PackagePolicy
    feed_cache_dir: Path | None = None
    now: datetime | None = None
    feed: FeedStatus | None = None
    rewrite_count: int = 0
    removed_links: list[PyPIGatewayDecision] | None = None

    def __post_init__(self) -> None:
        self.upstream_base = _normalize_upstream_base(self.upstream_base)
        self.removed_links = []


class PyPISimpleGateway:
    def __init__(
        self,
        *,
        upstream_base: str = DEFAULT_PYPI_UPSTREAM,
        policy: PackagePolicy,
        feed_cache_dir: Path | None = None,
        now: datetime | None = None,
    ) -> None:
        self.state = PyPIGatewayState(
            upstream_base=upstream_base,
            policy=policy,
            feed_cache_dir=feed_cache_dir,
            now=now,
        )
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def index_url(self) -> str:
        if self._server is None:
            raise RuntimeError("PyPI gateway is not started")
        host, port = self._server.server_address
        return f"http://{host}:{port}/simple"

    def __enter__(self) -> PyPISimpleGateway:
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    def start(self) -> None:
        if self._server is not None:
            return
        handler = _handler_for_state(self.state)
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": GATEWAY_SCHEMA,
            "index_url": self.index_url if self._server is not None else None,
            "upstream_base": self.state.upstream_base,
            "feed_state": self.state.feed.state if self.state.feed else None,
            "feed_snapshot": self.state.feed.snapshot.snapshot_id
            if self.state.feed and self.state.feed.snapshot
            else None,
            "rewrite_count": self.state.rewrite_count,
            "removed_links": [item.to_dict() for item in self.state.removed_links or []],
        }


def should_start_pypi_gateway(
    command_family: str,
    policy: PackagePolicy,
    feed: FeedStatus | None,
) -> bool:
    return (
        command_family == "pip"
        and (policy.malware.enabled or policy.package_age.enabled)
        and feed is not None
        and feed.snapshot is not None
    )


def pypi_gateway_child_env(env: dict[str, str], index_url: str) -> dict[str, str]:
    child_env = dict(env)
    child_env["PIP_INDEX_URL"] = index_url
    child_env["PIP_TRUSTED_HOST"] = urllib.parse.urlparse(index_url).hostname or "127.0.0.1"
    child_env["PIP_CONFIG_FILE"] = os.devnull
    child_env.pop("PIP_EXTRA_INDEX_URL", None)
    child_env.pop("PIP_FIND_LINKS", None)
    return child_env


def _handler_for_state(state: PyPIGatewayState):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ca9-pypi-gateway"

        def do_HEAD(self) -> None:
            self._proxy(rewrite=False, include_body=False)

        def do_GET(self) -> None:
            self._proxy(rewrite=True, include_body=True)

        def log_message(self, fmt: str, *args) -> None:  # pragma: no cover - silence server logs
            return

        def _proxy(self, *, rewrite: bool, include_body: bool) -> None:
            if not _is_loopback_client(self.client_address[0]):
                self.send_error(403, "gateway accepts only loopback clients")
                return
            if self.path.startswith(("http://", "https://")):
                self.send_error(403, "gateway does not proxy absolute URLs")
                return

            upstream_url = state.upstream_base + self.path
            try:
                status, headers, body = _fetch_upstream(upstream_url)
            except urllib.error.HTTPError as exc:
                status = exc.code
                headers = dict(exc.headers.items())
                body = exc.read()
            except OSError as exc:
                self.send_error(502, f"cannot fetch upstream PyPI simple page: {exc}")
                return

            output = body
            if rewrite and status == 200 and _looks_like_html(headers):
                package_name = _package_from_simple_path(self.path)
                rewritten = (
                    _rewrite_simple_html(body, package_name, state) if package_name else None
                )
                if rewritten is not None:
                    output = rewritten
                    headers = dict(headers)
                    headers["Content-Type"] = "text/html; charset=utf-8"
                    headers["Content-Length"] = str(len(output))

            self.send_response(status)
            _copy_headers(self, headers, content_length=len(output))
            self.end_headers()
            if include_body:
                self.wfile.write(output)

    return Handler


def _fetch_upstream(url: str) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(url, headers={"Accept": "text/html"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.status, dict(response.headers.items()), response.read()


def _rewrite_simple_html(
    body: bytes,
    package_name: str,
    state: PyPIGatewayState,
) -> bytes | None:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    links = _SimpleLinksParser()
    links.feed(text)
    if not links.links:
        return None

    feed = _ensure_feed(state)
    if feed is None or feed.snapshot is None:
        return None

    kept: list[_SimpleLink] = []
    removed: list[PyPIGatewayDecision] = []
    for link in links.links:
        version = _version_from_href(link.href, package_name)
        if version is None:
            kept.append(link)
            continue
        decision = _denied_version(
            package_name, version, link.href, state.policy, feed.snapshot, state
        )
        if decision is None:
            kept.append(link)
            continue
        removed.append(decision)

    if not removed:
        return None

    state.rewrite_count += 1
    if state.removed_links is not None:
        state.removed_links.extend(removed)
    return _render_simple_page(package_name, kept).encode("utf-8")


def _ensure_feed(state: PyPIGatewayState) -> FeedStatus | None:
    if state.feed is not None:
        return state.feed
    state.feed = feed_status(policy=state.policy, cache_dir=state.feed_cache_dir, now=state.now)
    if state.feed.state == "tampered":
        return None
    return state.feed


def _denied_version(
    package_name: str,
    version: str,
    href: str,
    policy: PackagePolicy,
    snapshot: FeedSnapshot,
    state: PyPIGatewayState,
) -> PyPIGatewayDecision | None:
    if policy.malware.enabled:
        matches = lookup_malware("pypi", package_name, version, snapshot=snapshot)
        if matches and action_for_mode("block", policy.mode.default) == "block":
            malware_id = matches[0].get("id") or "local-feed"
            return PyPIGatewayDecision(
                package=package_name,
                version=version,
                policy_id="ca9.malware",
                reason=f"local feed marks {package_name}=={version} as malicious ({malware_id})",
                href=href,
            )

    if policy.package_age.enabled and not _is_age_excluded(
        "pypi",
        package_name,
        version,
        policy.package_age.exclusions,
    ):
        now = state.now or datetime.now(timezone.utc)
        released_at = lookup_release_time("pypi", package_name, version, snapshot=snapshot)
        if not released_at:
            if release_window_covers(
                snapshot, "pypi", now=now, minimum_hours=policy.package_age.minimum_hours
            ):
                return None
            if action_for_mode("block", policy.mode.offline) == "block":
                return PyPIGatewayDecision(
                    package=package_name,
                    version=version,
                    policy_id="ca9.package_age_unknown",
                    reason=(
                        f"release time for {package_name}=={version} is not available "
                        "in the local feed"
                    ),
                    href=href,
                )
        elif action_for_mode("block", policy.mode.default) == "block":
            released = _parse_time(released_at)
            age_hours = (now - released).total_seconds() / 3600
            if age_hours < policy.package_age.minimum_hours:
                return PyPIGatewayDecision(
                    package=package_name,
                    version=version,
                    policy_id="ca9.package_age",
                    reason=(
                        f"package version age is {age_hours:.1f}h, below policy minimum "
                        f"of {policy.package_age.minimum_hours}h"
                    ),
                    href=href,
                )
    return None


def _is_age_excluded(
    ecosystem: str,
    package_name: str,
    version: str,
    exclusions: tuple[str, ...],
) -> bool:
    target = package_name.lower()
    versioned = f"{ecosystem}:{target}@{version}".lower()
    for pattern in exclusions:
        normalized = pattern.strip().lower()
        if normalized and (fnmatch(target, normalized) or fnmatch(versioned, normalized)):
            return True
    return False


@dataclass(frozen=True)
class _SimpleLink:
    href: str
    text: str
    attrs: tuple[tuple[str, str | None], ...]


class _SimpleLinksParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[_SimpleLink] = []
        self._active_attrs: tuple[tuple[str, str | None], ...] | None = None
        self._active_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            self._active_attrs = tuple(attrs)
            self._active_text = []

    def handle_data(self, data: str) -> None:
        if self._active_attrs is not None:
            self._active_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "a" or self._active_attrs is None:
            return
        href = ""
        for name, value in self._active_attrs:
            if name.lower() == "href" and value:
                href = value
                break
        if href:
            self.links.append(
                _SimpleLink(
                    href=href,
                    text="".join(self._active_text),
                    attrs=self._active_attrs,
                )
            )
        self._active_attrs = None
        self._active_text = []


def _render_simple_page(package_name: str, links: list[_SimpleLink]) -> str:
    lines = [
        "<!DOCTYPE html>",
        "<html>",
        f"<head><title>Links for {html.escape(package_name)}</title></head>",
        "<body>",
        f"<h1>Links for {html.escape(package_name)}</h1>",
    ]
    for link in links:
        attrs = _render_attrs(link.attrs)
        text = html.escape(link.text or PurePosixPath(_href_path(link.href)).name)
        lines.append(f"<a {attrs}>{text}</a><br/>")
    lines.extend(["</body>", "</html>", ""])
    return "\n".join(lines)


def _render_attrs(attrs: tuple[tuple[str, str | None], ...]) -> str:
    rendered: list[str] = []
    for name, value in attrs:
        if value is None:
            rendered.append(html.escape(name))
        else:
            rendered.append(f'{html.escape(name)}="{html.escape(value, quote=True)}"')
    return " ".join(rendered)


def _package_from_simple_path(path: str) -> str | None:
    parsed = urllib.parse.urlparse(path)
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2 or parts[0] != "simple":
        return None
    return str(canonicalize_name(urllib.parse.unquote(parts[1])))


def _version_from_href(href: str, package_name: str) -> str | None:
    filename = PurePosixPath(_href_path(href)).name
    if not filename:
        return None
    try:
        name, version, _, _ = parse_wheel_filename(filename)
    except InvalidWheelFilename:
        try:
            name, version = parse_sdist_filename(filename)
        except InvalidSdistFilename:
            return None
    if str(canonicalize_name(str(name))) != str(canonicalize_name(package_name)):
        return None
    return str(version)


def _href_path(href: str) -> str:
    parsed = urllib.parse.urlparse(href)
    return urllib.parse.unquote(parsed.path)


def _normalize_upstream_base(value: str) -> str:
    base = value.rstrip("/")
    if base.endswith("/simple"):
        return base[: -len("/simple")]
    return base


def _copy_headers(
    handler: BaseHTTPRequestHandler,
    headers: dict[str, str],
    *,
    content_length: int,
) -> None:
    skipped = {"connection", "transfer-encoding", "content-encoding", "content-length"}
    for key, value in headers.items():
        if key.lower() in skipped:
            continue
        handler.send_header(key, value)
    handler.send_header("Content-Length", str(content_length))


def _looks_like_html(headers: dict[str, str]) -> bool:
    content_type = ""
    for key, value in headers.items():
        if key.lower() == "content-type":
            content_type = value.lower()
            break
    return not content_type or "html" in content_type


def _is_loopback_client(host: str) -> bool:
    return host.startswith("127.") or host == "::1" or host == "localhost"


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
