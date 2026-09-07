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
from ca9.package_policy import PackagePolicy, action_for_mode, find_policy_exception

DEFAULT_PYPI_UPSTREAM = "https://pypi.org"
GATEWAY_SCHEMA = "ca9.pypi.gateway.v1"
EVALUATION_FAILURE_POLICY_ID = "ca9.pypi_gateway_evaluation_failed"


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
            "href": _sanitize_url_for_evidence(self.href),
        }


@dataclass(frozen=True)
class PyPIGatewayEvaluationFailure:
    package: str
    reason: str
    failure_kind: str
    policy_id: str = EVALUATION_FAILURE_POLICY_ID

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "policy_id": self.policy_id,
            "reason": self.reason,
            "evidence": {
                "ecosystem": "pypi",
                "failure_kind": self.failure_kind,
            },
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
    applied_exceptions: list[dict[str, Any]] | None = None
    evaluation_failures: list[PyPIGatewayEvaluationFailure] | None = None

    def __post_init__(self) -> None:
        self.upstream_base = _normalize_upstream_base(self.upstream_base)
        self.removed_links = []
        self.applied_exceptions = []
        self.evaluation_failures = []


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
            "upstream_base": _sanitize_url_for_evidence(self.state.upstream_base),
            "feed_state": self.state.feed.state if self.state.feed else None,
            "feed_snapshot": self.state.feed.snapshot.snapshot_id
            if self.state.feed and self.state.feed.snapshot
            else None,
            "rewrite_count": self.state.rewrite_count,
            "removed_links": [item.to_dict() for item in self.state.removed_links or []],
            "applied_exceptions": list(self.state.applied_exceptions or []),
            "evaluation_failures": [
                item.to_dict() for item in self.state.evaluation_failures or []
            ],
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
    no_proxy = _loopback_no_proxy(child_env)
    for key in list(child_env):
        if key.lower() == "pip_proxy":
            child_env.pop(key)
    child_env["PIP_INDEX_URL"] = index_url
    child_env["PIP_PYPI_URL"] = index_url
    child_env["PIP_TRUSTED_HOST"] = urllib.parse.urlparse(index_url).hostname or "127.0.0.1"
    child_env["PIP_CONFIG_FILE"] = os.devnull
    child_env.pop("PIP_EXTRA_INDEX_URL", None)
    child_env.pop("PIP_FIND_LINKS", None)
    child_env.pop("PIP_REQUIREMENT", None)
    child_env.pop("PIP_CONSTRAINT", None)
    child_env.pop("PIP_BUILD_CONSTRAINT", None)
    child_env.pop("PIP_REQUIREMENTS_FROM_SCRIPT", None)
    child_env.pop("PIP_EDITABLE", None)
    child_env.pop("PIP_GROUP", None)
    child_env["NO_PROXY"] = no_proxy
    child_env["no_proxy"] = no_proxy
    return child_env


def _loopback_no_proxy(env: dict[str, str]) -> str:
    values: list[str] = []
    for name, value in env.items():
        if name.lower() != "no_proxy":
            continue
        values.extend(item.strip() for item in value.split(",") if item.strip())
    for host in ("127.0.0.1", "localhost", "::1", "[::1]"):
        if host not in values:
            values.append(host)
    return ",".join(values)


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
            package_name = _package_from_simple_path(self.path)
            if rewrite and 200 <= status < 400 and package_name:
                if not _looks_like_html(headers):
                    _deny_project_page(
                        self,
                        state,
                        PyPIGatewayEvaluationFailure(
                            package=package_name,
                            failure_kind="unsupported_content_type",
                            reason=("PyPI project page is not HTML and cannot be safely evaluated"),
                        ),
                        include_body=include_body,
                    )
                    return
                try:
                    rewritten = _rewrite_simple_html(body, package_name, state)
                except _ProjectPageEvaluationError as exc:
                    _deny_project_page(
                        self,
                        state,
                        PyPIGatewayEvaluationFailure(
                            package=package_name,
                            failure_kind=exc.failure_kind,
                            reason=exc.reason,
                        ),
                        include_body=include_body,
                    )
                    return
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


class _ProjectPageEvaluationError(Exception):
    def __init__(self, failure_kind: str, reason: str) -> None:
        super().__init__(reason)
        self.failure_kind = failure_kind
        self.reason = reason


def _deny_project_page(
    handler: BaseHTTPRequestHandler,
    state: PyPIGatewayState,
    failure: PyPIGatewayEvaluationFailure,
    *,
    include_body: bool,
) -> None:
    if state.evaluation_failures is not None and failure not in state.evaluation_failures:
        state.evaluation_failures.append(failure)
    body = b"PyPI project page could not be safely evaluated\n"
    handler.send_response(403)
    handler.send_header("Content-Type", "text/plain; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    if include_body:
        handler.wfile.write(body)


def _fetch_upstream(url: str) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.pypi.simple.v1+html, text/html"},
    )
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
        raise _ProjectPageEvaluationError(
            "invalid_utf8",
            "PyPI project page is not valid UTF-8 and cannot be safely evaluated",
        ) from None
    links = _SimpleLinksParser()
    links.feed(text)
    links.close()
    if not links.saw_markup:
        raise _ProjectPageEvaluationError(
            "invalid_html",
            "PyPI project page is not valid HTML and cannot be safely evaluated",
        )
    if links.failure is not None:
        raise _ProjectPageEvaluationError(*links.failure)

    feed = _ensure_feed(state)
    if feed.snapshot is None:
        feed_state = feed.state
        if feed_state not in {"missing", "tampered"}:
            feed_state = "unavailable"
        raise _ProjectPageEvaluationError(
            f"feed_{feed_state}",
            f"PyPI policy feed is {feed_state} and the project page cannot be safely evaluated",
        )

    kept: list[_SimpleLink] = []
    removed: list[PyPIGatewayDecision] = []
    for link in links.links:
        version = _version_from_href(link.href, package_name)
        if version is None:
            raise _ProjectPageEvaluationError(
                "unparseable_distribution_link",
                (
                    "PyPI project page contains a distribution link with an unparseable "
                    "filename or version"
                ),
            )
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


def _ensure_feed(state: PyPIGatewayState) -> FeedStatus:
    state.feed = feed_status(policy=state.policy, cache_dir=state.feed_cache_dir, now=state.now)
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
            return _apply_gateway_exception(
                PyPIGatewayDecision(
                    package=package_name,
                    version=version,
                    policy_id="ca9.malware",
                    reason=(
                        f"local feed marks {package_name}=={version} as malicious ({malware_id})"
                    ),
                    href=href,
                ),
                state,
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
                return _apply_gateway_exception(
                    PyPIGatewayDecision(
                        package=package_name,
                        version=version,
                        policy_id="ca9.package_age_unknown",
                        reason=(
                            f"release time for {package_name}=={version} is not available "
                            "in the local feed"
                        ),
                        href=href,
                    ),
                    state,
                )
        elif action_for_mode("block", policy.mode.default) == "block":
            released = _parse_time(released_at)
            age_hours = (now - released).total_seconds() / 3600
            if age_hours < policy.package_age.minimum_hours:
                return _apply_gateway_exception(
                    PyPIGatewayDecision(
                        package=package_name,
                        version=version,
                        policy_id="ca9.package_age",
                        reason=(
                            f"package version age is {age_hours:.1f}h, below policy minimum "
                            f"of {policy.package_age.minimum_hours}h"
                        ),
                        href=href,
                    ),
                    state,
                )
    return None


def _apply_gateway_exception(
    decision: PyPIGatewayDecision,
    state: PyPIGatewayState,
) -> PyPIGatewayDecision | None:
    exception = find_policy_exception(
        state.policy.exceptions,
        policy_id=decision.policy_id,
        ecosystem="pypi",
        package=decision.package,
        version=decision.version,
        now=state.now,
    )
    if exception is None:
        return decision
    payload = {
        "action": exception.action,
        "package": decision.package,
        "version": decision.version,
        "policy_id": decision.policy_id,
        "reason": (
            f"{decision.reason}; exception owned by {exception.owner} applies until "
            f"{exception.expires}: {exception.reason}"
        ),
        "evidence": {
            "policy_exception": {
                **exception.to_dict(),
                "original_action": "block",
            }
        },
    }
    if state.applied_exceptions is not None and payload not in state.applied_exceptions:
        state.applied_exceptions.append(payload)
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
        self.saw_markup = False
        self.failure: tuple[str, str] | None = None
        self._anchor_open = False
        self._active_link_index: int | None = None
        self._active_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.saw_markup = True
        if tag.lower() != "a":
            return
        if self._anchor_open:
            self._fail(
                "invalid_anchor_structure",
                "PyPI project page contains nested anchor elements",
            )
            return

        self._anchor_open = True
        self._active_link_index = None
        self._active_text = []
        hrefs = [value for name, value in attrs if name.lower() == "href"]
        if len(hrefs) > 1:
            self._fail(
                "duplicate_href",
                "PyPI project page contains an anchor with duplicate href attributes",
            )
            return
        if not hrefs or not hrefs[0]:
            return
        self.links.append(_SimpleLink(href=hrefs[0], text="", attrs=tuple(attrs)))
        self._active_link_index = len(self.links) - 1

    def handle_data(self, data: str) -> None:
        if self._anchor_open and self._active_link_index is not None:
            self._active_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "a":
            return
        if not self._anchor_open:
            self._fail(
                "invalid_anchor_structure",
                "PyPI project page contains an unmatched closing anchor",
            )
            return
        if self._active_link_index is not None:
            active = self.links[self._active_link_index]
            self.links[self._active_link_index] = _SimpleLink(
                href=active.href,
                text="".join(self._active_text),
                attrs=active.attrs,
            )
        self._anchor_open = False
        self._active_link_index = None
        self._active_text = []

    def close(self) -> None:
        super().close()
        if self._anchor_open:
            self._fail(
                "invalid_anchor_structure",
                "PyPI project page contains an unclosed anchor element",
            )

    def _fail(self, failure_kind: str, reason: str) -> None:
        if self.failure is None:
            self.failure = (failure_kind, reason)


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
    if len(parts) != 2 or parts[0] != "simple":
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


def _sanitize_url_for_evidence(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return "[redacted-invalid-url]"
    hostname = parsed.hostname
    if hostname is None:
        netloc = "" if not parsed.netloc else "[redacted]"
    else:
        rendered_host = f"[{hostname}]" if ":" in hostname else hostname
        try:
            port = parsed.port
        except ValueError:
            port = None
        netloc = f"{rendered_host}:{port}" if port is not None else rendered_host
    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))


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
    if not content_type:
        return True
    media_type = content_type.split(";", 1)[0].strip()
    return media_type in {
        "text/html",
        "application/vnd.pypi.simple.v1+html",
    }


def _is_loopback_client(host: str) -> bool:
    return host.startswith("127.") or host == "::1" or host == "localhost"


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
