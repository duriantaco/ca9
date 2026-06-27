from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from fnmatch import fnmatch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from ca9.package_feed import (
    FeedSnapshot,
    FeedStatus,
    feed_status,
    lookup_malware,
    lookup_release_time,
    release_window_covers,
)
from ca9.package_policy import PackagePolicy, action_for_mode

DEFAULT_NPM_REGISTRY = "https://registry.npmjs.org"
GATEWAY_SCHEMA = "ca9.npm.gateway.v1"


@dataclass(frozen=True)
class NpmGatewayDecision:
    package: str
    version: str
    policy_id: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "version": self.version,
            "policy_id": self.policy_id,
            "reason": self.reason,
        }


@dataclass
class NpmGatewayState:
    upstream_registry: str
    policy: PackagePolicy
    feed_cache_dir: Path | None = None
    now: datetime | None = None
    feed: FeedStatus | None = None
    rewrite_count: int = 0
    removed_versions: list[NpmGatewayDecision] | None = None

    def __post_init__(self) -> None:
        self.removed_versions = []


class NpmMetadataGateway:
    def __init__(
        self,
        *,
        upstream_registry: str = DEFAULT_NPM_REGISTRY,
        policy: PackagePolicy,
        feed_cache_dir: Path | None = None,
        now: datetime | None = None,
    ) -> None:
        self.state = NpmGatewayState(
            upstream_registry=upstream_registry.rstrip("/"),
            policy=policy,
            feed_cache_dir=feed_cache_dir,
            now=now,
        )
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def registry_url(self) -> str:
        if self._server is None:
            raise RuntimeError("npm gateway is not started")
        host, port = self._server.server_address
        return f"http://{host}:{port}/"

    def __enter__(self) -> NpmMetadataGateway:
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
            "registry_url": self.registry_url if self._server is not None else None,
            "upstream_registry": self.state.upstream_registry,
            "feed_state": self.state.feed.state if self.state.feed else None,
            "feed_snapshot": self.state.feed.snapshot.snapshot_id
            if self.state.feed and self.state.feed.snapshot
            else None,
            "rewrite_count": self.state.rewrite_count,
            "removed_versions": [item.to_dict() for item in self.state.removed_versions or []],
        }


def should_start_npm_gateway(
    command_family: str,
    policy: PackagePolicy,
    feed: FeedStatus | None,
) -> bool:
    return (
        command_family == "npm"
        and (policy.malware.enabled or policy.package_age.enabled)
        and feed is not None
        and feed.snapshot is not None
    )


def npm_gateway_child_env(env: dict[str, str], registry_url: str) -> dict[str, str]:
    child_env = dict(env)
    child_env["npm_config_registry"] = registry_url
    child_env["NPM_CONFIG_REGISTRY"] = registry_url
    child_env["npm_config_userconfig"] = os.devnull
    child_env["NPM_CONFIG_USERCONFIG"] = os.devnull
    child_env["npm_config_globalconfig"] = os.devnull
    child_env["NPM_CONFIG_GLOBALCONFIG"] = os.devnull
    for key in list(child_env):
        lowered = key.lower()
        if lowered.startswith("npm_config_") and lowered.endswith(":registry"):
            child_env[key] = registry_url
    return child_env


def _handler_for_state(state: NpmGatewayState):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ca9-npm-gateway"

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

            upstream_url = state.upstream_registry + self.path
            try:
                status, headers, body = _fetch_upstream(upstream_url)
            except urllib.error.HTTPError as exc:
                status = exc.code
                headers = dict(exc.headers.items())
                body = exc.read()
            except OSError as exc:
                self.send_error(502, f"cannot fetch upstream npm metadata: {exc}")
                return

            output = body
            if rewrite and status == 200 and _looks_like_json(headers):
                rewritten = _rewrite_metadata(body, state)
                if rewritten is not None:
                    output = rewritten
                    headers = dict(headers)
                    headers["Content-Type"] = "application/json"
                    headers["Content-Length"] = str(len(output))

            self.send_response(status)
            _copy_headers(self, headers, content_length=len(output))
            self.end_headers()
            if include_body:
                self.wfile.write(output)

    return Handler


def _fetch_upstream(url: str) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.status, dict(response.headers.items()), response.read()


def _rewrite_metadata(body: bytes, state: NpmGatewayState) -> bytes | None:
    try:
        metadata = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(metadata, dict) or not isinstance(metadata.get("versions"), dict):
        return None

    package_name = str(metadata.get("name") or "")
    if not package_name:
        return None

    feed = _ensure_feed(state)
    if feed is None or feed.snapshot is None:
        return None

    versions = dict(metadata["versions"])
    metadata_time = metadata.get("time") if isinstance(metadata.get("time"), dict) else None
    removed: list[NpmGatewayDecision] = []
    for version in list(versions):
        decision = _denied_version(
            package_name, version, state.policy, feed.snapshot, state, metadata_time
        )
        if decision is None:
            continue
        removed.append(decision)
        versions.pop(version, None)

    if not removed:
        return None

    rewritten = dict(metadata)
    rewritten["versions"] = versions
    rewritten["dist-tags"] = _rewrite_dist_tags(metadata.get("dist-tags"), versions)
    state.rewrite_count += 1
    if state.removed_versions is not None:
        state.removed_versions.extend(removed)
    return (json.dumps(rewritten, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _ensure_feed(state: NpmGatewayState) -> FeedStatus | None:
    if state.feed is not None:
        return state.feed
    state.feed = feed_status(
        policy=state.policy,
        cache_dir=state.feed_cache_dir,
        now=state.now,
    )
    if state.feed.state == "tampered":
        return None
    return state.feed


def _denied_version(
    package_name: str,
    version: str,
    policy: PackagePolicy,
    snapshot: FeedSnapshot,
    state: NpmGatewayState,
    metadata_time: dict | None = None,
) -> NpmGatewayDecision | None:
    if policy.malware.enabled:
        matches = lookup_malware("npm", package_name, version, snapshot=snapshot)
        if matches and action_for_mode("block", policy.mode.default) == "block":
            malware_id = matches[0].get("id") or "local-feed"
            return NpmGatewayDecision(
                package=package_name,
                version=version,
                policy_id="ca9.malware",
                reason=f"local feed marks {package_name}@{version} as malicious ({malware_id})",
            )

    if policy.package_age.enabled and not _is_age_excluded(
        "npm",
        package_name,
        version,
        policy.package_age.exclusions,
    ):
        now = state.now or datetime.now(timezone.utc)
        released_at = lookup_release_time("npm", package_name, version, snapshot=snapshot)
        if not released_at and metadata_time:
            candidate = metadata_time.get(version)
            released_at = str(candidate) if candidate else None
        if not released_at:
            if release_window_covers(
                snapshot, "npm", now=now, minimum_hours=policy.package_age.minimum_hours
            ):
                return None
            if action_for_mode("block", policy.mode.offline) == "block":
                return NpmGatewayDecision(
                    package=package_name,
                    version=version,
                    policy_id="ca9.package_age_unknown",
                    reason=(
                        f"release time for {package_name}@{version} is not available "
                        "in the local feed"
                    ),
                )
        elif action_for_mode("block", policy.mode.default) == "block":
            released = _parse_time(released_at)
            age_hours = (now - released).total_seconds() / 3600
            if age_hours < policy.package_age.minimum_hours:
                return NpmGatewayDecision(
                    package=package_name,
                    version=version,
                    policy_id="ca9.package_age",
                    reason=(
                        f"package version age is {age_hours:.1f}h, below policy minimum "
                        f"of {policy.package_age.minimum_hours}h"
                    ),
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


def _rewrite_dist_tags(raw_dist_tags: Any, versions: dict[str, Any]) -> dict[str, str]:
    if not isinstance(raw_dist_tags, dict):
        return {}
    rewritten: dict[str, str] = {}
    for tag, version in raw_dist_tags.items():
        if isinstance(version, str) and version in versions:
            rewritten[str(tag)] = version
    if "latest" not in rewritten and versions:
        rewritten["latest"] = next(reversed(versions))
    return rewritten


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


def _looks_like_json(headers: dict[str, str]) -> bool:
    content_type = ""
    for key, value in headers.items():
        if key.lower() == "content-type":
            content_type = value.lower()
            break
    return not content_type or "json" in content_type


def _is_loopback_client(host: str) -> bool:
    return host.startswith("127.") or host == "::1" or host == "localhost"


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
