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
from tempfile import TemporaryDirectory
from typing import Any

from ca9.package_feed import (
    FeedSnapshot,
    FeedStatus,
    feed_status,
    lookup_malware,
    lookup_release_time,
    release_window_covers,
)
from ca9.package_policy import PackagePolicy, action_for_mode, find_policy_exception

DEFAULT_NPM_REGISTRY = "https://registry.npmjs.org"
GATEWAY_SCHEMA = "ca9.npm.gateway.v1"
EVALUATION_FAILURE_POLICY_ID = "ca9.npm_gateway_evaluation_failed"


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


@dataclass(frozen=True)
class NpmGatewayEvaluationFailure:
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
                "ecosystem": "npm",
                "failure_kind": self.failure_kind,
            },
        }


class NpmGatewayEvaluationError(ValueError):
    """Metadata could not be evaluated under the configured feed policy."""

    def __init__(self, *, package: str, failure_kind: str, reason: str) -> None:
        super().__init__(reason)
        self.package = package
        self.failure_kind = failure_kind
        self.reason = reason
        self.failure = NpmGatewayEvaluationFailure(package, reason, failure_kind)


@dataclass
class NpmGatewayState:
    upstream_registry: str
    policy: PackagePolicy
    feed_cache_dir: Path | None = None
    now: datetime | None = None
    feed: FeedStatus | None = None
    rewrite_count: int = 0
    removed_versions: list[NpmGatewayDecision] | None = None
    applied_exceptions: list[dict[str, Any]] | None = None
    evaluation_failures: list[NpmGatewayEvaluationFailure] | None = None

    def __post_init__(self) -> None:
        self.removed_versions = []
        self.applied_exceptions = []
        self.evaluation_failures = []


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
        self._npm_config_dir: TemporaryDirectory[str] | None = None
        self._user_config_path: Path | None = None
        self._global_config_path: Path | None = None

    @property
    def registry_url(self) -> str:
        if self._server is None:
            raise RuntimeError("npm gateway is not started")
        host, port = self._server.server_address
        return f"http://{host}:{port}/"

    @property
    def user_config_path(self) -> Path:
        if self._user_config_path is None:
            raise RuntimeError("npm gateway is not started")
        return self._user_config_path

    @property
    def global_config_path(self) -> Path:
        if self._global_config_path is None:
            raise RuntimeError("npm gateway is not started")
        return self._global_config_path

    def __enter__(self) -> NpmMetadataGateway:
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    def start(self) -> None:
        if self._server is not None:
            return
        config_dir: TemporaryDirectory[str] | None = None
        server: ThreadingHTTPServer | None = None
        thread: threading.Thread | None = None
        try:
            config_dir = TemporaryDirectory(prefix="ca9-npm-gateway-")
            config_root = Path(config_dir.name)
            user_config_path = config_root / "user.npmrc"
            global_config_path = config_root / "global.npmrc"
            user_config_path.touch(mode=0o600, exist_ok=False)
            global_config_path.touch(mode=0o600, exist_ok=False)

            handler = _handler_for_state(self.state)
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
        except BaseException:
            try:
                if server is not None:
                    if thread is not None and thread.is_alive():
                        server.shutdown()
                        thread.join(timeout=5)
                    server.server_close()
            finally:
                if config_dir is not None:
                    config_dir.cleanup()
            raise

        self._npm_config_dir = config_dir
        self._user_config_path = user_config_path
        self._global_config_path = global_config_path
        self._server = server
        self._thread = thread

    def stop(self) -> None:
        server = self._server
        thread = self._thread
        config_dir = self._npm_config_dir
        try:
            if server is not None:
                try:
                    if thread is not None and thread.is_alive():
                        server.shutdown()
                finally:
                    server.server_close()
                    if thread is not None:
                        thread.join(timeout=5)
        finally:
            self._server = None
            self._thread = None
            self._npm_config_dir = None
            self._user_config_path = None
            self._global_config_path = None
            if config_dir is not None:
                config_dir.cleanup()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": GATEWAY_SCHEMA,
            "registry_url": self.registry_url if self._server is not None else None,
            "upstream_registry": _sanitize_url_for_evidence(self.state.upstream_registry),
            "feed_state": self.state.feed.state if self.state.feed else None,
            "feed_snapshot": self.state.feed.snapshot.snapshot_id
            if self.state.feed and self.state.feed.snapshot
            else None,
            "rewrite_count": self.state.rewrite_count,
            "removed_versions": [item.to_dict() for item in self.state.removed_versions or []],
            "applied_exceptions": list(self.state.applied_exceptions or []),
            "evaluation_failures": [
                item.to_dict() for item in self.state.evaluation_failures or []
            ],
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


def npm_gateway_child_env(
    env: dict[str, str],
    registry_url: str,
    *,
    user_config_path: str | Path,
    global_config_path: str | Path,
) -> dict[str, str]:
    user_config = _validated_npm_config_path(user_config_path, "user")
    global_config = _validated_npm_config_path(global_config_path, "global")
    if os.path.samefile(user_config, global_config):
        raise ValueError("npm user and global config paths must be distinct files")

    child_env = dict(env)
    no_proxy = _loopback_no_proxy(child_env)
    child_env["npm_config_registry"] = registry_url
    child_env["NPM_CONFIG_REGISTRY"] = registry_url
    for key in list(child_env):
        lowered = key.lower()
        if lowered in {"npm_config_userconfig", "npm_config_globalconfig"}:
            child_env.pop(key)
            continue
        if lowered in {
            "npm_config_proxy",
            "npm_config_http_proxy",
            "npm_config_https_proxy",
            "npm_config_noproxy",
            "npm_config_no_proxy",
        }:
            child_env.pop(key)
            continue
        if lowered.startswith("npm_config_") and lowered.endswith(":registry"):
            child_env[key] = registry_url
    child_env["npm_config_userconfig"] = user_config
    child_env["NPM_CONFIG_USERCONFIG"] = user_config
    child_env["npm_config_globalconfig"] = global_config
    child_env["NPM_CONFIG_GLOBALCONFIG"] = global_config
    child_env["npm_config_proxy"] = "false"
    child_env["NPM_CONFIG_PROXY"] = "false"
    child_env["npm_config_https_proxy"] = "false"
    child_env["NPM_CONFIG_HTTPS_PROXY"] = "false"
    child_env["npm_config_noproxy"] = no_proxy
    child_env["NPM_CONFIG_NOPROXY"] = no_proxy
    child_env["NO_PROXY"] = no_proxy
    child_env["no_proxy"] = no_proxy
    return child_env


def _validated_npm_config_path(path: str | Path, kind: str) -> str:
    config_path = Path(path)
    try:
        resolved = config_path.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"npm {kind} config must be an existing file: {config_path}") from exc
    if resolved == Path(os.devnull).resolve():
        raise ValueError(f"npm {kind} config must not be {os.devnull}")
    if not resolved.is_file():
        raise ValueError(f"npm {kind} config must be a regular file: {config_path}")
    if resolved.stat().st_size != 0:
        raise ValueError(f"npm {kind} config must be empty: {config_path}")
    return str(resolved)


def _loopback_no_proxy(env: dict[str, str]) -> str:
    values: list[str] = []
    for name, value in env.items():
        if name.lower() not in {
            "no_proxy",
            "npm_config_noproxy",
            "npm_config_no_proxy",
        }:
            continue
        values.extend(item.strip() for item in value.split(",") if item.strip())
    for host in ("127.0.0.1", "localhost", "::1", "[::1]"):
        if host not in values:
            values.append(host)
    return ",".join(values)


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
            if rewrite and 200 <= status < 400 and _looks_like_json(headers):
                try:
                    rewritten = _rewrite_metadata(body, state)
                except NpmGatewayEvaluationError as exc:
                    _deny_metadata(self, state, exc.failure, include_body=include_body)
                    return
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


def _deny_metadata(
    handler: BaseHTTPRequestHandler,
    state: NpmGatewayState,
    failure: NpmGatewayEvaluationFailure,
    *,
    include_body: bool,
) -> None:
    if state.evaluation_failures is not None and failure not in state.evaluation_failures:
        state.evaluation_failures.append(failure)
    body = b"npm metadata could not be evaluated under the configured policy\n"
    handler.send_response(403)
    handler.send_header("Content-Type", "text/plain; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    if include_body:
        handler.wfile.write(body)


def _fetch_upstream(url: str) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.status, dict(response.headers.items()), response.read()


def _rewrite_metadata(body: bytes, state: NpmGatewayState) -> bytes | None:
    if not state.policy.malware.enabled and not state.policy.package_age.enabled:
        return None
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
    unavailable = feed.state != "ready" or feed.snapshot is None
    if (
        feed.action == "block"
        or feed.state == "tampered"
        or unavailable
        and state.policy.malware.enabled
        and state.policy.malware.fail_closed
    ):
        feed_state = feed.state if feed.state in {"missing", "stale", "tampered"} else "unavailable"
        raise NpmGatewayEvaluationError(
            package=package_name,
            failure_kind=f"feed_{feed_state}",
            reason=f"npm policy feed is {feed_state} and the configured policy requires blocking",
        )
    if feed.snapshot is None:
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


def _ensure_feed(state: NpmGatewayState) -> FeedStatus:
    # Revalidate for each packument: an earlier request does not establish that
    # the on-disk feed is still present, current, or intact for this evaluation.
    feed = feed_status(
        policy=state.policy,
        cache_dir=state.feed_cache_dir,
        now=state.now,
    )
    state.feed = feed
    return feed


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
            return _apply_gateway_exception(
                NpmGatewayDecision(
                    package=package_name,
                    version=version,
                    policy_id="ca9.malware",
                    reason=(
                        f"local feed marks {package_name}@{version} as malicious ({malware_id})"
                    ),
                ),
                state,
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
                return _apply_gateway_exception(
                    NpmGatewayDecision(
                        package=package_name,
                        version=version,
                        policy_id="ca9.package_age_unknown",
                        reason=(
                            f"release time for {package_name}@{version} is not available "
                            "in the local feed"
                        ),
                    ),
                    state,
                )
        elif action_for_mode("block", policy.mode.default) == "block":
            released = _parse_time(released_at)
            age_hours = (now - released).total_seconds() / 3600
            if age_hours < policy.package_age.minimum_hours:
                return _apply_gateway_exception(
                    NpmGatewayDecision(
                        package=package_name,
                        version=version,
                        policy_id="ca9.package_age",
                        reason=(
                            f"package version age is {age_hours:.1f}h, below policy minimum "
                            f"of {policy.package_age.minimum_hours}h"
                        ),
                    ),
                    state,
                )
    return None


def _apply_gateway_exception(
    decision: NpmGatewayDecision,
    state: NpmGatewayState,
) -> NpmGatewayDecision | None:
    exception = find_policy_exception(
        state.policy.exceptions,
        policy_id=decision.policy_id,
        ecosystem="npm",
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
