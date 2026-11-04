from __future__ import annotations

import json
import os
import re
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
from ca9.release_age import cached_publish_time, remember_npm_packument

DEFAULT_NPM_REGISTRY = "https://registry.npmjs.org"
GATEWAY_SCHEMA = "ca9.npm.gateway.v1"
EVALUATION_FAILURE_POLICY_ID = "ca9.npm_gateway_evaluation_failed"
_SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")


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
    packument_times: dict[str, dict[str, Any]] | None = None
    release_age_defaulted: bool = False

    def __post_init__(self) -> None:
        self.removed_versions = []
        self.applied_exceptions = []
        self.evaluation_failures = []
        self.packument_times = {}


class NpmMetadataGateway:
    def __init__(
        self,
        *,
        upstream_registry: str = DEFAULT_NPM_REGISTRY,
        policy: PackagePolicy,
        feed_cache_dir: Path | None = None,
        now: datetime | None = None,
        release_age_defaulted: bool = False,
    ) -> None:
        self.state = NpmGatewayState(
            upstream_registry=upstream_registry.rstrip("/"),
            policy=policy,
            feed_cache_dir=feed_cache_dir,
            now=now,
            release_age_defaulted=release_age_defaulted,
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
            # A path that does not start with "/" would extend the upstream host
            # (`registry.npmjs.org.attacker.example`) or add userinfo to it.
            if not self.path.startswith("/") or not _same_origin(
                upstream_url, state.upstream_registry
            ):
                self.send_error(403, "gateway only proxies paths on the upstream registry")
                return

            tarball = _tarball_request(self.path)
            if tarball is not None:
                try:
                    decision = _tarball_decision(*tarball, state)
                except NpmGatewayEvaluationError as exc:
                    _deny_metadata(self, state, exc.failure, include_body=include_body)
                    return
                if decision is not None:
                    _deny_tarball(self, state, decision, include_body=include_body)
                    return

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


def _deny_tarball(
    handler: BaseHTTPRequestHandler,
    state: NpmGatewayState,
    decision: NpmGatewayDecision,
    *,
    include_body: bool,
) -> None:
    if state.removed_versions is not None and decision not in state.removed_versions:
        state.removed_versions.append(decision)
    body = b"npm tarball is blocked by the configured policy\n"
    handler.send_response(403)
    handler.send_header("Content-Type", "text/plain; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    if include_body:
        handler.wfile.write(body)


class _UpstreamRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _redirect_allowed(req.full_url, newurl):
            fp.close()
            raise urllib.error.URLError(
                f"refusing upstream redirect to {_sanitize_url_for_evidence(newurl)}"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch_upstream(url: str) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    opener = urllib.request.build_opener(_UpstreamRedirectHandler)
    with opener.open(request, timeout=30) as response:
        return response.status, dict(response.headers.items()), response.read()


def _redirect_allowed(source_url: str, target_url: str) -> bool:
    # Follow redirects only within the upstream host, and never downgrade from
    # https; anything else is fetched by npm without the gateway's checks.
    try:
        source = urllib.parse.urlsplit(source_url)
        target = urllib.parse.urlsplit(target_url)
        if not source.hostname or not target.hostname or target.username or target.password:
            return False
        if source.hostname.lower() != target.hostname.lower():
            return False
        if target.scheme == source.scheme:
            return target.port == source.port
    except ValueError:
        return False
    return source.scheme == "http" and target.scheme == "https"


def _same_origin(url: str, base: str) -> bool:
    try:
        candidate = urllib.parse.urlsplit(url)
        expected = urllib.parse.urlsplit(base)
        return (
            candidate.scheme == expected.scheme
            and candidate.netloc == expected.netloc
            and candidate.port == expected.port
        )
    except ValueError:
        return False


def _tarball_request(path: str) -> tuple[str, str | None] | None:
    """Return (package, version) for a registry tarball path.

    The version is None when the path is a tarball path whose filename does not
    belong to the package, which is denied rather than passed through.
    """
    decoded = urllib.parse.unquote(urllib.parse.urlsplit(path).path)
    if "/-/" not in decoded or not decoded.lower().endswith(".tgz"):
        return None
    package_path, _, filename = decoded.rpartition("/-/")
    package = package_path.removeprefix("/")
    parts = package.split("/")
    scoped = package.startswith("@")
    if (
        not all(parts)
        or len(parts) != (2 if scoped else 1)
        or any(part in {".", ".."} for part in parts)
    ):
        return package, None
    basename = parts[-1]
    # Unscoped: /name/-/name-1.0.0.tgz. Scoped: /@scope/name/-/name-1.0.0.tgz,
    # or /@scope/name/-/@scope/name-1.0.0.tgz on some registries.
    prefixes = [f"{basename}-"]
    if scoped:
        prefixes.append(f"{package}-")
    for prefix in prefixes:
        if filename.lower().startswith(prefix.lower()):
            version = filename[len(prefix) : -len(".tgz")]
            return package, version or None
    return package, None


def _tarball_decision(
    package_name: str,
    version: str | None,
    state: NpmGatewayState,
) -> NpmGatewayDecision | None:
    if not state.policy.malware.enabled and not state.policy.package_age.enabled:
        return None
    if version is None:
        raise NpmGatewayEvaluationError(
            package=package_name,
            failure_kind="unparseable_tarball_path",
            reason="npm tarball path does not name a version of its package",
        )
    snapshot = _evaluation_snapshot(state, package_name)
    if snapshot is None:
        return None
    metadata_time = None
    if _needs_registry_release_time(package_name, version, state, snapshot):
        cached = cached_publish_time(
            "npm",
            package_name,
            version,
            registry=state.upstream_registry,
            cache_dir=_release_cache_root(state),
        )
        if cached:
            metadata_time = {version: cached}
        else:
            metadata_time = _packument_time(package_name, state)
    return _denied_version(package_name, version, state.policy, snapshot, state, metadata_time)


def _release_cache_root(state: NpmGatewayState) -> Path | None:
    if state.feed_cache_dir is None:
        return None
    return Path(state.feed_cache_dir).parent


def _needs_registry_release_time(
    package_name: str,
    version: str,
    state: NpmGatewayState,
    snapshot: FeedSnapshot,
) -> bool:
    policy = state.policy
    if not policy.package_age.enabled or _is_age_excluded(
        "npm", package_name, version, policy.package_age.exclusions
    ):
        return False
    if lookup_release_time("npm", package_name, version, snapshot=snapshot):
        return False
    return not release_window_covers(
        snapshot,
        "npm",
        now=state.now or datetime.now(timezone.utc),
        minimum_hours=policy.package_age.minimum_hours,
    )


def _packument_time(package_name: str, state: NpmGatewayState) -> dict[str, Any] | None:
    # Tarball requests carry no release time. Reuse the packument `time` field the
    # gateway already saw, or fetch the packument once (npm ci skips packuments).
    cache = state.packument_times if state.packument_times is not None else {}
    key = package_name.lower()
    if key in cache:
        return cache[key]
    url = f"{state.upstream_registry}/{urllib.parse.quote(package_name, safe='@')}"
    try:
        _, _, body = _fetch_upstream(url)
        metadata = json.loads(body.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    metadata_time = metadata.get("time") if isinstance(metadata, dict) else None
    if not isinstance(metadata_time, dict):
        return None
    cache[key] = metadata_time
    remember_npm_packument(
        package_name,
        metadata,
        registry=state.upstream_registry,
        cache_dir=_release_cache_root(state),
    )
    return metadata_time


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

    snapshot = _evaluation_snapshot(state, package_name)
    if snapshot is None:
        return None

    versions = dict(metadata["versions"])
    metadata_time = metadata.get("time") if isinstance(metadata.get("time"), dict) else None
    if metadata_time is not None and state.packument_times is not None:
        state.packument_times[package_name.lower()] = metadata_time
    removed: list[NpmGatewayDecision] = []
    for version in list(versions):
        decision = _denied_version(
            package_name, version, state.policy, snapshot, state, metadata_time
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


def _evaluation_snapshot(state: NpmGatewayState, package_name: str) -> FeedSnapshot | None:
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
    return feed.snapshot


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
            if state.release_age_defaulted:
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
    if "latest" not in rewritten:
        # Packument key order is not release order, so pick the highest remaining
        # stable release; never promote a prerelease to latest.
        latest = _highest_stable_version(versions)
        if latest is not None:
            rewritten["latest"] = latest
    return rewritten


def _highest_stable_version(versions: dict[str, Any]) -> str | None:
    best: tuple[tuple[int, int, int], str] | None = None
    for version in versions:
        match = _SEMVER_RE.fullmatch(version)
        if match is None or match.group(4) is not None:
            continue
        key = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
        if best is None or key > best[0]:
            best = (key, version)
    return best[1] if best is not None else None


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
