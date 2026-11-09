from __future__ import annotations

import base64
import contextlib
import functools
import hashlib
import http.client
import ipaddress
import os
import re
import socket
import stat
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from ca9.artifacts.model import ArtifactSnapshot
from ca9.artifacts.pypi import (
    DEFAULT_MAX_PYPI_RESOLUTIONS,
    MAX_PYPI_JSON_BYTES,
    is_pypi_resolution_candidate,
    parse_release_document,
    release_json_url,
    select_release_file,
)
from ca9.artifacts.unpack import AmbiguousArchiveError, UnpackConfig, unpack_artifact
from ca9.core.models import (
    Artifact,
    Evidence,
    Finding,
    Inventory,
    Package,
    RiskSignal,
    SourceEvidence,
)

DEFAULT_ARTIFACT_CACHE_DIR = Path(
    os.environ.get("CA9_ARTIFACT_CACHE_DIR", Path.home() / ".cache" / "ca9" / "artifacts")
)
DEFAULT_MAX_ARTIFACT_BYTES = 100 * 1024 * 1024
DEFAULT_MAX_EXTRACTED_BYTES = 250 * 1024 * 1024
DEFAULT_MAX_EXTRACTED_FILES = 5000
DEFAULT_REQUEST_TIMEOUT = 30.0
_READ_CHUNK = 64 * 1024
_MAX_RANGES_PER_REQUEST = 100
_MULTIPART_PART_OVERHEAD = 1024
_MULTIPART_LINE = 1024
# Public registries whose artifact hosts are fetched without further configuration.
DEFAULT_ARTIFACT_INDEXES = (
    "https://registry.npmjs.org",
    "https://registry.yarnpkg.com",
    "https://files.pythonhosted.org",
    "https://pypi.org",
)
_HASH_STRENGTH = {
    "md5": 0,
    "sha1": 1,
    "sha224": 2,
    "sha3_224": 2,
    "sha256": 3,
    "sha3_256": 3,
    "blake2s": 3,
    "sha384": 4,
    "sha3_384": 4,
    "sha512": 5,
    "sha3_512": 5,
    "blake2b": 5,
}
_WEAK_HASH_ALGORITHMS = frozenset({"md5", "sha1"})


@dataclass(frozen=True)
class ArtifactScanConfig:
    """Where and how artifacts are fetched.

    ``resolve_pypi_artifacts`` looks up pinned PyPI registry dependencies that have
    no file record (requirements files) in the PyPI JSON API and inspects one file
    each, at most ``max_pypi_resolutions``; names matching
    ``internal_package_patterns`` are never looked up. An unhashed local file is
    copied afresh on every run because a cached copy cannot be checked against it.
    """

    cache_dir: Path = DEFAULT_ARTIFACT_CACHE_DIR
    allow_unhashed_downloads: bool = False
    max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES
    max_extracted_bytes: int = DEFAULT_MAX_EXTRACTED_BYTES
    max_extracted_files: int = DEFAULT_MAX_EXTRACTED_FILES
    # Extra check for every URL and redirect hop. When set it decides which hosts are
    # trusted, replacing the index allowlist; HTTPS and public-address rules still apply.
    url_validator: Callable[[str], bool] | None = None
    # Local artifact paths are read only beneath these roots; None or () reads none.
    allowed_local_roots: tuple[Path, ...] | None = None
    # HTTPS index hosts trusted in addition to DEFAULT_ARTIFACT_INDEXES.
    trusted_indexes: tuple[str, ...] = ()
    # Trusted index hosts that may also resolve to private, loopback or link-local addresses.
    private_indexes: tuple[str, ...] = ()
    # Test-only escape hatch that skips the built-in URL policy (url_validator still runs).
    allow_untrusted_urls: bool = False
    resolve_pypi_artifacts: bool = False
    max_pypi_resolutions: int = DEFAULT_MAX_PYPI_RESOLUTIONS
    internal_package_patterns: tuple[str, ...] = ()
    request_timeout: float = DEFAULT_REQUEST_TIMEOUT
    deadline: float | None = None


@dataclass(frozen=True)
class ArtifactCollectionResult:
    snapshots: tuple[ArtifactSnapshot, ...] = ()
    findings: tuple[Finding, ...] = ()
    warnings: tuple[str, ...] = ()
    scanned_artifacts: int = 0
    skipped_artifacts: int = 0


@dataclass
class _CollectionState:
    snapshots: list[ArtifactSnapshot] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    scanned_artifacts: int = 0
    skipped_artifacts: int = 0


class _UntrustedArtifactURL(ValueError):
    """The artifact location is outside the fetch policy, so nothing was requested."""


class RegistryDocumentNotFound(ValueError):
    """The registry answered 404 or 410: the release or project is not published there."""


class TransferTimeout(ValueError):
    """A registry or artifact transfer exceeded its per-request timeout or overall deadline."""


class RangeNotServed(ValueError):
    """The server did not answer a byte-range request with exactly the bytes asked for."""


class _BlockedRedirect(urllib.error.URLError):
    pass


@dataclass(frozen=True)
class _HashCheck:
    ok: bool
    reason: str
    algorithm: str | None = None

    @property
    def weak(self) -> bool:
        return self.algorithm in _WEAK_HASH_ALGORITHMS


def collect_artifact_snapshots(
    inventory: Inventory,
    config: ArtifactScanConfig | None = None,
) -> ArtifactCollectionResult:
    active_config = config or ArtifactScanConfig()
    state = _CollectionState()
    resolutions = 0
    unresolved: dict[str, int] = {}

    for package in inventory.packages:
        for artifact in package.artifacts:
            if artifact.kind not in {"wheel", "sdist", "npm-tarball"}:
                continue
            _collect_one(package, artifact, active_config, state)
        if not active_config.resolve_pypi_artifacts:
            continue
        eligible, reason = is_pypi_resolution_candidate(
            package, active_config.internal_package_patterns
        )
        if not eligible:
            if reason in {
                "version is not pinned",
                "merged index setup; the serving index is not known",
            }:
                unresolved[reason] = unresolved.get(reason, 0) + 1
            continue
        if resolutions >= active_config.max_pypi_resolutions:
            state.skipped_artifacts += 1
            unresolved["resolution limit reached"] = (
                unresolved.get("resolution limit reached", 0) + 1
            )
            continue
        resolutions += 1
        _collect_pypi_release(package, active_config, state)

    for reason, count in sorted(unresolved.items()):
        state.warnings.append(
            f"{count} PyPI package(s) were not resolved for artifact scanning: {reason}"
        )

    return ArtifactCollectionResult(
        snapshots=tuple(state.snapshots),
        findings=tuple(state.findings),
        warnings=tuple(state.warnings),
        scanned_artifacts=state.scanned_artifacts,
        skipped_artifacts=state.skipped_artifacts,
    )


def _collect_pypi_release(
    package: Package,
    config: ArtifactScanConfig,
    state: _CollectionState,
) -> None:
    """Resolve a pinned PyPI dependency to one file and collect it.

    Without a --hash pin nothing is requested unless unhashed downloads are allowed;
    the file is then verified against the digest PyPI lists for it.
    """
    hashes = package.metadata.get("hashes")
    if not hashes and not config.allow_unhashed_downloads:
        state.skipped_artifacts += 1
        state.warnings.append(
            f"skipped {package.key}: requirement has no --hash pin; pass "
            "--allow-unhashed-downloads to resolve and scan it from PyPI"
        )
        return
    json_url = release_json_url(package.name, package.version or "")
    try:
        files = parse_release_document(
            _fetch_registry_json(json_url, config), package.name, package.version or ""
        )
    except _UntrustedArtifactURL as exc:
        state.skipped_artifacts += 1
        state.warnings.append(f"skipped {package.key}: PyPI lookup blocked by policy ({exc})")
        return
    except (OSError, ValueError, http.client.HTTPException) as exc:
        state.skipped_artifacts += 1
        state.warnings.append(f"skipped {package.key}: PyPI release lookup failed ({exc})")
        return
    selection = select_release_file(package, files, json_url)
    if selection.artifact is None:
        state.skipped_artifacts += 1
        state.warnings.append(f"skipped {package.key}: {selection.reason}")
        return
    _collect_one(package, selection.artifact, config, state)


def _fetch_registry_json(
    url: str,
    config: ArtifactScanConfig,
    accept: str = "application/json",
) -> bytes:
    """Fetch bounded registry metadata under the same URL policy as artifacts."""
    policy = _URLPolicy.from_config(config)
    rejection = policy.rejection(url)
    if rejection is not None:
        raise _UntrustedArtifactURL(rejection)
    request = urllib.request.Request(
        url,
        headers={"Accept": accept, "User-Agent": "ca9-artifact-scanner"},
    )
    try:
        with policy.opener().open(request, timeout=policy.timeout(url)) as response:
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > MAX_PYPI_JSON_BYTES:
                raise ValueError(f"registry metadata exceeds {MAX_PYPI_JSON_BYTES} bytes")
            parts = []
            total = 0
            for chunk in _read_chunks(response, policy, url):
                parts.append(chunk)
                total += len(chunk)
                if total > MAX_PYPI_JSON_BYTES:
                    break
            raw = b"".join(parts)
    except _BlockedRedirect as exc:
        raise _UntrustedArtifactURL(str(exc.reason)) from None
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 410):
            raise RegistryDocumentNotFound(f"HTTP {exc.code} from {_display_url(url)}") from None
        raise ValueError(f"HTTP {exc.code} from {_display_url(url)}") from None
    except urllib.error.URLError as exc:
        if _is_timeout(exc):
            raise TransferTimeout(f"timed out reaching {_display_url(url)}") from None
        raise ValueError(f"cannot reach {_display_url(url)}: {exc.reason}") from None
    except TimeoutError:
        raise TransferTimeout(f"timed out reading {_display_url(url)}") from None
    if len(raw) > MAX_PYPI_JSON_BYTES:
        raise ValueError(f"registry metadata exceeds {MAX_PYPI_JSON_BYTES} bytes")
    return raw


def _is_declared_local_source(package: Package, artifact: Artifact) -> bool:
    """A path dependency's own archive: the scanned file is the file that installs."""
    return (
        package.metadata.get("source_kind") == "path"
        and artifact.kind in {"wheel", "sdist"}
        and _local_artifact_path(artifact.url or "") is not None
    )


def _collect_one(
    package: Package,
    artifact: Artifact,
    config: ArtifactScanConfig,
    state: _CollectionState,
) -> None:
    if not artifact.url:
        state.skipped_artifacts += 1
        state.warnings.append(f"skipped {package.key} {artifact.kind}: artifact has no URL")
        return

    if (
        not artifact.hash
        and not config.allow_unhashed_downloads
        and not _is_declared_local_source(package, artifact)
    ):
        state.skipped_artifacts += 1
        state.warnings.append(
            f"skipped {package.key} {artifact.kind}: artifact has no hash; "
            "pass --allow-unhashed-downloads to scan it"
        )
        return

    archive_path = _cache_path(package, artifact, config)
    try:
        hash_check = _fetch_to_cache(artifact, archive_path, config)
    except _UntrustedArtifactURL as exc:
        state.skipped_artifacts += 1
        state.findings.append(
            _artifact_finding(
                package,
                artifact,
                signal_type="artifact_untrusted_url",
                title=f"Artifact not fetched (untrusted URL) for {package.name}",
                severity="medium",
                action="investigate",
                reason=f"not fetched (untrusted URL): {exc}",
            )
        )
        return
    except (OSError, ValueError, http.client.HTTPException) as exc:
        state.skipped_artifacts += 1
        state.findings.append(
            _artifact_finding(
                package,
                artifact,
                signal_type="artifact_fetch_error",
                title=f"Could not fetch artifact for {package.name}",
                severity="medium",
                action="investigate",
                reason=str(exc),
            )
        )
        return

    if hash_check is not None and not hash_check.ok:
        state.skipped_artifacts += 1
        state.findings.append(
            _artifact_finding(
                package,
                artifact,
                signal_type="artifact_hash_mismatch",
                title=f"Artifact hash mismatch for {package.name}",
                severity="critical",
                action="block",
                reason=hash_check.reason,
            )
        )
        return
    if hash_check is not None and hash_check.weak:
        state.findings.append(
            _artifact_finding(
                package,
                artifact,
                signal_type="artifact_weak_integrity",
                title=f"Weak artifact integrity for {package.name}",
                severity="low",
                action="warn",
                reason=(
                    f"artifact matched only a {hash_check.algorithm} digest, which is not "
                    "collision resistant; regenerate the lockfile to record sha512 integrity"
                ),
            )
        )

    unpack_dir = _unpack_dir(package, artifact, config)
    try:
        snapshot = unpack_artifact(
            package,
            artifact,
            archive_path,
            unpack_dir,
            UnpackConfig(
                max_files=config.max_extracted_files,
                max_total_bytes=config.max_extracted_bytes,
            ),
        )
    except AmbiguousArchiveError as exc:
        state.skipped_artifacts += 1
        state.findings.append(
            _artifact_finding(
                package,
                artifact,
                signal_type="artifact_ambiguous_archive",
                title=f"Ambiguous archive format for {package.name}",
                severity="critical",
                action="block",
                reason=str(exc),
            )
        )
        return
    except (
        OSError,
        ValueError,
        tarfile.TarError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
    ) as exc:
        state.skipped_artifacts += 1
        state.findings.append(
            _artifact_finding(
                package,
                artifact,
                signal_type="artifact_unpack_error",
                title=f"Unsafe or invalid artifact for {package.name}",
                severity="critical",
                action="block",
                reason=str(exc),
            )
        )
        return

    state.snapshots.append(snapshot)
    state.scanned_artifacts += 1


def _fetch_to_cache(
    artifact: Artifact,
    archive_path: Path,
    config: ArtifactScanConfig,
) -> _HashCheck | None:
    """Place a verified copy of the artifact at archive_path and return its hash check.

    Bytes reach archive_path only by an atomic rename after verification, so an
    interrupted or concurrent run never leaves or reads a partial cache entry. A cached
    entry that fails verification is discarded and fetched once more before a mismatch
    is reported. Returns None when the artifact has no hash to check.
    """
    artifact_url = artifact.url or ""
    policy = _URLPolicy.from_config(config)
    source_path = _local_artifact_path(artifact_url)
    validated_source = None
    if source_path is not None:
        if config.url_validator is not None and not config.url_validator(artifact_url):
            raise _UntrustedArtifactURL("artifact URL blocked by policy")
        validated_source = _validate_local_artifact_source(source_path, config.allowed_local_roots)
    else:
        rejection = policy.rejection(artifact_url)
        if rejection is not None:
            raise _UntrustedArtifactURL(rejection)
    if artifact.hash and not _strongest_hash_candidates(artifact.hash):
        return _HashCheck(False, f"unsupported artifact hash format: {artifact.hash}")

    if archive_path.is_file() and (artifact.hash or validated_source is None):
        if archive_path.stat().st_size <= config.max_artifact_bytes:
            cached_check = _check_hash(archive_path, artifact.hash) if artifact.hash else None
            if cached_check is None or cached_check.ok:
                return cached_check
        archive_path.unlink(missing_ok=True)

    archive_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{archive_path.name}.", suffix=".part", dir=archive_path.parent
    )
    os.close(descriptor)
    temp_path = Path(temp_name)
    try:
        if validated_source is not None:
            _copy_local_artifact(
                validated_source,
                temp_path,
                config.max_artifact_bytes,
                config.allowed_local_roots,
            )
        else:
            _download_artifact(artifact_url, temp_path, config.max_artifact_bytes, policy)
        fetched_check = _check_hash(temp_path, artifact.hash) if artifact.hash else None
        if fetched_check is None or fetched_check.ok:
            os.replace(temp_path, archive_path)
        return fetched_check
    finally:
        temp_path.unlink(missing_ok=True)


def _copy_local_artifact(
    source_path: Path,
    archive_path: Path,
    max_bytes: int,
    allowed_roots: tuple[Path, ...] | None,
) -> None:
    try:
        resolved_source = _validate_local_artifact_source(source_path, allowed_roots)
        open_flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(resolved_source, open_flags)
        with os.fdopen(descriptor, "rb") as source:
            source_stat = os.fstat(source.fileno())
            if not stat.S_ISREG(source_stat.st_mode):
                raise ValueError(f"local artifact is not a regular file: {source_path}")
            if source_stat.st_size > max_bytes:
                raise ValueError(
                    f"artifact is too large: {source_stat.st_size} bytes exceeds {max_bytes}"
                )
            total = 0
            with archive_path.open("wb") as destination:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError(f"artifact is too large: exceeds {max_bytes} bytes")
                    destination.write(chunk)
    except ValueError:
        archive_path.unlink(missing_ok=True)
        raise
    except OSError as exc:
        archive_path.unlink(missing_ok=True)
        raise ValueError(f"cannot copy local artifact {source_path}: {exc}") from exc


def _validate_local_artifact_source(
    source_path: Path,
    allowed_roots: tuple[Path, ...] | None,
) -> Path:
    if not allowed_roots:
        raise _UntrustedArtifactURL(
            "local artifact paths are only read beneath an explicitly allowed root"
        )
    # Check containment before touching the file so the result does not reveal whether
    # paths outside the allowed roots exist.
    try:
        contained = _within_roots(source_path.resolve(), allowed_roots)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"cannot read local artifact {source_path}: {exc}") from exc
    if not contained:
        raise _UntrustedArtifactURL(f"local artifact is outside the allowed roots: {source_path}")
    try:
        resolved_source = source_path.resolve(strict=True)
        source_stat = resolved_source.stat()
    except OSError as exc:
        raise ValueError(f"cannot read local artifact {source_path}: {exc}") from exc
    if not _within_roots(resolved_source, allowed_roots):
        raise _UntrustedArtifactURL(f"local artifact is outside the allowed roots: {source_path}")
    if not stat.S_ISREG(source_stat.st_mode):
        raise ValueError(f"local artifact is not a regular file: {source_path}")
    return resolved_source


def _within_roots(path: Path, roots: tuple[Path, ...]) -> bool:
    return any(path.is_relative_to(root.resolve()) for root in roots)


@dataclass(frozen=True)
class _URLPolicy:
    """Which artifact URLs may be requested, applied to the first URL and every redirect."""

    trusted_hosts: frozenset[tuple[str, int]]
    private_hosts: frozenset[tuple[str, int]] = frozenset()
    validator: Callable[[str], bool] | None = None
    unrestricted: bool = False
    request_timeout: float = DEFAULT_REQUEST_TIMEOUT
    deadline: float | None = None

    @classmethod
    def from_config(cls, config: ArtifactScanConfig) -> _URLPolicy:
        return cls(
            trusted_hosts=_index_hosts(
                (*DEFAULT_ARTIFACT_INDEXES, *config.trusted_indexes, *config.private_indexes)
            ),
            private_hosts=_index_hosts(config.private_indexes),
            validator=config.url_validator,
            unrestricted=config.allow_untrusted_urls,
            request_timeout=config.request_timeout,
            deadline=config.deadline,
        )

    def timeout(self, url: str) -> float:
        """Socket timeout for connect and each read: the per-request cap or the time left."""
        budget = self.request_timeout
        if self.deadline is not None:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise TransferTimeout(f"timed out before requesting {_display_url(url)}")
            budget = min(budget, remaining)
        return max(budget, 0.001)

    def check_deadline(self, url: str) -> None:
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise TransferTimeout(f"timed out reading {_display_url(url)}: deadline reached")

    def __call__(self, url: str) -> bool:
        return self.rejection(url) is None

    def rejection(self, url: str) -> str | None:
        if not self.unrestricted:
            reason = self._transport_rejection(url)
            if reason is not None:
                return reason
        if self.validator is not None and not self.validator(url):
            return "artifact URL blocked by policy"
        return None

    def _transport_rejection(self, url: str) -> str | None:
        if "\\" in url or any(ord(char) <= 32 or ord(char) == 127 for char in url):
            return "artifact URL contains unsafe characters"
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme.lower() != "https":
            return f"only https artifact URLs are fetched (got {parsed.scheme or 'no'} scheme)"
        if parsed.username is not None or parsed.password is not None:
            return "artifact URLs with embedded credentials are not fetched"
        endpoint = _endpoint(url)
        if endpoint is None:
            return "artifact URL has no valid host"
        host = endpoint[0]
        if (
            _is_ip_literal(host)
            and not _is_public_address(host)
            and endpoint not in self.private_hosts
        ):
            return f"artifact host {host} is not a public address"
        if self.validator is None and endpoint not in self.trusted_hosts:
            return f"artifact host {host} is not a trusted package index"
        return None

    def opener(self) -> urllib.request.OpenerDirector:
        if self.unrestricted:
            handlers = () if self.validator is None else (_ValidatedRedirectHandler(self),)
            return urllib.request.build_opener(*handlers)
        # Only HTTPS is reachable; every connection re-checks the address it dials.
        director = urllib.request.OpenerDirector()
        for handler in (
            urllib.request.ProxyHandler(),
            urllib.request.UnknownHandler(),
            urllib.request.HTTPDefaultErrorHandler(),
            _ValidatedRedirectHandler(self),
            urllib.request.HTTPErrorProcessor(),
            _GuardedHTTPSHandler(self.private_hosts),
        ):
            director.add_handler(handler)
        return director


class _ValidatedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, validator: Callable[[str], bool]) -> None:
        super().__init__()
        self._validator = validator

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        if not self._validator(newurl):
            reason = (
                self._validator.rejection(newurl)
                if isinstance(self._validator, _URLPolicy)
                else None
            )
            raise _BlockedRedirect(
                f"artifact redirect blocked by URL policy: {_display_url(newurl)}"
                + (f" ({reason})" if reason else "")
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _GuardedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that dials only vetted addresses, so DNS cannot point it inward."""

    def __init__(
        self,
        *args,  # noqa: ANN002
        private_hosts: frozenset[tuple[str, int]] = frozenset(),
        **kwargs,  # noqa: ANN003
    ) -> None:
        super().__init__(*args, **kwargs)
        self._private_hosts = private_hosts
        self._create_connection = self._connect_vetted

    def _connect_vetted(
        self,
        address: tuple[str, int],
        timeout: float | None,
        source_address: tuple[str, int] | None = None,
    ) -> socket.socket:
        tunnel_host = getattr(self, "_tunnel_host", None)
        if tunnel_host:
            # The socket goes to the operator's proxy, which resolves the origin itself;
            # refuse origins that resolve inward here, but tolerate proxy-only DNS.
            with contextlib.suppress(socket.gaierror):
                _vetted_addresses(
                    tunnel_host, getattr(self, "_tunnel_port", None) or 443, self._private_hosts
                )
            return socket.create_connection(address, timeout, source_address)
        host, port = address
        last_error: OSError | None = None
        for ip in _vetted_addresses(host, port, self._private_hosts):
            try:
                return socket.create_connection((ip, port), timeout, source_address)
            except OSError as exc:
                last_error = exc
        raise last_error or OSError(f"cannot connect to {host}")


class _GuardedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, private_hosts: frozenset[tuple[str, int]]) -> None:
        super().__init__()
        self._private_hosts = private_hosts

    def https_open(self, req):  # noqa: ANN001
        connection = functools.partial(_GuardedHTTPSConnection, private_hosts=self._private_hosts)
        return self.do_open(connection, req, context=self._context)


def _vetted_addresses(
    host: str,
    port: int,
    private_hosts: frozenset[tuple[str, int]],
) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(str(info[4][0]) for info in infos))
    if (_normalize_host(host), port) not in private_hosts:
        for address in addresses:
            if not _is_public_address(address):
                raise _UntrustedArtifactURL(
                    f"artifact host {host} resolves to non-public address {address}"
                )
    return addresses


def _download_artifact(
    url: str,
    archive_path: Path,
    max_bytes: int,
    url_validator: Callable[[str], bool] | None = None,
) -> None:
    policy = (
        url_validator
        if isinstance(url_validator, _URLPolicy)
        else _URLPolicy(_index_hosts(DEFAULT_ARTIFACT_INDEXES), validator=url_validator)
    )
    rejection = policy.rejection(url)
    if rejection is not None:
        raise _UntrustedArtifactURL(rejection)
    request = urllib.request.Request(url, headers={"User-Agent": "ca9-artifact-scanner"})
    try:
        with policy.opener().open(request, timeout=policy.timeout(url)) as response:
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > max_bytes:
                raise ValueError(
                    f"artifact is too large: {content_length} bytes exceeds {max_bytes}"
                )
            total = 0
            with archive_path.open("wb") as out:
                for chunk in _read_chunks(response, policy, url):
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError(f"artifact is too large: exceeds {max_bytes} bytes")
                    out.write(chunk)
    except _BlockedRedirect as exc:
        archive_path.unlink(missing_ok=True)
        raise _UntrustedArtifactURL(str(exc.reason)) from None
    except ValueError:
        archive_path.unlink(missing_ok=True)
        raise
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        archive_path.unlink(missing_ok=True)
        if _is_timeout(exc):
            raise TransferTimeout(f"timed out downloading {_display_url(url)}") from None
        raise ValueError(f"cannot download artifact {url}: {exc}") from exc


def _read_artifact_range(
    url: str, start: int, length: int, size: int, config: ArtifactScanConfig
) -> bytes:
    """``length`` bytes from offset ``start`` of the ``size``-byte artifact at ``url``.

    The request passes the same URL policy, address checks and deadline as a full
    download; a local file is read only beneath ``allowed_local_roots``. A server that
    ignores the range or reports another total size raises RangeNotServed.
    """
    if length <= 0:
        return b""
    source_path = _local_artifact_path(url)
    if source_path is not None:
        if config.url_validator is not None and not config.url_validator(url):
            raise _UntrustedArtifactURL("artifact URL blocked by policy")
        resolved = _validate_local_artifact_source(source_path, config.allowed_local_roots)
        try:
            with resolved.open("rb") as stream:
                if os.fstat(stream.fileno()).st_size != size:
                    raise RangeNotServed(f"local artifact is not {size} bytes: {source_path}")
                stream.seek(start)
                data = stream.read(length)
        except OSError as exc:
            raise ValueError(f"cannot read local artifact {source_path}: {exc}") from exc
        if len(data) != length:
            raise RangeNotServed(f"local artifact ended before byte {start + length}")
        return data
    policy = _URLPolicy.from_config(config)
    rejection = policy.rejection(url)
    if rejection is not None:
        raise _UntrustedArtifactURL(rejection)
    end = start + length - 1
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "ca9-artifact-scanner",
            "Range": f"bytes={start}-{end}",
            "Accept-Encoding": "identity",
        },
    )
    try:
        with policy.opener().open(request, timeout=policy.timeout(url)) as response:
            served = response.headers.get("Content-Range", "")
            if response.status != 206 or served.strip() != f"bytes {start}-{end}/{size}":
                raise RangeNotServed(
                    f"{_display_url(url)} did not serve bytes {start}-{end} of {size}"
                )
            data = bytearray()
            for chunk in _read_chunks(response, policy, url):
                data.extend(chunk)
                if len(data) > length:
                    break
    except _BlockedRedirect as exc:
        raise _UntrustedArtifactURL(str(exc.reason)) from None
    except ValueError:
        raise
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        if _is_timeout(exc):
            raise TransferTimeout(f"timed out reading {_display_url(url)}") from None
        raise ValueError(f"cannot read artifact {url}: {exc}") from exc
    if len(data) != length:
        raise RangeNotServed(f"{_display_url(url)} served {len(data)} of {length} bytes")
    return bytes(data)


def _read_artifact_ranges(
    url: str, spans: list[tuple[int, int]], size: int, config: ArtifactScanConfig
) -> list[bytes]:
    """Bytes of each ``(start, end)`` span of the ``size``-byte artifact at ``url``.

    Spans are asked for in multipart byte-range requests of at most
    ``_MAX_RANGES_PER_REQUEST``; any span the server leaves out, or every span when it
    does not answer with multipart byte ranges, is read on its own."""
    if len(spans) <= 1 or _local_artifact_path(url) is not None:
        return [_read_artifact_range(url, start, end - start, size, config) for start, end in spans]
    found: dict[tuple[int, int], bytes] = {}
    for first in range(0, len(spans), _MAX_RANGES_PER_REQUEST):
        batch = spans[first : first + _MAX_RANGES_PER_REQUEST]
        with contextlib.suppress(RangeNotServed):
            found.update(_multipart_ranges(url, batch, size, config))
    return [
        found.get((start, end)) or _read_artifact_range(url, start, end - start, size, config)
        for start, end in spans
    ]


def _multipart_ranges(
    url: str, spans: list[tuple[int, int]], size: int, config: ArtifactScanConfig
) -> dict[tuple[int, int], bytes]:
    policy = _URLPolicy.from_config(config)
    rejection = policy.rejection(url)
    if rejection is not None:
        raise _UntrustedArtifactURL(rejection)
    wanted = set(spans)
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "ca9-artifact-scanner",
            "Range": "bytes=" + ",".join(f"{start}-{end - 1}" for start, end in spans),
            "Accept-Encoding": "identity",
        },
    )
    limit = sum(end - start for start, end in spans) + _MULTIPART_PART_OVERHEAD * len(spans)
    try:
        with policy.opener().open(request, timeout=policy.timeout(url)) as response:
            boundary = response.headers.get_param("boundary")
            if (
                response.status != 206
                or response.headers.get_content_type() != "multipart/byteranges"
                or not isinstance(boundary, str)
                or not boundary
            ):
                raise RangeNotServed(f"{_display_url(url)} did not serve multipart byte ranges")
            reader = _BoundedReader(response, policy, url, limit)
            parts = _byte_range_parts(reader, boundary.encode("ascii", "replace"), size)
    except _BlockedRedirect as exc:
        raise _UntrustedArtifactURL(str(exc.reason)) from None
    except ValueError:
        raise
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        if _is_timeout(exc):
            raise TransferTimeout(f"timed out reading {_display_url(url)}") from None
        raise RangeNotServed(f"cannot read byte ranges of {_display_url(url)}: {exc}") from exc
    if len(parts) > len(spans):
        raise RangeNotServed(f"{_display_url(url)} served more parts than were asked for")
    return {(start, end): data for start, end, data in parts if (start, end) in wanted}


class _BoundedReader:
    """Reads a response at most ``limit`` bytes far, checking the deadline between reads."""

    def __init__(
        self, response: http.client.HTTPResponse, policy: _URLPolicy, url: str, limit: int
    ) -> None:
        self.response = response
        self.policy = policy
        self.url = url
        self.left = limit

    def readline(self) -> bytes:
        self.policy.check_deadline(self.url)
        line = self.response.readline(min(_MULTIPART_LINE, self.left + 1))
        self._charge(len(line))
        return line

    def read(self, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            self.policy.check_deadline(self.url)
            chunk = self.response.read(min(_READ_CHUNK, size - len(data)))
            if not chunk:
                break
            self._charge(len(chunk))
            data.extend(chunk)
        return bytes(data)

    def _charge(self, count: int) -> None:
        self.left -= count
        if self.left < 0:
            raise RangeNotServed(f"{_display_url(self.url)} served more bytes than asked for")


def _byte_range_parts(
    reader: _BoundedReader, boundary: bytes, size: int
) -> list[tuple[int, int, bytes]]:
    """The (start, end, bytes) parts of a multipart/byteranges body."""
    delimiter = b"--" + boundary
    parts: list[tuple[int, int, bytes]] = []
    while True:
        line = reader.readline()
        if not line:
            return parts
        line = line.rstrip(b"\r\n")
        if not line:
            continue
        if line == delimiter + b"--":
            return parts
        if line != delimiter:
            raise RangeNotServed("malformed multipart byte-range body")
        span = None
        while header := reader.readline().rstrip(b"\r\n"):
            name, _colon, value = header.partition(b":")
            if name.strip().lower() == b"content-range":
                match = re.fullmatch(rb"bytes (\d+)-(\d+)/(\d+)", value.strip())
                if match is None or int(match[3]) != size or int(match[2]) < int(match[1]):
                    raise RangeNotServed("malformed Content-Range in a multipart part")
                span = (int(match[1]), int(match[2]) + 1)
        if span is None:
            raise RangeNotServed("multipart part without Content-Range")
        data = reader.read(span[1] - span[0])
        if len(data) != span[1] - span[0]:
            raise RangeNotServed("multipart part ended early")
        parts.append((span[0], span[1], data))


def _read_chunks(
    response: http.client.HTTPResponse, policy: _URLPolicy, url: str
) -> Iterator[bytes]:
    """Yield response bytes one socket read at a time, stopping at the deadline.

    ``read1`` returns after a single read, so a server that trickles bytes cannot
    hold the transfer open past the deadline; each read is bounded by the socket
    timeout set when the request was opened.
    """
    reader = getattr(response, "read1", None) or response.read
    while True:
        policy.check_deadline(url)
        chunk = reader(_READ_CHUNK)
        if not chunk:
            return
        yield chunk


def _is_timeout(exc: BaseException) -> bool:
    if isinstance(exc, TimeoutError):
        return True
    return isinstance(getattr(exc, "reason", None), TimeoutError)


def _verify_hash(path: Path, expected: str) -> tuple[bool, str]:
    check = _check_hash(path, expected)
    return check.ok, check.reason


def _check_hash(path: Path, expected: str) -> _HashCheck:
    """Verify against the strongest listed algorithm, as SRI consumers do.

    Weaker digests listed alongside a stronger one are ignored rather than accepted.
    """
    selected = _strongest_hash_candidates(expected)
    if not selected:
        return _HashCheck(False, f"unsupported artifact hash format: {expected}")

    digests: dict[str, bytes] = {}
    reason = ""
    for algorithm, expected_value, encoding in selected:
        if algorithm not in digests:
            digest = hashlib.new(algorithm)
            with path.open("rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    digest.update(chunk)
            digests[algorithm] = digest.digest()
        if encoding == "base64":
            actual = base64.b64encode(digests[algorithm]).decode("ascii")
            if actual == expected_value:
                return _HashCheck(True, "hash verified", algorithm)
            reason = f"expected {algorithm}-{expected_value}, got {algorithm}-{actual}"
        else:
            actual = digests[algorithm].hex()
            if actual == expected_value.lower():
                return _HashCheck(True, "hash verified", algorithm)
            reason = f"expected {algorithm}:{expected_value}, got {algorithm}:{actual}"
    return _HashCheck(False, reason, selected[0][0])


def _strongest_hash_candidates(expected: str) -> list[tuple[str, str, str]]:
    candidates = [
        candidate
        for candidate in _parse_hash_candidates(expected)
        if candidate[0] in _HASH_STRENGTH and candidate[0] in hashlib.algorithms_available
    ]
    if not candidates:
        return []
    strongest = max(_HASH_STRENGTH[algorithm] for algorithm, _, _ in candidates)
    return [candidate for candidate in candidates if _HASH_STRENGTH[candidate[0]] == strongest]


_SRI_HASH_RE = re.compile(r"^(sha(?:1|256|384|512))-([A-Za-z0-9+/]+={0,2})$")


def _parse_hash_candidates(value: str) -> list[tuple[str, str, str]]:
    """Parse a hash spec into (algorithm, expected, encoding) candidates.

    Supports npm Subresource-Integrity (``sha512-<base64>``, legacy ``sha1-<base64>``,
    possibly several space-separated) alongside ``algo:hexdigest`` / bare-hex forms.
    """
    candidates: list[tuple[str, str, str]] = []
    for token in value.split():
        sri = _SRI_HASH_RE.match(token)
        if sri:
            candidates.append((sri.group(1), sri.group(2), "base64"))
            continue
        algorithm, digest = _parse_hash(token)
        if digest:
            candidates.append((algorithm, digest, "hex"))
    return candidates


def _parse_hash(value: str) -> tuple[str, str]:
    if ":" in value:
        algorithm, digest = value.split(":", 1)
    elif "=" in value:
        algorithm, digest = value.split("=", 1)
    else:
        algorithm, digest = "sha256", value
    return algorithm.lower().replace("-", ""), digest.strip()


def _is_weak_hash(value: str) -> bool:
    selected = _strongest_hash_candidates(value)
    return not selected or selected[0][0] in _WEAK_HASH_ALGORITHMS


def _cache_key(package: Package, artifact: Artifact) -> str:
    if artifact.hash and not _is_weak_hash(artifact.hash):
        stable = artifact.hash
    elif artifact.hash:
        # A collision-prone digest must not let one URL's bytes stand in for another's.
        stable = f"{artifact.hash}\n{artifact.url}"
    else:
        stable = f"{package.key}:{artifact.kind}:{artifact.url}"
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()


def _cache_path(package: Package, artifact: Artifact, config: ArtifactScanConfig) -> Path:
    suffix = _artifact_suffix(artifact)
    return config.cache_dir / "downloads" / f"{_cache_key(package, artifact)}{suffix}"


def _unpack_dir(package: Package, artifact: Artifact, config: ArtifactScanConfig) -> Path:
    return config.cache_dir / "unpacked" / _cache_key(package, artifact)


def _artifact_suffix(artifact: Artifact) -> str:
    url_path = urllib.parse.urlparse(artifact.url or "").path
    for suffix in (".tar.gz", ".tgz", ".zip", ".whl", ".tar.bz2", ".tar.xz"):
        if url_path.endswith(suffix):
            return suffix
    if artifact.kind == "wheel":
        return ".whl"
    return ".tar.gz"


def _local_artifact_path(url: str) -> Path | None:
    if url.startswith(("//", "\\")):
        return None
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "file":
        return Path(urllib.parse.unquote(parsed.path))
    if parsed.scheme:
        return None
    return Path(url)


def _index_hosts(values: tuple[str, ...]) -> frozenset[tuple[str, int]]:
    hosts = set()
    for value in values:
        raw = value.strip()
        endpoint = _endpoint(raw if "://" in raw else f"https://{raw}") if raw else None
        if endpoint is not None:
            hosts.add(endpoint)
    return frozenset(hosts)


def _endpoint(url: str) -> tuple[str, int] | None:
    try:
        parsed = urllib.parse.urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if not hostname:
        return None
    host = _normalize_host(hostname)
    # Only HTTPS is fetched, so an index entry without a port means 443 whatever its scheme.
    return (host, port or 443) if host else None


def _normalize_host(host: str) -> str:
    try:
        normalized = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return ""
    return normalized[:-1] if normalized.endswith(".") else normalized


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _is_public_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_global and not address.is_multicast


def _display_url(url: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(url)
        return f"{parsed.scheme}://{parsed.hostname or ''}{parsed.path}"
    except ValueError:
        return "<invalid URL>"


def _artifact_finding(
    package: Package,
    artifact: Artifact,
    *,
    signal_type: str,
    title: str,
    severity: str,
    action: str,
    reason: str,
) -> Finding:
    source = SourceEvidence(
        source="artifact acquisition",
        path=artifact.url,
        reader="ca9 artifact scanner",
    )
    evidence = Evidence(
        kind="artifact_scan",
        description=reason,
        source=source,
        metadata={
            "artifact_kind": artifact.kind,
            "artifact_url": artifact.url,
            "artifact_hash": artifact.hash,
            "package": package.name,
            "version": package.version,
        },
    )
    signal = RiskSignal(
        signal_type=signal_type,
        package_key=package.key,
        severity=severity,
        confidence="high",
        evidence=(evidence,),
        metadata={"package": package.name, "version": package.version},
    )
    return Finding(
        title=title,
        signal_type=signal_type,
        package_key=package.key,
        severity=severity,
        signals=(signal,),
        evidence=(evidence,),
        metadata={
            "action": action,
            "reason": reason,
            "package": package.name,
            "version": package.version,
            "dependency_kind": package.dependency_kind,
            "policy_id": f"ca9.{signal_type}",
        },
    )
