from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from ca9.models import AffectedComponent, Vulnerability

_GENERIC_SUBMODULE_NAMES = frozenset({
    "utils", "base", "common", "helpers", "core", "misc", "compat", "exceptions",
})


@dataclass(frozen=True)
class AffectedComponentInference:
    candidates: tuple[str, ...]
    source: str
    confidence: int  # 0-100
    notes: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    def to_affected_component(self, import_name: str) -> AffectedComponent:
        if self.confidence >= 75:
            conf_str = "high"
        elif self.confidence >= 40:
            conf_str = "medium"
        else:
            conf_str = "low"
        file_hints: tuple[str, ...] = ()
        if hasattr(self, "_file_hints"):
            file_hints = self._file_hints
        return AffectedComponent(
            package_import_name=import_name,
            submodule_paths=self.candidates,
            file_hints=file_hints,
            confidence=conf_str,
            extraction_source=self.source,
        )


_CURATED: dict[str, list[tuple[re.Pattern[str], tuple[str, ...], tuple[str, ...]]]] = {
    "django": [
        (re.compile(r"admin(?:docs)?", re.I), ("django.contrib.admin",), ()),
        (re.compile(r"admindocs", re.I), ("django.contrib.admindocs",), ()),
        (re.compile(r"(?:session|SESSION)", re.I), ("django.contrib.sessions",), ()),
        (
            re.compile(r"(?:auth(?:entication)?|password|login|logout)", re.I),
            ("django.contrib.auth",),
            (),
        ),
        (re.compile(r"QuerySet|aggregat|\.db\.models", re.I), ("django.db.models",), ()),
        (re.compile(r"Truncat|utils\.text", re.I), ("django.utils.text",), ()),
        (re.compile(r"utils\.encoding", re.I), ("django.utils.encoding",), ()),
        (re.compile(r"multipart|MultiPartParser", re.I), ("django.http.multipartparser",), ()),
        (re.compile(r"(?:template|Template)", re.I), ("django.template",), ()),
        (re.compile(r"(?:GIS|Geo|GDAL|GeoJSON)", re.I), ("django.contrib.gis",), ()),
        (re.compile(r"(?:syndication|feed)", re.I), ("django.contrib.syndication",), ()),
        (re.compile(r"validators?\.URL|URLValidator", re.I), ("django.core.validators",), ()),
        (
            re.compile(r"FileUpload|UploadedFile|InMemoryUploadedFile", re.I),
            ("django.core.files",),
            (),
        ),
        (re.compile(r"(?:cache|caching)", re.I), ("django.core.cache",), ()),
    ],
    "werkzeug": [
        (re.compile(r"debug|Debug", re.I), ("werkzeug.debug",), ("debugger.py",)),
        (re.compile(r"formparser|FormDataParser|multipart", re.I), ("werkzeug.formparser",), ()),
        (re.compile(r"safe_join|utils", re.I), ("werkzeug.utils",), ()),
    ],
    "jinja2": [
        (re.compile(r"sandbox|Sandbox", re.I), ("jinja2.sandbox",), ("sandbox.py",)),
        (re.compile(r"xmlattr|filters", re.I), ("jinja2.filters",), ()),
    ],
    "pyyaml": [
        (re.compile(r"yaml\.load|unsafe_load|FullLoader|UnsafeLoader", re.I), ("yaml",), ()),
    ],
    "urllib3": [
        (re.compile(r"CRLF|header.inject", re.I), ("urllib3",), ()),
        (re.compile(r"proxy|CONNECT", re.I), ("urllib3",), ()),
    ],
}

_GITHUB_COMMIT_RE = re.compile(r"https://github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})")

_COMMIT_CACHE_DIR = Path(
    os.environ.get("CA9_CACHE_DIR", Path.home() / ".cache" / "ca9")
) / "commits"
_COMMIT_CACHE_TTL = 7 * 24 * 60 * 60  # 7 days (commits are immutable)


@dataclass
class CommitFetchResult:
    status: str  # "ok", "no_ref", "fetch_failed", "rate_limited"
    files: list[str] = field(default_factory=list)
    warning: str = ""


def _read_commit_cache(owner_repo: str, sha: str) -> list[str] | None:
    safe_key = f"{owner_repo.replace('/', '_')}_{sha[:12]}"
    path = _COMMIT_CACHE_DIR / f"{safe_key}.json"
    if not path.exists():
        return None
    try:
        if time.time() - path.stat().st_mtime > _COMMIT_CACHE_TTL:
            return None
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _write_commit_cache(owner_repo: str, sha: str, files: list[str]) -> None:
    try:
        _COMMIT_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        safe_key = f"{owner_repo.replace('/', '_')}_{sha[:12]}"
        (_COMMIT_CACHE_DIR / f"{safe_key}.json").write_text(json.dumps(files))
    except OSError:
        pass


def _fetch_commit_files(owner_repo: str, sha: str) -> CommitFetchResult:
    cached = _read_commit_cache(owner_repo, sha)
    if cached is not None:
        return CommitFetchResult(status="ok", files=cached)

    url = f"https://api.github.com/repos/{owner_repo}/commits/{sha}"
    headers = {
        "Accept": "application/json",
        "User-Agent": "ca9-scanner",
    }

    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            return CommitFetchResult(
                status="rate_limited",
                warning=f"GitHub rate limited fetching {owner_repo}/commit/{sha[:8]}",
            )
        return CommitFetchResult(
            status="fetch_failed",
            warning=f"HTTP {exc.code} fetching {owner_repo}/commit/{sha[:8]}",
        )
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        return CommitFetchResult(
            status="fetch_failed",
            warning=f"Failed to fetch {owner_repo}/commit/{sha[:8]}: {exc}",
        )

    files = [f["filename"] for f in data.get("files", []) if "filename" in f]
    _write_commit_cache(owner_repo, sha, files)
    return CommitFetchResult(status="ok", files=files)


def _file_paths_to_submodules(
    file_paths: list[str],
    import_name: str,
) -> list[str]:
    prefix = import_name.replace(".", "/").lower()
    submodules: set[str] = set()

    for fp in file_paths:
        if not fp.endswith(".py"):
            continue

        fp_lower = fp.lower()

        basename = fp.rsplit("/", 1)[-1] if "/" in fp else fp
        if basename.startswith("test_") or basename == "conftest.py":
            continue
        if "/tests/" in fp_lower or "/test/" in fp_lower:
            continue

        idx = fp_lower.find(prefix + "/")
        if idx == -1:
            if fp_lower == prefix + ".py" or fp_lower.endswith("/" + prefix + ".py"):
                submodules.add(import_name)
            continue

        rel = fp[idx:]
        rel = rel[:-3]
        dotted = rel.replace("/", ".")
        if dotted.endswith(".__init__"):
            dotted = dotted[: -len(".__init__")]

        if dotted:
            submodules.add(dotted)

    return sorted(submodules)


def _penalize_generic_names(submodules: tuple[str, ...]) -> int:
    if not submodules:
        return 0
    penalty = 0
    for sub in submodules:
        last_part = sub.rsplit(".", 1)[-1].lower()
        if last_part in _GENERIC_SUBMODULE_NAMES:
            penalty += 10
    return min(penalty, 20)


def _match_commits(
    vuln: Vulnerability,
) -> AffectedComponent | None:
    if not vuln.references:
        return None

    from ca9.analysis.ast_scanner import pypi_to_import_name

    import_name = pypi_to_import_name(vuln.package_name)

    all_submodules: set[str] = set()
    file_hints: set[str] = set()
    fetch_warnings: list[str] = []

    for ref in vuln.references:
        m = _GITHUB_COMMIT_RE.search(ref)
        if not m:
            continue

        owner_repo, sha = m.group(1), m.group(2)
        result = _fetch_commit_files(owner_repo, sha)

        if result.status != "ok" or not result.files:
            if result.warning:
                fetch_warnings.append(result.warning)
            continue

        submodules = _file_paths_to_submodules(result.files, import_name)
        all_submodules.update(submodules)

        for fp in result.files:
            if fp.endswith(".py"):
                basename = fp.rsplit("/", 1)[-1] if "/" in fp else fp
                if not basename.startswith("test_") and basename != "conftest.py":
                    file_hints.add(basename)

    if all_submodules:
        base_confidence = 90
        if fetch_warnings:
            base_confidence -= 10
        penalty = _penalize_generic_names(tuple(sorted(all_submodules)))
        confidence = max(base_confidence - penalty, 75)

        if confidence >= 75:
            conf_str = "high"
        else:
            conf_str = "medium"
        return AffectedComponent(
            package_import_name=import_name,
            submodule_paths=tuple(sorted(all_submodules)),
            file_hints=tuple(sorted(file_hints)),
            confidence=conf_str,
            extraction_source="commit_analysis",
            warnings=tuple(fetch_warnings),
        )

    return None


_DOTTED_PATH_RE = re.compile(r"`([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)+)`")


def _match_curated(
    package_name: str,
    text: str,
) -> AffectedComponent | None:
    key = package_name.lower()
    patterns = _CURATED.get(key)
    if not patterns:
        return None

    from ca9.analysis.ast_scanner import pypi_to_import_name

    import_name = pypi_to_import_name(package_name)

    for regex, submodule_paths, file_hints in patterns:
        if regex.search(text):
            base_confidence = 85
            penalty = _penalize_generic_names(submodule_paths)
            confidence = max(base_confidence - penalty, 75)
            if confidence >= 75:
                conf_str = "high"
            else:
                conf_str = "medium"
            return AffectedComponent(
                package_import_name=import_name,
                submodule_paths=submodule_paths,
                file_hints=file_hints,
                confidence=conf_str,
                extraction_source=f"curated:{key}:{regex.pattern}",
            )

    return None


def _extract_from_text(
    package_name: str,
    text: str,
) -> AffectedComponent | None:
    from ca9.analysis.ast_scanner import pypi_to_import_name

    import_name = pypi_to_import_name(package_name)
    prefix = import_name.lower()

    matches = _DOTTED_PATH_RE.findall(text)
    submodule_paths: list[str] = []

    for match in matches:
        if match.lower().startswith(prefix + "."):
            submodule_paths.append(match)

    if submodule_paths:
        sorted_paths = tuple(sorted(set(submodule_paths)))
        base_confidence = 55
        penalty = _penalize_generic_names(sorted_paths)
        confidence = max(base_confidence - penalty, 35)
        if confidence >= 40:
            conf_str = "medium"
        else:
            conf_str = "low"
        return AffectedComponent(
            package_import_name=import_name,
            submodule_paths=sorted_paths,
            confidence=conf_str,
            extraction_source="regex:dotted_path",
        )

    return None


_CLASS_NAME_RE = re.compile(r"\b([A-Z][a-z]+(?:[A-Z][a-z0-9]+)+)\b")
_GENERIC_NAMES = frozenset(
    {
        "JavaScript",
        "TypeError",
        "ValueError",
        "KeyError",
        "IndexError",
        "RuntimeError",
        "ImportError",
        "AttributeError",
        "HttpResponse",
        "ContentType",
        "StackOverflow",
        "GitHub",
        "PullRequest",
        "ChangeLog",
        "ReadOnly",
        "ReleaseNotes",
    }
)


def _find_package_source_dir(package_name: str) -> str | None:
    import importlib.metadata
    import importlib.util

    from ca9.analysis.ast_scanner import pypi_to_import_name

    import_name = pypi_to_import_name(package_name)
    top_level = import_name.split(".")[0]

    spec = importlib.util.find_spec(top_level)
    if spec is None or spec.origin is None:
        return None

    origin = spec.origin
    if origin.endswith("__init__.py"):
        return str(origin.rsplit("/", 1)[0]) if "/" in origin else None
    return origin


def _scan_package_for_name(
    source_dir: str,
    class_name: str,
    import_name: str,
) -> str | None:
    import ast
    import os

    if source_dir.endswith(".py"):
        try:
            with open(source_dir, encoding="utf-8", errors="replace") as f:
                tree = ast.parse(f.read(), filename=source_dir)
        except (SyntaxError, OSError):
            return None
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
                and node.name == class_name
            ):
                return import_name
        return None

    for dirpath, _dirnames, filenames in os.walk(source_dir):
        for fname in filenames:
            if not fname.endswith(".py"):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, encoding="utf-8", errors="replace") as f:
                    source = f.read()
            except OSError:
                continue

            if class_name not in source:
                continue

            try:
                tree = ast.parse(source, filename=fpath)
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
                    and node.name == class_name
                ):
                    rel = fpath[len(source_dir) :]
                    if rel.startswith("/"):
                        rel = rel[1:]
                    if rel.endswith(".py"):
                        rel = rel[:-3]
                    dotted = rel.replace("/", ".")
                    if dotted.endswith(".__init__"):
                        dotted = dotted[:-9]
                    return f"{import_name}.{dotted}" if dotted else import_name

    return None


def _resolve_class_names(
    package_name: str,
    text: str,
) -> AffectedComponent | None:
    from ca9.analysis.ast_scanner import pypi_to_import_name

    import_name = pypi_to_import_name(package_name)

    candidates = set(_CLASS_NAME_RE.findall(text)) - _GENERIC_NAMES
    if not candidates:
        return None

    source_dir = _find_package_source_dir(package_name)
    if source_dir is None:
        return None

    submodule_paths: list[str] = []
    for name in candidates:
        result = _scan_package_for_name(source_dir, name, import_name)
        if result:
            submodule_paths.append(result)

    if submodule_paths:
        sorted_paths = tuple(sorted(set(submodule_paths)))
        base_confidence = 55
        penalty = _penalize_generic_names(sorted_paths)
        confidence = max(base_confidence - penalty, 40)
        if confidence >= 40:
            conf_str = "medium"
        else:
            conf_str = "low"
        return AffectedComponent(
            package_import_name=import_name,
            submodule_paths=sorted_paths,
            confidence=conf_str,
            extraction_source="class_name_resolution",
        )

    return None


def extract_affected_component(vuln: Vulnerability) -> AffectedComponent:
    from ca9.analysis.ast_scanner import pypi_to_import_name

    text = f"{vuln.title} {vuln.description}"

    result = _match_commits(vuln)
    if result is not None:
        return result

    result = _match_curated(vuln.package_name, text)
    if result is not None:
        return result

    result = _extract_from_text(vuln.package_name, text)
    if result is not None:
        return result

    result = _resolve_class_names(vuln.package_name, text)
    if result is not None:
        return result

    import_name = pypi_to_import_name(vuln.package_name)
    return AffectedComponent(
        package_import_name=import_name,
        confidence="low",
        extraction_source="fallback",
    )
