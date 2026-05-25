from __future__ import annotations

import ast
import json
import re
from contextlib import suppress
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

_EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".nox",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "dist-packages",
    "htmlcov",
    "node_modules",
    "site-packages",
    "venv",
}

_TEST_AND_DOC_DIRS = {
    "benchmarks",
    "benchmark",
    "demo",
    "demos",
    "doc",
    "docs",
    "example",
    "examples",
    "fixtures",
    "test",
    "testing",
    "tests",
}

_ENTRYPOINT_DECORATORS = {
    "route",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "websocket",
    "api_view",
    "handler",
    "command",
    "tool",
    "kernel_function",
}

_FUNCTION_NAME_KEYWORDS = {
    "decode",
    "deserialize",
    "extract",
    "handle",
    "import",
    "load",
    "parse",
    "process",
    "read",
    "render",
    "request",
    "tokenize",
    "unpack",
    "upload",
    "validate",
}

_PARAM_NAME_KEYWORDS = {
    "body",
    "content",
    "data",
    "file",
    "filename",
    "input",
    "message",
    "payload",
    "path",
    "query",
    "raw",
    "request",
    "text",
    "token",
    "url",
    "xml",
    "yaml",
}

_TEXT_TYPES = {"str", "string"}
_BYTES_TYPES = {"bytes", "bytearray", "memoryview"}
_STRUCTURED_TYPES = {"dict", "list", "tuple", "Mapping", "Sequence", "Any"}


@dataclass(frozen=True)
class HuntSignal:
    kind: str
    detail: str
    weight: int
    line: int | None = None

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "kind": self.kind,
            "detail": self.detail,
            "weight": self.weight,
        }
        if self.line is not None:
            data["line"] = self.line
        return data


@dataclass(frozen=True)
class HuntTarget:
    file_path: str
    qualified_name: str
    function_name: str
    line: int
    end_line: int
    parameters: tuple[str, ...] = ()
    required_parameters: tuple[str, ...] = ()
    decorators: tuple[str, ...] = ()
    complexity: int = 1
    sinks: tuple[str, ...] = ()
    signals: tuple[HuntSignal, ...] = ()
    score: int = 0
    priority: str = "low"
    harness_kind: str = "manual"
    harness_reason: str = ""
    input_parameter: str | None = None
    input_kind: str = "text"
    is_async: bool = False
    fuzz_introspector: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        categories = _categories_for_sinks(set(self.sinks))
        return {
            "file_path": self.file_path,
            "qualified_name": self.qualified_name,
            "function_name": self.function_name,
            "line": self.line,
            "end_line": self.end_line,
            "parameters": list(self.parameters),
            "required_parameters": list(self.required_parameters),
            "decorators": list(self.decorators),
            "complexity": self.complexity,
            "sinks": list(self.sinks),
            "categories": categories,
            "risk_categories": categories,
            "signals": [s.to_dict() for s in self.signals],
            "score": self.score,
            "priority": self.priority,
            "harness_kind": self.harness_kind,
            "harness_recommended": self.harness_kind == "atheris",
            "harness": {
                "kind": self.harness_kind,
                "reason": self.harness_reason,
                "input_parameter": self.input_parameter,
                "input_kind": self.input_kind,
            },
            "fuzz_introspector": self.fuzz_introspector,
        }


@dataclass(frozen=True)
class HuntReport:
    repo_path: str
    targets: tuple[HuntTarget, ...]
    warnings: tuple[str, ...] = ()
    generated_harnesses: tuple[str, ...] = ()
    research_packets: tuple[str, ...] = ()
    private_artifact_root: str | None = None
    private_artifact_roots: tuple[str, ...] = ()
    containment: tuple[str, ...] = ()

    def summary(self) -> dict[str, int]:
        return {
            "targets": len(self.targets),
            "high": sum(1 for t in self.targets if t.priority == "high"),
            "medium": sum(1 for t in self.targets if t.priority == "medium"),
            "low": sum(1 for t in self.targets if t.priority == "low"),
            "generated_harnesses": len(self.generated_harnesses),
            "research_packets": len(self.research_packets),
        }

    def to_dict(self) -> dict[str, object]:
        private_roots = self.private_artifact_roots
        if self.private_artifact_root and self.private_artifact_root not in private_roots:
            private_roots = (*private_roots, self.private_artifact_root)
        return {
            "schema_version": "ca9.hunt.v1",
            "repo_path": self.repo_path,
            "summary": self.summary(),
            "targets": [t.to_dict() for t in self.targets],
            "warnings": list(self.warnings),
            "generated_harnesses": list(self.generated_harnesses),
            "research_packets": list(self.research_packets),
            "private_artifact_root": self.private_artifact_root,
            "private_artifact_roots": list(private_roots),
            "containment": list(self.containment),
        }


@dataclass(frozen=True)
class _ParameterInfo:
    name: str
    required: bool
    annotation: str | None = None


@dataclass(frozen=True)
class _SinkRule:
    pattern: str
    kind: str
    detail: str
    weight: int
    suffix: bool = False


_SINK_RULES = (
    _SinkRule("eval", "code_execution", "dynamic eval", 50),
    _SinkRule("exec", "code_execution", "dynamic exec", 50),
    _SinkRule("os.system", "command_execution", "shell command execution", 45, suffix=True),
    _SinkRule("os.popen", "command_execution", "shell command execution", 45, suffix=True),
    _SinkRule("subprocess.run", "command_execution", "subprocess execution", 40, suffix=True),
    _SinkRule("subprocess.Popen", "command_execution", "subprocess execution", 40, suffix=True),
    _SinkRule("subprocess.call", "command_execution", "subprocess execution", 40, suffix=True),
    _SinkRule(
        "subprocess.check_call", "command_execution", "subprocess execution", 40, suffix=True
    ),
    _SinkRule(
        "subprocess.check_output", "command_execution", "subprocess execution", 40, suffix=True
    ),
    _SinkRule("pickle.load", "deserialization", "pickle deserialization", 45, suffix=True),
    _SinkRule("pickle.loads", "deserialization", "pickle deserialization", 45, suffix=True),
    _SinkRule("marshal.load", "deserialization", "marshal deserialization", 35, suffix=True),
    _SinkRule("marshal.loads", "deserialization", "marshal deserialization", 35, suffix=True),
    _SinkRule("yaml.load", "deserialization", "YAML loader", 35, suffix=True),
    _SinkRule("yaml.safe_load", "parser", "YAML parser", 18, suffix=True),
    _SinkRule("json.load", "parser", "JSON parser", 14, suffix=True),
    _SinkRule("json.loads", "parser", "JSON parser", 14, suffix=True),
    _SinkRule("ast.literal_eval", "parser", "Python literal parser", 18, suffix=True),
    _SinkRule("xml.etree.ElementTree.fromstring", "parser", "XML parser", 25, suffix=True),
    _SinkRule("lxml.etree.fromstring", "parser", "XML parser", 25, suffix=True),
    _SinkRule("tarfile.extractall", "archive_extraction", "archive extraction", 35, suffix=True),
    _SinkRule("zipfile.extractall", "archive_extraction", "archive extraction", 35, suffix=True),
    _SinkRule("open", "filesystem", "filesystem open", 14),
    _SinkRule("pathlib.Path.open", "filesystem", "filesystem open", 14, suffix=True),
    _SinkRule("read_text", "filesystem", "filesystem read", 12, suffix=True),
    _SinkRule("write_text", "filesystem", "filesystem write", 18, suffix=True),
    _SinkRule("requests.get", "network", "network request", 18, suffix=True),
    _SinkRule("requests.post", "network", "network request", 18, suffix=True),
    _SinkRule("requests.request", "network", "network request", 18, suffix=True),
    _SinkRule("urllib.request.urlopen", "network", "network request", 18, suffix=True),
    _SinkRule("re.compile", "regex", "regular expression compiler", 10, suffix=True),
    _SinkRule("re.match", "regex", "regular expression match", 10, suffix=True),
    _SinkRule("re.search", "regex", "regular expression search", 10, suffix=True),
    _SinkRule("jinja2.Template", "template", "template rendering", 25, suffix=True),
    _SinkRule("render_template_string", "template", "template rendering", 25, suffix=True),
    _SinkRule("hashlib.md5", "weak_crypto", "weak hash function", 30, suffix=True),
    _SinkRule("hashlib.sha1", "weak_crypto", "weak hash function", 28, suffix=True),
)


class _LocalNodeVisitor(ast.NodeVisitor):
    def generic_visit(self, node: ast.AST) -> Any:
        for _field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.visit(item)
            elif isinstance(value, ast.AST):
                self.visit(value)


def scan_hunt_targets(
    repo_path: str | Path,
    *,
    limit: int | None = None,
    include_tests: bool = False,
) -> HuntReport:
    """Find local attack-surface candidates for authorized unknown-bug research."""
    repo = Path(repo_path).resolve()
    warnings: list[str] = []
    targets: list[HuntTarget] = []

    for py_file in sorted(repo.rglob("*.py")):
        if not _should_scan_file(py_file, repo, include_tests=include_tests):
            continue
        try:
            source = py_file.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            warnings.append(f"Could not read {py_file}: {exc}")
            continue
        try:
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError as exc:
            warnings.append(f"Could not parse {py_file}: {exc}")
            continue

        rel_path = str(py_file.relative_to(repo))
        aliases = _collect_import_aliases(tree)
        module_name = _module_name(rel_path)
        visitor = _HuntVisitor(rel_path, module_name, aliases)
        visitor.visit(tree)
        targets.extend(visitor.targets)

    targets.sort(key=lambda t: (-t.score, t.file_path, t.line, t.qualified_name))
    if limit is not None:
        targets = targets[:limit]

    return HuntReport(repo_path=str(repo), targets=tuple(targets), warnings=tuple(warnings))


def hunt_report_to_json(report: HuntReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def apply_fuzz_introspector_summary(report: HuntReport, summary_path: str | Path) -> HuntReport:
    """Merge optional Fuzz Introspector summary.json sink/reachability evidence."""
    data = json.loads(Path(summary_path).read_text())
    hits = _extract_fuzz_introspector_hits(data)
    if not hits:
        return report

    matched: set[int] = set()
    updated: list[HuntTarget] = []
    for target in report.targets:
        hit_index, hit = _match_fuzz_introspector_hit(target, hits)
        if hit is None:
            updated.append(target)
            continue
        matched.add(hit_index)
        signals = [*target.signals]
        weight = 18 if hit["reach_state"] == "not_reached" else 8
        signals.append(
            HuntSignal(
                kind="fuzz_introspector.sink",
                detail=f"Fuzz Introspector sink evidence: {hit['reach_state']}",
                weight=weight,
                line=target.line,
            )
        )
        score = min(100, target.score + weight)
        updated.append(
            replace(
                target,
                signals=tuple(signals),
                score=score,
                priority=_priority(score, set(target.sinks)),
                fuzz_introspector={
                    "reach_state": hit["reach_state"],
                    "reached_by_fuzzers": hit["reached_by_fuzzers"],
                    "source": str(summary_path),
                },
            )
        )

    warnings = list(report.warnings)
    if len(matched) < len(hits):
        warnings.append(
            f"Fuzz Introspector sinks not matched to ca9 targets: {len(hits) - len(matched)}"
        )

    updated.sort(key=lambda t: (-t.score, t.file_path, t.line, t.qualified_name))
    return HuntReport(
        repo_path=report.repo_path,
        targets=tuple(updated),
        warnings=tuple(warnings),
        generated_harnesses=report.generated_harnesses,
        research_packets=report.research_packets,
        private_artifact_root=report.private_artifact_root,
        private_artifact_roots=report.private_artifact_roots,
        containment=report.containment,
    )


def hunt_report_to_table(report: HuntReport) -> str:
    summary = report.summary()
    lines = [
        f"ca9 hunt report for {report.repo_path}",
        (
            f"Targets: {summary['targets']} | high: {summary['high']} | "
            f"medium: {summary['medium']} | low: {summary['low']}"
        ),
    ]
    if report.warnings:
        lines.append("")
        lines.append("Warnings:")
        lines.extend(f"  - {warning}" for warning in report.warnings)
    if report.generated_harnesses:
        lines.append("")
        lines.append("Generated harnesses:")
        lines.extend(f"  - {path}" for path in report.generated_harnesses)
    if report.research_packets:
        lines.append("")
        lines.append("Research packets:")
        lines.extend(f"  - {path}" for path in report.research_packets)
    if report.private_artifact_root:
        lines.append("")
        lines.append(f"Private artifact root: {report.private_artifact_root}")
    if report.private_artifact_roots:
        lines.append("")
        lines.append("Private artifact roots:")
        lines.extend(f"  - {path}" for path in report.private_artifact_roots)
    if report.containment:
        lines.append("")
        lines.append("Containment:")
        lines.extend(f"  - {item}" for item in report.containment)
    if report.targets:
        lines.append("")
        lines.append("Targets:")
        for index, target in enumerate(report.targets, start=1):
            signal_text = ", ".join(_compact_signal(signal) for signal in target.signals[:4])
            lines.append(
                f"  {index}. [{target.priority.upper()}] score={target.score} "
                f"{target.qualified_name} ({target.file_path}:{target.line})"
            )
            lines.append(
                f"     complexity={target.complexity} harness={target.harness_kind} "
                f"sinks={', '.join(target.sinks) or 'none'}"
            )
            if signal_text:
                lines.append(f"     signals={signal_text}")
    return "\n".join(lines)


def generate_atheris_harnesses(
    report: HuntReport,
    output_dir: str | Path,
    *,
    limit: int | None = None,
    private: bool = True,
) -> HuntReport:
    out = Path(output_dir)
    containment: list[str] = list(report.containment)
    if private:
        _prepare_private_artifact_dir(out)
        containment.extend(
            [
                "generated artifacts are written locally only",
                "artifact directory is ignored by git",
                "raw fuzzing inputs are not included in hunt reports",
            ]
        )
    else:
        out.mkdir(parents=True, exist_ok=True)

    selected = [t for t in report.targets if t.harness_kind == "atheris"]
    if limit is not None:
        selected = selected[:limit]

    generated: list[str] = []
    for target in selected:
        filename = f"fuzz_{_safe_name(target.qualified_name)}.py"
        path = out / filename
        path.write_text(_render_atheris_harness(target), encoding="utf-8")
        generated.append(str(path))

    return HuntReport(
        repo_path=report.repo_path,
        targets=report.targets,
        warnings=report.warnings,
        generated_harnesses=tuple(generated),
        research_packets=report.research_packets,
        private_artifact_root=str(out) if private else report.private_artifact_root,
        private_artifact_roots=_append_private_artifact_root(
            report.private_artifact_roots,
            str(out) if private else None,
        ),
        containment=tuple(dict.fromkeys(containment)),
    )


def generate_research_packets(
    report: HuntReport,
    output_dir: str | Path,
    *,
    limit: int | None = 5,
    private: bool = True,
    scope: str | None = None,
    recipient: str | None = None,
) -> HuntReport:
    """Write private candidate packets for human researcher validation."""
    out = Path(output_dir)
    containment: list[str] = list(report.containment)
    if private:
        _prepare_private_artifact_dir(out)
        containment.extend(
            [
                "research packets are private triage material, not public advisories",
                "research packets do not include exploit payloads or crash inputs",
                "share packets only with authorized researchers or maintainers",
            ]
        )
    else:
        out.mkdir(parents=True, exist_ok=True)

    selected = list(report.targets)
    if limit is not None:
        selected = selected[:limit]

    generated: list[str] = []
    candidate_entries: list[dict[str, object]] = []
    for index, target in enumerate(selected, start=1):
        filename = f"candidate_{index:03d}_{_safe_name(target.qualified_name)}.md"
        path = out / filename
        path.write_text(
            _render_research_packet(
                report=report,
                target=target,
                scope=scope,
                recipient=recipient,
            ),
            encoding="utf-8",
        )
        generated.append(str(path))
        candidate_entries.append(
            {
                "packet": str(path),
                "qualified_name": target.qualified_name,
                "file_path": target.file_path,
                "line": target.line,
                "end_line": target.end_line,
                "priority": target.priority,
                "score": target.score,
                "categories": _categories_for_sinks(set(target.sinks)),
            }
        )

    manifest_path = out / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": "ca9.research_packet.v1",
                "repo_path": report.repo_path,
                "scope": scope,
                "recipient": recipient,
                "candidate_count": len(candidate_entries),
                "containment": [
                    "private triage only",
                    "no exploit payloads",
                    "no crash inputs",
                    "authorized disclosure workflow required",
                ],
                "candidates": candidate_entries,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    generated.insert(0, str(manifest_path))

    return HuntReport(
        repo_path=report.repo_path,
        targets=report.targets,
        warnings=report.warnings,
        generated_harnesses=report.generated_harnesses,
        research_packets=tuple((*report.research_packets, *generated)),
        private_artifact_root=report.private_artifact_root or (str(out) if private else None),
        private_artifact_roots=_append_private_artifact_root(
            report.private_artifact_roots,
            str(out) if private else None,
        ),
        containment=tuple(dict.fromkeys(containment)),
    )


class _HuntVisitor(_LocalNodeVisitor):
    def __init__(self, rel_path: str, module_name: str, aliases: dict[str, str]) -> None:
        self.rel_path = rel_path
        self.module_name = module_name
        self.aliases = aliases
        self.class_stack: list[str] = []
        self.targets: list[HuntTarget] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self._record_function(node, is_async=False)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._record_function(node, is_async=True)
        self.generic_visit(node)

    def _record_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        params = _function_parameters(node)
        decorators = tuple(_decorator_name(d) for d in node.decorator_list if _decorator_name(d))
        analysis = _FunctionAnalyzer(node, self.aliases)
        analysis.visit(node)

        signals = _score_function(
            node=node,
            rel_path=self.rel_path,
            params=params,
            decorators=decorators,
            complexity=analysis.complexity,
            sink_signals=analysis.sink_signals,
        )
        if not signals:
            return

        score = min(100, sum(signal.weight for signal in signals))
        if score < 25 and not analysis.sinks:
            return

        path_parts = [self.module_name, *self.class_stack, node.name]
        qualified_name = ".".join(part for part in path_parts if part)
        harness_kind, harness_reason, input_param, input_kind = _recommend_harness(
            class_stack=self.class_stack,
            params=params,
            sinks=analysis.sinks,
        )

        self.targets.append(
            HuntTarget(
                file_path=self.rel_path,
                qualified_name=qualified_name,
                function_name=node.name,
                line=node.lineno,
                end_line=getattr(node, "end_lineno", node.lineno),
                parameters=tuple(p.name for p in params),
                required_parameters=tuple(p.name for p in params if p.required),
                decorators=decorators,
                complexity=analysis.complexity,
                sinks=tuple(sorted(analysis.sinks)),
                signals=tuple(signals),
                score=score,
                priority=_priority(score, analysis.sinks),
                harness_kind=harness_kind,
                harness_reason=harness_reason,
                input_parameter=input_param,
                input_kind=input_kind,
                is_async=is_async,
            )
        )


class _FunctionAnalyzer(_LocalNodeVisitor):
    def __init__(
        self, root: ast.FunctionDef | ast.AsyncFunctionDef, aliases: dict[str, str]
    ) -> None:
        self.root = root
        self.aliases = aliases
        self.complexity = 1
        self.sinks: set[str] = set()
        self.sink_signals: list[HuntSignal] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        if node is self.root:
            self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        if node is self.root:
            self.generic_visit(node)

    def visit_If(self, node: ast.If) -> Any:
        self.complexity += 1
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> Any:
        self.complexity += 1
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self.complexity += 1
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> Any:
        self.complexity += 1
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> Any:
        self.complexity += 1 + len(node.handlers)
        self.generic_visit(node)

    def visit_IfExp(self, node: ast.IfExp) -> Any:
        self.complexity += 1
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> Any:
        self.complexity += max(1, len(node.values) - 1)
        self.generic_visit(node)

    def visit_Match(self, node: ast.Match) -> Any:
        self.complexity += len(node.cases)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        call_name = _call_name(node.func, self.aliases)
        for rule in _SINK_RULES:
            if _matches_sink(call_name, rule):
                self.sinks.add(rule.kind)
                self.sink_signals.append(
                    HuntSignal(
                        kind=f"sink.{rule.kind}",
                        detail=f"{rule.detail}: {call_name}",
                        weight=rule.weight,
                        line=node.lineno,
                    )
                )
                break

        if call_name.endswith((".execute", ".executemany", ".executescript")):
            self.sinks.add("database")
            weight = 30 if _call_has_sql_literal(node) else 24
            self.sink_signals.append(
                HuntSignal(
                    kind="sink.database",
                    detail=f"SQL execution: {call_name}",
                    weight=weight,
                    line=node.lineno,
                )
            )

        self.generic_visit(node)


def _score_function(
    *,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    rel_path: str,
    params: list[_ParameterInfo],
    decorators: tuple[str, ...],
    complexity: int,
    sink_signals: list[HuntSignal],
) -> list[HuntSignal]:
    signals: list[HuntSignal] = []
    lower_name = node.name.lower()
    rel_lower = rel_path.lower()

    decorator_hits = [
        dec for dec in decorators if any(token in dec.lower() for token in _ENTRYPOINT_DECORATORS)
    ]
    if decorator_hits:
        signals.append(
            HuntSignal(
                kind="exposure.decorator",
                detail=f"entrypoint decorator: {', '.join(decorator_hits[:3])}",
                weight=24,
                line=node.lineno,
            )
        )

    function_keywords = sorted(kw for kw in _FUNCTION_NAME_KEYWORDS if kw in lower_name)
    if function_keywords:
        signals.append(
            HuntSignal(
                kind="exposure.name",
                detail=f"fuzz-friendly function name: {', '.join(function_keywords)}",
                weight=16,
                line=node.lineno,
            )
        )

    input_params = [p.name for p in params if _looks_like_input_param(p)]
    if input_params:
        signals.append(
            HuntSignal(
                kind="input.parameter",
                detail=f"attacker-shaped parameter: {', '.join(input_params[:4])}",
                weight=14,
                line=node.lineno,
            )
        )

    annotated = [
        p.name for p in params if p.annotation in _TEXT_TYPES | _BYTES_TYPES | _STRUCTURED_TYPES
    ]
    if annotated:
        signals.append(
            HuntSignal(
                kind="input.annotation",
                detail=f"fuzzable type annotation: {', '.join(annotated[:4])}",
                weight=8,
                line=node.lineno,
            )
        )

    if any(part in rel_lower for part in ("parser", "api", "route", "upload", "import", "reader")):
        signals.append(
            HuntSignal(
                kind="exposure.file",
                detail=f"attack-surface filename: {rel_path}",
                weight=8,
                line=node.lineno,
            )
        )

    if complexity >= 12:
        signals.append(
            HuntSignal(
                kind="complexity.high",
                detail=f"high cyclomatic complexity: {complexity}",
                weight=18,
                line=node.lineno,
            )
        )
    elif complexity >= 7:
        signals.append(
            HuntSignal(
                kind="complexity.medium",
                detail=f"moderate cyclomatic complexity: {complexity}",
                weight=10,
                line=node.lineno,
            )
        )

    signals.extend(_dedupe_signals(sink_signals))
    return signals


def _recommend_harness(
    *,
    class_stack: list[str],
    params: list[_ParameterInfo],
    sinks: set[str],
) -> tuple[str, str, str | None, str]:
    if class_stack:
        return "manual", "method target needs object setup", None, "text"

    required = [p for p in params if p.required]
    fuzzable = [p for p in params if _looks_fuzzable(p)]
    if not fuzzable:
        return "manual", "no obvious fuzzable input parameter", None, "text"

    target_param = _best_input_parameter(fuzzable)
    if required and not (len(required) == 1 and required[0].name == target_param.name):
        return "manual", "multiple required parameters need domain setup", target_param.name, "text"

    if not (sinks & {"archive_extraction", "deserialization", "parser", "regex", "template"}):
        if not _looks_like_input_param(target_param):
            return "manual", "target is not clearly parser-like", target_param.name, "text"

    input_kind = "bytes" if target_param.annotation in _BYTES_TYPES else "text"
    return (
        "atheris",
        "single fuzzable input can be exercised locally",
        target_param.name,
        input_kind,
    )


def _render_atheris_harness(target: HuntTarget) -> str:
    if target.input_parameter is None:
        raise ValueError("Atheris harness requires an input parameter")
    target_function = target.qualified_name.rsplit(".", 1)[-1]
    is_async = "True" if target.is_async else "False"
    return f"""from __future__ import annotations

# Generated by ca9 hunt as a starting point for authorized local fuzzing.
# Review setup, side effects, and expected exceptions before running for long periods.

import importlib.util
import inspect
import sys
from pathlib import Path

import atheris

TARGET_RELATIVE = {target.file_path!r}
TARGET_FUNCTION = {target_function!r}
INPUT_PARAMETER = {target.input_parameter!r}
INPUT_KIND = {target.input_kind!r}
TARGET_IS_ASYNC = {is_async}


def _find_target_file() -> Path:
    here = Path(__file__).resolve()
    for root in (here.parent, *here.parents):
        candidate = root / TARGET_RELATIVE
        if candidate.is_file():
            return candidate
    raise RuntimeError(f"Could not locate target file {{TARGET_RELATIVE!r}}")


def _load_target():
    target_file = _find_target_file()
    spec = importlib.util.spec_from_file_location("ca9_hunt_target", target_file)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not import {{target_file}}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["ca9_hunt_target"] = module
    spec.loader.exec_module(module)
    return getattr(module, TARGET_FUNCTION)


TARGET = _load_target()


def _coerce_input(data: bytes):
    if INPUT_KIND == "bytes":
        return data
    return data.decode("utf-8", errors="ignore")


def TestOneInput(data: bytes) -> None:
    value = _coerce_input(data)
    try:
        result = TARGET(**{{INPUT_PARAMETER: value}})
        if TARGET_IS_ASYNC or inspect.isawaitable(result):
            import asyncio

            asyncio.run(result)
    except (ValueError, UnicodeDecodeError, KeyError, OverflowError):
        return


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
"""


def _render_research_packet(
    *,
    report: HuntReport,
    target: HuntTarget,
    scope: str | None,
    recipient: str | None,
) -> str:
    categories = ", ".join(_categories_for_sinks(set(target.sinks))) or "unknown"
    sinks = ", ".join(target.sinks) or "none"
    signal_lines = "\n".join(
        f"- {signal.kind}: {signal.detail}"
        + (f" (line {signal.line})" if signal.line is not None else "")
        for signal in target.signals[:8]
    )
    if not signal_lines:
        signal_lines = "- none"

    scope_text = scope or "not specified"
    recipient_text = recipient or "not specified"
    return f"""# ca9 Research Candidate

Status: private triage candidate
Repository: {report.repo_path}
Authorized scope: {scope_text}
Intended recipient: {recipient_text}

## Target

- Qualified name: {target.qualified_name}
- Location: {target.file_path}:{target.line}-{target.end_line}
- Priority: {target.priority}
- Score: {target.score}
- Risk categories: {categories}
- Sinks: {sinks}
- Harness recommendation: {target.harness_kind} ({target.harness_reason or "not specified"})

## Signals

{signal_lines}

## Researcher Validation

- Confirm this target is inside the authorized research scope.
- Validate reachability from attacker-controlled or untrusted input.
- Reproduce only in a local isolated environment.
- Determine impact, affected versions, and practical exploitability.
- Use the project's private security policy or bug bounty process for disclosure.

## Containment

- This packet intentionally omits exploit payloads and crash inputs.
- Do not publish this packet before coordinated disclosure is complete.
- Keep raw fuzzer corpora, crashes, and proof material in a private workspace.
"""


def _prepare_private_artifact_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    with suppress(OSError):
        path.chmod(0o700)

    ignore_path = path / ".gitignore"
    if not ignore_path.exists():
        ignore_path.write_text("*\n!.gitignore\n", encoding="utf-8")


def _append_private_artifact_root(roots: tuple[str, ...], root: str | None) -> tuple[str, ...]:
    if root is None:
        return roots
    return tuple(dict.fromkeys((*roots, root)))


def _extract_fuzz_introspector_hits(data: dict[str, object]) -> list[dict[str, object]]:
    analyses = data.get("analyses")
    if not isinstance(analyses, dict):
        return []
    raw_hits = analyses.get("SinkCoverageAnalyser")
    if not isinstance(raw_hits, list):
        return []

    hits: list[dict[str, object]] = []
    for item in raw_hits:
        if not isinstance(item, dict):
            continue
        name = _optional_str(item.get("func_name") or item.get("function_name") or item.get("name"))
        if not name:
            continue
        source_file = _optional_str(
            item.get("source_file")
            or item.get("function_filename")
            or item.get("filename")
            or item.get("file")
        )
        reached_by = _string_list(
            item.get("fuzzer_reach")
            or item.get("reached_by_fuzzers")
            or item.get("fuzzers_reaching")
        )
        call_loc = str(item.get("call_loc") or "")
        reach_state = (
            "reached" if reached_by and call_loc.lower() != "not in call tree" else "not_reached"
        )
        hits.append(
            {
                "name": name,
                "name_tail": name.rsplit(".", 1)[-1],
                "source_file": source_file,
                "reached_by_fuzzers": reached_by,
                "reach_state": reach_state,
            }
        )
    return hits


def _match_fuzz_introspector_hit(
    target: HuntTarget,
    hits: list[dict[str, object]],
) -> tuple[int, dict[str, object] | None]:
    target_names = {target.qualified_name, target.function_name}
    best: tuple[int, dict[str, object]] | None = None
    for index, hit in enumerate(hits):
        hit_name = str(hit["name"])
        hit_tail = str(hit["name_tail"])
        if hit_name not in target_names and hit_tail != target.function_name:
            continue
        source_file = hit.get("source_file")
        if isinstance(source_file, str) and source_file:
            normalized = source_file.replace("\\", "/")
            if not (
                normalized.endswith(target.file_path)
                or target.file_path.endswith(normalized)
                or normalized.endswith(target.file_path.split("/", 1)[-1])
            ):
                if best is None:
                    best = (index, hit)
                continue
            return index, hit
        if best is None:
            best = (index, hit)
    if best is None:
        return -1, None
    return best


def _optional_str(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _should_scan_file(py_file: Path, repo: Path, *, include_tests: bool) -> bool:
    try:
        rel_parts = py_file.relative_to(repo).parts
    except ValueError:
        return False
    parent_names = set(rel_parts[:-1])
    if _EXCLUDED_DIRS & parent_names:
        return False
    if not include_tests and _TEST_AND_DOC_DIRS & parent_names:
        return False
    if py_file.name == "conftest.py":
        return False
    return include_tests or not (
        py_file.name.startswith("test_") or py_file.name.endswith("_test.py")
    )


def _module_name(rel_path: str) -> str:
    parts = Path(rel_path).parts
    if len(parts) > 1 and parts[0] in {"lib", "python", "src"}:
        rel_path = str(Path(*parts[1:]))
    if rel_path.endswith("/__init__.py"):
        rel_path = rel_path[: -len("/__init__.py")]
    elif rel_path.endswith(".py"):
        rel_path = rel_path[:-3]
    return rel_path.replace("/", ".")


def _categories_for_sinks(sinks: set[str]) -> list[str]:
    categories: set[str] = set()
    mapping = {
        "archive_extraction": "path_traversal",
        "code_execution": "command_injection",
        "command_execution": "command_injection",
        "database": "sql_injection",
        "deserialization": "unsafe_deserialization",
        "filesystem": "path_traversal",
        "regex": "regex_dos",
        "template": "template_injection",
        "weak_crypto": "weak_crypto",
    }
    for sink in sinks:
        category = mapping.get(sink)
        if category:
            categories.add(category)
    return sorted(categories)


def _collect_import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                aliases[local] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                aliases[local] = f"{node.module}.{alias.name}"
    return aliases


def _function_parameters(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[_ParameterInfo]:
    params: list[_ParameterInfo] = []
    positional = [*node.args.posonlyargs, *node.args.args]
    positional_defaults = [None] * (len(positional) - len(node.args.defaults)) + list(
        node.args.defaults
    )
    for arg, default in zip(positional, positional_defaults, strict=True):
        if arg.arg in {"self", "cls"}:
            continue
        params.append(
            _ParameterInfo(
                name=arg.arg,
                required=default is None,
                annotation=_annotation_name(arg.annotation),
            )
        )
    for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True):
        params.append(
            _ParameterInfo(
                name=arg.arg,
                required=default is None,
                annotation=_annotation_name(arg.annotation),
            )
        )
    if node.args.vararg:
        params.append(
            _ParameterInfo(
                name=node.args.vararg.arg,
                required=False,
                annotation=_annotation_name(node.args.vararg.annotation),
            )
        )
    if node.args.kwarg:
        params.append(
            _ParameterInfo(
                name=node.args.kwarg.arg,
                required=False,
                annotation=_annotation_name(node.args.kwarg.annotation),
            )
        )
    return params


def _annotation_name(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Attribute):
        base = _annotation_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Subscript):
        return _annotation_name(node.value)
    if isinstance(node, ast.BinOp):
        left = _annotation_name(node.left)
        right = _annotation_name(node.right)
        if left and right:
            return f"{left}|{right}"
    return None


def _decorator_name(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _decorator_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _call_name(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value, aliases)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func, aliases)
    return ""


def _matches_sink(call_name: str, rule: _SinkRule) -> bool:
    if not call_name:
        return False
    if call_name == rule.pattern:
        return True
    if rule.suffix and call_name.endswith(f".{rule.pattern}"):
        return True
    if rule.suffix and call_name.endswith(rule.pattern):
        return True
    return rule.pattern in {"read_text", "write_text"} and call_name.endswith(f".{rule.pattern}")


def _call_has_sql_literal(node: ast.Call) -> bool:
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            upper = arg.value.upper()
            return any(keyword in upper for keyword in ("SELECT ", "INSERT ", "UPDATE ", "DELETE "))
    return False


def _looks_like_input_param(param: _ParameterInfo) -> bool:
    lower = param.name.lower()
    return any(keyword in lower for keyword in _PARAM_NAME_KEYWORDS)


def _looks_fuzzable(param: _ParameterInfo) -> bool:
    if _looks_like_input_param(param):
        return True
    if param.annotation is None:
        return False
    annotation_parts = set(re.split(r"[^A-Za-z0-9_.]+", param.annotation))
    return bool(annotation_parts & (_TEXT_TYPES | _BYTES_TYPES | _STRUCTURED_TYPES))


def _best_input_parameter(params: list[_ParameterInfo]) -> _ParameterInfo:
    for param in params:
        if _looks_like_input_param(param):
            return param
    return params[0]


def _priority(score: int, sinks: set[str]) -> str:
    dangerous = {"archive_extraction", "code_execution", "command_execution", "deserialization"}
    if score >= 75 or (score >= 55 and bool(sinks & dangerous)):
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def _dedupe_signals(signals: list[HuntSignal]) -> list[HuntSignal]:
    seen: set[tuple[str, str]] = set()
    result: list[HuntSignal] = []
    for signal in signals:
        key = (signal.kind, signal.detail)
        if key in seen:
            continue
        seen.add(key)
        result.append(signal)
    return result


def _compact_signal(signal: HuntSignal) -> str:
    return f"{signal.kind}:{signal.weight}"


def _safe_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]+", "_", name).strip("_").lower()
    return cleaned[:120] or "target"
