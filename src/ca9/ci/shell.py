"""Find installs, tool installs, downloads, checks and publish commands in CI scripts.

This reads shell text; it never runs it. Each simple command is classified
from its argv after wrappers such as ``sudo`` and ``env`` are removed. Facts
carry an ``order`` so a job can tell what happened before a publish step.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ca9.agent_config.mcp_launch import DOCKER_RUN_VALUE_FLAGS
from ca9.ci.images import image_pinned, image_reference
from ca9.ci.model import MAX_NAME_LENGTH, Download, Indirect, Install, Publish, Tool

MAX_SCRIPT_CHARS = 200_000
MAX_DEPTH = 3
PLACEHOLDER = "__CA9EXPR__"

_EXPR_RE = re.compile(r"\$\{\{(.*?)\}\}", re.S)
_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
_HEREDOC_RE = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
_EXACT_VERSION_RE = re.compile(r"^v?\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.+-]+)?$")
_HEX64_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
_URL_RE = re.compile(r"(?:https?|ftp)://[^\s'\"()<>|;&`]+")
_PIP_SPEC_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(===|==|~=|!=|<=|>=|<|>)?\s*([^;\s]*)"
)
_HOST_RE = re.compile(r"^[a-z0-9.-]+$")
_SUBSTITUTION_PIPE_RE = re.compile(
    r"(?:\b(?:ba|z|da|k)?sh\b|\bsource\b|\beval\b|(?:^|\s)\.)[^|;&\n]*?(?:<\(|\$\()\s*"
    r"(?:sudo\s+)?(?:curl|wget)\b[^)\n]*?((?:https?|ftp)://[^\s)'\"]+)"
)
_POWERSHELL_PIPE_RE = re.compile(
    r"\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|\n]*?((?:https?)://[^\s'\")|]+)"
    r"[^|\n]*\|\s*(?:iex|Invoke-Expression)\b",
    re.I,
)
_POWERSHELL_STRING_RE = re.compile(
    r"\b(?:iex|Invoke-Expression)\b[^\n]*DownloadString\(\s*['\"]((?:https?)://[^'\"]+)",
    re.I,
)
_OIDC_REQUEST_RE = re.compile(r"ACTIONS_ID_TOKEN_REQUEST_(?:URL|TOKEN)")
_NPM_AUTH_LINE_RE = re.compile(r"_authToken|npm\s+config\s+set\s+\S*(?:auth|token)", re.I)
_PYPIRC_RE = re.compile(r"\.pypirc|pypi-token|password\s*=", re.I)

_CONTEXT_PATHS = {
    "github.workspace": "$GITHUB_WORKSPACE",
    "runner.temp": "$RUNNER_TEMP",
    "runner.tool_cache": "$RUNNER_TOOL_CACHE",
    "github.action_path": "$GITHUB_ACTION_PATH",
}
_SUDO_VALUE_FLAGS = frozenset({"-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U"})
_ENV_VALUE_FLAGS = frozenset({"-u", "-C", "-S"})
_SEPARATORS = frozenset({";", "&&", "||", "&", "(", ")", "{", "}", ";;", "$", "`", "<(", ">("})
_PIPES = frozenset({"|", "|&"})
_OUT_REDIRECTS = frozenset({">", ">>", ">|", "&>", "&>>"})
_SKIP_NEXT_REDIRECTS = frozenset({"<", "<<", "<<-", "<<<", ">&", "<&", "&>&"})
_KEYWORDS = frozenset({"if", "then", "else", "elif", "do", "while", "until", "!", "fi", "done"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash"})
_INDIRECT_TOOLS = {
    "make": "make",
    "gmake": "gmake",
    "just": "just",
    "task": "task",
    "go-task": "task",
    "tox": "tox",
    "nox": "nox",
}
_CONTAINER_SUBCOMMANDS = frozenset({"build", "buildx", "compose", "run"})
_DOCKER_VALUE_FLAGS = frozenset(
    {
        "--config",
        "--context",
        "-c",
        "--host",
        "-H",
        "--log-level",
        "-l",
        "--tlscacert",
        "--tlscert",
        "--tlskey",
    }
)
_NOT_REPO_DIRS = frozenset({"node_modules", ".venv", "venv", "site-packages", ".tox", ".nox"})
_INTERPRETERS = frozenset({"python", "python3", "node", "perl", "ruby", "pwsh", "powershell"})
_ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz2", ".tar", ".zip")
_BIN_DIR_RE = re.compile(r"(?:^|/)(?:s?bin|\.local/bin)(?:/|$)")
_CHECKSUM_PROGRAMS = frozenset(
    {"sha256sum", "sha512sum", "sha384sum", "sha1sum", "md5sum", "shasum", "b2sum", "cksum"}
)
_SIGNATURE_COMMANDS = (
    ("gpg", "--verify"),
    ("gpgv", None),
    ("cosign", "verify-blob"),
    ("cosign", "verify"),
    ("cosign", "verify-attestation"),
    ("slsa-verifier", "verify-artifact"),
    ("minisign", "-V"),
    ("gh", "attestation"),
)
_SELF_UPDATE = {"npm": frozenset({"npm"}), "pip": frozenset({"pip"})}
_KNOWN_BINS = {
    "changeset": "@changesets/cli",
    "tsc": "typescript",
    "lerna": "lerna",
    "semantic-release": "semantic-release",
    "release-it": "release-it",
    "playwright": "@playwright/test",
    "vitest": "vitest",
    "jest": "jest",
    "eslint": "eslint",
    "prettier": "prettier",
    "tsx": "tsx",
    "ts-node": "ts-node",
    "nx": "nx",
    "turbo": "turbo",
    "vite": "vite",
}
_NPM_VALUE_FLAGS = frozenset(
    {
        "--prefix",
        "-C",
        "--dir",
        "--workspace",
        "-w",
        "--registry",
        "--tag",
        "--access",
        "--otp",
        "--userconfig",
        "--cache",
        "--loglevel",
        "--location",
        "--omit",
        "--include",
        "--filter",
        "-F",
        "--cwd",
        "--reporter",
        "--workspace-dir",
        "--publish-branch",
        "-p",
        "--package",
        "--network-concurrency",
        "--mode",
    }
)
_PIP_VALUE_FLAGS = frozenset(
    {
        "-r",
        "--requirement",
        "-c",
        "--constraint",
        "-i",
        "--index-url",
        "--extra-index-url",
        "-f",
        "--find-links",
        "-t",
        "--target",
        "--prefix",
        "--root",
        "--python-version",
        "--platform",
        "--implementation",
        "--abi",
        "--only-binary",
        "--no-binary",
        "--progress-bar",
        "--src",
        "-e",
        "--editable",
        "--trusted-host",
        "--cert",
        "--client-cert",
        "--cache-dir",
        "--log",
        "--proxy",
        "--retries",
        "--timeout",
        "--exists-action",
        "--upgrade-strategy",
        "--report",
        "--config-settings",
        "-C",
        "--uploaded-prior-to",
        "--python",
        "-p",
        "--group",
        "--spec",
        "--with",
        "--from",
        "--index",
    }
)
_CURL_VALUE_FLAGS = frozenset(
    {
        "-o",
        "--output",
        "-H",
        "--header",
        "-d",
        "--data",
        "--data-raw",
        "--data-binary",
        "--data-urlencode",
        "-X",
        "--request",
        "-u",
        "--user",
        "-A",
        "--user-agent",
        "-e",
        "--referer",
        "--retry",
        "--max-time",
        "-m",
        "--connect-timeout",
        "-w",
        "--write-out",
        "--output-dir",
        "-T",
        "--upload-file",
        "-F",
        "--form",
        "--cacert",
        "--cert",
        "-K",
        "--config",
        "--proto",
        "--retry-delay",
        "--retry-max-time",
        "-r",
        "--range",
        "-b",
        "--cookie",
        "-c",
        "--cookie-jar",
        "--limit-rate",
        "--resolve",
        "-x",
        "--proxy",
        "--oauth2-bearer",
        "--url",
        "-z",
        "--time-cond",
    }
)
_WGET_VALUE_FLAGS = frozenset(
    {
        "-O",
        "--output-document",
        "-P",
        "--directory-prefix",
        "-o",
        "--output-file",
        "-a",
        "--append-output",
        "--header",
        "--user",
        "--password",
        "-U",
        "--user-agent",
        "-t",
        "--tries",
        "-T",
        "--timeout",
        "--post-data",
        "--post-file",
        "-e",
        "--execute",
    }
)
_UPLOAD_FLAGS = frozenset(
    {"-T", "--upload-file", "-F", "--form", "-d", "--data", "--data-binary", "--data-raw"}
)


@dataclass
class ShellContext:
    """What a script can see: literal env values, package scripts, local binaries."""

    env: dict[str, str] = field(default_factory=dict)
    scripts: dict[str, str] = field(default_factory=dict)
    local_packages: frozenset[str] = frozenset()
    yarn_berry: bool = False
    inputs: dict[str, str] = field(default_factory=dict)


@dataclass
class Extract:
    file: str | None
    directory: str
    line: int
    order: tuple[int, ...]


@dataclass
class Move:
    source: str
    destination: str
    line: int
    order: tuple[int, ...]


@dataclass
class Removal:
    paths: list[str]
    order: tuple[int, ...]


@dataclass
class Execution:
    file: str
    order: tuple[int, ...]


@dataclass
class Verification:
    text: str
    line: int
    order: tuple[int, ...]


@dataclass
class Credential:
    registry: str
    name: str
    line: int


@dataclass
class ScriptFacts:
    installs: list[Install] = field(default_factory=list)
    tools: list[Tool] = field(default_factory=list)
    other_tools: list[Tool] = field(default_factory=list)
    downloads: list[Download] = field(default_factory=list)
    publishes: list[Publish] = field(default_factory=list)
    indirect: list[Indirect] = field(default_factory=list)
    extracts: list[Extract] = field(default_factory=list)
    moves: list[Move] = field(default_factory=list)
    removals: list[Removal] = field(default_factory=list)
    executions: list[Execution] = field(default_factory=list)
    verifications: list[Verification] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    oidc_requests: list[int] = field(default_factory=list)
    registry_hosts: set[str] = field(default_factory=set)

    def extend(self, other: ScriptFacts) -> None:
        for name in (
            "installs",
            "tools",
            "other_tools",
            "downloads",
            "publishes",
            "indirect",
            "extracts",
            "moves",
            "removals",
            "executions",
            "verifications",
            "credentials",
            "oidc_requests",
        ):
            getattr(self, name).extend(getattr(other, name))
        self.registry_hosts.update(other.registry_hosts)


@dataclass
class _Command:
    argv: list[str]
    line: int
    raw: str
    stdout: str | None = None
    pipe_next: bool = False


class _Scanner:
    def __init__(self, context: ShellContext, base: tuple[int, ...]) -> None:
        self.context = context
        self.base = base
        self.counter = 0
        self.facts = ScriptFacts()

    def order(self) -> tuple[int, ...]:
        self.counter += 1
        return (*self.base, self.counter)

    def scan(self, text: str, start_line: int, depth: int = 0) -> None:
        if depth > MAX_DEPTH or not text:
            return
        text = text[:MAX_SCRIPT_CHARS]
        for raw, line in _logical_lines(text, start_line):
            self._raw_line_facts(raw, line)
            prepared = _substitute_expressions(raw, self.context)
            commands = _commands(prepared, line)
            for pipeline in _pipelines(commands):
                self._pipeline(pipeline, depth)

    def _raw_line_facts(self, raw: str, line: int) -> None:
        if _OIDC_REQUEST_RE.search(raw):
            self.facts.oidc_requests.append(line)
        lowered = raw.lower()
        if "registry.npmjs.org" in lowered or "npmjs.com" in lowered:
            self.facts.registry_hosts.add("npm")
        if "upload.pypi.org" in lowered or "pypi.org/_/oidc" in lowered:
            self.facts.registry_hosts.add("pypi")
        if _NPM_AUTH_LINE_RE.search(raw):
            self.facts.credentials.append(Credential("npm", "_authToken", line))
        if _PYPIRC_RE.search(raw) and "pypi" in lowered:
            self.facts.credentials.append(Credential("pypi", ".pypirc", line))
        for pattern in (_SUBSTITUTION_PIPE_RE, _POWERSHELL_PIPE_RE, _POWERSHELL_STRING_RE):
            for match in pattern.finditer(raw):
                self.facts.tools.append(
                    Tool(
                        _url_tool_name(match.group(1)), "curl_pipe", False, line, order=self.order()
                    )
                )

    def _pipeline(self, pipeline: list[_Command], depth: int) -> None:
        first = pipeline[0]
        argv, assigns = _unwrap(first.argv)
        if not argv:
            return
        program, args = _program(argv)
        if program in {"curl", "wget"} and len(pipeline) > 1:
            if self._download_pipe(program, args, pipeline[1:], first):
                return
        for command in pipeline:
            command_argv, command_assigns = _unwrap(command.argv)
            if command_argv:
                self._command(command, command_argv, command_assigns, depth)

    def _download_pipe(
        self, program: str, args: list[str], rest: list[_Command], first: _Command
    ) -> bool:
        url = _first_url(args)
        if program == "curl":
            output = _curl_output(args, url)
        else:
            output = _wget_output(args, url)
        if output not in {None, "-"} or url is None:
            return False
        for command in rest:
            argv, _ = _unwrap(command.argv)
            if not argv:
                continue
            target, target_args = _program(argv)
            if target in _SHELLS | _INTERPRETERS or target in {"iex", "invoke-expression"}:
                if _reads_stdin(target, target_args):
                    self.facts.tools.append(
                        Tool(
                            _url_tool_name(url), "curl_pipe", False, first.line, order=self.order()
                        )
                    )
                    return True
                return True
            if target == "tar" and _tar_extracts(target_args):
                order = self.order()
                directory = _tar_directory(target_args) or "."
                self.facts.downloads.append(
                    Download(
                        host=_host(url),
                        line=first.line,
                        target=None,
                        archive=True,
                        lands_in=directory,
                        order=order,
                    )
                )
                self.facts.extracts.append(Extract(None, directory, first.line, order))
                return True
            if target in {"tee"} and target_args:
                files = [arg for arg in target_args if not arg.startswith("-")]
                if files:
                    self.facts.downloads.append(
                        Download(_host(url), first.line, target=files[0], order=self.order())
                    )
                return True
        return True

    def _command(
        self, command: _Command, argv: list[str], assigns: dict[str, str], depth: int
    ) -> None:
        program, args = _program(argv)
        line = command.line
        indirect = _indirect_command(program, argv, args)
        if indirect is not None:
            self.facts.indirect.append(Indirect(indirect, line, order=self.order()))
        if program in _SHELLS and "-c" in args:
            index = args.index("-c")
            if index + 1 < len(args):
                self.scan(args[index + 1], line, depth + 1)
            return
        if program in {"pwsh", "powershell"}:
            for flag in ("-Command", "-c"):
                if flag in args and args.index(flag) + 1 < len(args):
                    self.scan(args[args.index(flag) + 1], line, depth + 1)
                    return
        handler = _HANDLERS.get(program)
        if handler is not None:
            handler(self, args, command, assigns, depth)
            return
        if program in _CHECKSUM_PROGRAMS:
            self._checksum(args, command)
            return
        if argv[0].startswith("./") or argv[0].startswith("/"):
            self.facts.executions.append(Execution(argv[0], self.order()))

    def _checksum(self, args: list[str], command: _Command) -> None:
        checking = any(
            arg in {"-c", "--check"}
            or (arg.startswith("-") and not arg.startswith("--") and "c" in arg)
            for arg in args
        )
        compares = bool(_HEX64_RE.search(command.raw)) or bool(
            re.search(r"(?:!=|==|\s=\s|\s-eq\s|\s-ne\s)", command.raw)
        )
        if checking or compares:
            self.facts.verifications.append(Verification(command.raw, command.line, self.order()))

    def ignore_scripts(self, args: list[str], assigns: dict[str, str]) -> bool:
        if "--ignore-scripts" in args:
            return True
        for source in (assigns, self.context.env):
            for key, value in source.items():
                if key.lower() == "npm_config_ignore_scripts" and value.strip().lower() in {
                    "true",
                    "1",
                }:
                    return True
                if key == "YARN_ENABLE_SCRIPTS" and value.strip().lower() in {"false", "0"}:
                    return True
        return False

    def add_install(self, ecosystem: str, manager: str, kind: str, ignore: bool, line: int) -> None:
        self.facts.installs.append(
            Install(ecosystem, manager, kind, ignore, line, order=self.order())
        )

    def add_tool(self, name: str, route: str, pinned: bool, line: int) -> None:
        self_update = name.lower() in _SELF_UPDATE.get(route, frozenset())
        self.facts.tools.append(
            Tool(
                _safe_name(name),
                route,
                pinned,
                line,
                self_update=self_update,
                order=self.order(),
            )
        )

    def add_other_tool(self, name: str, manager: str, pinned: bool, line: int) -> None:
        self.facts.other_tools.append(
            Tool(_safe_name(name), manager, pinned, line, manager=manager, order=self.order())
        )

    def add_publish(
        self,
        registry: str,
        command: str,
        line: int,
        *,
        via: str = "command",
        provenance: bool = False,
    ) -> None:
        self.facts.publishes.append(
            Publish(
                registry=registry,
                line=line,
                command=command,
                via=via,
                provenance=provenance,
                order=self.order(),
            )
        )

    def run_script(self, name: str, command: _Command, depth: int) -> None:
        """Follow a package script; a script named like a publish counts as one when its
        body hides the registry call (for example ``tsx scripts/publishCI.ts``)."""
        body = self.context.scripts.get(name)
        found = False
        if body and depth < MAX_DEPTH:
            nested = _Scanner(self.context, self.base)
            nested.counter = self.counter
            nested.scan(body, command.line, depth + 1)
            self.counter = nested.counter
            for publish in nested.facts.publishes:
                publish.via = f"script:{name}"
                publish.line = command.line
                self.facts.publishes.append(publish)
                found = True
            for item in nested.facts.indirect:
                item.line = command.line
                self.facts.indirect.append(item)
            self.facts.credentials.extend(nested.facts.credentials)
        if not found and "publish" in name.lower() and "--dry-run" not in command.raw:
            self.add_publish("npm", f"run {name}", command.line, via=f"script_name:{name}")

    def local_binary(self, name: str) -> bool:
        package = _KNOWN_BINS.get(name, name)
        return package in self.context.local_packages or name in self.context.local_packages


def _indirect_command(program: str, argv: list[str], args: list[str]) -> str | None:
    """The tool name of a command that may install packages out of sight: build runners,
    container builds and runs, test-environment managers and repository scripts."""
    if program in _INDIRECT_TOOLS:
        return _INDIRECT_TOOLS[program]
    if program in {"docker", "podman"}:
        if _container_subcommand(args) in _CONTAINER_SUBCOMMANDS:
            return program
        return None
    if program in {"docker-compose", "podman-compose"}:
        return program
    if program in _SHELLS:
        if any(arg in {"-c", "-s"} for arg in args):
            return None
        positionals = [arg for arg in args if not arg.startswith("-")]
        if positionals and _repo_path(positionals[0]):
            return _script_name(positionals[0])
        return None
    if program not in _HANDLERS and _repo_path(argv[0]) and "/" in argv[0]:
        return _script_name(argv[0])
    return None


def _container_subcommand(args: list[str]) -> str | None:
    words: list[str] = []
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg.startswith("-"):
            skip = "=" not in arg and arg in _DOCKER_VALUE_FLAGS
            continue
        words.append(arg)
        if len(words) == 2:
            break
    if not words:
        return None
    if words[0] in {"image", "container"} and len(words) > 1:
        return words[1]
    return words[0]


def _repo_path(path: str) -> bool:
    text = path.replace("\\", "/")
    if not text or text.startswith(("/", "~", "$", "%", PLACEHOLDER)) or "://" in text:
        return False
    if re.match(r"^[A-Za-z]:/", text):
        return False
    return not any(part in _NOT_REPO_DIRS for part in text.split("/")[:-1])


def _script_name(path: str) -> str:
    text = path.replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return _safe_name(text or path)


def scan_script(
    text: str,
    start_line: int,
    context: ShellContext,
    base: tuple[int, ...] = (),
) -> ScriptFacts:
    """Classify every command in ``text``; lines are absolute file lines."""
    scanner = _Scanner(context, base)
    scanner.scan(text, start_line)
    return scanner.facts


def _logical_lines(text: str, start_line: int) -> list[tuple[str, int]]:
    result: list[tuple[str, int]] = []
    pending = ""
    pending_line = start_line
    heredoc: str | None = None
    for offset, physical in enumerate(text.split("\n")):
        number = start_line + offset
        if heredoc is not None:
            if physical.strip() == heredoc:
                heredoc = None
            continue
        code = _strip_comment(physical)
        if not pending:
            pending_line = number
        if code.rstrip().endswith("\\"):
            pending += code.rstrip()[:-1] + " "
            continue
        pending += code
        if pending.strip():
            result.append((pending, pending_line))
            match = _HEREDOC_RE.search(pending)
            if match:
                heredoc = match.group(2)
        pending = ""
    if pending.strip():
        result.append((pending, pending_line))
    return result


def _strip_comment(line: str) -> str:
    quote: str | None = None
    for index, char in enumerate(line):
        if quote:
            if char == quote:
                quote = None
        elif char in {"'", '"'}:
            quote = char
        elif char == "#" and (index == 0 or line[index - 1] in " \t;"):
            return line[:index]
    return line


def _substitute_expressions(text: str, context: ShellContext) -> str:
    def replace(match: re.Match[str]) -> str:
        inner = match.group(1).strip()
        if inner in _CONTEXT_PATHS:
            return _CONTEXT_PATHS[inner]
        env_match = re.fullmatch(r"(?:env|vars)\.([A-Za-z_][A-Za-z0-9_]*)", inner)
        if env_match and env_match.group(1) in context.env:
            return context.env[env_match.group(1)]
        input_match = re.fullmatch(r"inputs\.([A-Za-z0-9_-]+)", inner)
        if input_match and input_match.group(1) in context.inputs:
            return context.inputs[input_match.group(1)]
        return PLACEHOLDER

    return _EXPR_RE.sub(replace, text)


def _tokens(line: str) -> list[str]:
    lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|()<>")
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError:
        tokens = re.findall(r"&&|\|\||[;&|()<>]|[^\s;&|()<>]+", line)
        return [token.strip("'\"") for token in tokens if token.strip("'\"")]


def _commands(line: str, number: int) -> list[_Command]:
    commands: list[_Command] = []
    current = _Command([], number, "")
    tokens = _tokens(line)
    index = 0

    def finish(pipe: bool) -> None:
        nonlocal current
        if current.argv:
            current.pipe_next = pipe
            current.raw = line.strip()
            commands.append(current)
        current = _Command([], number, "")

    while index < len(tokens):
        token = tokens[index]
        if token in _PIPES:
            finish(True)
        elif token in _SEPARATORS:
            finish(False)
        elif token in _OUT_REDIRECTS:
            if current.argv and current.argv[-1].isdigit():
                current.argv.pop()
            if index + 1 < len(tokens):
                current.stdout = tokens[index + 1]
            index += 1
        elif token in _SKIP_NEXT_REDIRECTS:
            if current.argv and current.argv[-1].isdigit():
                current.argv.pop()
            index += 1
        elif not current.argv and token in _KEYWORDS:
            pass
        else:
            current.argv.append(token)
        index += 1
    finish(False)
    return commands


def _pipelines(commands: list[_Command]) -> list[list[_Command]]:
    pipelines: list[list[_Command]] = []
    current: list[_Command] = []
    for command in commands:
        current.append(command)
        if not command.pipe_next:
            pipelines.append(current)
            current = []
    if current:
        pipelines.append(current)
    return pipelines


def _unwrap(argv: list[str]) -> tuple[list[str], dict[str, str]]:
    assigns: dict[str, str] = {}
    index = 0
    while index < len(argv):
        token = argv[index]
        if _ASSIGN_RE.match(token):
            key, _, value = token.partition("=")
            assigns[key] = value
            index += 1
            continue
        base = posixpath.basename(token).lower()
        if base == "sudo":
            index += 1
            while index < len(argv) and argv[index].startswith("-"):
                index += 1 + (argv[index] in _SUDO_VALUE_FLAGS)
            continue
        if base == "env":
            index += 1
            while index < len(argv) and argv[index].startswith("-"):
                index += 1 + (argv[index] in _ENV_VALUE_FLAGS)
            continue
        if base in {"time", "nohup", "exec", "command", "builtin", "stdbuf", "xvfb-run"}:
            index += 1
            while index < len(argv) and argv[index].startswith("-"):
                index += 1
            continue
        if base == "nice":
            index += 1
            if index < len(argv) and argv[index] == "-n":
                index += 2
            continue
        if base == "timeout":
            index += 1
            while index < len(argv) and argv[index].startswith("-"):
                index += 1
            index += 1
            continue
        break
    return argv[index:], assigns


def _program(argv: list[str]) -> tuple[str, list[str]]:
    name = posixpath.basename(argv[0].replace("\\", "/")).lower()
    for suffix in (".exe", ".cmd", ".bat"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    if re.fullmatch(r"python[0-9.]*|py|pypy3?", name):
        index = 1
        while index < len(argv) and argv[index].startswith("-") and argv[index] != "-m":
            index += 1
        if index + 1 < len(argv) and argv[index] == "-m":
            module = argv[index + 1].lower()
            if re.fullmatch(r"pip[0-9.]*", module):
                module = "pip"
            return module, argv[index + 2 :]
        return "python", argv[1:]
    if re.fullmatch(r"pip[0-9.]*", name):
        return "pip", argv[1:]
    return name, argv[1:]


def _positionals(args: list[str], value_flags: frozenset[str]) -> list[str]:
    result: list[str] = []
    skip = False
    after_dashes = False
    for arg in args:
        if skip:
            skip = False
            continue
        if after_dashes:
            result.append(arg)
            continue
        if arg == "--":
            after_dashes = True
            continue
        if arg.startswith("-") and len(arg) > 1:
            if "=" not in arg and arg in value_flags:
                skip = True
            continue
        result.append(arg)
    return result


def _flag_value(args: list[str], *names: str) -> str | None:
    for index, arg in enumerate(args):
        for name in names:
            if arg == name and index + 1 < len(args):
                return args[index + 1]
            if arg.startswith(name + "="):
                return arg.split("=", 1)[1]
    return None


def _resolve(value: str, context: ShellContext) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        return context.env.get(name, match.group(0))

    return _VAR_RE.sub(replace, value)


def _unresolved(value: str) -> bool:
    return PLACEHOLDER in value or "$" in value


def _exact(version: str | None) -> bool:
    if not version:
        return False
    if _unresolved(version):
        return True
    return bool(_EXACT_VERSION_RE.match(version.strip()))


def _npm_spec(spec: str) -> tuple[str, str | None]:
    index = spec.find("@", int(spec.startswith("@")))
    if index > 0:
        return spec[:index], spec[index + 1 :]
    return spec, None


def _local_path(spec: str) -> bool:
    return (
        spec.startswith((".", "/", "~", "file:", "link:", "workspace:"))
        or spec.endswith((".whl", ".tgz", ".tar.gz", ".zip"))
        or ("/" in spec and "://" not in spec and not spec.startswith("@") and "+" not in spec)
        or spec in {PLACEHOLDER}
    )


def _safe_name(raw: str) -> str:
    name = raw
    if "://" in raw:
        target = raw
        if re.match(r"^[a-z]+\+", raw):
            target = raw.split("+", 1)[1]
        name = _url_tool_name(target)
    name = re.sub(r"^[^/@\s]*:[^/@\s]*@", "", name)
    return name[:MAX_NAME_LENGTH]


def _host(url: str | None) -> str:
    if not url:
        return "unknown"
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return "unknown"
    if not host or not _HOST_RE.match(host):
        return "unknown"
    return host


def _url_tool_name(url: str) -> str:
    host = _host(url)
    try:
        path = urlsplit(url).path.rstrip("/")
    except ValueError:
        path = ""
    tail = path.rsplit("/", 1)[-1]
    if PLACEHOLDER in tail or "$" in tail or not tail:
        return host[:MAX_NAME_LENGTH]
    return f"{host}/{tail}"[:MAX_NAME_LENGTH]


def _first_url(args: list[str]) -> str | None:
    url_flag = _flag_value(args, "--url", "-Uri", "-uri")
    if url_flag:
        return url_flag
    for arg in args:
        match = _URL_RE.match(arg)
        if match:
            return match.group(0)
    return None


def _curl_output(args: list[str], url: str | None) -> str | None:
    for index, arg in enumerate(args):
        if arg in {"-o", "--output"} and index + 1 < len(args):
            return args[index + 1]
        if arg.startswith("--output="):
            return arg.split("=", 1)[1]
        if arg in {"-O", "--remote-name"}:
            return _remote_name(url)
        if arg.startswith("-") and not arg.startswith("--") and len(arg) > 1:
            cluster = arg[1:]
            if cluster.endswith("o") and index + 1 < len(args):
                return args[index + 1]
            if "O" in cluster:
                return _remote_name(url)
    return None


def _wget_output(args: list[str], url: str | None) -> str | None:
    for index, arg in enumerate(args):
        if arg in {"-O", "--output-document"} and index + 1 < len(args):
            return args[index + 1]
        if arg.startswith("--output-document="):
            return arg.split("=", 1)[1]
        if arg.startswith("-") and not arg.startswith("--") and "O" in arg[1:]:
            rest = arg[arg.index("O") + 1 :]
            if rest:
                return rest
            if index + 1 < len(args):
                return args[index + 1]
    prefix = _flag_value(args, "-P", "--directory-prefix")
    name = _remote_name(url)
    if prefix and name:
        return posixpath.join(prefix, name)
    return name


def _remote_name(url: str | None) -> str | None:
    if not url:
        return None
    try:
        path = urlsplit(url).path
    except ValueError:
        return None
    name = path.rstrip("/").rsplit("/", 1)[-1]
    return name or None


def _reads_stdin(program: str, args: list[str]) -> bool:
    if program in {"iex", "invoke-expression"}:
        return True
    if any(arg in {"-c", "-e", "--eval", "-Command"} for arg in args):
        return False
    if "-s" in args or "-" in args:
        return True
    positionals = [arg for arg in args if not arg.startswith("-")]
    return not positionals


def _tar_extracts(args: list[str]) -> bool:
    if not args:
        return False
    if "--extract" in args or "--get" in args:
        return True
    first = args[0]
    if not first.startswith("-") and "x" in first:
        return True
    return any(arg.startswith("-") and not arg.startswith("--") and "x" in arg for arg in args)


def _tar_file(args: list[str]) -> str | None:
    value = _flag_value(args, "--file")
    if value:
        return value
    for index, arg in enumerate(args):
        cluster = arg.lstrip("-")
        is_cluster = arg.startswith("-") and not arg.startswith("--") or (index == 0 and "x" in arg)
        if is_cluster and "f" in cluster:
            rest = cluster[cluster.index("f") + 1 :]
            if rest:
                return rest
            if index + 1 < len(args):
                return args[index + 1]
    for arg in args:
        if arg.endswith(_ARCHIVE_SUFFIXES):
            return arg
    return None


def _tar_directory(args: list[str]) -> str | None:
    return _flag_value(args, "-C", "--directory")


def _npm(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    positionals = _positionals(args, _NPM_VALUE_FLAGS)
    if not positionals:
        return
    sub, rest = positionals[0], positionals[1:]
    line = command.line
    ignore = scanner.ignore_scripts(args, assigns)
    global_install = (
        any(arg in {"-g", "--global", "--location=global"} for arg in args)
        or _flag_value(args, "--location") == "global"
    )
    if sub in {"ci", "clean-install", "install-clean", "ic", "isntall-clean"}:
        scanner.add_install("npm", "npm", "frozen", ignore, line)
    elif sub in {"install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isntall", "add"}:
        _package_installs(scanner, "npm", rest, global_install, ignore, line)
    elif sub in {"update", "up", "upgrade", "udpate"}:
        scanner.add_install("npm", "npm", "install", ignore, line)
    elif sub in {"exec", "x"}:
        _npx(scanner, args[args.index(sub) + 1 :], command, depth, remote=False)
    elif sub == "publish" or (sub == "stage" and rest[:1] == ["publish"]):
        if "--dry-run" not in args:
            label = "npm publish"
            if sub == "stage":
                label = "npm stage publish"
            scanner.add_publish("npm", label, line, provenance="--provenance" in args)
    elif sub in {"run", "run-script", "rr", "urn"} and rest:
        scanner.run_script(rest[0], command, depth)


def _package_installs(
    scanner: _Scanner,
    manager: str,
    specs: list[str],
    global_install: bool,
    ignore: bool,
    line: int,
) -> None:
    named = [spec for spec in specs if not _local_path(spec)]
    if global_install:
        scanner.add_install("npm", manager, "global", ignore, line)
    elif named:
        scanner.add_install("npm", manager, "add", ignore, line)
    else:
        scanner.add_install("npm", manager, "install", ignore, line)
    for spec in named:
        resolved = _resolve(spec, scanner.context)
        name, version = _npm_spec(resolved)
        scanner.add_tool(name, "npm", _exact(version), line)


def _npx(
    scanner: _Scanner,
    args: list[str],
    command: _Command,
    depth: int,
    *,
    remote: bool,
) -> None:
    package = _flag_value(args, "-p", "--package")
    positionals = _positionals(args, _NPM_VALUE_FLAGS)
    if not positionals and not package:
        return
    binary_spec = (positionals or [package or ""])[0]
    spec = package or binary_spec
    name, version = _npm_spec(_resolve(spec, scanner.context))
    binary, _ = _npm_spec(binary_spec)
    if remote or not scanner.local_binary(binary):
        scanner.add_tool(name, "npm", _exact(version), command.line)
    if positionals:
        _classify_binary(scanner, [binary, *positionals[1:]], command, depth)


def _classify_binary(scanner: _Scanner, argv: list[str], command: _Command, depth: int) -> None:
    if depth >= MAX_DEPTH:
        return
    nested = _Command(argv, command.line, command.raw)
    scanner._command(nested, argv, {}, depth + 1)


def _pnpm(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    positionals = _positionals(args, _NPM_VALUE_FLAGS)
    if not positionals:
        return
    sub, rest = positionals[0], positionals[1:]
    line = command.line
    ignore = scanner.ignore_scripts(args, assigns)
    if sub in {"recursive", "m", "multi"} and rest:
        sub, rest = rest[0], rest[1:]
    if sub in {"install", "i"}:
        if rest:
            _package_installs(scanner, "pnpm", rest, False, ignore, line)
        elif "--no-frozen-lockfile" in args or "--fix-lockfile" in args:
            scanner.add_install("npm", "pnpm", "install", ignore, line)
        else:
            scanner.add_install("npm", "pnpm", "frozen", ignore, line)
    elif sub == "fetch":
        scanner.add_install("npm", "pnpm", "frozen", ignore, line)
    elif sub == "add":
        _package_installs(scanner, "pnpm", rest, "-g" in args or "--global" in args, ignore, line)
    elif sub in {"update", "up", "upgrade"}:
        scanner.add_install("npm", "pnpm", "install", ignore, line)
    elif sub == "dlx":
        _npx(scanner, args[args.index("dlx") + 1 :], command, depth, remote=True)
    elif sub == "exec":
        _classify_binary(scanner, rest, command, depth)
    elif sub == "publish":
        if "--dry-run" not in args:
            scanner.add_publish("npm", "pnpm publish", line, provenance="--provenance" in args)
    elif sub in {"run", "run-script"} and rest:
        scanner.run_script(rest[0], command, depth)
    elif sub in scanner.context.scripts:
        scanner.run_script(sub, command, depth)
    elif sub not in {"store", "config", "env", "setup", "version", "list", "ls", "why", "audit"}:
        _classify_binary(scanner, [sub, *rest], command, depth)


def _yarn(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    positionals = _positionals(args, _NPM_VALUE_FLAGS)
    line = command.line
    ignore = scanner.ignore_scripts(args, assigns)
    if not positionals or positionals[0] == "install":
        frozen = (
            "--frozen-lockfile" in args
            or "--immutable" in args
            or (scanner.context.yarn_berry and "--no-immutable" not in args)
        )
        kind = "install"
        if frozen:
            kind = "frozen"
        scanner.add_install("npm", "yarn", kind, ignore, line)
        return
    sub, rest = positionals[0], positionals[1:]
    if sub == "add":
        _package_installs(scanner, "yarn", rest, False, ignore, line)
    elif sub == "global" and rest[:1] == ["add"]:
        _package_installs(scanner, "yarn", rest[1:], True, ignore, line)
    elif sub == "dlx":
        _npx(scanner, args[args.index("dlx") + 1 :], command, depth, remote=True)
    elif sub == "npm" and rest[:1] == ["publish"]:
        if "--dry-run" not in args:
            scanner.add_publish("npm", "yarn npm publish", line, provenance="--provenance" in args)
    elif sub == "publish":
        scanner.add_publish("npm", "yarn publish", line)
    elif sub == "workspaces" and "publish" in rest:
        index = rest.index("publish")
        if index > 0 and rest[index - 1] == "npm" and "--dry-run" not in args:
            scanner.add_publish("npm", "yarn npm publish", line)
    elif sub == "run" and rest:
        scanner.run_script(rest[0], command, depth)
    elif sub == "exec":
        _classify_binary(scanner, rest, command, depth)
    elif sub in scanner.context.scripts:
        scanner.run_script(sub, command, depth)
    elif sub not in {"config", "version", "set", "plugin", "cache", "info", "why"}:
        _classify_binary(scanner, [sub, *rest], command, depth)


def _bun(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    positionals = _positionals(args, _NPM_VALUE_FLAGS)
    if not positionals:
        return
    sub, rest = positionals[0], positionals[1:]
    line = command.line
    ignore = scanner.ignore_scripts(args, assigns)
    if sub in {"install", "i"}:
        if rest:
            _package_installs(
                scanner, "bun", rest, "-g" in args or "--global" in args, ignore, line
            )
        else:
            kind = "install"
            if "--frozen-lockfile" in args:
                kind = "frozen"
            scanner.add_install("npm", "bun", kind, ignore, line)
    elif sub == "ci":
        scanner.add_install("npm", "bun", "frozen", ignore, line)
    elif sub in {"add", "a"}:
        _package_installs(scanner, "bun", rest, "-g" in args or "--global" in args, ignore, line)
    elif sub == "x":
        _npx(scanner, args[args.index("x") + 1 :], command, depth, remote=False)
    elif sub == "publish":
        if "--dry-run" not in args:
            scanner.add_publish("npm", "bun publish", line)
    elif sub == "run" and rest:
        scanner.run_script(rest[0], command, depth)
    elif sub in scanner.context.scripts:
        scanner.run_script(sub, command, depth)


def _npx_command(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    _npx(scanner, args, command, depth, remote=False)


def _pip(
    scanner: _Scanner,
    args: list[str],
    command: _Command,
    assigns: dict[str, str],
    depth: int,
    *,
    manager: str = "pip",
) -> None:
    positionals = _positionals(args, _PIP_VALUE_FLAGS)
    if not positionals:
        return
    sub = positionals[0]
    line = command.line
    if sub == "sync":
        scanner.add_install("pypi", manager, "frozen", False, line)
        return
    if sub != "install":
        return
    hashed = "--require-hashes" in args or any(arg.startswith("--hash") for arg in args)
    requirement = _flag_value(args, "-r", "--requirement")
    specs = [spec for spec in positionals[1:] if not _local_path(spec)]
    if requirement or len(positionals) > len(specs) + 1 or _flag_value(args, "-e", "--editable"):
        kind = "install"
        if hashed:
            kind = "frozen"
        scanner.add_install("pypi", manager, kind, False, line)
    if specs:
        scanner.add_install("pypi", manager, "add", False, line)
    for spec in specs:
        resolved = _resolve(spec, scanner.context)
        match = _PIP_SPEC_RE.match(resolved)
        if "://" in resolved or match is None:
            pinned = bool(re.search(r"@[0-9a-f]{40}\b", resolved)) or hashed
            scanner.add_tool(resolved, "pip", pinned, line)
            continue
        operator, version = match.group(3), match.group(4)
        pinned = hashed or (
            operator in {"==", "==="}
            and bool(version)
            and "*" not in version
            and "," not in version
        )
        if version and _unresolved(version) and operator in {"==", "==="}:
            pinned = True
        scanner.add_tool(match.group(1), "pip", pinned, line)


def _uv(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    positionals = _positionals(args, _PIP_VALUE_FLAGS)
    if not positionals:
        return
    sub, rest = positionals[0], positionals[1:]
    line = command.line
    if sub == "pip":
        _pip(scanner, args[args.index("pip") + 1 :], command, assigns, depth, manager="uv")
    elif sub == "sync":
        kind = "install"
        if "--locked" in args or "--frozen" in args:
            kind = "frozen"
        scanner.add_install("pypi", "uv", kind, False, line)
    elif sub == "add":
        scanner.add_install("pypi", "uv", "add", False, line)
    elif sub == "tool" and rest[:1] in (["install"], ["run"]):
        if rest[1:]:
            _uvx_spec(scanner, rest[1], line)
    elif sub == "publish":
        scanner.add_publish("pypi", "uv publish", line)
        if _flag_value(args, "--token", "-t") or _flag_value(args, "--password", "-p"):
            scanner.facts.credentials.append(Credential("pypi", "--token", line))
    elif sub == "run":
        tail = args[args.index("run") + 1 :]
        with_spec = _flag_value(tail, "--with")
        if with_spec:
            _uvx_spec(scanner, with_spec, line)
        tail_positionals = _positionals(tail, _PIP_VALUE_FLAGS)
        if tail_positionals:
            _classify_binary(scanner, tail_positionals, command, depth)


def _uvx_spec(scanner: _Scanner, spec: str, line: int) -> None:
    resolved = _resolve(spec, scanner.context)
    if "@" in resolved and "==" not in resolved:
        name, version = resolved.split("@", 1)
        scanner.add_tool(name, "pip", _exact(version), line)
        return
    match = _PIP_SPEC_RE.match(resolved)
    if match is None:
        scanner.add_tool(resolved, "pip", False, line)
        return
    scanner.add_tool(
        match.group(1), "pip", match.group(3) in {"==", "==="} and bool(match.group(4)), line
    )


def _uvx(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    source = _flag_value(args, "--from")
    positionals = _positionals(args, _PIP_VALUE_FLAGS)
    if source:
        _uvx_spec(scanner, source, command.line)
    elif positionals:
        _uvx_spec(scanner, positionals[0], command.line)


def _pipx(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    positionals = _positionals(args, _PIP_VALUE_FLAGS)
    if len(positionals) < 2 or positionals[0] not in {"install", "run", "upgrade", "inject"}:
        return
    spec = _flag_value(args, "--spec") or positionals[1]
    _uvx_spec(scanner, spec, command.line)


def _poetry(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    positionals = _positionals(
        args,
        frozenset(
            {
                "-C",
                "--directory",
                "-P",
                "--project",
                "--with",
                "--without",
                "--only",
                "-E",
                "--extras",
                "-r",
                "--repository",
                "-u",
                "--username",
                "-p",
                "--password",
            }
        ),
    )
    if not positionals:
        return
    sub = positionals[0]
    line = command.line
    if sub in {"install", "sync"}:
        scanner.add_install("pypi", "poetry", "install", False, line)
    elif sub == "add":
        scanner.add_install("pypi", "poetry", "add", False, line)
    elif sub == "self" and positionals[1:2] == ["add"]:
        for spec in positionals[2:]:
            _uvx_spec(scanner, spec, line)
    elif sub == "publish" and "--dry-run" not in args:
        scanner.add_publish("pypi", "poetry publish", line)
        if _flag_value(args, "-p", "--password"):
            scanner.facts.credentials.append(Credential("pypi", "--password", line))
    elif sub == "config" and any("pypi-token" in arg or "http-basic" in arg for arg in positionals):
        scanner.facts.credentials.append(Credential("pypi", "poetry config", line))


def _twine(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    if not args or args[0] != "upload":
        return
    scanner.add_publish("pypi", "twine upload", command.line)
    if _flag_value(args, "-p", "--password"):
        scanner.facts.credentials.append(Credential("pypi", "--password", command.line))


def _simple_publisher(registry: str, label: str, verbs: frozenset[str]) -> object:
    def handler(
        scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
    ) -> None:
        positionals = _positionals(
            args,
            frozenset(
                {
                    "-r",
                    "--repository",
                    "--token",
                    "--registry",
                    "-k",
                    "--key",
                    "-s",
                    "--source",
                    "--api-key",
                }
            ),
        )
        if positionals[:1] and positionals[0] in verbs and "--dry-run" not in args:
            scanner.add_publish(registry, f"{label} {positionals[0]}", command.line)

    return handler


def _changeset(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    if _positionals(args, frozenset({"--tag", "--otp"}))[:1] == ["publish"]:
        scanner.add_publish("npm", "changeset publish", command.line)


def _lerna(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    if _positionals(args, frozenset())[:1] == ["publish"]:
        scanner.add_publish("npm", "lerna publish", command.line)


def _release_tool(name: str) -> object:
    def handler(
        scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
    ) -> None:
        if "--dry-run" not in args and "-d" not in args:
            scanner.add_publish("npm", name, command.line)

    return handler


def _nx(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    positionals = _positionals(args, frozenset({"--projects", "-p", "--groups", "-g"}))
    if positionals[:1] != ["release"] or "--dry-run" in args or "-d" in args:
        return
    if (
        positionals[1:2] == ["publish"]
        or (len(positionals) == 1 or positionals[1] not in {"version", "changelog", "plan"})
        and "--skip-publish" not in args
    ):
        scanner.add_publish("npm", "nx release", command.line)


def _apt(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    positionals = _positionals(args, frozenset({"-o", "-c", "-t", "--target-release"}))
    if not positionals or positionals[0] != "install":
        return
    for spec in positionals[1:]:
        if spec.endswith(".deb") or spec.startswith(("./", "/")):
            scanner.facts.executions.append(Execution(spec, scanner.order()))
            continue
        name, _, version = spec.partition("=")
        scanner.add_tool(name, "apt", bool(version), command.line)


def _brew(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    positionals = _positionals(args, frozenset())
    if positionals[:1] in (["install"], ["reinstall"], ["upgrade"]):
        for spec in positionals[1:]:
            scanner.add_tool(spec, "brew", False, command.line)


def _other_installer(manager: str, verbs: frozenset[str], separator: str | None) -> object:
    def handler(
        scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
    ) -> None:
        positionals = _positionals(
            args,
            frozenset(
                {
                    "--version",
                    "-v",
                    "--repository",
                    "-X",
                    "--root",
                    "--source",
                    "--index",
                    "--registry",
                }
            ),
        )
        if not positionals or positionals[0] not in verbs:
            return
        version_flag = _flag_value(args, "--version", "-v", "--vers")
        for spec in positionals[1:]:
            if spec.startswith((".", "/")):
                continue
            pinned = bool(version_flag)
            name = spec
            if separator and separator in spec:
                name, _, version = spec.partition(separator)
                pinned = pinned or (
                    bool(version) and version.lower() not in {"latest", "master", "main", "head"}
                )
            scanner.add_other_tool(name, manager, pinned, command.line)

    return handler


def _go(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    positionals = _positionals(args, frozenset({"-C", "-ldflags", "-tags", "-o"}))
    if positionals[:1] != ["install"]:
        return
    for spec in positionals[1:]:
        if spec.startswith((".", "/")):
            continue
        name, _, version = spec.partition("@")
        pinned = bool(version) and version.lower() not in {"latest", "master", "main", "head"}
        scanner.add_other_tool(name, "go", pinned, command.line)


def _curl(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    if any(
        arg in _UPLOAD_FLAGS or arg.startswith(("--data", "--form", "--upload")) for arg in args
    ):
        return
    url = _first_url(args)
    if url is None:
        return
    output = _curl_output(args, url) or command.stdout
    output_dir = _flag_value(args, "--output-dir")
    if output and output_dir and not output.startswith("/"):
        output = posixpath.join(output_dir, output)
    if not output or output == "-" or output.startswith("/dev/"):
        return
    scanner.facts.downloads.append(
        Download(_host(url), command.line, target=output, order=scanner.order())
    )


def _wget(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    url = _first_url(args)
    if url is None or any(arg.startswith("--post") for arg in args):
        return
    output = _wget_output(args, url)
    if command.stdout and output in {None, "-"}:
        output = command.stdout
    if not output or output == "-" or output.startswith("/dev/"):
        return
    scanner.facts.downloads.append(
        Download(_host(url), command.line, target=output, order=scanner.order())
    )


def _gh(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    if args[:2] == ["release", "download"]:
        target = _flag_value(args, "-O", "--output") or _flag_value(args, "-p", "--pattern")
        directory = _flag_value(args, "-D", "--dir")
        if target and directory:
            target = posixpath.join(directory, target)
        scanner.facts.downloads.append(
            Download(
                "github.com", command.line, target=target or directory or ".", order=scanner.order()
            )
        )
    elif args[:2] == ["attestation", "verify"]:
        scanner.facts.verifications.append(Verification(command.raw, command.line, scanner.order()))


def _web_request(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    url = _first_url(args)
    output = _flag_value(args, "-OutFile", "-outfile", "-o")
    if url and output:
        scanner.facts.downloads.append(
            Download(_host(url), command.line, target=output, order=scanner.order())
        )


def _tar(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    if _tar_extracts(args):
        scanner.facts.extracts.append(
            Extract(_tar_file(args), _tar_directory(args) or ".", command.line, scanner.order())
        )


def _unzip(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    positionals = _positionals(args, frozenset({"-d", "-x"}))
    if positionals:
        directory = _flag_value(args, "-d") or "."
        scanner.facts.extracts.append(
            Extract(positionals[0], directory, command.line, scanner.order())
        )


def _move(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    positionals = _positionals(args, frozenset({"-t", "--target-directory", "-S", "--suffix"}))
    if len(positionals) >= 2:
        order = scanner.order()
        for source in positionals[:-1]:
            scanner.facts.moves.append(Move(source, positionals[-1], command.line, order))


def _install_command(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    positionals = _positionals(
        args, frozenset({"-m", "--mode", "-o", "--owner", "-g", "--group", "-t"})
    )
    for source in positionals[:-1]:
        scanner.facts.executions.append(Execution(source, scanner.order()))


def _remove(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    paths = _positionals(args, frozenset())
    if paths:
        scanner.facts.removals.append(Removal(paths, scanner.order()))


def _chmod(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    positionals = _positionals(args, frozenset())
    if len(positionals) >= 2 and (
        "x" in positionals[0] or positionals[0][-1:] in {"5", "7", "1", "3"}
    ):
        for path in positionals[1:]:
            scanner.facts.executions.append(Execution(path, scanner.order()))


def _run_file(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    positionals = [arg for arg in args if not arg.startswith("-")]
    if positionals and not any(arg in {"-c", "-e", "--eval"} for arg in args):
        scanner.facts.executions.append(Execution(positionals[0], scanner.order()))


def _package_file_installer(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    for arg in args:
        if not arg.startswith("-"):
            scanner.facts.executions.append(Execution(arg, scanner.order()))


def _signature(program: str) -> object:
    def handler(
        scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
    ) -> None:
        for name, flag in _SIGNATURE_COMMANDS:
            if name == program and (flag is None or flag in args):
                scanner.facts.verifications.append(
                    Verification(command.raw, command.line, scanner.order())
                )
                return

    return handler


_HANDLERS: dict[str, object] = {
    "npm": _npm,
    "pnpm": _pnpm,
    "yarn": _yarn,
    "bun": _bun,
    "npx": _npx_command,
    "bunx": _npx_command,
    "pip": _pip,
    "uv": _uv,
    "uvx": _uvx,
    "pipx": _pipx,
    "poetry": _poetry,
    "twine": _twine,
    "flit": _simple_publisher("pypi", "flit", frozenset({"publish"})),
    "hatch": _simple_publisher("pypi", "hatch", frozenset({"publish"})),
    "pdm": _simple_publisher("pypi", "pdm", frozenset({"publish"})),
    "maturin": _simple_publisher("pypi", "maturin", frozenset({"publish", "upload"})),
    "cargo": _simple_publisher("other", "cargo", frozenset({"publish"})),
    "gem": _simple_publisher("other", "gem", frozenset({"push"})),
    "nuget": _simple_publisher("other", "nuget", frozenset({"push"})),
    "changeset": _changeset,
    "lerna": _lerna,
    "semantic-release": _release_tool("semantic-release"),
    "release-it": _release_tool("release-it"),
    "nx": _nx,
    "apt": _apt,
    "apt-get": _apt,
    "aptitude": _apt,
    "brew": _brew,
    "apk": _other_installer("apk", frozenset({"add"}), "="),
    "yum": _other_installer("yum", frozenset({"install"}), "-"),
    "dnf": _other_installer("dnf", frozenset({"install"}), None),
    "choco": _other_installer("choco", frozenset({"install"}), None),
    "snap": _other_installer("snap", frozenset({"install"}), None),
    "go": _go,
    "gem-install": _other_installer("gem", frozenset({"install"}), ":"),
    "dotnet": _other_installer("dotnet", frozenset({"tool"}), None),
    "curl": _curl,
    "wget": _wget,
    "gh": _gh,
    "invoke-webrequest": _web_request,
    "iwr": _web_request,
    "tar": _tar,
    "unzip": _unzip,
    "mv": _move,
    "cp": _move,
    "install": _install_command,
    "rm": _remove,
    "chmod": _chmod,
    "sh": _run_file,
    "bash": _run_file,
    "python": _run_file,
    "node": _run_file,
    "dpkg": _package_file_installer,
    "rpm": _package_file_installer,
    "gpg": _signature("gpg"),
    "gpgv": _signature("gpgv"),
    "cosign": _signature("cosign"),
    "slsa-verifier": _signature("slsa-verifier"),
    "minisign": _signature("minisign"),
}


def _gem(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    positionals = _positionals(args, frozenset({"--key", "-k", "--host"}))
    if positionals[:1] == ["push"]:
        if "--dry-run" not in args:
            scanner.add_publish("other", "gem push", command.line)
        return
    _HANDLERS["gem-install"](scanner, args, command, assigns, depth)


def _cargo(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    positionals = _positionals(
        args,
        frozenset({"--token", "--registry", "--version", "--vers", "--root", "-p", "--package"}),
    )
    if positionals[:1] == ["publish"]:
        if "--dry-run" not in args:
            scanner.add_publish("other", "cargo publish", command.line)
        if _flag_value(args, "--token"):
            scanner.facts.credentials.append(Credential("other", "--token", command.line))
        return
    if positionals[:1] in (["install"], ["binstall"]):
        version = _flag_value(args, "--version", "--vers")
        for spec in positionals[1:]:
            name, _, at_version = spec.partition("@")
            scanner.add_other_tool(name, "cargo", bool(version or at_version), command.line)


def _dotnet(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    positionals = _positionals(args, frozenset({"--version", "-k", "--api-key", "-s", "--source"}))
    if positionals[:2] == ["nuget", "push"]:
        scanner.add_publish("other", "dotnet nuget push", command.line)
    elif positionals[:2] == ["tool", "install"]:
        version = _flag_value(args, "--version")
        for spec in positionals[2:]:
            scanner.add_other_tool(spec, "dotnet", bool(version), command.line)


def _container_run(
    scanner: _Scanner, args: list[str], command: _Command, assigns: dict[str, str], depth: int
) -> None:
    """``docker run IMAGE`` / ``podman container run IMAGE``: the image runs with the job's
    environment and workspace, so it is a tool of the job."""
    index = 0
    while index < len(args) and args[index].startswith("-"):
        skip = "=" not in args[index] and args[index] in _DOCKER_VALUE_FLAGS
        index += 1 + int(skip)
    if args[index : index + 2] == ["container", "run"]:
        index += 2
    elif args[index : index + 1] == ["run"]:
        index += 1
    else:
        return
    while index < len(args):
        arg = args[index]
        if arg == "--":
            index += 1
            break
        if not arg.startswith("-"):
            break
        skip = "=" not in arg and arg in DOCKER_RUN_VALUE_FLAGS
        index += 1 + int(skip)
    if index >= len(args) or PLACEHOLDER in args[index]:
        return
    image = image_reference(args[index])
    if image is not None:
        scanner.facts.other_tools.append(
            Tool(
                image,
                "docker_run",
                image_pinned(image),
                command.line,
                manager="docker_run",
                order=scanner.order(),
            )
        )


_HANDLERS["gem"] = _gem
_HANDLERS["cargo"] = _cargo
_HANDLERS["dotnet"] = _dotnet
_HANDLERS["docker"] = _container_run
_HANDLERS["podman"] = _container_run


def is_archive(path: str | None) -> bool:
    return bool(path) and str(path).lower().endswith(_ARCHIVE_SUFFIXES)


def in_bin_dir(path: str | None) -> bool:
    return bool(path) and bool(_BIN_DIR_RE.search(str(path)))
