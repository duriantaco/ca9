"""What a GitHub Actions ``if:`` condition proves when it evaluates to true.

A condition protects a publish only when its truth implies the run is on one
literal branch (``github.ref == 'refs/heads/<name>'``, or
``startsWith(github.ref, 'refs/heads/')`` together with ``github.ref_name ==
'<name>'``; ``ref_name`` alone also matches a tag of that name) or rules out an
event (``github.event_name == 'push'``, ``github.event_name != 'x'``).
Negation is pushed through the tree, so ``!(github.ref == ...)`` proves nothing
and ``!(github.ref != ...)`` proves the branch. A value that mixes ``${{ }}``
with other text is a non-empty string, which is always true, so it proves
nothing; so does anything that does not parse.
"""

from __future__ import annotations

import re
from typing import Any

BRANCH_REF = ("ref_branch",)
REF_IS_BRANCH = ("ref_is_branch",)
REF_NAME = ("ref_name",)
NOTHING: frozenset[tuple[str, ...]] = frozenset()

_TOKEN_RE = re.compile(
    r"\s+|(?P<string>'(?:[^']|'')*')|(?P<number>\d+(?:\.\d+)?)"
    r"|(?P<operator>==|!=|<=|>=|&&|\|\||[!<>(),.\[\]*])|(?P<name>[A-Za-z_][A-Za-z0-9_-]*)"
)
_BRANCH_PREFIX = "refs/heads/"


class _ParseError(ValueError):
    """The text is not an expression this module understands."""


def condition_facts(condition: object) -> frozenset[tuple[str, ...]]:
    """Facts that must hold whenever ``condition`` is true; empty when nothing is proven."""
    if not isinstance(condition, str):
        return NOTHING
    text = condition.strip()
    if text.startswith("${{") and text.endswith("}}") and text.count("${{") == 1:
        text = text[3:-2]
    elif "${{" in text:
        return NOTHING
    if not text.strip():
        return NOTHING
    try:
        node = _Parser(_tokens(text)).parse()
    except (_ParseError, RecursionError):
        return NOTHING
    return _proven(node)


def blocks(facts: frozenset[tuple[str, ...]], event: str, chooses_ref: bool) -> bool:
    """True when ``facts`` stop a run started by ``event``.

    ``chooses_ref`` marks routes where the starter picks the ref (workflow_dispatch,
    push); for events that always run on the default or base branch a ref check
    proves nothing.
    """
    if ("event_ne", event) in facts:
        return True
    if any(fact[0] == "event_eq" and fact[1] != event for fact in facts):
        return True
    if not chooses_ref:
        return False
    return BRANCH_REF in facts or {REF_IS_BRANCH, REF_NAME} <= facts


def _tokens(text: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    position = 0
    while position < len(text):
        match = _TOKEN_RE.match(text, position)
        if match is None or match.end() == position:
            raise _ParseError(f"unexpected character at {position}")
        position = match.end()
        kind = match.lastgroup
        if kind is not None:
            tokens.append((kind, match.group(kind)))
    return tokens


class _Parser:
    def __init__(self, tokens: list[tuple[str, str]]) -> None:
        self.tokens = tokens
        self.index = 0

    def parse(self) -> Any:
        node = self.either()
        if self.index != len(self.tokens):
            raise _ParseError("trailing tokens")
        return node

    def peek(self) -> str | None:
        if self.index < len(self.tokens):
            return self.tokens[self.index][1]
        return None

    def take(self) -> tuple[str, str]:
        if self.index >= len(self.tokens):
            raise _ParseError("unexpected end")
        token = self.tokens[self.index]
        self.index += 1
        return token

    def expect(self, value: str) -> None:
        if self.take()[1] != value:
            raise _ParseError(f"expected {value}")

    def either(self) -> Any:
        parts = [self.both()]
        while self.peek() == "||":
            self.take()
            parts.append(self.both())
        if len(parts) == 1:
            return parts[0]
        return ("or", parts)

    def both(self) -> Any:
        parts = [self.equality()]
        while self.peek() == "&&":
            self.take()
            parts.append(self.equality())
        if len(parts) == 1:
            return parts[0]
        return ("and", parts)

    def equality(self) -> Any:
        left = self.comparison()
        while self.peek() in {"==", "!="}:
            operator = self.take()[1]
            left = ("compare", operator, left, self.comparison())
        return left

    def comparison(self) -> Any:
        left = self.unary()
        while self.peek() in {"<", "<=", ">", ">="}:
            operator = self.take()[1]
            left = ("compare", operator, left, self.unary())
        return left

    def unary(self) -> Any:
        if self.peek() == "!":
            self.take()
            return ("not", self.unary())
        return self.postfix()

    def postfix(self) -> Any:
        node = self.primary()
        while self.peek() in {".", "["}:
            if self.take()[1] == ".":
                kind, value = self.take()
                if kind != "name" and value != "*":
                    raise _ParseError("expected a property name")
                node = _member(node, value)
            else:
                index = self.either()
                self.expect("]")
                if index[0] == "literal":
                    node = _member(node, index[1])
                else:
                    node = ("other",)
        return node

    def primary(self) -> Any:
        kind, value = self.take()
        if kind == "string":
            return ("literal", value[1:-1].replace("''", "'").lower())
        if kind == "number":
            return ("other",)
        if value == "(":
            node = self.either()
            self.expect(")")
            return node
        if kind != "name":
            raise _ParseError(f"unexpected {value}")
        if self.peek() == "(":
            self.take()
            arguments: list[Any] = []
            if self.peek() != ")":
                arguments.append(self.either())
                while self.peek() == ",":
                    self.take()
                    arguments.append(self.either())
            self.expect(")")
            return ("call", value.lower(), arguments)
        if value.lower() in {"true", "false", "null"}:
            return ("other",)
        return ("path", value.lower())


def _member(node: Any, name: str) -> Any:
    if node[0] != "path":
        return ("other",)
    return ("path", f"{node[1]}.{name.lower()}")


def _proven(node: Any) -> frozenset[tuple[str, ...]]:
    kind = node[0]
    if kind == "and":
        return frozenset().union(*(_proven(part) for part in node[1]))
    if kind == "or":
        return frozenset.intersection(*(_proven(part) for part in node[1]))
    if kind == "not":
        return _refuted(node[1])
    if kind == "compare":
        return _equality(node, negated=False)
    if kind == "call" and node[1] == "startswith" and len(node[2]) == 2:
        subject, prefix = node[2]
        if subject == ("path", "github.ref") and prefix[0] == "literal":
            if prefix[1].startswith(_BRANCH_PREFIX):
                return frozenset({REF_IS_BRANCH})
    return NOTHING


def _refuted(node: Any) -> frozenset[tuple[str, ...]]:
    """Facts that hold whenever ``node`` is false."""
    kind = node[0]
    if kind == "and":
        return frozenset.intersection(*(_refuted(part) for part in node[1]))
    if kind == "or":
        return frozenset().union(*(_refuted(part) for part in node[1]))
    if kind == "not":
        return _proven(node[1])
    if kind == "compare":
        return _equality(node, negated=True)
    return NOTHING


def _equality(node: Any, *, negated: bool) -> frozenset[tuple[str, ...]]:
    _, operator, left, right = node
    if operator not in {"==", "!="}:
        return NOTHING
    pair = _path_and_literal(left, right)
    if pair is None:
        return NOTHING
    path, literal = pair
    equal = (operator == "==") != negated
    if path == "github.event_name":
        if equal:
            return frozenset({("event_eq", literal)})
        return frozenset({("event_ne", literal)})
    if not equal:
        return NOTHING
    if (
        path == "github.ref"
        and literal.startswith(_BRANCH_PREFIX)
        and len(literal) > len(_BRANCH_PREFIX)
    ):
        return frozenset({BRANCH_REF})
    if path == "github.ref_name" and literal:
        return frozenset({REF_NAME})
    return NOTHING


def _path_and_literal(left: Any, right: Any) -> tuple[str, str] | None:
    if left[0] == "path" and right[0] == "literal":
        return left[1], right[1]
    if right[0] == "path" and left[0] == "literal":
        return right[1], left[1]
    return None
