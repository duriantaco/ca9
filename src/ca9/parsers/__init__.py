from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from .dependabot import DependabotParser
from .grype import GrypeParser
from .osv_scanner import OsvScannerParser
from .pip_audit import PipAuditParser
from .snyk import SnykParser
from .trivy import TrivyParser

if TYPE_CHECKING:
    from .base import SCAParser

_PARSERS: list[type[SCAParser]] = [
    SnykParser,
    DependabotParser,
    TrivyParser,
    GrypeParser,
    OsvScannerParser,
    PipAuditParser,
]


def detect_parser(path: Path) -> SCAParser:
    data = json.loads(path.read_text())

    for parser_cls in _PARSERS:
        parser = parser_cls()
        if parser.can_parse(data):
            return parser

    raise ValueError(f"Cannot detect SCA format for {path}")
