from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from ca9.core.models import Decision, Finding, Inventory


@dataclass(frozen=True)
class PipelineContext:
    repo_path: Path
    policy_path: Path | None = None
    options: dict[str, object] = field(default_factory=dict)


class Reader(Protocol):
    name: str

    def read(self, context: PipelineContext) -> Inventory: ...


class Enricher(Protocol):
    name: str

    def enrich(self, inventory: Inventory, context: PipelineContext) -> dict[str, object]: ...


class Analyzer(Protocol):
    name: str

    def analyze(
        self,
        inventory: Inventory,
        enrichments: dict[str, object],
        context: PipelineContext,
    ) -> list[Finding]: ...


class PolicyEngine(Protocol):
    name: str

    def evaluate(self, findings: list[Finding], context: PipelineContext) -> list[Decision]: ...


class Reporter(Protocol):
    name: str

    def render(
        self,
        inventory: Inventory,
        findings: list[Finding],
        decisions: list[Decision],
        context: PipelineContext,
    ) -> str: ...
