from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ca9.models import Report, Verdict, VerdictResult


@dataclass(frozen=True)
class ServiceContext:
    name: str = ""
    criticality: str = "default"  # critical, high, default, low
    behind_auth: bool = False
    rate_limited: bool = False
    network_isolated: bool = False
    read_only: bool = False
    internal_only: bool = False
    sandbox: bool = False
    extra: dict = field(default_factory=dict)


def load_runtime_context(path: Path) -> ServiceContext:
    data = json.loads(path.read_text())
    return ServiceContext(
        name=data.get("name", ""),
        criticality=data.get("criticality", "default"),
        behind_auth=data.get("behind_auth", False),
        rate_limited=data.get("rate_limited", False),
        network_isolated=data.get("network_isolated", False),
        read_only=data.get("read_only", False),
        internal_only=data.get("internal_only", False),
        sandbox=data.get("sandbox", False),
        extra=data.get("extra", {}),
    )


def _get_blast_radius(result: VerdictResult):
    br = result.blast_radius
    if br is None or not hasattr(br, "capabilities"):
        return None
    return br


def apply_runtime_context(report: Report, ctx: ServiceContext) -> Report:
    for result in report.results:
        _apply_mitigations(result, ctx)
    return report


def _apply_mitigations(result: VerdictResult, ctx: ServiceContext) -> None:
    if result.verdict != Verdict.REACHABLE:
        return

    mitigations: list[str] = []
    br = _get_blast_radius(result)
    caps = set(br.capabilities) if br else set()

    if ctx.network_isolated and "network.egress" in caps:
        mitigations.append(
            "network.egress mitigated: service is network-isolated, "
            "egress capability cannot reach external targets"
        )

    if ctx.behind_auth:
        mitigations.append(
            "attack surface reduced: service requires authentication, "
            "unauthenticated exploitation unlikely"
        )

    if ctx.rate_limited:
        mitigations.append(
            "exploitation difficulty increased: service is rate-limited, "
            "brute-force and high-volume attacks constrained"
        )

    if ctx.read_only and any(c.endswith(".write") or c == "db.write" for c in caps):
        mitigations.append(
            "write capabilities mitigated: service runs in read-only mode, "
            "write operations will fail at runtime"
        )

    if ctx.sandbox and "exec.shell" in caps:
        mitigations.append(
            "exec.shell mitigated: service runs in sandboxed environment, "
            "shell access is restricted"
        )

    if ctx.internal_only:
        mitigations.append(
            "exposure reduced: service is internal-only, not accessible from public networks"
        )

    if not mitigations:
        return

    result.runtime_mitigations = mitigations
    original_reason = result.reason
    mitigation_summary = "; ".join(m.split(":")[0] for m in mitigations)
    result.reason = f"{original_reason} [runtime mitigations: {mitigation_summary}]"

    if ctx.criticality == "low" and len(mitigations) >= 2:
        result.runtime_adjusted_priority = "low"
    elif ctx.criticality == "critical":
        result.runtime_adjusted_priority = "critical"


def runtime_context_to_dict(ctx: ServiceContext) -> dict:
    return {
        "name": ctx.name,
        "criticality": ctx.criticality,
        "behind_auth": ctx.behind_auth,
        "rate_limited": ctx.rate_limited,
        "network_isolated": ctx.network_isolated,
        "read_only": ctx.read_only,
        "internal_only": ctx.internal_only,
        "sandbox": ctx.sandbox,
    }
