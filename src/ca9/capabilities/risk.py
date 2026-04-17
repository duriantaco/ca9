from __future__ import annotations

import re

from ca9.capabilities.models import AssetChange, CapabilityChange, CapabilityHit, Risk

SENSITIVE_PATHS = [
    r"/etc/.*",
    r"/\.ssh/.*",
    r".*\.pem$",
    r"/var/run/.*",
    r"^/\*\*$",
]


def assess_risk(
    assets_added: list[AssetChange],
    assets_changed: list[AssetChange],
    capabilities_added: list[CapabilityChange],
    capabilities_widened: list[CapabilityChange],
) -> Risk:
    level = "low"
    reasons: list[str] = []

    for cap in capabilities_added:
        if cap.capability == "exec.shell":
            level = upgrade_risk_level(level, "high")
            reasons.append("Shell execution capability added")
        if cap.capability == "db.write":
            level = upgrade_risk_level(level, "high")
            reasons.append("Database write capability added")
        if cap.capability == "filesystem.write":
            if is_sensitive_scope(cap.scope):
                level = upgrade_risk_level(level, "high")
                reasons.append(f"Filesystem write to sensitive path added: {cap.scope}")
            else:
                level = upgrade_risk_level(level, "medium")
                reasons.append(f"Filesystem write capability added: {cap.scope}")
        if cap.capability == "network.egress":
            level = upgrade_risk_level(level, "medium")
            reasons.append(f"New network egress to {cap.scope}")

    for cap in capabilities_widened:
        if cap.capability in ("filesystem.read", "filesystem.write"):
            if is_sensitive_scope(cap.to_scope or ""):
                level = upgrade_risk_level(level, "high")
                reasons.append(
                    f"{cap.capability} widened to sensitive path: {cap.from_scope} -> {cap.to_scope}"
                )
            else:
                level = upgrade_risk_level(level, "medium")
                reasons.append(
                    f"{cap.capability} scope widened: {cap.from_scope} -> {cap.to_scope}"
                )

    for asset in assets_changed:
        if asset.kind == "prompt" and "system" in asset.id.lower():
            level = upgrade_risk_level(level, "medium")
            reasons.append(f"System prompt modified: {asset.id}")

    for asset in assets_added:
        if asset.kind == "agent_framework":
            level = upgrade_risk_level(level, "medium")
            reasons.append(f"New agent framework added: {asset.id}")
        if asset.kind == "mcp_server":
            level = upgrade_risk_level(level, "medium")
            reasons.append(f"New MCP server added: {asset.id}")

    has_exec = any(c.capability == "exec.shell" for c in capabilities_added)
    has_broad_fs_write = any(
        c.capability == "filesystem.write" and is_sensitive_scope(c.scope)
        for c in capabilities_added
    )
    has_egress = any(c.capability == "network.egress" for c in capabilities_added)

    if has_exec and has_broad_fs_write:
        level = "critical"
        reasons.append("CRITICAL: Shell execution combined with broad filesystem write access")
    if has_broad_fs_write and has_egress:
        level = upgrade_risk_level(level, "critical")
        reasons.append("CRITICAL: Sensitive filesystem access combined with network egress")

    return Risk(level=level, reasons=list(dict.fromkeys(reasons)))


def assess_blast_radius_risk(hits: list[CapabilityHit]) -> Risk:
    level = "low"
    reasons: list[str] = []
    cap_names = {h.name for h in hits}

    if "exec.shell" in cap_names:
        level = upgrade_risk_level(level, "high")
        reasons.append("Attacker gains shell execution")
    if "db.write" in cap_names:
        level = upgrade_risk_level(level, "high")
        reasons.append("Attacker gains database write access")
    if "db.read" in cap_names:
        level = upgrade_risk_level(level, "medium")
        reasons.append("Attacker gains database read access")
    if "filesystem.write" in cap_names:
        sensitive = any(is_sensitive_scope(h.scope) for h in hits if h.name == "filesystem.write")
        if sensitive:
            level = upgrade_risk_level(level, "high")
            reasons.append("Attacker gains filesystem write to sensitive paths")
        else:
            level = upgrade_risk_level(level, "medium")
            reasons.append("Attacker gains filesystem write access")
    if "network.egress" in cap_names:
        level = upgrade_risk_level(level, "medium")
        reasons.append("Attacker gains network egress (data exfiltration risk)")
    for name in cap_names:
        if name.startswith("storage.") and name.endswith(".write"):
            level = upgrade_risk_level(level, "medium")
            reasons.append(f"Attacker gains cloud storage write ({name})")
        if name.startswith("storage.") and name.endswith(".read"):
            if "network.egress" in cap_names:
                level = upgrade_risk_level(level, "high")
                reasons.append(f"Cloud storage read ({name}) + network egress = exfiltration risk")

    if "filesystem.read" in cap_names and "network.egress" in cap_names:
        level = upgrade_risk_level(level, "high")
        reasons.append("Filesystem read + network egress = exfiltration risk")
    if "db.read" in cap_names and "network.egress" in cap_names:
        level = upgrade_risk_level(level, "high")
        reasons.append("Database read + network egress = data exfiltration risk")
    if "db.write" in cap_names and "network.egress" in cap_names:
        level = upgrade_risk_level(level, "critical")
        reasons.append("CRITICAL: Database write + network egress = remote data manipulation")

    if "exec.shell" in cap_names and any(
        h.name == "filesystem.write" and is_sensitive_scope(h.scope) for h in hits
    ):
        level = "critical"
        reasons.append("CRITICAL: Shell + sensitive filesystem write")
    if "exec.shell" in cap_names and "network.egress" in cap_names:
        level = upgrade_risk_level(level, "critical")
        reasons.append("CRITICAL: Shell execution + network egress = full remote control")

    return Risk(level=level, reasons=list(dict.fromkeys(reasons)))


def upgrade_risk_level(current: str, new: str) -> str:
    levels = ["low", "medium", "high", "critical"]
    current_idx = levels.index(current) if current in levels else 0
    new_idx = levels.index(new) if new in levels else 0
    return levels[max(current_idx, new_idx)]


def is_sensitive_scope(scope: str) -> bool:
    return any(re.match(pattern, scope) for pattern in SENSITIVE_PATHS)
