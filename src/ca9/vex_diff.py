from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO


@dataclass
class VerdictChange:
    vuln_id: str
    package: str
    version: str
    old_status: str
    new_status: str
    old_justification: str | None = None
    new_justification: str | None = None
    change_type: str = ""

    def to_dict(self) -> dict:
        d: dict = {
            "vuln_id": self.vuln_id,
            "package": self.package,
            "version": self.version,
            "old_status": self.old_status,
            "new_status": self.new_status,
            "change_type": self.change_type,
        }
        if self.old_justification:
            d["old_justification"] = self.old_justification
        if self.new_justification:
            d["new_justification"] = self.new_justification
        return d


@dataclass
class VEXDiff:
    base_timestamp: str
    head_timestamp: str
    became_affected: list[VerdictChange] = field(default_factory=list)
    became_safe: list[VerdictChange] = field(default_factory=list)
    status_changed: list[VerdictChange] = field(default_factory=list)
    new_vulns: list[VerdictChange] = field(default_factory=list)
    removed_vulns: list[VerdictChange] = field(default_factory=list)
    unchanged_count: int = 0

    def to_dict(self) -> dict:
        return {
            "base_timestamp": self.base_timestamp,
            "head_timestamp": self.head_timestamp,
            "summary": {
                "became_affected": len(self.became_affected),
                "became_safe": len(self.became_safe),
                "status_changed": len(self.status_changed),
                "new_vulnerabilities": len(self.new_vulns),
                "removed_vulnerabilities": len(self.removed_vulns),
                "unchanged": self.unchanged_count,
                "requires_attention": len(self.became_affected) + len(self.new_vulns),
            },
            "became_affected": [c.to_dict() for c in self.became_affected],
            "became_safe": [c.to_dict() for c in self.became_safe],
            "status_changed": [c.to_dict() for c in self.status_changed],
            "new_vulnerabilities": [c.to_dict() for c in self.new_vulns],
            "removed_vulnerabilities": [c.to_dict() for c in self.removed_vulns],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @property
    def has_regressions(self) -> bool:
        return len(self.became_affected) > 0 or len(self.new_vulns) > 0


def _statement_key(stmt: dict) -> str:
    vuln_name = stmt.get("vulnerability", {}).get("name", "")
    products = stmt.get("products", [])
    product_id = products[0].get("@id", "") if products else ""
    return f"{vuln_name}|{product_id}"


def _extract_package_info(stmt: dict) -> tuple[str, str]:
    products = stmt.get("products", [])
    if not products:
        return "", ""
    purl = products[0].get("@id", "")
    if "@" in purl:
        name_part, version = purl.rsplit("@", 1)
        name = name_part.split("/")[-1] if "/" in name_part else name_part
        return name, version
    return purl, ""


def compute_vex_diff(base_vex: dict, head_vex: dict) -> VEXDiff:
    base_timestamp = base_vex.get("timestamp", "unknown")
    head_timestamp = head_vex.get("timestamp", "unknown")

    base_stmts = {_statement_key(s): s for s in base_vex.get("statements", [])}
    head_stmts = {_statement_key(s): s for s in head_vex.get("statements", [])}

    diff = VEXDiff(base_timestamp=base_timestamp, head_timestamp=head_timestamp)

    for key, head_stmt in head_stmts.items():
        head_status = head_stmt.get("status", "")
        head_just = head_stmt.get("justification")
        pkg, ver = _extract_package_info(head_stmt)
        vuln_id = head_stmt.get("vulnerability", {}).get("name", "")

        if key not in base_stmts:
            diff.new_vulns.append(
                VerdictChange(
                    vuln_id=vuln_id,
                    package=pkg,
                    version=ver,
                    old_status="",
                    new_status=head_status,
                    new_justification=head_just,
                    change_type="new",
                )
            )
            continue

        base_stmt = base_stmts[key]
        base_status = base_stmt.get("status", "")
        base_just = base_stmt.get("justification")

        if base_status == head_status and base_just == head_just:
            diff.unchanged_count += 1
            continue

        change = VerdictChange(
            vuln_id=vuln_id,
            package=pkg,
            version=ver,
            old_status=base_status,
            new_status=head_status,
            old_justification=base_just,
            new_justification=head_just,
        )

        if base_status == "not_affected" and head_status == "affected":
            change.change_type = "became_affected"
            diff.became_affected.append(change)
        elif base_status == "affected" and head_status == "not_affected":
            change.change_type = "became_safe"
            diff.became_safe.append(change)
        elif base_status == "under_investigation" and head_status == "affected":
            change.change_type = "became_affected"
            diff.became_affected.append(change)
        elif base_status == "affected" and head_status == "under_investigation":
            change.change_type = "status_changed"
            diff.status_changed.append(change)
        else:
            change.change_type = "status_changed"
            diff.status_changed.append(change)

    for key, base_stmt in base_stmts.items():
        if key not in head_stmts:
            base_status = base_stmt.get("status", "")
            pkg, ver = _extract_package_info(base_stmt)
            vuln_id = base_stmt.get("vulnerability", {}).get("name", "")
            diff.removed_vulns.append(
                VerdictChange(
                    vuln_id=vuln_id,
                    package=pkg,
                    version=ver,
                    old_status=base_status,
                    new_status="",
                    change_type="removed",
                )
            )

    return diff


def write_vex_diff(diff: VEXDiff, output: Path | TextIO | None = None) -> str:
    text = diff.to_json()
    if isinstance(output, Path):
        output.write_text(text)
    elif output is not None:
        output.write(text)
    return text
