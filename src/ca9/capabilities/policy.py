from __future__ import annotations

import os
import re
from typing import Any


def evaluate_policy(diff_data: dict[str, Any], policy_path: str) -> dict[str, Any]:
    try:
        import yaml
    except ImportError:
        return {
            "decision": "error",
            "triggered_rules": [],
            "error": "PyYAML is required for policy evaluation. Install with: pip install pyyaml",
        }

    with open(policy_path) as f:
        policy = yaml.safe_load(f)

    validate_policy(policy)

    triggered_rules: list[dict[str, str]] = []
    for rule in policy.get("rules", []):
        if _evaluate_rule(rule, diff_data):
            triggered_rules.append(
                {"id": rule["id"], "action": rule["action"], "message": rule["message"]}
            )

    decision = "pass"
    for rule in triggered_rules:
        if rule["action"] == "block":
            decision = "block"
            break
        if rule["action"] == "require_approval":
            if not _check_approval(rule.get("approval", {})):
                decision = "block"
                break
        if rule["action"] == "warn" and decision == "pass":
            decision = "warn"

    return {"decision": decision, "triggered_rules": triggered_rules}


def validate_policy(policy: dict[str, Any]) -> None:
    if "version" not in policy:
        raise ValueError("Policy must have a 'version' field")
    if "rules" not in policy or not isinstance(policy["rules"], list):
        raise ValueError("Policy must have a 'rules' list")
    for i, rule in enumerate(policy["rules"]):
        _validate_rule(rule, i)


def _validate_rule(rule: dict[str, Any], index: int) -> None:
    rule_id = rule.get("id", index)
    if "id" not in rule:
        raise ValueError(f"Rule {index} must have an 'id' field")
    if "when" not in rule:
        raise ValueError(f"Rule {rule_id} must have a 'when' field")
    if "action" not in rule:
        raise ValueError(f"Rule {rule_id} must have an 'action' field")
    if rule["action"] not in ("block", "warn", "require_approval"):
        raise ValueError(f"Rule {rule_id} has invalid action: {rule['action']}")
    if "message" not in rule:
        raise ValueError(f"Rule {rule_id} must have a 'message' field")


def _evaluate_rule(rule: dict[str, Any], diff_data: dict[str, Any]) -> bool:
    when = rule.get("when", {})

    if "capability_added" in when:
        cap_name = when["capability_added"]
        for cap in diff_data.get("capabilities", {}).get("added", []):
            if cap["capability"] == cap_name:
                if "scope_matches_any" in when:
                    if _scope_matches_any(cap["scope"], when["scope_matches_any"]):
                        return True
                else:
                    return True

    if "capability_widened" in when:
        cap_name = when["capability_widened"]
        for cap in diff_data.get("capabilities", {}).get("widened", []):
            if cap["capability"] == cap_name:
                if "scope_matches_any" in when:
                    if _scope_matches_any(cap["to"], when["scope_matches_any"]):
                        return True
                else:
                    return True

    if "asset_added_kind" in when:
        kind = when["asset_added_kind"]
        for asset in diff_data.get("assets", {}).get("added", []):
            if asset["kind"] == kind:
                return True

    if "asset_changed_kind" in when:
        kind = when["asset_changed_kind"]
        for asset in diff_data.get("assets", {}).get("changed", []):
            if asset["kind"] == kind:
                if "prompt_type" in when:
                    if when["prompt_type"].lower() in asset["id"].lower():
                        return True
                else:
                    return True

    return False


def _scope_matches_any(scope: str, patterns: list[str]) -> bool:
    return any(_scope_matches(scope, p) for p in patterns)


def _scope_matches(scope: str, pattern: str) -> bool:
    if pattern == "/**":
        return True
    regex = pattern.replace("**", "DOUBLESTAR").replace("*", "[^/]*").replace("DOUBLESTAR", ".*")
    return re.match(f"^{regex}$", scope) is not None


def _check_approval(approval_config: dict[str, Any]) -> bool:
    if approval_config.get("mode") == "pr_label":
        label = approval_config.get("label")
        pr_labels = [
            part.strip() for part in os.environ.get("PR_LABELS", "").split(",") if part.strip()
        ]
        return label in pr_labels
    return False
