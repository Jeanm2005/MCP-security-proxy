"""
Policy engine: loads policy.yaml and decides what should happen to a tool
call before it's forwarded to the real server. 
"""

from pathlib import Path

import yaml

from storage import get_policy_override

POLICY_PATH = Path(__file__).parent / "policy.yaml"

def load_policy() -> dict:
    with open(POLICY_PATH) as f:
        return yaml.safe_load(f)

def get_action(tool_name: str, policy: dict) -> tuple[str, str]:
    """Returns (action, reason) for a given tool name. Checks the runtime
    override table first, then falls back to the static policy.yaml."""
    override = get_policy_override(tool_name)
    if override:
        action, reason = override
        return action, f"[runtime override] {reason}"

    rules = policy.get("rules", {})
    if tool_name in rules:
        rule = rules[tool_name]
        return rule.get("action", policy.get("default", "allow")), rule.get("reason", "")
    return policy.get("default", "allow"), ""