"""
Blue agent: the autonomous defender half of the red/blue pair.

Each run: reads everything Watchtower has flagged since the last run
(flagged calls, description findings, rug pulls, cascade findings),
asks an LLM to reason about whether any tool's recent behavior warrants
tightening policy, and -- if so -- writes a policy override that the
proxy checks on the very next call. Every decision (including "no action
needed") is logged to blue_agent_decisions for a full audit trail.

This is the literal-match, reactive half of the defender. The planned
aggregation-inference work (see RESEARCH.md) is a separate, experimental
extension layered on top of this later -- this script is the reliable
baseline that has to work first.

Requires ANTHROPIC_API_KEY in the environment.

Usage:
    python agents/blue/blue_agent.py             # single pass
    python agents/blue/blue_agent.py --loop 60    # repeat every 60s
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

import anthropic

REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "proxy"))

from storage import (
    get_blue_agent_last_run,
    get_recent_findings,
    log_blue_agent_decision,
    set_blue_agent_last_run,
    set_policy_override,
)

MODEL = os.environ.get("WATCHTOWER_BLUE_AGENT_MODEL", "claude-haiku-4-5-20251001")

SYSTEM_PROMPT = """You are the blue-team defender for an MCP security gateway called \
Watchtower. You review findings from its detectors (tool poisoning, runtime \
response injection, rug-pull/fingerprint drift, cross-server cascade exfiltration) \
and decide whether any specific tool's recent behavior warrants tightening its \
runtime policy.

For each tool with concerning findings, decide one of:
- "no_action" -- findings noted, but not severe/repeated enough to act on yet
- "require_approval" -- tool should require human approval on every call going forward
- "deny" -- tool should be blocked outright

Respond ONLY with a JSON array, one object per tool that has findings, each with:
{"tool_name": "...", "decision": "no_action" | "require_approval" | "deny", "reasoning": "one or two sentences"}

Be conservative: only recommend "deny" for clear, severe, repeated malicious \
patterns. A single ambiguous finding should usually be "no_action" or, at most, \
"require_approval"."""

def summarize_findings(findings: dict) -> str:
    lines = []

    if findings["flagged_calls"]:
        lines.append("=== Flagged calls (runtime response injection) ===")
        for row in findings["flagged_calls"]:
            lines.append(f"- {row['tool_name']}: flags={row['flags']}")

    if findings["description_findings"]:
        lines.append("\n=== Static tool-poisoning findings ===")
        for row in findings["description_findings"]:
            lines.append(f"- {row['tool_name']}: {row['findings']}")

    if findings["rug_pulls"]:
        lines.append("\n=== Rug-pull (fingerprint drift) detections ===")
        for row in findings["rug_pulls"]:
            lines.append(f"- {row['tool_name']}")

    if findings["cascade_findings"]:
        lines.append("\n=== Cross-server cascade findings ===")
        for row in findings["cascade_findings"]:
            lines.append(
                f"- {row['source_server']}__{row['source_tool']} -> "
                f"{row['dest_server']}__{row['dest_tool']}: {row['matched_value']!r}"
            )

    return "\n".join(lines) if lines else ""

def run_once(client: anthropic.Anthropic) -> int:
    """Returns the number of policy overrides applied this run."""
    last_run = get_blue_agent_last_run()
    now = time.time()

    findings = get_recent_findings(last_run)
    summary = summarize_findings(findings)

    if not summary:
        print("[blue-agent] no new findings since last run -- nothing to review")
        set_blue_agent_last_run(now)
        return 0

    print(f"[blue-agent] reviewing findings since {last_run:.0f}:\n{summary}\n")

    response = client.messages.create(
        model=MODEL,
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": summary}],
    )
    raw_text = response.content[0].text.strip()

    if raw_text.startswith("```"):
        raw_text = raw_text.split("```")[1]
        raw_text = raw_text.removeprefix("json")
        raw_text = raw_text.strip()

    try:
        decisions = json.loads(raw_text)
    except json.JSONDecodeError:
        print(f"[blue-agent] ERROR: model response wasn't valid JSON, skipping this run:\n{raw_text}")
        return 0

    overrides_applied = 0
    for item in decisions:
        tool_name = item.get("tool_name")
        decision = item.get("decision")
        reasoning = item.get("reasoning", "")

        if not tool_name or decision not in ("no_action", "require_approval", "deny"):
            print(f"[blue-agent] skipping malformed decision: {item}")
            continue

        log_blue_agent_decision(tool_name, decision, reasoning)
        print(f"[blue-agent] {tool_name}: {decision} -- {reasoning}")

        if decision != "no_action":
            set_policy_override(tool_name, decision, reasoning, added_by="blue-agent")

    set_blue_agent_last_run(now)
    return overrides_applied

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--loop", type=int, default=None, help="repeat every N seconds instead of running once")
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY is not set", file=sys.stderr)
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)

    if args.loop:
        print(f"[blue-agent] running every {args.loop}s (Ctrl+C to stop)")
        while True:
            run_once(client)
            time.sleep(args.loop)
    else:
        run_once(client)

if __name__ == "__main__":
    main()