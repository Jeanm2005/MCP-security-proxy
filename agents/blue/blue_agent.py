"""
Blue agent: the autonomous defender half of the red/blue pair.

Talks to the proxy ONLY over HTTP, via its admin API -- never touches the
database or filesystem directly. This is deliberate: it means the blue
agent works identically whether it's running on the same machine as the
proxy, in a different container, or eventually a different pod entirely.
No shared-filesystem assumption anywhere.

Each run: reads everything Watchtower has flagged since the last run,
asks an LLM to reason about whether any tool's recent behavior warrants
tightening policy, and -- if so -- posts a policy override that the proxy
checks on the very next call. Every decision (including "no action
needed") is logged via the admin API for a full audit trail.

Requires ANTHROPIC_API_KEY in the environment.

Usage:
    python agents/blue/blue_agent.py                          # single pass
    python agents/blue/blue_agent.py --loop 60                # repeat every 60s
    python agents/blue/blue_agent.py --proxy-url http://...   # non-default proxy location
"""

import argparse
import json
import os
import sys
import time

import anthropic
import httpx

DEFAULT_PROXY_URL = os.environ.get("WATCHTOWER_PROXY_URL", "http://127.0.0.1:8000")
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


def strip_markdown_fence(text: str) -> str:
    """Models often wrap JSON in a markdown code fence even when told not
    to -- strip it before parsing rather than fighting the model further."""
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        text = text.removeprefix("json")
        text = text.strip()
    return text


def run_once(client: anthropic.Anthropic, http: httpx.Client, proxy_url: str) -> int:
    """Returns the number of policy overrides applied this run."""
    last_run = http.get(f"{proxy_url}/admin/blue-agent/last-run").json()["last_run"]
    now = time.time()

    findings = http.get(f"{proxy_url}/admin/findings", params={"since": last_run}).json()
    summary = summarize_findings(findings)

    if not summary:
        print("[blue-agent] no new findings since last run -- nothing to review")
        http.post(f"{proxy_url}/admin/blue-agent/last-run", json={"timestamp": now})
        return 0

    print(f"[blue-agent] reviewing findings since {last_run:.0f}:\n{summary}\n")

    response = client.messages.create(
        model=MODEL,
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": summary}],
    )
    raw_text = strip_markdown_fence(response.content[0].text)

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

        http.post(
            f"{proxy_url}/admin/blue-agent/decisions",
            json={"tool_name": tool_name, "decision": decision, "reasoning": reasoning},
        )
        print(f"[blue-agent] {tool_name}: {decision} -- {reasoning}")

        if decision != "no_action":
            http.post(
                f"{proxy_url}/admin/policy-overrides",
                json={"tool_name": tool_name, "action": decision, "reason": reasoning, "added_by": "blue-agent"},
            )
            overrides_applied += 1

    http.post(f"{proxy_url}/admin/blue-agent/last-run", json={"timestamp": now})
    return overrides_applied


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--loop", type=int, default=None, help="repeat every N seconds instead of running once")
    parser.add_argument("--proxy-url", default=DEFAULT_PROXY_URL, help="base URL of the proxy's admin API")
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY is not set", file=sys.stderr)
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)

    with httpx.Client(timeout=30) as http:
        if args.loop:
            print(f"[blue-agent] running every {args.loop}s against {args.proxy_url} (Ctrl+C to stop)")
            while True:
                run_once(client, http, args.proxy_url)
                time.sleep(args.loop)
        else:
            run_once(client, http, args.proxy_url)


if __name__ == "__main__":
    main()