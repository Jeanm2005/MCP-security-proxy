"""
Watchtower proxy. Sits between a real MCP client and a real MCP server,
forwarding every request transparently -- but on the way through, it logs
every call, fingerprints every tool definition (catching rug pulls), and
scans every description/response for injection patterns.

Usage:
    python proxy.py -- python ../vulnerable-server/server.py
"""
import asyncio
import os
import sys
import anyio
from detectors import scan_text
from policy import get_action, load_policy
from slack_notifier import send_slack_message
from mcp import ClientSession, StdioServerParameters
import mcp.types as types
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from storage import (
    check_and_update_fingerprint,
    init_db,
    log_call,
    log_description_findings,
    create_pending_approval,
    get_approval_status,
)

proxy = Server("mcp-watchtower-proxy")
_upstream: ClientSession | None = None
_policy: dict = {}

APPROVAL_POLL_INTERVAL_SECONDS = 2
APPROVAL_TIMEOUT_SECONDS = int(os.environ.get("WATCHTOWER_APPROVAL_TIMEOUT", "300"))


def _alert(message: str) -> None:
    """v1 alerting: stderr + Slack (if configured)."""
    print(f"\n[WATCHTOWER ALERT] {message}\n", file=sys.stderr, flush=True)
    send_slack_message(f":rotating_light: *Watchtower* {message}")

@proxy.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    assert _upstream is not None
    result = await _upstream.list_tools()

    for tool in result.tools:
        description = tool.description or ""

        rug_pull = check_and_update_fingerprint(tool.name, description, tool.inputSchema)
        if rug_pull:
            _alert(
                f"RUG PULL on tool '{tool.name}': its description/schema changed "
                f"since it was first seen (first_seen={rug_pull['first_seen']:.0f}). "
                f"This tool was already trusted before this change happened."
            )

        findings = scan_text(description)
        if findings:
            labels = ", ".join(f["label"] for f in findings)
            _alert(f"SUSPICIOUS TOOL DESCRIPTION on '{tool.name}': {labels}")
            log_description_findings(tool.name, description, findings)

    return result.tools

async def _wait_for_approval(approval_id: int, tool_name: str) -> bool:
    """Polls the DB for a human decision. Returns True if approved, False
    if denied or timed out.
    """
    elapsed = 0
    while elapsed < APPROVAL_TIMEOUT_SECONDS:
        status = get_approval_status(approval_id)
        if status == "approved":
            return True
        if status == "denied":
            return False
        await asyncio.sleep(APPROVAL_POLL_INTERVAL_SECONDS)
        elapsed += APPROVAL_POLL_INTERVAL_SECONDS

    _alert(f"Approval request #{approval_id} for '{tool_name}' timed out -- denying by default.")
    return False

def _denied_result(message: str) -> types.CallToolRequest:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=f"[Watchtower] Blocked: {message}")],
        isError=True,
    )

@proxy.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> types.CallToolResult:
    action, reason = get_action(name, _policy)

    if action == "deny":
        _alert(f"POLICY DENY: call to '{name}' blocked outright. Reason: {reason}")
        return _denied_result(f"tool '{name}' is denied by policy ({reason})")

    if action == "require_approval":
        approval_id = create_pending_approval(name, arguments, reason)
        _alert(
            f"APPROVAL REQUIRED: call to '{name}' (args={arguments}) is waiting on "
            f"approval #{approval_id}. Reason: {reason}\n"
            f"  Run: python tools/approve.py {approval_id} approve   (or deny)"
        )
        approved = await _wait_for_approval(approval_id, name)
        if not approved:
            return _denied_result(f"tool '{name}' approval #{approval_id} was denied or timed out")

    # action == "allow", or action == "require_approval" and it was approved
    assert _upstream is not None
    result = await _upstream.call_tool(name, arguments)

    response_text = "\n".join(
        block.text for block in result.content if isinstance(block, types.TextContent)
    )

    findings = scan_text(response_text)
    if findings:
        labels = ", ".join(f["label"] for f in findings)
        _alert(
            f"SUSPICIOUS TOOL RESPONSE from '{name}' (args={arguments}): {labels}\n"
            f"  Raw response: {response_text!r}"
        )

    log_call(name, arguments, response_text, findings)

    return result

async def main() -> None:
    if "--" not in sys.argv:
        print("Usage: python proxy.py -- <command to launch real MCP server>", file=sys.stderr)
        sys.exit(1)

    split = sys.argv.index("--")
    upstream_cmd = sys.argv[split + 1]
    upstream_args = sys.argv[split + 2:]

    init_db()

    global _upstream, _policy
    _policy = load_policy()

    server_params = StdioServerParameters(command=upstream_cmd, args=upstream_args, env=dict(os.environ))

    async with (
        stdio_client(server_params) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        _upstream = session
        print("[watchtower] connected to upstream MCP server", file=sys.stderr)

        async with stdio_server() as (proxy_read, proxy_write):
            await proxy.run(
                proxy_read,
                proxy_write,
                proxy.create_initialization_options(),
            )

if __name__ == "__main__":
    anyio.run(main)