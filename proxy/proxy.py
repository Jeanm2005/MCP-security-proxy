"""
Watchtower proxy -- multi-server aggregator.

Connects to multiple upstream MCP servers (defined in server.yaml),
merges their tools into one list (prefixed as "servername__toolname" to
avoid collisions), and routes each call to the right backend. Every call
from every server funnels through this one process, which is what makes
cross-server cascade detection possible.
"""

import asyncio
import os
import sys
from contextlib import AsyncExitStack
from pathlib import Path

import anyio
import uvicorn
import yaml
from cascade import check_for_cascade, record_output
from detectors import scan_text
from mcp import ClientSession, types
from mcp.client.streamable_http import streamablehttp_client
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from policy import get_action, load_policy
from slack_notifier import send_slack_message
from starlette.applications import Starlette
from starlette.routing import Route
from storage import (
    check_and_update_fingerprint,
    create_pending_approval,
    get_approval_status,
    init_db,
    log_call,
    log_cascade_findings,
    log_description_findings,
    set_approval_decision,
)

SERVERS_CONFIG_PATH = Path(__file__).parent / "servers.yaml"
PREFIX_SEP = "__"

proxy = Server("mcp-watchtower-proxy")

_upstreams: dict[str, ClientSession] = {}
_tool_routes: dict[str, tuple[str, str]] = {}
_policy: dict = {}

APPROVAL_POLL_INTERVAL_SECONDS = 2
APPROVAL_TIMEOUT_SECONDS = int(os.environ.get("WATCHTOWER_APPROVAL_TIMEOUT", "300"))


def _alert(message: str) -> None:
    print(f"\n[WATCHTOWER ALERT] {message}\n", file=sys.stderr, flush=True)
    send_slack_message(f":rotating_light: *Watchtower* {message}")


def _denied_result(message: str) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=f"[Watchtower] Blocked: {message}")],
        isError=True,
    )


@proxy.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    merged: list[types.Tool] = []
    _tool_routes.clear()

    for server_name, session in _upstreams.items():
        result = await session.list_tools()
        for tool in result.tools:
            prefixed_name = f"{server_name}{PREFIX_SEP}{tool.name}"
            description = tool.description or ""

            rug_pull = check_and_update_fingerprint(prefixed_name, description, tool.inputSchema)
            if rug_pull:
                _alert(
                    f"RUG PULL on tool '{prefixed_name}': its description/schema changed "
                    f"since it was first seen (first_seen={rug_pull['first_seen']:.0f})."
                )

            findings = scan_text(description)
            if findings:
                labels = ", ".join(f["label"] for f in findings)
                _alert(f"SUSPICIOUS TOOL DESCRIPTION on '{prefixed_name}': {labels}")
                log_description_findings(prefixed_name, description, findings)

            _tool_routes[prefixed_name] = (server_name, tool.name)
            merged.append(tool.model_copy(update={"name": prefixed_name}))

    return merged


async def _wait_for_approval(approval_id: int, tool_name: str) -> bool:
    if os.environ.get("WATCHTOWER_CI_AUTO_APPROVE") == "true":
        _alert(f"[TEST MODE] auto-approving #{approval_id} for '{tool_name}'")
        set_approval_decision(approval_id, "approved")
        return True

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


@proxy.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> types.CallToolResult:
    if name not in _tool_routes:
        return _denied_result(f"unknown tool '{name}' -- not in any connected server's tool list")

    server_name, original_name = _tool_routes[name]

    action, reason = get_action(original_name, _policy)

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

    cascade = check_for_cascade(server_name, original_name, arguments)
    if cascade:
        _alert(
            f"CASCADE ALERT: output from '{cascade['source_server']}__{cascade['source_tool']}' "
            f"showed up as input to '{name}'. This looks like data crossing a server "
            f"boundary it was never meant to cross.\n"
            f"  Matched value: {cascade['matched_value']!r}"
        )
        log_cascade_findings(
            cascade["source_server"], cascade["source_tool"],
            cascade["dest_server"], cascade["dest_tool"], cascade["matched_value"],
        )

    session = _upstreams[server_name]
    result = await session.call_tool(original_name, arguments)

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
    record_output(server_name, original_name, response_text)

    return result


class _MCPASGIApp:
    """Thin ASGI wrapper delegating every request to the MCP session
    manager. Kept as an explicit class (mirroring the pattern FastMCP
    itself uses internally) rather than a bare function, since Starlette's
    Route needs a real 3-arg ASGI callable, not a typical request handler.
    """

    def __init__(self, session_manager: StreamableHTTPSessionManager) -> None:
        self.session_manager = session_manager

    async def __call__(self, scope, receive, send) -> None:
        await self.session_manager.handle_request(scope, receive, send)


def _load_servers_config() -> dict:
    with open(SERVERS_CONFIG_PATH) as f:
        return yaml.safe_load(f)


async def main(config: dict) -> None:
    init_db()

    global _policy
    _policy = load_policy()

    async with AsyncExitStack() as stack:
        for server_cfg in config["servers"]:
            url = server_cfg["url"]
            read, write, _get_session_id = await stack.enter_async_context(
                streamablehttp_client(url)
            )
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            _upstreams[server_cfg["name"]] = session
            print(f"[watchtower] connected to upstream '{server_cfg['name']}' at {url}", file=sys.stderr)

        session_manager = StreamableHTTPSessionManager(app=proxy, stateless=False)
        mcp_asgi_app = _MCPASGIApp(session_manager)

        starlette_app = Starlette(
            routes=[Route("/mcp", endpoint=mcp_asgi_app)],
            lifespan=lambda app: session_manager.run(),
        )

        host = os.environ.get("HOST", "127.0.0.1")
        port = int(os.environ.get("PORT", "8000"))
        uvicorn_config = uvicorn.Config(starlette_app, host=host, port=port, log_level="info")
        uv_server = uvicorn.Server(uvicorn_config)
        print(f"[watchtower] proxy listening on http://{host}:{port}/mcp", file=sys.stderr)
        await uv_server.serve()


if __name__ == "__main__":
    server_config = _load_servers_config()
    anyio.run(main, server_config)