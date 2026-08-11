import asyncio
import os
import sys
from pathlib import Path

import anyio
import uvicorn
import yaml
from cascade import check_for_cascade, record_output
from detectors import scan_text
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from policy import get_action, load_policy
from slack_notifier import send_slack_message
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from storage import (
    check_and_update_fingerprint,
    create_pending_approval,
    create_red_agent_run,
    finish_red_agent_run,
    get_approval_status,
    get_blue_agent_last_run,
    get_recent_findings,
    init_db,
    log_blue_agent_decision,
    log_call,
    log_cascade_findings,
    log_description_findings,
    log_red_agent_step,
    set_approval_decision,
    set_blue_agent_last_run,
    set_policy_override,
)
from upstream_connection import UpstreamConnection

SERVERS_CONFIG_PATH = Path(os.environ.get("WATCHTOWER_SERVERS_CONFIG", str(Path(__file__).parent / "servers.yaml")))
PREFIX_SEP = "__"
CASCADE_ACTION = os.environ.get("WATCHTOWER_CASCADE_ACTION", "deny")

proxy = Server("mcp-watchtower-proxy")

# server_name -> UpstreamConnection (each manages its own reconnect logic)
_upstreams: dict[str, UpstreamConnection] = {}
# prefixed_tool_name -> (server_name, original_tool_name)
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

    for server_name, conn in _upstreams.items():
        result = await conn.call(lambda s: s.list_tools())
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

    # Policy is matched on the ORIGINAL (unprefixed) tool name, so existing
    # policy.yaml rules keep working unchanged regardless of which server
    # a tool happens to live on.
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
        _alert(f"CASCADE ALERT: output from '{cascade['source_server']}__{cascade['source_tool']}' showed up as input to '{name}'.")
        log_cascade_findings(cascade["source_server"], cascade["source_tool"], cascade["dest_server"], cascade["dest_tool"], cascade["matched_value"])

        if CASCADE_ACTION == "deny":
            return _denied_result(
                f"call to '{name}' blocked: its arguments contain data that recently came out of "
                f"'{cascade['source_server']}__{cascade['source_tool']}', a different server -- this looks like "
                f"cross-server exfiltration in progress"
            )

    conn = _upstreams[server_name]
    result = await conn.call(lambda s: s.call_tool(original_name, arguments))

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

async def admin_get_findings(request: Request) -> JSONResponse:
    """Everything an agent needs to reason about recent Watchtower activity,
    over HTTP -- no filesystem/DB access required, works identically
    whether the agent and proxy are on the same machine or not."""
    since = float(request.query_params.get("since", "0"))
    findings = get_recent_findings(since)
    serializable = {key: [dict(row) for row in rows] for key, rows in findings.items()}
    return JSONResponse(serializable)

async def admin_set_policy_override(request: Request) -> JSONResponse:
    body = await request.json()
    set_policy_override(
        body["tool_name"], body["action"], body["reason"], body.get("added_by", "agent")
    )
    return JSONResponse({"ok": True})

async def admin_get_blue_agent_last_run(request: Request) -> JSONResponse:
    return JSONResponse({"last_run": get_blue_agent_last_run()})


async def admin_set_blue_agent_last_run(request: Request) -> JSONResponse:
    body = await request.json()
    set_blue_agent_last_run(body["timestamp"])
    return JSONResponse({"ok": True})


async def admin_log_blue_agent_decision(request: Request) -> JSONResponse:
    body = await request.json()
    log_blue_agent_decision(body["tool_name"], body["decision"], body["reasoning"])
    return JSONResponse({"ok": True})


async def admin_create_red_agent_run(request: Request) -> JSONResponse:
    body = await request.json()
    run_id = create_red_agent_run(body["goal"])
    return JSONResponse({"run_id": run_id})


async def admin_log_red_agent_step(request: Request) -> JSONResponse:
    run_id = int(request.path_params["run_id"])
    body = await request.json()
    log_red_agent_step(
        run_id, body["step_number"], body["tool_called"], body["arguments"], body["result"], body["blocked"]
    )
    return JSONResponse({"ok": True})


async def admin_finish_red_agent_run(request: Request) -> JSONResponse:
    run_id = int(request.path_params["run_id"])
    body = await request.json()
    finish_red_agent_run(run_id, body["outcome"], body["summary"])
    return JSONResponse({"ok": True})

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

    for server_cfg in config["servers"]:
        conn = UpstreamConnection(server_cfg["name"], server_cfg["url"])
        _upstreams[server_cfg["name"]] = conn

    session_manager = StreamableHTTPSessionManager(app=proxy, stateless=False)
    mcp_asgi_app = _MCPASGIApp(session_manager)

    starlette_app = Starlette(
        routes=[
            Route("/mcp", endpoint=mcp_asgi_app),
            Route("/admin/findings", endpoint=admin_get_findings, methods=["GET"]),
            Route("/admin/policy-overrides", endpoint=admin_set_policy_override, methods=["POST"]),
            Route("/admin/blue-agent/last-run", endpoint=admin_get_blue_agent_last_run, methods=["GET"]),
            Route("/admin/blue-agent/last-run", endpoint=admin_set_blue_agent_last_run, methods=["POST"]),
            Route("/admin/blue-agent/decisions", endpoint=admin_log_blue_agent_decision, methods=["POST"]),
            Route("/admin/red-agent/runs", endpoint=admin_create_red_agent_run, methods=["POST"]),
            Route("/admin/red-agent/runs/{run_id}/steps", endpoint=admin_log_red_agent_step, methods=["POST"]),
            Route("/admin/red-agent/runs/{run_id}/finish", endpoint=admin_finish_red_agent_run, methods=["POST"]),
        ],
        lifespan=lambda app: session_manager.run(),
    )

    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    uvicorn_config = uvicorn.Config(starlette_app, host=host, port=port, log_level="info")
    uv_server = uvicorn.Server(uvicorn_config)

    async with anyio.create_task_group() as tg:
        for conn in _upstreams.values():
            tg.start_soon(conn.run_supervisor)

        print(f"[watchtower] proxy listening on http://{host}:{port}/mcp", file=sys.stderr)
        await uv_server.serve()
        tg.cancel_scope.cancel()

if __name__ == "__main__":
    server_config = _load_servers_config()
    anyio.run(main, server_config)