"""
Watchtower proxy. Sits between a real MCP client and a real MCP server,
forwarding every request transparently -- but on the way through, it logs
every call, fingerprints every tool definition (catching rug pulls), and
scans every description/response for injection patterns.

Usage:
    python proxy.py -- python ../vulnerable-server/server.py
"""
import os
import sys
import anyio
import mcp.types as types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from detectors import scan_text
from storage import init_db, check_and_update_fingerprint, log_call, log_description_findings

proxy = Server("mcp-watchtower-proxy")
_upstream: ClientSession | None = None


def _alert(message: str) -> None:
    """v1 alerting: stderr. A Slack webhook slots in here later without
    touching any other code."""
    print(f"\n[WATCHTOWER ALERT] {message}\n", file=sys.stderr, flush=True)


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
            log_description_findings(tool.name, description, findings)  # <-- new

    return result.tools


@proxy.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> types.CallToolResult:
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
    print(f"[proxy debug] my own WATCHTOWER_VARIANT = {os.environ.get('WATCHTOWER_VARIANT')!r}", file=sys.stderr)
    global _upstream
    server_params = StdioServerParameters(command=upstream_cmd, args=upstream_args, env=dict(os.environ))

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
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