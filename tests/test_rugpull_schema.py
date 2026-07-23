"""
Proves the fingerprint-diff rug-pull detector actually fires on a real
schema/description change -- not just the runtime-response injection we've
already tested. Connects to the lab server through the proxy TWICE, in two
separate processes, with WATCHTOWER_VARIANT flipped between them. This
models an agent reconnecting to the same MCP server after a redeploy
silently changed a tool's description.

Uses the SAME watchtower.db across both runs (default location), since
that's the realistic scenario: the proxy remembers what it saw last time.
"""

import asyncio
import os
import sys
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

REPO_ROOT = Path(__file__).parent.parent

async def connect_and_list(variant: str):
    env = os.environ.copy()
    env["WATCHTOWER_VARIANT"] = variant

    server_params = StdioServerParameters(
        command=sys.executable,
        args = [
            "proxy.py",
            "--",
            sys.executable,
            str(REPO_ROOT / "vulnerable-server" / "server.py"),
        ],
        cwd=str(REPO_ROOT / "proxy"),
        env=env,
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            for t in tools.tools:
                if t.name == "check_status":
                    print(f" check_status description: {t.description!r}")

async def main():
    print("=== Connection 1: WATCHTOWER_VARIANT=clean (expect no alert) ===")
    await connect_and_list("clean")

    print()
    print("=== Connection 2: WATCHTOWER_VARIANT=poisoned (expect RUG PULL alert) ===")
    await connect_and_list("poisoned")

if __name__ == "__main__":
    asyncio.run(main())