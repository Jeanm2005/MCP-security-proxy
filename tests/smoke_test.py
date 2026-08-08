import asyncio
import os
import sys
import time
from pathlib import Path

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

REPO_ROOT = Path(__file__).parent.parent
SERVER_URL = "http://127.0.0.1:8001/mcp"


async def wait_for_server(url: str, timeout: float = 10.0) -> None:
    """Poll until the server accepts a real MCP connection, or give up."""
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            async with (
                streamablehttp_client(url) as (read, write, _),
                ClientSession(read, write) as session,
            ):
                await session.initialize()
                return
        except Exception as e:  # noqa: BLE001 -- intentionally broad: any connection failure just means "not up yet"
            last_error = e
            await asyncio.sleep(0.3)
    raise RuntimeError(f"Server at {url} never came up: {last_error}")


async def main():
    env = os.environ.copy()
    env["HOST"] = "127.0.0.1"
    env["PORT"] = "8001"
    env["WATCHTOWER_VARIANT"] = "clean"

    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        str(REPO_ROOT / "vulnerable-server" / "server.py"),
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )

    try:
        await wait_for_server(SERVER_URL)

        async with (
            streamablehttp_client(SERVER_URL) as (read, write, _),
            ClientSession(read, write) as session,
        ):
            await session.initialize()

            tools = await session.list_tools()
            print("=== Tools discovered ===")
            for t in tools.tools:
                print(f"- {t.name}: {t.description!r}")
            print()

            print("=== Call 1: get_weather (baseline, should be clean) ===")
            r = await session.call_tool("get_weather", {"city": "Manatí"})
            print(r.content[0].text)
            print()

            print("=== Call 2: get_compliance_status (tool poisoning check) ===")
            r = await session.call_tool("get_compliance_status", {"vendor_id": "V-042"})
            print(r.content[0].text)
            print()

            print("=== Calls 3-7: lookup_user x5 (watch for the rug pull at call 4) ===")
            for i in range(5):
                r = await session.call_tool("lookup_user", {"username": "jdoe"})
                print(f"  call #{i + 1}: {r.content[0].text}")
    finally:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except TimeoutError:
            proc.kill()


if __name__ == "__main__":
    asyncio.run(main())