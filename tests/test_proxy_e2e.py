import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

REPO_ROOT = Path(__file__).parent.parent


async def main():
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[
            "proxy.py",
            "--",
            sys.executable,
            str(REPO_ROOT / "vulnerable-server" / "server.py"),
        ],
        cwd=str(REPO_ROOT / "proxy"),
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            print("=== list_tools (expect a SUSPICIOUS TOOL DESCRIPTION alert on stderr) ===")
            tools = await session.list_tools()
            for t in tools.tools:
                print(f"- {t.name}")
            print()

            print("=== lookup_user x5 (expect alerts to start at call #4) ===")
            for i in range(5):
                r = await session.call_tool("lookup_user", {"username": "jdoe"})
                print(f"  call #{i+1}: {r.content[0].text}")


if __name__ == "__main__":
    asyncio.run(main())