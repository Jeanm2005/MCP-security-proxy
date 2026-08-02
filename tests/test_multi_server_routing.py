"""
Proves the multi-server plumbing works BEFORE we build the cascade detector
on top of it: connects to the proxy (which internally aggregates both
filesrv and mailsrv per servers.yaml), confirms tools from both servers
show up correctly prefixed, and confirms calling a tool routes to the
right backend server and gets a real response back.
"""

import asyncio
import sys
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

REPO_ROOT = Path(__file__).parent.parent

async def main():
    server_params = StdioServerParameters(
        command=sys.executable,
        args=["proxy.py"],
        cwd=str(REPO_ROOT / "proxy"),
    )

    async with (
        stdio_client(server_params) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()

        print("=== list_tools (expect tools from BOTH filesrv and mailsrv) ===")
        tools = await session.list_tools()
        names = [t.name for t in tools.tools]
        for n in names:
            print(f"- {n}")
        print()

        assert any(n.startswith("filesrv__") for n in names), "no filesrv tools found!"
        assert any(n.startswith("mailsrv__") for n in names), "no mailsrv tools found!"
        print("OK: tools from both servers present\n")

        print("=== Call filesrv__get_weather (should route to filesrv) ===")
        r = await session.call_tool("filesrv__get_weather", {"city": "Manatí"})
        print(r.content[0].text)
        assert "sunny" in r.content[0].text.lower()
        print()

        print("=== Call mailsrv__send_email (should route to mailsrv) ===")
        r = await session.call_tool(
            "mailsrv__send_email",
            {"to": "test@example.com", "subject": "hello", "body": "just a routing test"},
        )
        print(r.content[0].text)
        assert "email sent" in r.content[0].text.lower()
        print()

        print("ALL ROUTING CHECKS PASSED")


if __name__ == "__main__":
    asyncio.run(main())