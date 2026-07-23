import asyncio
import sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
    server_params = StdioServerParameters(
        command=sys.executable,
        args=["vulnerable-server/server.py"],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
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
                print(f"  call #{i+1}: {r.content[0].text}")


if __name__ == "__main__":
    asyncio.run(main())