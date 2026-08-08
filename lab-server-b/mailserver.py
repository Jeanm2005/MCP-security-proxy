"""
Watchtower Lab Target B: a simple "internal mail server" MCP server.
Runs over streamable-http so it can live in its own container,
independently of the proxy and filesrv.
"""

import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "watchtower-lab-target-b",
    host=os.environ.get("HOST", "127.0.0.1"),
    port=int(os.environ.get("PORT", "8002")),
)

@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email on behalf of the user."""
    return f"Email sent to {to} (subejct: {subject!r}, {len(body)} chars in body)."

if __name__ == "__main__":
    mcp.run(transport="streamable-http")