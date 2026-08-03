"""
Watchtower Lab Target B: "internal mail server" MCP server.

Paired with vulnerable-server/server.py (which plays the role of a "file
server" with a secret-returning tool) to give us a cross-server
boundary to test cascade detection against: something reads a secret from
one server, something else sends it out via a completely different server.

Nothing here is malicious on its own. The risk only exists in the combination:
secret-from-server-A landing in the body of a call to server-B.
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("watchtower-labl-target-b")

@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """
    Send an email to the given address with the given subject and body.
    """
    return f"Email sent to {to} (subject: {subject!r}, {len(body)} chars in body)."

if __name__ == "__main__":
    mcp.run(transport="stdio")