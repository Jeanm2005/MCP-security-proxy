"""
Wraps a single upstream MCP connection with automatic reconnect. Each
upstream (filesrv, mailsrv, ...) gets its own instance, managed
independently -- one server dropping and reconnecting never affects the
others or requires restarting the whole proxy.
"""

import sys
from contextlib import AsyncExitStack

import anyio
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


class UpstreamConnection:
    def __init__(self, name: str, url: str) -> None:
        self.name = name
        self.url = url
        self.session: ClientSession | None = None
        self._stack: AsyncExitStack | None = None

    def mark_broken(self) -> None:
        """
        Called from request-handling code when a call to this
        upstream fails. Never touches the connection directly,
        just signals the supervisor task.
        """
        self.session = None
        self._reconnect_needed.set()

    async def run_supervisor(self) -> None:
        """
        Runs for the whole lifetime of the proxy, on one task,
        spawned once from main(). Owns the entire lifecycle.
        """
        backoff = 1.0
        while True:
            try:
                async with (
                    streamablehttp_client(self.url) as (read, write, _get_session_id),
                    ClientSession(read, write) as session,
                ):
                    await session.initialize()
                    self.session = session
                    backoff = 1.0
                    print(f"[watchtower] connected to upstream '{self.name}' at {self.url}", file=sys.stderr)

                    self._reconnect_needed = anyio.Event()
                    await self._reconnect_needed.wait()
                    print(f"[watchtower] tearing down connection to '{self.name}' to reconnect...", file=sys.stderr)
            except Exception as e: # noqa: BLE001
                self.session = None
                print(
                    f"[watchtower] connection to '{self.name}' failed ({e}). Retrying in {backoff:.1f}s...",
                    file=sys.stderr,
                )
                await anyio.sleep(backoff)
                backoff = min(backoff * 2, 30)

    async def call(self, fn):
        for _ in range(50): # ~5s total at 0.1s each
            if self.session is not None:
                break
            await anyio.sleep(0.1)
        else:
            raise RuntimeError(f"upstream '{self.name}' is not connected")

        try:
            return await fn(self.session)
        except Exception:
            print(f"[watchtower] call to upstream '{self.name}' failed, marking broken for reconnect", file=sys.stderr)
            self.mark_broken()
            raise