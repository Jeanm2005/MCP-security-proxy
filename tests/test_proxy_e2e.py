import asyncio
import os
import sys
import tempfile
import time
from pathlib import Path

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

REPO_ROOT = Path(__file__).parent.parent
FILESRV_URL = "http://127.0.0.1:8001/mcp"
PROXY_URL = "http://127.0.0.1:8000/mcp"

LOCAL_SERVERS_YAML = """
servers:
    - name: filesrv
      url: http://127.0.0.1:8001/mcp
"""

async def wait_for_url(url: str, timeout: float = 15.0) -> None:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    host, port = parsed.hostname, parsed.port

    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            _reader, writer = await asyncio.open_connection(host, port)
            writer.close()
            await writer.wait_closed()
            return
        except OSError as e:
            last_error = e
            await asyncio.sleep(0.3)
    raise RuntimeError(f"{url} never came up: {last_error}")

async def main():
    filesrv_env = os.environ.copy()
    filesrv_env["HOST"] = "127.0.0.1"
    filesrv_env["PORT"] = "8001"
    filesrv_env["WATCHTOWER_VARIANT"] = "clean"

    filesrv_proc = await asyncio.create_subprocess_exec(
        sys.executable,
        str(REPO_ROOT / "vulnerable-server" / "server.py"),
        env=filesrv_env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(LOCAL_SERVERS_YAML)
        servers_config_path = f.name

    proxy_env = os.environ.copy()
    proxy_env["HOST"] = "127.0.0.1"
    proxy_env["PORT"] = "8000"
    proxy_env["WATCHTOWER_CI_AUTO_APPROVE"] = "true"
    proxy_env["WATCHTOWER_SERVERS_CONFIG"] = servers_config_path
    proxy_env["WATCHTOWER_DB_PATH"] = str(REPO_ROOT / "proxy" / "watchtower.db")

    proxy_proc = await asyncio.create_subprocess_exec(
        sys.executable,
        str(REPO_ROOT / "proxy" / "proxy.py"),
        cwd=str(REPO_ROOT / "proxy"),
        env=proxy_env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )

    try:
        await wait_for_url(FILESRV_URL)
        await wait_for_url(PROXY_URL)

        async with (
            streamablehttp_client(PROXY_URL) as (read, write, _),
            ClientSession(read, write) as session,
        ):
            await session.initialize()

            print("=== list_tools (expect a suspicious tool description alert in proxy output) ===")
            tools = await session.list_tools()
            for t in tools.tools:
                print(f"- {t.name}")
            print()

            print("=== lookup_user x5 (expect alerts to start at call #4) ===")
            for i in range(5):
                r = await session.call_tool("filesrv__lookup_user", {"username": "jdoe"})
                print(f" call #{i + 1}: {r.content[0].text}")

    finally:
        for proc in (proxy_proc, filesrv_proc):
            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except TimeoutError:
                    proc.kill()

        proxy_output = (await proxy_proc.stdout.read()).decode(errors="replace") if proxy_proc.stdout else ""
        print("\n=== proxy output ===")
        print(proxy_output)

        Path(servers_config_path).unlink(missing_ok=True)

if __name__ == "__main__":
    asyncio.run(main())