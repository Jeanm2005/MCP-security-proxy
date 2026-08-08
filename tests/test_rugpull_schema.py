"""
Proves the fingerprint-diff rug-pull detector fires on a real schema/
description change.
"""

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

async def start_filesrv(variant: str):
    env = os.environ.copy()
    env["HOST"] = "127.0.0.1"
    env["PORT"] = "8001"
    env["WATCHTOWER_VARIANT"] = variant
    return await asyncio.create_subprocess_exec(
        sys.executable,
        str(REPO_ROOT / "vulnerable-server" / "server.py"),
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )

async def stop_proc(proc) -> None:
    proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), timeout=5)
    except TimeoutError:
        proc.kill()

async def get_check_status_description(session: ClientSession) -> str:
    tools = await session.list_tools()
    for t in tools.tools:
        if t.name == "filesrv__check_status":
            return t.description or ""
    raise RuntimeError("filesrv__check_status not found in tool list")

async def main():
    filesrv_proc = await start_filesrv("clean")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(LOCAL_SERVERS_YAML)
        servers_config_path = f.name

    proxy_env = os.environ.copy()
    proxy_env["HOST"] = "127.0.0.1"
    proxy_env["PORT"] = "8000"
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

        print("=== Connection 1: filesrv clean (expect no rug-pull alert) ===")
        async with (
            streamablehttp_client(PROXY_URL) as (read, write, _),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            desc = await get_check_status_description(session)
            print(f"  check_status description: {desc!r}")

        print()
        print("=== Restarting filesrv with WATCHTOWER_VARIANT=poisoned (proxy must reconnect on its own) ===")
        await stop_proc(filesrv_proc)
        filesrv_proc = await start_filesrv("poisoned")
        await wait_for_url(FILESRV_URL)

        print()
        print("=== Connection 2: expect the proxy to have reconnected and see the poisoned description ===")
        desc = None
        last_error = None
        for _ in range(15):
            try:
                async with (
                    streamablehttp_client(PROXY_URL) as (read, write, _),
                    ClientSession(read, write) as session,
                ):
                    await session.initialize()
                    desc = await get_check_status_description(session)
                    if "<system>" in desc:
                        break
            except Exception as e:  # noqa: BLE001
                last_error = e
            await asyncio.sleep(1)

        print(f"  check_status description: {desc!r}")
        assert desc is not None and "<system>" in desc, (
            f"proxy never picked up the poisoned description (last connection error: {last_error})"
        )
        print("\nOK: proxy reconnected to the restarted filesrv AND detected the rug pull")
    finally:
        await stop_proc(proxy_proc)
        await stop_proc(filesrv_proc)

        proxy_output = (await proxy_proc.stdout.read()).decode(errors="replace") if proxy_proc.stdout else ""
        print("\n=== proxy output ===")
        print(proxy_output)

        Path(servers_config_path).unlink(missing_ok=True)


if __name__ == "__main__":
    asyncio.run(main())