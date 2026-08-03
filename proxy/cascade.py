"""
Cascade tracker

Keeps a short, in-memory, time-windowed record of recent tool outputs,
tagged by which server produced them. Before forwarding any new call, it
checks whether that call's arguments contain something that recently came
out of a different server.
"""

import time

CASCADE_WINDOW_SECONDS = 120
MIN_TRACKED_VALUE_LENGTH = 12

_recent_outputs: list[dict] = []

def record_output(server_name: str, tool_name: str, response_text: str) -> None:
    """Call this after every successful tool call, with its response."""
    now = time.time()
    _prune(now)

    if len(response_text.strip()) >= MIN_TRACKED_VALUE_LENGTH:
        _recent_outputs.append(
            {
                "server": server_name,
                "tool": tool_name,
                "value": response_text,
                "timestamp": now,
            }
        )

def check_for_cascade(dest_server: str, dest_tool: str, arguments: dict) -> dict | None:
    """
    Call this before forwarding a new call. Returns a finding dict if
    the call's arguments contain a recent output from a different server,
    else None.
    """
    now = time.time()
    _prune(now)

    args_text = str(arguments)

    for record in _recent_outputs:
        if record["server"] == dest_server:
            continue
        if record["value"] in args_text:
            return {
                "source_server": record["server"],
                "source_tool": record["tool"],
                "dest_server": dest_server,
                "dest_tool": dest_tool,
                "matched_value": record["value"],
                "timestamp": now,
            }

    return None

def _prune(now: float) -> None:
    cutoff = now - CASCADE_WINDOW_SECONDS
    _recent_outputs[:] = [r for r in _recent_outputs if r["timestamp"] >= cutoff]