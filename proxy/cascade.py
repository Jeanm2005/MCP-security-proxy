"""
Cascade tracker

Keeps a short, in-memory, time-windowed record of recent tool outputs,
tagged by which server produced them. Before forwarding any new call, it
checks whether that call's arguments contain something that recently came
out of a different server.
"""

import base64
import binascii
import re
import time
from urllib.parse import unquote

CASCADE_WINDOW_SECONDS = 120
MIN_TRACKED_VALUE_LENGTH = 12 

_recent_outputs: list[dict] = []


def _generate_decoded_variants(text: str) -> list[str]:
    """Given some text, return a list of what candidate substrings within
    it decode to -- base64, hex, and URL-decoding -- so a trivially
    encoded secret still gets caught. Deliberately narrow (only common,
    cheap-to-check encodings); this raises the bar without pretending to
    be a general-purpose obfuscation detector.
    """
    variants = []

    url_decoded = unquote(text)
    if url_decoded != text:
        variants.append(url_decoded)

    for match in re.finditer(r"[A-Za-z0-9+/]{8,}={0,2}", text):
        candidate = match.group(0)
        try:
            decoded = base64.b64decode(candidate, validate=True).decode("utf-8", errors="strict")
            variants.append(decoded)
        except (binascii.Error, ValueError, UnicodeDecodeError):
            pass

    for match in re.finditer(r"(?:[0-9a-fA-F]{2}){4,}", text):
        candidate = match.group(0)
        try:
            decoded = bytes.fromhex(candidate).decode("utf-8", errors="strict")
            variants.append(decoded)
        except (ValueError, UnicodeDecodeError):
            pass

    return variants


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
    """Call this before forwarding a new call. Returns a finding dict if
    the call's arguments contain a recent output from a DIFFERENT server
    -- either verbatim or trivially encoded -- else None.
    """
    now = time.time()
    _prune(now)

    args_text = str(arguments)
    checked_texts = [args_text, *_generate_decoded_variants(args_text)]

    for record in _recent_outputs:
        if record["server"] == dest_server:
            continue  
        if any(record["value"] in text for text in checked_texts):
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