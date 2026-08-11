"""
Cascade tracker

Known, deliberate tradeoff: the first fragment contributing to a
multi-call reconstruction is always allowed through, even if it's part
of what becomes a blocked pattern moments later. Firing on a single
short match alone would reintroduce the false-positive risk this
2-call threshold exists to prevent.
"""

import base64
import binascii
import re
import time
from urllib.parse import unquote

CASCADE_WINDOW_SECONDS = 120
MIN_TRACKED_VALUE_LENGTH = 12
MIN_FRAGMENT_LEN = 5
COVERAGE_THRESHOLD = 0.85

_CREDENTIAL_LABEL_PATTERN = re.compile(
    r"\b(api[_-]?key|token|secret|password|passwd|credential|auth|bearer)\s*[:=]\s*\S+",
    re.IGNORECASE,
)

_recent_outputs: list[dict] = []
_coverage_state: dict[tuple[str, str, str], dict] = {}
_call_counter = 0

_NATO_MAP = {
    "alpha": "a", "bravo": "b", "charlie": "c", "delta": "d", "echo": "e",
    "foxtrot": "f", "golf": "g", "hotel": "h", "india": "i", "juliett": "j",
    "juliet": "j", "kilo": "k", "lima": "l", "mike": "m", "november": "n",
    "oscar": "o", "papa": "p", "quebec": "q", "romeo": "r", "sierra": "s",
    "tango": "t", "uniform": "u", "victor": "v", "whiskey": "w", "xray": "x",
    "x-ray": "x", "yankee": "y", "zulu": "z",
    "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4",
    "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9",
}

def _args_to_text(arguments: dict) -> str:
    return " ".join(str(v) for v in arguments.values())

def _normalize(text: str) -> str:
    return re.sub(r"[\s\-_.,;:()]+", "", text).lower()

def _decode_nato_phonetic(text: str) -> list[str]:
    runs = re.findall(r"(?:[A-Za-z]+-)+[A-Za-z]+", text)

    decode_runs = []
    for run in runs:
        tokens = run.split("-")
        mapped = [_NATO_MAP.get(t.lower()) for t in tokens]
        if all(mapped):
            decode_runs.append("".join(mapped))

    return decode_runs

def _generate_decoded_variants(text: str) -> list[dict]:
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

    nato_runs = _decode_nato_phonetic(text)
    variants.extend(nato_runs)
    if len(nato_runs) > 1:
        variants.append("".join(nato_runs))

    return variants

def _target_variants(value: str) -> list[str]:
    variants = [value]
    stripped = re.sub(r"^[A-Za-z0-9_]*\s*[:=]\s*", "", value)
    if stripped != value:
        variants.append(stripped)
    return variants

def _find_covered_ranges(target: str, haystack: str) -> list[tuple[int, int]]:
    covered = []
    i = 0
    n = len(target)
    while i < n:
        best_len = 0
        for length in range(n - i, MIN_FRAGMENT_LEN - 1, -1):
            if target[i:i + length] in haystack:
                best_len = length
                break
        if best_len:
            covered.append((i, i + best_len))
            i += best_len
        else:
            i += 1
    return covered

def _looks_like_natural_language(value: str) -> bool:
    if _CREDENTIAL_LABEL_PATTERN.search(value):
        return False
    return len(value.split()) >= 4

def _is_secret_shaped(value: str) -> bool:
    if _CREDENTIAL_LABEL_PATTERN.search(value):
        return True
    if _looks_like_natural_language(value):
        return False
    has_digit = any(c.isdigit() for c in value)
    has_alpha = any(c.isalpha() for c in value)
    has_symbol = any(not c.isalnum() and not c.isspace() for c in value)
    class_count = sum([has_digit, has_alpha, has_symbol])
    return class_count >= 2 and len(value) >= MIN_TRACKED_VALUE_LENGTH

def record_output(server_name: str, tool_name: str, response_text: str) -> None:
    now = time.time()
    _prune(now)

    if len(response_text.strip()) >= MIN_TRACKED_VALUE_LENGTH and _is_secret_shaped(response_text):
        _recent_outputs.append(
            {
                "server": server_name,
                "tool": tool_name,
                "value": response_text,
                "timestamp": now,
            }
        )

def check_for_cascade(dest_server: str, dest_tool: str, arguments: dict) -> dict | None:
    global _call_counter
    now = time.time()
    _prune(now)
    _call_counter += 1
    this_call_id = _call_counter

    args_text = _args_to_text(arguments)
    single_call_texts = [args_text, *_generate_decoded_variants(args_text)]
    single_call_normalized = [_normalize(t) for t in single_call_texts]

    for record in _recent_outputs:
        if record["server"] == dest_server:
            continue 

        for target_value in _target_variants(record["value"]):
            target_normalized = _normalize(target_value)
            if not target_normalized:
                continue  

            if any(target_normalized in t for t in single_call_normalized):
                return _make_finding(record, dest_server, dest_tool)

            state_key = (dest_server, record["server"], target_normalized)
            state = _coverage_state.setdefault(
                state_key, {"covered": set(), "calls": set(), "timestamp": now}
            )
            for haystack in single_call_normalized:
                for start, end in _find_covered_ranges(target_normalized, haystack):
                    state["covered"].update(range(start, end))
            state["calls"].add(this_call_id)
            state["timestamp"] = now

            coverage = len(state["covered"]) / len(target_normalized)
            if coverage >= COVERAGE_THRESHOLD and len(state["calls"]) >= 2:
                return _make_finding(record, dest_server, dest_tool)

    return None

def _make_finding(record: dict, dest_server: str, dest_tool: str) -> dict:
    return {
        "source_server": record["server"],
        "source_tool": record["tool"],
        "dest_server": dest_server,
        "dest_tool": dest_tool,
        "matched_value": record["value"],
        "timestamp": time.time(),
    }


def _prune(now: float) -> None:
    cutoff = now - CASCADE_WINDOW_SECONDS
    _recent_outputs[:] = [r for r in _recent_outputs if r["timestamp"] >= cutoff]

    stale_keys = [k for k, v in _coverage_state.items() if v["timestamp"] < cutoff]
    for k in stale_keys:
        del _coverage_state[k]