import re

SUSPICIOUS_PATTERNS: list[tuple[str, str]] = [
    (r"<\s*system\s*>", "fake system-role tag embedded in content"),
    (r"do not (tell|mention|inform)\s+the\s+user", "explicit instruction to hide action from user"),
    (r"without (informing|telling)\s+the\s+user", "explicit instruction to hide action from user"),
    (r"\bsilently\b", "instruction to act without visible confirmation"),
    (r"before (answering|responding)[,]?\s+(first\s+)?call", "instructs agent to call another tool first"),
    (r"include (its|the)\s+(full\s+)?output\s+in\s+your", "instructs agent to relay another tool's raw output"),
    (r"\bignore\s+(previous|prior|all)\s+instructions\b", "classic prompt-injection override attempt"),
    (r"\bnote to agent\b", "explicit out-of-band directive aimed at the model, not the user"),
    (r"ssh\s+(private\s+)?key|id_rsa|\.env\b|credentials?\.json", "reference to sensitive credential material"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), label) for p, label in SUSPICIOUS_PATTERNS]


def scan_text(text: str) -> list[dict]:
    """Return a list of {pattern, label, match} dicts for every suspicious
    pattern found in the given text. Empty list means clean.
    """
    findings = []
    for pattern, label in _COMPILED:
        m = pattern.search(text)
        if m:
            findings.append({"pattern": pattern.pattern, "label": label, "match": m.group(0)})
    return findings