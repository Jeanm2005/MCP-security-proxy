"""
Small CLI to inspect watchtower.db without wrestling with PowerShell quoting
on inline python -c commands. Run from the repo root.

Usage:
    python tools\\inspect_db.py fingerprints
    python tools\\inspect_db.py calls
    python tools\\inspect_db.py descriptions
    python tools\\inspect_db.py all
"""
import sqlite3
import sys
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "proxy" / "watchtower.db"

def show(query: str, label: str) -> None:
    print(f"--- {label} ---")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(query).fetchall()
    if not rows:
        print("(no rows)")
    for row in rows:
        print(dict(row))
    conn.close()
    print()

def main() -> None:
    target = sys.argv[1] if len(sys.argv) > 1 else "all"

    if target in ("fingerprints", "all"):
        show("SELECT tool_name, last_flag, first_seen, last_seen FROM tool_fingerprints", "tool_fingerprints")

    if target in ("calls", "all"):
        show("SELECT id, tool_name, flags FROM calls WHERE flags IS NOT NULL", "flagged calls")

    if target in ("descriptions", "all"):
        show("SELECT tool_name, findings, timestamp FROM description_findings", "description_findings")


if __name__ == "__main__":
    main()