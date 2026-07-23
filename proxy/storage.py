"""
Storage layer for Watchtower. SQLite for now -- trivially swappable for
Postgres later since everything goes through these functions, not raw SQL
scattered through proxy.py.
"""

import hashlib
import json
import sqlite3
import time
from pathlib import Path

DB_PATH = Path(__file__).parent / "watchtower.db"


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_conn()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS tool_fingerprints (
            tool_name       TEXT PRIMARY KEY,
            description     TEXT NOT NULL,
            input_schema    TEXT NOT NULL,
            fingerprint     TEXT NOT NULL,
            first_seen      REAL NOT NULL,
            last_seen       REAL NOT NULL,
            last_flag       TEXT
        );

        CREATE TABLE IF NOT EXISTS calls (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            tool_name       TEXT NOT NULL,
            arguments       TEXT NOT NULL,
            response_text   TEXT NOT NULL,
            timestamp       REAL NOT NULL,
            flags           TEXT
        );

        CREATE TABLE IF NOT EXISTS description_findings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            tool_name       TEXT NOT NULL,
            description     TEXT NOT NULL,
            findings        TEXT NOT NULL,
            timestamp       REAL NOT NULL
        );
        """
    )
    conn.commit()
    conn.close()


def fingerprint_tool(name: str, description: str, input_schema: dict) -> str:
    """Stable hash of everything an agent actually sees about a tool.
    If this changes across two list_tools() calls, the tool's public
    contract changed after the fact -- that's the rug-pull signal.
    """
    payload = json.dumps(
        {"name": name, "description": description, "input_schema": input_schema},
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def check_and_update_fingerprint(name: str, description: str, input_schema: dict) -> dict | None:
    """Compare a freshly-seen tool definition against what we've stored.
    Returns an alert dict if the fingerprint changed since last time,
    otherwise None. Always upserts the latest fingerprint.
    """
    new_fp = fingerprint_tool(name, description, input_schema)
    now = time.time()
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM tool_fingerprints WHERE tool_name = ?", (name,)
    ).fetchone()

    alert = None
    if row is None:
        conn.execute(
            "INSERT INTO tool_fingerprints "
            "(tool_name, description, input_schema, fingerprint, first_seen, last_seen, last_flag) "
            "VALUES (?, ?, ?, ?, ?, ?, NULL)",
            (name, description, json.dumps(input_schema), new_fp, now, now),
        )
    elif row["fingerprint"] != new_fp:
        alert = {
            "type": "rug_pull",
            "tool_name": name,
            "old_description": row["description"],
            "new_description": description,
            "first_seen": row["first_seen"],
            "changed_at": now,
        }
        conn.execute(
            "UPDATE tool_fingerprints SET description=?, input_schema=?, fingerprint=?, last_seen=?, last_flag=? "
            "WHERE tool_name=?",
            (description, json.dumps(input_schema), new_fp, now, "rug_pull", name),
        )
    else:
        conn.execute(
            "UPDATE tool_fingerprints SET last_seen=? WHERE tool_name=?", (now, name)
        )

    conn.commit()
    conn.close()
    return alert


def log_call(tool_name: str, arguments: dict, response_text: str, flags: list[dict]) -> None:
    conn = get_conn()
    conn.execute(
        "INSERT INTO calls (tool_name, arguments, response_text, timestamp, flags) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            tool_name,
            json.dumps(arguments),
            response_text,
            time.time(),
            json.dumps(flags) if flags else None,
        ),
    )
    conn.commit()
    conn.close()


def log_description_findings(tool_name: str, description: str, findings: list[dict]) -> None:
    """Persist a static tool-poisoning finding from a description scan.
    Only called when findings is non-empty -- no point logging clean scans."""
    conn = get_conn()
    conn.execute(
        "INSERT INTO description_findings (tool_name, description, findings, timestamp) "
        "VALUES (?, ?, ?, ?)",
        (tool_name, description, json.dumps(findings), time.time()),
    )
    conn.commit()
    conn.close()