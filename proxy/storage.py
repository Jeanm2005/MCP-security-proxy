"""
Storage layer for Watchtower. SQLite for now -- trivially swappable for
Postgres later since everything goes through these functions, not raw SQL
scattered through proxy.py.
"""
import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path

DB_PATH = Path(os.environ.get("WATCHTOWER_DB_PATH", str(Path(__file__).parent / "watchtower.db")))


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

        CREATE TABLE IF NOT EXISTS cascade_findings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            source_server   TEXT NOT NULL,
            source_tool     TEXT NOT NULL,
            dest_server     TEXT NOT NULL,
            dest_tool       TEXT NOT NULL,
            matched_value   TEXT NOT NULL,
            timestamp       REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS pending_approvals (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            tool_name       TEXT NOT NULL,
            arguments       TEXT NOT NULL,
            reason          TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'pending',
            requested_at    TEXT NOT NULL,
            decided_at      REAL
        );

        CREATE TABLE IF NOT EXISTS policy_overrides (
            tool_name       TEXT PRIMARY KEY,
            action          TEXT NOT NULL,
            reason          TEXT NOT NULL,
            added_by        TEXT NOT NULL,
            created_at      REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS blue_agent_decisions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            tool_name       TEXT NOT NULL,
            decision        TEXT NOT NULL,
            reasoning       TEXT NOT NULL,
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

def log_cascade_findings(source_server, source_tool, dest_server, dest_tool, matched_value):
    conn = get_conn()
    conn.execute(
        "INSERT INTO cascade_findings (source_server, source_tool, dest_server, dest_tool, matched_value, timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (source_server, source_tool, dest_server, dest_tool, matched_value, time.time()),
    )
    conn.commit()
    conn.close()

def create_pending_approval(tool_name: str, arguments: dict, reason: dict) -> int:
    """Creates a pending approval row and returns its id."""
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO pending_approvals (tool_name, arguments, reason, status, requested_at) "
        "VALUES (?, ?, ?, 'pending', ?)",
        (tool_name, json.dumps(arguments), reason, time.time()),
    )
    conn.commit()
    approval_id = cur.lastrowid
    conn.close()
    return approval_id

def get_approval_status(approval_id: int) -> str:
    """Returns 'pending', 'approved', or 'denied'."""
    conn = get_conn()
    row = conn.execute(
        "SELECT status FROM pending_approvals WHERE id = ?", (approval_id,)
    ).fetchone()
    conn.close()
    return row["status"] if row else "denied"

def set_approval_decision(approval_id: int, decision: str) -> None:
    """Decision must be 'approved' or 'denied'."""
    conn = get_conn()
    cur = conn.execute(
        "UPDATE pending_approvals SET status = ?, decided_at = ? WHERE id = ?",
        (decision, time.time(), approval_id),
    )
    conn.commit()
    updated = cur.rowcount > 0
    conn.close()
    return updated

def list_pending_approvals() -> list[sqlite3.Row]:
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM pending_approvals WHERE status = 'pending' ORDER BY requested_at"
    ).fetchall()
    conn.close()
    return rows

def set_policy_override(tool_name: str, action: str, reason: str, added_by: str = "blue-agent") -> None:
    """Insert or update a runtime policy override. This is checked before
    policy.yaml, so the blue agent (or a human, via tools/) can tighten or
    loosen policy live without editing/redeploying the static config."""
    conn = get_conn()
    conn.execute(
        "INSERT INTO policy_overrides (tool_name, action, reason, added_by, created_at) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(tool_name) DO UPDATE SET action=excluded.action, reason=excluded.reason, "
        "added_by=excluded.added_by, created_at=excluded.created_at",
        (tool_name, action, reason, added_by, time.time()),
    )
    conn.commit()
    conn.close()

def get_policy_override(tool_name: str):
    """Returns (action, reason) if an override exists for this tool, else None."""
    conn = get_conn()
    row = conn.execute("SELECT action, reason FROM policy_overrides WHERE tool_name = ?", (tool_name,)).fetchone()
    conn.close()
    return (row["action"], row["reason"]) if row else None

def list_policy_overrides():
    conn = get_conn()
    rows = conn.execute("SELECT * FROM policy_overrides ORDER BY created_at DESC").fetchall()
    conn.close()
    return rows

def clear_policy_overrides(tool_name: str) -> bool:
    conn = get_conn()
    cur = conn.execute("DELETE FROM policy_overrides WHERE tool_name = ?", (tool_name,))
    conn.commit()
    updated = cur.rowcount > 0
    conn.close()
    return updated

def log_blue_agent_decision(tool_name: str, decision: str, reasoning: str) -> None:
    conn = get_conn()
    conn.execute(
        "INSERT INTO blue_agent_decisions (tool_name, decision, reasoning, timestamp) VALUES (?, ?, ?, ?)",
        (tool_name, decision, reasoning, time.time()),
    )
    conn.commit()
    conn.close()

def get_recent_findings(since_timestamp: float):
    """Everything the blue agent needs to reason about: flagged calls,
    description findings, rug pulls, and cascade findings since a given time."""
    conn = get_conn()
    findings = {
        "flagged_calls": conn.execute(
            "SELECT tool_name, arguments, response_text, flags, timestamp FROM calls "
            "WHERE flags IS NOT NULL AND timestamp > ? ORDER BY timestamp",
            (since_timestamp,),
        ).fetchall(),
        "description_findings": conn.execute(
            "SELECT tool_name, findings, timestamp FROM description_findings WHERE timestamp > ? ORDER BY timestamp",
            (since_timestamp,),
        ).fetchall(),
        "rug_pulls": conn.execute(
            "SELECT tool_name, last_seen FROM tool_fingerprints WHERE last_flag = 'rug_pull' AND last_seen > ?",
            (since_timestamp,),
        ).fetchall(),
        "cascade_findings": conn.execute(
            "SELECT source_server, source_tool, dest_server, dest_tool, matched_value, timestamp "
            "FROM cascade_findings WHERE timestamp > ? ORDER BY timestamp",
            (since_timestamp,),
        ).fetchall(),
    }
    conn.close()
    return findings