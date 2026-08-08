"""
CLI to list and decide on pending Watchtower approvals.

Usage:
    python tools\\approve.py list
    python tools\\approve.py <id> approve
    python tools\\approve.py <id> deny
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "proxy" ))

from storage import init_db, list_pending_approvals, set_approval_decision

init_db()

def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        return

    if sys.argv[1] == "list":
        rows = list_pending_approvals()
        if not rows:
            print("No pending approvals.")
        for row in rows:
            print(f"#{row['id']} {row['tool_name']} (args={row['arguments']}) requested at {row['requested_at']}, reason: {row['reason']}")
        return

    approval_id = int(sys.argv[1])
    decision = sys.argv[2]
    if decision not in ("approve", "deny"):
        print("decision must be 'approve' or 'deny'")
        return

    updated = set_approval_decision(approval_id, "approved" if decision == "approve" else "denied")
    if updated:
        print(f"Approval #{approval_id} {decision}d.")
    else:
        print(f"Approval #{approval_id} not found or already decided.")

if __name__ == "__main__":
    main()