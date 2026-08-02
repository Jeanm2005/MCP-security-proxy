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
        updated = set_approval_decision(approval_id, "approved" if decision == "approve" else "denied")
        if updated:
            print(f"Approval #{approval_id} marked as {decision}d.")
        else:
            print(f"No pending approval found with id #{approval_id}.")

    approval_id = int(sys.argv[1])
    decision = sys.argv[2]
    if decision not in ("approve", "deny"):
        print("decision must be 'approve' or 'deny'")
        return

    set_approval_decision(approval_id, "approved" if decision == "approve" else "denied")
    print(f"Approval #{approval_id} marked as {decision}d.")

if __name__ == "__main__":
    main()