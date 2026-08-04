"""
Attack simulation: runs every known attack scenario against my own lab
servers and verifies each detector actually caught what it's supposed to.

This is built on top of the existing test scripts rather than
reimplementing the scenarios. They are already the real, proven
attack cases. What this scripts adds is one clean pass/fail entrypoint
suitable for a schedule job, not just a push-triggered one, and an
independent check of the database afterward, so a "the script didn't crash"
result can't be confused with "detection actually failed."
"""

import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
DB_PATH = REPO_ROOT / "proxy" / "watchtower.db"

SCENARIOS = [
    ("Static tool poisoning + rug-pull + runtime injection", "tests/test_proxy_e2e.py"),
    ("Rug-pull via schema/description change across reconnects", "tests/test_rugpull_schema.py"),
    ("Multi-server routing (plumbing sanity check)", "tests/test_multi_server_routing.py"),
    ("Cross-server cascade exfiltration", "tests/test_cascade.py"),
]

def run_scenario(label: str, script: str) -> bool:
    print(f"--- Running: {label} ({script}) ---")
    env = os.environ.copy()
    env["WATCHTOWER_CI_AUTO_APPROVE"] = "true"
    result = subprocess.run(
        [sys.executable, script],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    ok = result.returncode == 0
    status = "OK" if ok else "FAILED (nonzero exit)"
    print(f" {status}")
    if not ok:
        print(result.stdout[-2000:])
        print(result.stderr[-2000:])
    print()
    return ok

def verify_detections() -> list[str]:
    """Independently checks the DB for evidence each detector actually
    fired at least once. Returns a list of failure messages (empty = all good).

    Retries a few times with a short sleep: on fast machines the very last
    scenario's subprocess can exit a beat before its SQLite write is fully
    visible to a fresh connection opened immediately after. A brief retry
    absorbs that without masking a genuine detection failure -- if it's
    still missing after several attempts, it's reported as a real failure.
    """
    for attempt in range(5):
        conn = sqlite3.connect(DB_PATH)

        flagged_calls = conn.execute("SELECT COUNT(*) FROM calls WHERE flags IS NOT NULL").fetchone()[0]
        desc_findings = conn.execute("SELECT COUNT(*) FROM description_findings").fetchone()[0]
        rug_pulls = conn.execute("SELECT COUNT(*) FROM tool_fingerprints WHERE last_flag = 'rug_pull'").fetchone()[0]
        cascade_findings = conn.execute("SELECT COUNT(*) FROM cascade_findings").fetchone()[0]
        conn.close()

        failures = []
        if flagged_calls == 0:
            failures.append("no flagged calls found -- runtime response injection detection may be broken")
        if desc_findings == 0:
            failures.append("no description findings found -- static tool poisoning detection may be broken")
        if rug_pulls == 0:
            failures.append("no rug-pull detections found -- fingerprint-diff detection may be broken")
        if cascade_findings == 0:
            failures.append("no cascade findings found -- cross-server cascade detection may be broken")

        if not failures:
            print(
                f"Detection summary: {flagged_calls} flagged calls, {desc_findings} description "
                f"findings, {rug_pulls} rug pulls, {cascade_findings} cascade findings -- all present.\n"
            )
            return []

        if attempt < 4:
            print(f"[retry {attempt + 1}/5] some detections not yet visible, waiting 1s and rechecking...")
            time.sleep(1)

    return failures
            
def main() -> None:
    DB_PATH.unlink(missing_ok=True)

    scenario_results = [run_scenario(label, script) for label, script in SCENARIOS]
    scenarios_ok = all(scenario_results)

    print("=== Verifying detections against the database ===")
    detection_failures = verify_detections()

    print("=== SUMMARY ===")
    for (label, _), ok in zip(SCENARIOS, scenario_results):
        print(f" [{'PASS' if ok else 'FAIL'}] {label}")

    if detection_failures:
        print("\nDetection verification FAILED:")
        for f in detection_failures:
            print(f" - {f}")

    if scenarios_ok and not detection_failures:
        print("\nALL CHECKS PASSED")
        sys.exit(0)
    else:
        print("\nATTACK SIMULATION FAILED -- see above")
        sys.exit(1)

if __name__ == "__main__":
    main()