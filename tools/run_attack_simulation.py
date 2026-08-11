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
LOCAL_DB_PATH = REPO_ROOT / "proxy" / "watchtower.db"
DOCKER_DB_COPY_PATH = REPO_ROOT / "docker_watchtower.db"

SELF_CONTAINED_SCENARIOS = [
    ("Lab target sanity check", "tests/smoke_test.py"),
    ("Static poisoning + policy + runtime injection", "tests/test_proxy_e2e.py"),
    ("Rug-pull via schema change + reconnect", "tests/test_rugpull_schema.py"),
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
    print(f" {'OK' if ok else 'FAILED (nonzero exit)'}")
    if not ok:
        print(result.stdout[-2000:])
        print(result.stderr[-2000:])
    print()
    return ok

def run_docker_scenario() -> bool:
    print("--- Running: Full Docker Compose stack (cross-server cascade detection) ---")

    def run(cmd, **kwargs):
        return subprocess.run(cmd, cwd=(REPO_ROOT), check=False, **kwargs)

    run(["docker", "compose", "up", "--build", "-d", "proxy", "filesrv", "mailsrv"])

    print(" waiting for proxy to be reachable...")
    up = False
    for _ in range(30):
        result = run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "http://localhost:8000/mcp"],
            capture_output=True,
            text=True,
        )
        if result.stdout.strip():
            up = True
            break
        time.sleep(1)

    if not up:
        print(" FAILED: proxy never became reachable")
        run(["docker", "compose", "logs", "proxy"])
        run(["docker", "compose", "down", "-v"])
        return False

    test_result = run(
        [sys.executable, "tests/test_docker_stack.py"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    ok = test_result.returncode == 0
    print(f" {'OK' if ok else 'FAILED (nonzero exit)'}")
    if not ok:
        print(test_result.stdout[-2000:])
        print(test_result.stderr[-2000:])

    DOCKER_DB_COPY_PATH.unlink(missing_ok=True)
    run(["docker", "compose", "cp", "proxy:/app/data/watchtower.db", str(DOCKER_DB_COPY_PATH)])
    run(["docker", "compose", "logs", "proxy"])
    run(["docker", "compose", "down"])

    print()
    return ok

def verify_counts(db_path: Path, checks: dict) -> list:
    if not db_path.exists():
        return [f"expected database at {db_path}, but it doesn't exist"]

    failures = []
    conn = sqlite3.connect(db_path)
    for message, query in checks.items():
        count = conn.execute(query).fetchone()[0]
        if count == 0:
            failures.append(message)
    conn.close()
    return failures

def main() -> None:
    LOCAL_DB_PATH.unlink(missing_ok=True)

    scenario_results = [run_scenario(label, script) for label, script in SELF_CONTAINED_SCENARIOS]
    docker_ok = run_docker_scenario()

    print("=== Verifying self-contained detections against the database ===")
    self_contained_failures = verify_counts(
        LOCAL_DB_PATH,
        {
            "no flagged calls found -- runtime response injection detection may be broken":
                "SELECT COUNT(*) FROM calls WHERE flags IS NOT NULL",
            "no description findings found -- static tool poisoning detection may be broken":
                "SELECT COUNT(*) FROM description_findings",
            "no rug-pull detections found -- fingerprint-diff detection may be broken":
                "SELECT COUNT(*) FROM tool_fingerprints WHERE last_flag = 'rug_pull'",
        },
    )

    print("=== Verifying Docker-stack cascade detection against the database ===")
    docker_failures = verify_counts(
        DOCKER_DB_COPY_PATH,
        {
            "no cascade findings found -- cross-server cascade detection may be broken":
                "SELECT COUNT(*) FROM cascade_findings",
        },
    )

    print("=== SUMMARY ===")
    for (label, _), ok in zip(SELF_CONTAINED_SCENARIOS, scenario_results):
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    print(f"  [{'PASS' if docker_ok else 'FAIL'}] Full Docker Compose stack")

    all_failures = self_contained_failures + docker_failures
    if all_failures:
        print("\nDetection verification FAILED:")
        for f in all_failures:
            print(f"  - {f}")

    if all(scenario_results) and docker_ok and not all_failures:
        print("\nALL CHECKS PASSED")
        sys.exit(0)
    else:
        print("\nATTACK SIMULATION FAILED -- see above")
        sys.exit(1)


if __name__ == "__main__":
    main()