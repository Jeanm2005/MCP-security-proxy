"""
Sends alerts to a Slack Incoming Webhook, if one is configured. Deliberately
a no-op (not an error) when SLACK_WEBHOOK_URL isn't set, so the whole
project still runs fine for anyone who hasn't set up Slack yet.

Setup: create an Incoming Webhook at https://api.slack.com/messaging/webhooks,
then set the env var: $env:SLACK_WEBHOOK_URL = "https://hooks.slack.com/..."
"""

import json
import os
import sys
import urllib.request

SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")

def send_slack_message(text: str) -> None:
    if not SLACK_WEBHOOK_URL:
        return

    payload = json.dump({"text": text}).encode("utf-8")
    req = urllib.request.Request(
        SLACK_WEBHOOK_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"[watchtower] Slack notify failed: {e}", file=sys.stderr)