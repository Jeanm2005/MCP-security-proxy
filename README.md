# Watchtower

**A hands-on runtime security gateway for MCP servers.**

[![CI](https://github.com/Jeanm2005/MCP-security-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/Jeanm2005/MCP-security-proxy/actions/workflows/ci.yml)
[![Scheduled Attack Simulation](https://github.com/Jeanm2005/MCP-security-proxy/actions/workflows/scheduled-attack-simulation.yml/badge.svg)](https://github.com/Jeanm2005/MCP-security-proxy/actions/workflows/scheduled-attack-simulation.yml)

## What this is

Watchtower is a hands-on implementation of MCP runtime security concepts — the same attack taxonomy documented by OWASP's MCP Top 10 and Invariant Labs' own security research (tool poisoning, rug pulls, cross-server data flow/exfiltration) — built from scratch to understand these mechanisms deeply.

What's here is a fully working, CI-proven system: a persistent multi-server gateway with automatic reconnect, static and runtime tool-poisoning detection, fingerprint-diff rug-pull detection, cross-server cascade tracking, and a policy engine with human-approval workflows — all built and tested against real adversarial scenarios, not just described.

## What it catches

| Detector | What it looks for |
|---|---|
| Static tool poisoning | Hidden instructions embedded in a tool's description |
| Runtime response injection | Instructions smuggled into a tool's *response*, not its description |
| Rug pull (fingerprint drift) | A tool's description/schema silently changing between two connections |
| Cross-server cascade | Output from one server's tool appearing as input to a different server's tool |

Every detector above is backed by a real, adversarial test — a deliberately vulnerable lab server modeling each attack pattern, with both positive and negative test cases (so we know detection fires *and* doesn't false-positive on legitimate traffic).

## Architecture

  Agent
      │
      │ MCP (streamable-http)
      ▼

┌─────────────┐
│ Watchtower │──── policy engine (allow / deny / require_approval)
│ Proxy │──── detectors (poisoning, injection, rug-pull, cascade)
│ (persistent, │──── Slack alerting
│ shared │──── SQLite audit log
│ gateway) │
└──────┬───────┘
│
┌─────┴─────┐
▼ ▼
filesrv mailsrv
(container) (container)

The proxy is a **persistent, shared service** — not spun up per-connection. Multiple agents connect to the same instance concurrently and share the same detection state, which is what makes cross-agent cascade detection possible: if Agent A reads a secret and disconnects, and Agent B connects fresh minutes later and tries to leak that same secret through a different server, Watchtower still catches it.

Each upstream connection is supervised independently with automatic reconnect and exponential backoff — a container restart underneath the proxy (a real, common event in Kubernetes) doesn't take the whole gateway down.

## Quickstart

```bash
docker compose up --build
```

That's it — three containers (`filesrv`, `mailsrv`, `proxy`), networked, with the proxy's port published to `localhost:8000`. Prove it works:

```bash
python tests/test_docker_stack.py
docker compose logs proxy   # see the alerts fire
```

## Repo structure
proxy/ the gateway: routing, detectors, policy, cascade tracking
vulnerable-server/ lab target "filesrv" — deliberately vulnerable, used for testing
lab-server-b/ lab target "mailsrv" — the cross-server exfiltration destination
tests/ self-contained tests (no Docker) + full Docker-stack tests
tools/ approve.py (policy approval CLI), run_attack_simulation.py
.github/workflows/ CI (every push) + scheduled attack simulation (weekly, independent of code changes)


## Development

```bash
python -m venv venv
venv\Scripts\Activate.ps1   # or source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt   # ruff
ruff check .
```

Branch flow: `develop` → `staging` → `main`, all gated on CI passing and PR review (see `.github/`).

## Roadmap

Watchtower's detection core is complete and CI-proven. Next: extending this into a multi-agent red/blue teaming platform, orchestrated on Kubernetes.