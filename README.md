# Watchtower

**A hands-on runtime security gateway for MCP servers.**

[![CI](https://github.com/Jeanm2005/MCP-security-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/Jeanm2005/MCP-security-proxy/actions/workflows/ci.yml)
[![Scheduled Attack Simulation](https://github.com/Jeanm2005/MCP-security-proxy/actions/workflows/scheduled-attack-simulation.yml/badge.svg)](https://github.com/Jeanm2005/MCP-security-proxy/actions/workflows/scheduled-attack-simulation.yml)

**Live deployment:** `http://watchtower-security.dev:8000` — running on DigitalOcean Kubernetes right now. Try it:

```bash
curl http://watchtower-security.dev:8000/admin/findings?since=0
```

## What this is

Watchtower is a hands-on implementation of MCP runtime security concepts — the same attack taxonomy documented by OWASP's MCP Top 10 and Invariant Labs' own security research (tool poisoning, rug pulls, cross-server data flow/exfiltration) — built from scratch to understand these mechanisms deeply.

What's here is a fully working, CI-proven system: a persistent multi-server gateway with automatic reconnect, static and runtime tool-poisoning detection, fingerprint-diff rug-pull detection, cross-server cascade tracking, and a policy engine with human-approval workflows — deployed live on Kubernetes, and validated by an autonomous red/blue agent pair that has found and closed several real detection gaps through live adversarial testing (encoding evasion, fragmented reconstruction, character-reversal) rather than being described as "supported" without proof.

## What it catches

| Detector | What it looks for |
|---|---|
| Static tool poisoning | Hidden instructions embedded in a tool's description |
| Runtime response injection | Instructions smuggled into a tool's *response*, not its description |
| Rug pull (fingerprint drift) | A tool's description/schema silently changing between two connections |
| Cross-server cascade | Output from one server's tool appearing as input to a different server's tool — including several bounded, deterministic evasions (base64/hex/URL encoding, NATO phonetic spelling, character reversal, and multi-call fragment reconstruction), each found live by an autonomous red-team agent and fixed with a verified regression test |

Every detector above is backed by a real, adversarial test — a deliberately vulnerable lab server modeling each attack pattern, with both positive and negative test cases (so we know detection fires *and* doesn't false-positive on legitimate traffic).

## Autonomous red/blue testing

On top of the core gateway, Watchtower includes:

- **Blue agent** (`agents/blue/`) — runs continuously, reviews Watchtower's own findings via an LLM, and autonomously tightens policy (deny/require-approval) on tools showing real malicious patterns. Every decision is logged for audit.
- **Red agent** (`agents/red/`) — an LLM-driven adversary given a goal, not a fixed script. Discovers tools live, adapts when blocked, and has repeatedly found genuine detection gaps this project's own maintainer hadn't anticipated.

Both run as real Kubernetes workloads: the blue agent as a continuous Deployment, the red agent as an on-demand Job.

## Architecture

```
        Agent
          │
          │ MCP (streamable-http)
          ▼
   ┌─────────────┐
   │   Watchtower │──── policy engine (allow / deny / require_approval)
   │    Proxy     │──── detectors (poisoning, injection, rug-pull, cascade)
   │ (persistent, │──── admin API (agents talk to the proxy over HTTP only)
   │  shared      │──── SQLite audit log (persisted via Kubernetes PVC)
   │  gateway)    │
   └──────┬───────┘
          │
    ┌─────┴─────┐
    ▼           ▼
 filesrv     mailsrv
(container)  (container)
```

The proxy is a **persistent, shared service** — not spun up per-connection. Multiple agents connect to the same instance concurrently and share the same detection state, which is what makes cross-agent cascade detection possible: if Agent A reads a secret and disconnects, and Agent B connects fresh minutes later and tries to leak that same secret through a different server, Watchtower still catches it.

Each upstream connection is supervised independently with automatic reconnect and exponential backoff — a container restart underneath the proxy (a real, common event in Kubernetes) doesn't take the whole gateway down.

## Quickstart (local)

```bash
docker compose up --build
```

That's it — three containers (`filesrv`, `mailsrv`, `proxy`), networked, with the proxy's port published to `localhost:8000`. Prove it works:

```bash
python tests/test_docker_stack.py
docker compose logs proxy   # see the alerts fire
```

## Running on Kubernetes

Manifests are provided for three environments:

- `k8s/` — local development, tested against Docker Desktop's built-in Kubernetes
- `k8s-do/` — DigitalOcean Kubernetes (DOKS), the live deployment above
- `k8s-eks/` — AWS EKS, a reference deployment (built and torn down; not left running)

Each includes Deployments for `proxy`, `filesrv`, `mailsrv`, and the blue agent, a Service for the proxy, a PersistentVolumeClaim for the SQLite audit log, and Job manifests for on-demand red-agent runs.

## Repo structure

```
proxy/                 the gateway: routing, detectors, policy, cascade tracking
agents/blue/            the autonomous defender
agents/red/              the autonomous adversary
vulnerable-server/      lab target "filesrv" — deliberately vulnerable, used for testing
lab-server-b/           lab target "mailsrv" — the cross-server exfiltration destination
k8s/, k8s-do/, k8s-eks/  Kubernetes manifests for local, DigitalOcean, and AWS deployment
tests/                  self-contained tests (no Docker) + full Docker-stack tests
tools/                  approve.py (policy approval CLI), run_attack_simulation.py
.github/workflows/      CI (every push) + scheduled attack simulation (weekly, independent of code changes)
```

## Development

```bash
python -m venv venv
venv\Scripts\Activate.ps1   # or source venv/bin/activate
pip install -r requirements.txt
ruff check .
```

Branch flow: `develop` → `staging` → `main`, all gated on CI passing and PR review (see `.github/`).

## Status

Watchtower's detection core, policy engine, and Kubernetes deployment are complete, CI-proven, and running live. The autonomous red/blue agent pair continues to be the main active area of development — new adversarial findings are documented and fixed as they're found.