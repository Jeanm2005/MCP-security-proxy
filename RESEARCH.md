# Research direction: aggregation inference in MCP agent traffic

Watchtower's cascade detector currently catches exfiltration by literal
match — does a value that came out of one server's tool show up, verbatim,
as input to another server's tool. That's real and it works, but it's a
narrower problem than what the security research community currently
identifies as unsolved.

## The actual open problem

A 2026 paper on agentic identity governance states directly that the
*aggregation inference problem* -- whether a combination of individually
authorized, individually harmless data accesses can jointly reveal
something none of them exposes alone -- remains unsolved in the general
case (Authorization Propagation in Multi-Agent AI Systems, arXiv
2605.05440). The same paper cites a documented attack technique with a
roughly 71% success rate that works specifically by splitting a sensitive
request into several individually-benign subtasks. A separate paper
(MosaicLeaks, arXiv 2605.30727) built a dedicated benchmark around the
same effect for research agents combining private and public data
sources.

This isn't a new idea in principle -- "the mosaic effect" is a
long-recognized problem in classified-information handling and
statistical database security. What's new is how much easier LLM agents
make it to pull off automatically, at scale, across ordinary-looking tool
calls.

## Why this project is aimed at it

Every MCP-focused security tool reviewed for this project (mcp-scan,
MCP-Shield, Toxic Flow Analysis) -- and Watchtower's own cascade detector
as it exists today -- operates at the literal-match level: exact string
reuse across a server boundary. None of them reason about whether several
individually-harmless outputs, combined, add up to something sensitive
none of them state on their own. That's the gap this project is
consciously building toward, not solving outright.

## Planned approach (first attempt, not a claimed solution)

- Track a sliding window of recent tool outputs (not just the single most
  recent one, as the current cascade detector does).
- Use embedding similarity to find outputs that are topically related
  even without literal overlap.
- Use an LLM judge over that related set to assess whether the
  combination reveals something none of the individual outputs state.

This is explicitly an experiment layered on top of the existing,
proven, literal-match cascade detector -- not a replacement for it. The
literal-match detector stays as the reliable baseline; the aggregation-
inference work is the frontier piece, and it may not fully work. That's
expected and worth documenting honestly as it develops, including
approaches that don't pan out.

## Sources

- Authorization Propagation in Multi-Agent AI Systems: Identity
  Governance as Infrastructure. arXiv:2605.05440.
- MosaicLeaks: Privacy Risks in Querying-in-the-Open for Deep Research
  Agents. arXiv:2605.30727.
- Coalition for Secure AI (CoSAI), The Future of Agentic Security: From
  Chatbots to Autonomous Swarms, May 2026.