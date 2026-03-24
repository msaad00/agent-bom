# ADR-004: Proxy-Based Runtime Enforcement

**Status:** Accepted
**Date:** 2026-03-11

## Context

Static scanning catches known CVEs and configuration issues, but cannot detect
runtime attacks like tool poisoning (rug pulls), credential exfiltration,
prompt injection via tool arguments, or rate-limit abuse. MCP servers
communicate over stdio — there is no network layer to intercept at the
transport level.

We need runtime protection that works without modifying MCP server code or
requiring endpoint agents on every machine.

## Decision

Implement a **stdio MCP proxy** (`proxy.py`) that sits between the MCP client
and server, intercepting all JSON-RPC messages. The proxy:

1. **Relays** messages bidirectionally (client ↔ server)
2. **Inspects** every tool call and response through a detector pipeline
3. **Enforces** policies (block/allow/audit per tool, per argument pattern)
4. **Logs** all traffic to JSONL audit files for forensic replay

**Detector pipeline (8 detectors):**

| Detector | Threat |
|----------|--------|
| ToolDrift | Rug pull — server changes tool definitions after initial handshake |
| ArgumentAnalyzer | Prompt injection / command injection in tool arguments |
| CredentialLeak | API keys, tokens, secrets in tool responses |
| RateLimit | Per-tool sliding window rate limiting (deque-based) |
| SequenceAnalyzer | Multi-step exfiltration patterns (read→encode→send) |
| ResponseInspector | Cloaking attacks, SVG injection, invisible Unicode |
| VectorDBInjection | Injection in vector DB query/retrieval payloads |

**Deployment model:** Users configure their MCP client to run
`agent-bom proxy <original-command>` instead of the direct server command.
The `proxy-configure` command automates this wrapping for all discovered
servers.

**Alternatives considered:**

1. *Network proxy (HTTP MITM)* — Only works for SSE/HTTP MCP transports.
   Most MCP servers use stdio. Would miss the majority of deployments.
2. *Endpoint agent* — Requires installation on every machine running MCP
   servers. Too heavy for an open-source tool; better suited for enterprise
   products.
3. *Server-side middleware* — Requires modifying each MCP server's code.
   Not practical for third-party servers.

## Consequences

- **Positive:** Works with any stdio MCP server without code changes.
- **Positive:** Zero-trust: every message is inspected, regardless of server
  trust level.
- **Positive:** JSONL audit log enables forensic replay and SIEM integration.
- **Positive:** Policy-as-code: declarative JSON policies with 17 condition
  types + expression engine.
- **Trade-off:** Adds ~1-5ms latency per message for detector pipeline.
  Acceptable for interactive AI assistant usage.
- **Trade-off:** Must be explicitly configured per server. Not transparent
  like a network proxy. The `proxy-configure` command mitigates this.
- **Trade-off:** Cannot protect HTTP/SSE MCP servers (separate transport).
  Future work: HTTP reverse proxy mode.
