# Blast Radius

Maps the full impact chain from a CVE to the business assets at risk.

## How it works

```
CVE → Package → MCP Server → Agent → Credentials + Tools
```

For each vulnerability found, agent-bom traces:

1. **Which package** is affected
2. **Which MCP servers** depend on that package
3. **Which AI agents** (clients) connect to those servers
4. **Which credentials** are accessible through those agents
5. **Which tools** an attacker could invoke

## Usage

```bash
# CLI
agent-bom agents   # blast radius is included in scan output

# MCP tool
blast_radius(cve_id="CVE-2024-21538")
```

## Scoring

Each CVE gets a blast radius score (0–10) factoring in:

- CVSS base score
- EPSS exploit probability
- Number of affected agents
- Credential exposure count
- Tool access scope
- CISA KEV listing (known exploited)

## Context graph

The `context_graph` tool extends blast radius with lateral movement analysis — BFS traversal showing how compromising one server can reach others through shared agents.

```bash
# MCP tool
context_graph()
```
