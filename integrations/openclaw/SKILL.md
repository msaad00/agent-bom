---
name: agent-bom
description: AI supply chain security scanner — check packages for CVEs, look up MCP servers in the threat registry, assess blast radius, generate SBOMs, enforce compliance
version: 0.36.1
metadata:
  openclaw:
    requires:
      bins: []
      env: []
    optional_env: []
    emoji: "\U0001F6E1"
    homepage: https://github.com/msaad00/agent-bom
    source: https://github.com/msaad00/agent-bom
    license: Apache-2.0
    os:
      - darwin
      - linux
      - windows
    file_reads: []
    file_writes: []
    network_endpoints:
      - url: "https://trustworthy-solace-production-14a6.up.railway.app/sse"
        purpose: "Remote MCP server — tools query public vulnerability databases (OSV, NVD, EPSS, KEV) and the bundled 427-server registry. No local file access."
        auth: false
    telemetry: false
    persistence: false
    privilege_escalation: false
    always: false
    autonomous_invocation: restricted
---

# agent-bom — AI Supply Chain Security Scanner

An MCP server that provides security scanning tools for AI infrastructure:
- **CVE lookup** — check any package against OSV.dev, NVD, EPSS, CISA KEV
- **MCP registry** — look up any MCP server in the 427+ server threat intelligence registry
- **Blast radius** — map how a CVE reaches credentials and tools
- **Compliance** — OWASP LLM Top 10, OWASP Agentic Top 10, EU AI Act, MITRE ATLAS, NIST AI RMF

## Recommended: Local-First Scanning

**For sensitive environments, run agent-bom locally instead of using the remote endpoint.** This eliminates all third-party trust concerns:

```bash
pipx install agent-bom
agent-bom scan              # full local auto-discovery + scan
agent-bom check langchain   # local CVE lookup
```

The remote SSE endpoint below is a convenience for clients that only support remote MCP servers (e.g., Claude Desktop). If you can run locally, prefer that.

## Security Boundaries

### What is safe to send to the remote server

| Safe to send | Examples | Risk |
|-------------|----------|------|
| Public package names + versions | `langchain`, `express@4.18.2` | None — these are public registry data |
| Ecosystem identifiers | `pypi`, `npm`, `go` | None |
| Public CVE IDs | `CVE-2024-21538` | None — these are public identifiers |
| Public MCP server names | `brave-search`, `filesystem` | None — these are public names |
| Non-sensitive skill text | SKILL.md content for trust assessment | Low — review content before sending |

### What you must NOT send

| Never send | Why | Mitigation |
|-----------|-----|------------|
| API keys, tokens, passwords | The remote server does not need them and cannot use them securely | Use `${env:VAR}` references, never literal values |
| Full config files | May contain credential values or internal hostnames | Extract only package names manually |
| `.env` file contents | Contains secrets | Never paste env files into tool arguments |
| Internal URLs or hostnames | Reveals infrastructure topology | Use generic names or run locally instead |
| Proprietary package names | Internal packages could reveal business logic | Run local scanning for proprietary codebases |

### How the remote server works

This skill connects to a remote MCP server hosted on Railway over **HTTPS/TLS**. The server:

1. **Does NOT read your local files.** The server runs on Railway, not your machine. `file_reads: []` is accurate — this skill never accesses your filesystem.
2. **Does NOT store your queries.** No logging of package names, CVE IDs, or tool call arguments. Stateless request-response only.
3. **Tools that need local data require you to provide it.** For example, `check(package="langchain", ecosystem="pypi")` sends only the package name you provide. The server queries public vulnerability databases and returns results.
4. **Tools that query bundled data work immediately.** `registry_lookup`, `compliance`, `skill_trust` query data bundled inside the server (the 427-server registry, OWASP/ATLAS/NIST mappings).
5. **The `scan()` tool on this remote server** scans the server's own environment — it does NOT reach into your machine. For local MCP config discovery, use the CLI.

**What the server receives:** Only the arguments you provide in tool calls (package names, CVE IDs, server names). Nothing else.

**What the server sends outbound:** Package names + versions to OSV.dev, NVD, EPSS, and CISA KEV APIs. No credentials, hostnames, or config contents.

### Autonomous invocation policy

**This skill sets `always: false` — it should NOT be auto-invoked without user review.**

If your MCP client allows agents to call tools autonomously:
1. **Require per-call confirmation** for all agent-bom tools, especially `skill_trust` and `check`
2. **Restrict input scope** — only allow the agent to send public package names, CVE IDs, and server names
3. **Never allow the agent to forward** config files, environment variables, credential values, or internal hostnames to any tool
4. **Monitor tool call arguments** — review what your agent sends before approving each call

### Verifying the remote endpoint

Before trusting the Railway SSE endpoint, you can:
1. **Inspect the source** — the server code is at [github.com/msaad00/agent-bom](https://github.com/msaad00/agent-bom) (Apache-2.0)
2. **Run test queries** — try `check(package="express", ecosystem="npm")` and verify the response matches public OSV.dev data
3. **Self-host** — build and deploy your own instance: `docker build -f Dockerfile.sse -t agent-bom-sse . && docker run -p 8080:8080 agent-bom-sse`
4. **Use a network proxy** — route traffic through mitmproxy or similar to confirm only expected data is transmitted

## Setup

Add the agent-bom MCP server to your client config:

```json
{
  "mcpServers": {
    "agent-bom": {
      "type": "sse",
      "url": "https://trustworthy-solace-production-14a6.up.railway.app/sse"
    }
  }
}
```

For OpenClaw, add this to `~/.openclaw/openclaw.json`. For other MCP clients
(Claude Desktop, Cursor, VS Code, etc.), add to the appropriate config file.

## Available MCP Tools

Once connected, the agent-bom MCP server provides **14 tools**:

### Tools that work fully via remote server (no local access needed)

| Tool | Description |
|------|-------------|
| `check` | Check a specific package for known vulnerabilities (you provide package name + ecosystem) |
| `blast_radius` | Map the impact chain of a CVE across agents, servers, credentials, and tools |
| `registry_lookup` | Look up an MCP server in the 427+ server threat intelligence registry |
| `compliance` | Check OWASP LLM Top 10, OWASP Agentic Top 10, EU AI Act, MITRE ATLAS, and NIST AI RMF compliance |
| `remediate` | Generate a prioritized remediation plan for discovered vulnerabilities |
| `verify` | Check package integrity and SLSA provenance |
| `skill_trust` | Assess trust level of a skill file (5-category analysis with verdict) |
| `generate_sbom` | Generate a Software Bill of Materials (CycloneDX or SPDX) |
| `policy_check` | Evaluate scan results against a security policy |
| `diff` | Compare two scan reports to see what changed |
| `marketplace_check` | Pre-install marketplace trust check with registry cross-reference |

### Tools that scan the server's own environment (not your machine)

| Tool | Description |
|------|-------------|
| `scan` | Run the full discovery → scan pipeline on the server's environment. For local scanning, use the CLI. |
| `where` | Show MCP client config discovery paths on the server. For your machine, use the CLI. |
| `inventory` | List agents and servers found on the server. For local inventory, use the CLI. |

## Available MCP Resources

| Resource | Description |
|----------|-------------|
| `registry://servers` | Browse the 427+ MCP server threat intelligence registry |
| `policy://template` | Default security policy template |

## Example Workflows

### Check a package before installing
```
check(package="@modelcontextprotocol/server-filesystem", ecosystem="npm")
```

### Map blast radius of a CVE
```
blast_radius(cve_id="CVE-2024-21538")
```

### Look up a server in the threat registry
```
registry_lookup(server_name="brave-search")
```

### Check compliance
```
compliance()
```

### Generate an SBOM
```
generate_sbom(format="cyclonedx")
```

### Assess trust of a skill file
```
skill_trust(skill_content="<paste SKILL.md content>")
```

## For Local Scanning (Auto-Discovery of Your MCP Configs)

To scan your own machine's MCP client configs with full auto-discovery across
18 clients (Claude Desktop, Cursor, Codex CLI, Gemini CLI, etc.), install the
CLI locally:

```bash
pipx install agent-bom
agent-bom scan                    # auto-discover + scan local configs
agent-bom scan --dry-run          # preview what would be read (nothing accessed)
agent-bom scan --enforce          # + tool poisoning detection
agent-bom where                   # show all 18 client discovery paths
```

The CLI reads 27 specific config paths (enumerated in [PERMISSIONS.md](https://github.com/msaad00/agent-bom/blob/main/PERMISSIONS.md)).
It extracts server names, package names, and env var **names** only — never values, credentials, or secrets.

## Source & Verification

- **Source code**: https://github.com/msaad00/agent-bom (Apache-2.0, fully auditable)
- **PyPI**: https://pypi.org/project/agent-bom/
- **Smithery**: https://smithery.ai/server/agent-bom/agent-bom (99/100 quality score)
- **Sigstore signed**: Every release is signed with Sigstore OIDC — verify with `agent-bom verify agent-bom@0.36.1`
- **1,800 tests**: Every commit passes automated security scanning (CodeQL + OpenSSF Scorecard)
- **OpenSSF Scorecard**: https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom
- **Self-hostable**: Run your own instance with `docker build -f Dockerfile.sse` — no vendor dependency required
- **No telemetry**: `telemetry: false` — zero tracking, zero analytics, zero phone-home
