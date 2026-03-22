# I Scanned My AI Agents and Found 57 Vulnerabilities

> A real scan of Cursor + Claude Desktop reveals the hidden attack surface of MCP servers.

## The Setup

Every developer using Cursor, Claude Desktop, or Windsurf has MCP servers running locally. These servers have npm/PyPI dependencies. Those dependencies have CVEs. And those CVEs have access to your credentials.

I ran one command to find out how bad it was:

```bash
pip install agent-bom
agent-bom agents
```

## What I Found

**2 agents. 4 MCP servers. 13 packages. 57 vulnerabilities.**

The blast radius was worse than the CVE count suggests:

- `pillow@9.0.0` had 13 CVEs (2 critical) — used by the Cursor agent
- `cryptography@39.0.0` had 11 CVEs — used by both agents
- Every CVE had a direct path to `ANTHROPIC_KEY` and `DB_URL`

The scariest part: `CVE-2023-4863` (KEV — actively exploited) affected pillow, which was loaded by an MCP server with `read_file` and `write_file` tools. An attacker exploiting this CVE could read any file on my machine through the MCP tool chain.

## The Blast Radius

This is what makes agent-bom different from running `npm audit`:

```
CVE-2023-4863  (CRITICAL · CVSS 8.8 · CISA KEV · EPSS 94%)
  |── pillow@9.0.0
       |── image-processor  (MCP Server)
            |── Cursor  (Agent · 2 servers · 8 tools)
            |── ANTHROPIC_KEY, OPENAI_KEY  (Credentials exposed)
            |── read_file, write_file  (Tools at risk)
```

A traditional scanner says: "pillow has a CVE, upgrade it." agent-bom says: "This CVE gives an attacker access to your Anthropic API key through the Cursor agent's file tools."

## The Fix

```bash
# See what to upgrade
agent-bom agents --remediate plan.md

# Gate your CI
agent-bom agents --fail-on critical
```

The remediation plan prioritized by blast radius, not just severity:

1. `pillow 9.0.0 → 10.2.0` — clears 13 vulns, 1 agent
2. `cryptography 39.0.0 → 39.0.1` — clears 11 vulns, 1 agent
3. `werkzeug 2.2.2 → 2.2.3` — clears 9 vulns, 1 agent

## What You Should Do

1. **Run a scan**: `pip install agent-bom && agent-bom agents`
2. **Check your CI**: Add `agent-bom agents --fail-on critical` to your pipeline
3. **Generate an AI BOM**: `agent-bom agents -f cyclonedx -o ai-bom.json`

Every MCP server you install is an attack surface. Know what's running.

---

*agent-bom is open-source (Apache 2.0). Star it on [GitHub](https://github.com/msaad00/agent-bom) if you found this useful.*
