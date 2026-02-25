---
name: agent-bom
description: The open-source Grype for the AI era — scan packages for CVEs, assess credential exposure, map blast radius from vulnerabilities to tools, OWASP/MITRE/NIST compliance
version: 0.32.0
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
      - url: "https://agent-bom-mcp.up.railway.app/sse"
        purpose: "MCP server endpoint — all 13 tools are accessed via this single SSE connection"
        auth: false
    telemetry: false
    persistence: false
    privilege_escalation: false
---

# agent-bom — The Open-Source Grype for the AI Era

An MCP-powered skill that scans the AI supply chain for security risks:
- **CVEs** in packages, dependencies, and images (OSV.dev + NVD + EPSS + CISA KEV)
- **Config security** — credential exposure, tool access risks, privilege escalation
- **Blast radius** — links CVEs to exposed credentials and tools via server → agent mapping
- **Compliance** — OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF

All through a remote MCP server. No local binary install required. Agentless, read-only, non-root.

## Setup

Add the agent-bom MCP server to your client config:

```json
{
  "mcpServers": {
    "agent-bom": {
      "type": "sse",
      "url": "https://agent-bom-mcp.up.railway.app/sse"
    }
  }
}
```

For OpenClaw, add this to `~/.openclaw/openclaw.json`. For other MCP clients
(Claude Desktop, Cursor, VS Code, etc.), add to the appropriate config file.

## Available MCP Tools

Once connected, the agent-bom MCP server provides **13 tools**:

| Tool | Description |
|------|-------------|
| `scan` | Full scan pipeline — discover agents, extract packages, scan for CVEs, return results |
| `check` | Check a specific package for known vulnerabilities |
| `blast_radius` | Map the impact chain of a CVE across agents, servers, credentials, and tools |
| `policy_check` | Evaluate scan results against a security policy |
| `registry_lookup` | Look up an MCP server in the 427+ server threat intelligence registry |
| `generate_sbom` | Generate a Software Bill of Materials (CycloneDX or SPDX) |
| `compliance` | Check OWASP LLM Top 10, MITRE ATLAS, and NIST AI RMF compliance |
| `remediate` | Generate a prioritized remediation plan for discovered vulnerabilities |
| `verify` | Check package integrity and SLSA provenance |
| `where` | Show all MCP client config discovery paths and which exist on this system |
| `inventory` | List discovered agents and servers without running a CVE scan |
| `diff` | Compare two scan reports to see what changed |
| `skill_trust` | Assess trust level of a skill file (5-category analysis with verdict) |

## Available MCP Resources

| Resource | Description |
|----------|-------------|
| `registry://servers` | Browse the 427+ MCP server threat intelligence registry |
| `policy://template` | Get a starter security policy template |

## Example Workflows

### Scan for vulnerabilities
Call the `scan` tool with no arguments to auto-discover local MCP configs and scan:
```
scan()
```

### Check a package before installing
```
check(package="@modelcontextprotocol/server-filesystem", ecosystem="npm")
```

### Map blast radius of a CVE
```
blast_radius(cve_id="CVE-2024-21538")
```

### Generate an SBOM
```
generate_sbom(format="cyclonedx")
```

### Check compliance
```
compliance()
```

### Look up a server in the threat registry
```
registry_lookup(server_name="brave-search")
```

## What the MCP Server Does

The remote server discovers MCP client configurations, extracts package dependencies,
queries public vulnerability databases (OSV.dev, NVD, EPSS, CISA KEV), and assesses
config security (credential exposure, tool access patterns, privilege escalation risks).
It returns structured results — CVE IDs, severity scores, config findings, blast radius
chains linking vulnerabilities to exposed credentials and tools, and remediation advice.

Agentless, read-only, non-root. No binary install required.

**Data handling:**
- Only package names and versions are sent to vulnerability APIs
- Config file contents, env var values, and credentials are never transmitted
- All results are returned to the calling agent — nothing is stored server-side

## Source & Verification

- **Source code**: https://github.com/msaad00/agent-bom (Apache-2.0)
- **PyPI**: https://pypi.org/project/agent-bom/
- **Smithery**: https://smithery.ai/server/agent-bom/agent-bom (99/100 quality score)
- **Sigstore signed**: Every release is signed with Sigstore OIDC
- **1000+ tests**: Every commit passes automated security scanning
- **OpenSSF Scorecard**: https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom

For local/offline usage, install the CLI: `pipx install agent-bom`
