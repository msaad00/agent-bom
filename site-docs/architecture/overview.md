# Architecture Overview

For detailed architecture diagrams and module breakdown, see the [full architecture doc](https://github.com/msaad00/agent-bom/blob/main/docs/ARCHITECTURE.md).

For the data-model contract between native `agent-bom` objects and optional OCSF projection, see [Canonical Model vs OCSF](canonical-vs-ocsf.md).

## Scanning pipeline

```mermaid
graph LR
    A[MCP Client Configs] --> B[Discovery]
    B --> C[Package Extraction]
    C --> D[CVE Lookup]
    D --> E[Blast Radius]
    E --> F[Compliance Mapping]
    F --> G[Output]

    D --> |OSV, NVD, EPSS| H[(Vuln DBs)]
    B --> |30 clients| I[Config Files]
```

## Key modules

| Module | Path | Purpose |
|--------|------|---------|
| Discovery | `src/agent_bom/discovery/` | MCP client config parsing |
| Enrichment | `src/agent_bom/enrichment.py` | CVE lookup (OSV, NVD, EPSS, KEV) |
| Blast Radius | `src/agent_bom/blast_radius.py` | Impact chain mapping |
| Context Graph | `src/agent_bom/context_graph.py` | Lateral movement analysis |
| Registry | `src/agent_bom/registry.py` | 427+ server security metadata |
| Compliance | `src/agent_bom/compliance/` | 14 framework mappings |
| Asset Tracker | `src/agent_bom/asset_tracker.py` | Persistent vuln tracking — first_seen, resolved, MTTR |
| Proxy | `src/agent_bom/proxy.py` | Runtime MCP interception |
| Protection | `src/agent_bom/runtime/` | 7-detector anomaly engine |
| Enforcement | `src/agent_bom/enforcement.py` | Tool poisoning detection |
| Security | `src/agent_bom/security.py` | Path validation, credential redaction |
| MCP Server | `src/agent_bom/mcp_server.py` | 32-tool FastMCP server |
| API | `src/agent_bom/api/` | REST API (FastAPI) |
| Output | `src/agent_bom/output/` | HTML, Prometheus, Mermaid, SVG, STIX |

## Security boundaries

- All scanning is local-first — zero outbound calls except public vuln databases
- Config file env var values are always redacted before output
- Path validation restricts file access to user home directory
- No telemetry, no analytics, no tracking
