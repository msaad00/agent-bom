# Security Metadata Registry

A curated registry of 427+ MCP server security metadata entries.

## What's in each entry

| Field | Description |
|-------|-------------|
| `package` | Package name and ecosystem |
| `risk_level` | Category-derived risk level |
| `risk_justification` | Why this risk level was assigned |
| `tools` | Tools the server exposes |
| `credential_env_vars` | Heuristic-inferred credential variables |
| `verified` | Whether the entry has been manually verified |
| `license` | Package license |
| `source_url` | Source repository URL |
| `command_patterns` | Common installation/run commands |

## Usage

```bash
# CLI
agent-bom registry search brave-search
agent-bom registry list --risk high

# MCP tool
registry_lookup(server_name="brave-search")
```

## Fleet scanning

Batch lookup for MCP server inventories:

```bash
# MCP tool
fleet_scan(servers=["brave-search", "filesystem", "postgres"])
```

## Registry sources

Entries are synced from:

- Smithery registry
- MCP official registry
- Glama.ai catalog
- Manual curation + community contributions

## Marketplace check

Pre-install trust assessment combining registry data with integrity verification:

```bash
# MCP tool
marketplace_check(server_name="brave-search")
```
