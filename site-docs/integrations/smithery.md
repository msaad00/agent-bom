# Smithery Manifest

agent-bom ships a Smithery-compatible manifest at `integrations/smithery.yaml`.
This page documents the field-naming convention used by Smithery's session config
and how those values map to the environment variables the agent-bom MCP server
actually reads.

The manifest and release workflow are ready for Smithery publication, but the
public catalog entry is only considered live after the Smithery release workflow
successfully publishes against a public unauthenticated MCP endpoint. Until then,
use Glama, OpenClaw, local `uvx agent-bom mcp server`, or your own Railway/Docker
deployment as the active MCP surfaces.

## Why two naming conventions exist

agent-bom standardises on `AGENT_BOM_*` snake-case environment variables across CLI,
API, Helm values, Docker Compose, and the runtime MCP server. Smithery's
`configSchema` follows the [JSON Schema](https://json-schema.org/) draft convention
used by the Smithery SDK and hosted UI, which expects camelCase property names. As a
result, the public Smithery integration manifest at `integrations/smithery.yaml`
declares config fields in camelCase, while the agent-bom code path that consumes them
expects snake-case env vars.

This is not a drift bug — it is the documented translation boundary between two
ecosystems. Smithery's runner is responsible for promoting session config values into
the process environment before invoking `agent_bom.mcp_server.create_smithery_server`.

## Mapping table

The current `integrations/smithery.yaml` schema declares two optional config fields.
The Smithery runner promotes each camelCase key into the corresponding env var before
the agent-bom MCP server starts.

| Smithery `configSchema` field | Type   | Promoted env var            | Read by                                    | Effect                                                                              |
| ----------------------------- | ------ | --------------------------- | ------------------------------------------ | ----------------------------------------------------------------------------------- |
| `nvdApiKey`                   | string | `NVD_API_KEY`               | `agent_bom.enrichment` (NVD CVSS lookup)    | Lifts NVD enrichment rate limit from 5 requests / 30s to 50 requests / 30s.         |
| `clickhouseUrl`               | string | `AGENT_BOM_CLICKHOUSE_URL`  | `agent_bom.cloud.clickhouse` and CLI flags  | Enables ClickHouse-backed vulnerability trend storage and posture history.          |

`NVD_API_KEY` is intentionally not prefixed with `AGENT_BOM_` because the value is the
NVD-issued key itself, not an agent-bom configuration knob — multiple tools in the
same workspace may share it.

## Self-hosting outside Smithery

When operating the MCP server yourself (Railway, Docker, Helm, Glama, OpenClaw, or any
non-Smithery runtime), set the snake-case environment variables directly. The
camelCase `configSchema` is purely a Smithery surface and has no effect on a
self-hosted deployment.

```bash
# Railway, Fly, Render, Docker, etc.
export NVD_API_KEY="<your-nvd-api-key>"
export AGENT_BOM_CLICKHOUSE_URL="https://<host>:8443"
agent-bom serve mcp
```

```yaml
# Helm values.yaml
controlPlane:
  api:
    env:
      - name: NVD_API_KEY
        valueFrom:
          secretKeyRef:
            name: agent-bom-control-plane-auth
            key: nvd-api-key
      - name: AGENT_BOM_CLICKHOUSE_URL
        value: "http://clickhouse:8123"
```

## Adding new Smithery config fields

When a new env var becomes operator-tunable through Smithery:

1. Add the field to `integrations/smithery.yaml` `configSchema.properties` using
   **camelCase** (Smithery convention).
2. Add a row to the [Mapping table](#mapping-table) above with the snake-case env
   var, the consuming module, and the effect.
3. Confirm the agent-bom code path reads the env var via `os.environ` (not the
   camelCase key), so self-hosted and Smithery-hosted deployments behave identically.
4. Smoke-test the Smithery deployment by setting the field via Smithery's UI and
   confirming the runtime reads the promoted env var.

## Related references

- [Smithery integration manifest](https://github.com/msaad00/agent-bom/blob/main/integrations/smithery.yaml)
- [agent-bom configuration reference](../reference/configuration.md)
- [MCP tools reference](../reference/mcp-tools.md)
- [Hosted MCP overview](../deployment/overview.md)
