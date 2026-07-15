# Configuration

## Policy file

Security policies are JSON files with rules for enforcement:

```json
{
  "rules": [
    {
      "id": "rule-name",
      "action": "block",
      "condition": "severity == 'critical'",
      "block_tools": ["exec", "shell"],
      "arg_pattern": {
        "path": "/etc/passwd"
      }
    }
  ]
}
```

### Rule fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique rule identifier |
| `action` | string | `block` or `log` |
| `condition` | string | Expression (AND/OR/NOT, comparisons) |
| `block_tools` | list | Tool names to block |
| `arg_pattern` | object | Argument name → regex pattern |

### Condition expressions

Supports 17 conditions (16 declarative + expression engine):

- `severity == 'critical'`
- `epss_score > 0.5`
- `kev == true`
- `min_scorecard_score < 5`
- AND/OR/NOT combinations

## MCP server configuration

```json
{
  "mcpServers": {
    "agent-bom": {
      "command": "uvx",
      "args": ["agent-bom", "mcp", "server"]
    }
  }
}
```

## Proxy configuration

All proxy options can be set via CLI flags:

```bash
agent-bom proxy \
  --policy policy.json \
  --log audit.jsonl \
  --block-undeclared \
  --metrics-port 8422 \
  -- <server-command>
```

## Governance: ABAC conditions, delegation tokens, and served MCP-client-config

### Conditional-access (ABAC) attributes

Conditional-access policies (`/v1/conditional-access-policies`) gate a call on
request-time context. Alongside the existing environment / time-window /
weekday / source-CIDR conditions, policies also match on **device**, **group**,
and **client** attributes:

| Condition | Matches against | Request header |
|-----------|-----------------|----------------|
| `allowed_devices` | calling workstation / device id (exact) | `x-agent-device-id` |
| `allowed_groups` | caller's directory groups (membership) | `x-agent-groups` (comma-separated) |
| `allowed_clients` | MCP client application id (exact) | `x-agent-client-id` |

All conditions are **fail-closed**: a policy that requires a device / group /
client denies the call when the request cannot prove the attribute. The same
conditions are enforced at both the gateway and the proxy decision points.

### Scoped delegation tokens

Multi-agent handoffs carry a **scoped, verifiable, expiring** delegation token
(`POST /v1/identities/{id}/delegations`). The token is HMAC-signed, lists the
explicit delegated capabilities (`scopes`), and expires. A receiver validates it
with `POST /v1/delegations/verify` (an over-scoped or expired token is
rejected); further hops re-issue via `POST /v1/delegations/propagate`, which can
only **narrow** scope and never extends the expiry or the delegation-depth
budget.

Set `AGENT_BOM_DELEGATION_SIGNING_KEY` (file via `*_FILE`, or env) so tokens
survive process restarts and verify consistently across replicas. When unset, a
per-process ephemeral key is used (tokens become invalid after restart).

### Served MCP-client-config distribution

Assigning a profile composes chosen connectors + a runtime role blueprint into
ONE distributable, **read-only**, tenant-scoped `.mcp.json` document:

- `POST /v1/mcp-config/assignments` — assign a profile + connectors → returns a
  `config_url`.
- `GET /v1/mcp-config/{config_id}/mcp.json` — the served `mcpServers` document.

The served config references each connector's credential env-vars as `${VAR}`
placeholders and each cloud connection by opaque handle — it **never embeds
secret material**. Access is RBAC-gated; a cross-tenant fetch is a 404.
