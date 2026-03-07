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
      "args": ["agent-bom", "mcp-server"]
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
