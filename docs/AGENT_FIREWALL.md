# Inter-agent firewall

The agent-bom inter-agent firewall is a tenant-scoped policy engine that controls
which agents are allowed to delegate to which other agents through the MCP runtime
plane. It exists so a compromised or untrusted agent cannot move laterally through
delegation chains.

This page documents the policy schema and CLI tooling. Enforcement is layered:

- **proxy** sits in the existing MCP detector chain and applies a local fast-path
  decision against a cached policy.
- **gateway** is the central authority — it loads the policy file, hot-reloads
  on change, and emits decisions to the existing `/v1/proxy/audit` HMAC-chained
  audit relay.

## Policy file format

```json
{
  "version": 1,
  "tenant_id": "acme",
  "enforcement_mode": "enforce",
  "default_decision": "allow",
  "rules": [
    {
      "source": "cursor",
      "target": "snowflake-cli",
      "decision": "deny",
      "description": "Cursor must not delegate directly to the Snowflake CLI"
    },
    {
      "source": "role:trusted-orchestrator",
      "target": "role:data-plane",
      "decision": "allow"
    },
    {
      "source": "role:untrusted",
      "target": "*",
      "decision": "deny"
    }
  ]
}
```

### Fields

| Field | Type | Default | Notes |
|---|---|---|---|
| `version` | int | `1` | Schema version. Only `1` accepted today. |
| `tenant_id` | string \| null | `null` | When set, the gateway applies this policy only to the named tenant. |
| `enforcement_mode` | `"enforce" \| "dry_run"` | `"enforce"` | In `dry_run`, every `deny` decision is downgraded to `warn` so operators can preview impact. |
| `default_decision` | `"allow" \| "deny" \| "warn"` | `"allow"` | Applied when no rule matches the source/target pair. |
| `rules` | list | `[]` | See below. |

### Rule format

| Field | Type | Notes |
|---|---|---|
| `source` | string | Agent name (`cursor`), wildcard (`*`), or role tag (`role:trusted`). |
| `target` | string | Same as `source`. |
| `decision` | `"allow" \| "deny" \| "warn"` | What to do on match. `warn` audits without blocking. |
| `description` | string | Free-form note shown by `agent-bom firewall list`. |

### Pattern matching

- Plain names use `fnmatch` (so `snowflake-*` matches `snowflake-cli`).
- `role:<tag>` matches when the agent carries that role tag (also `fnmatch`-globbed).
- `*` alone matches everything.

### Precedence

When more than one rule matches:

1. **Most-specific rule wins.** Concrete agent names beat role tags beat wildcards.
2. **DENY beats WARN beats ALLOW** at the same specificity (conservative default).

When no rule matches, `default_decision` applies.

### Dry-run mode

Set `enforcement_mode: "dry_run"` to preview a policy. Every `deny` decision is
downgraded to `warn` so the gateway audits but never blocks. This matches the rest
of the platform's "audit before enforce" pattern.

## CLI

```bash
# Validate schema
agent-bom firewall validate ./firewall.json

# List rules
agent-bom firewall list ./firewall.json
agent-bom firewall list ./firewall.json --json

# Test a pair
agent-bom firewall check ./firewall.json cursor snowflake-cli
agent-bom firewall check ./firewall.json cursor snowflake-cli \
    --source-role trusted-orchestrator
```

## Roadmap

This is PR 1 of a four-PR series implementing #982:

1. **Foundation** (this PR) — schema, loader, evaluator, CLI, tests.
2. **Gateway evaluator** — gateway loads the policy, evaluates on each agent→agent
   path, emits decisions to `/v1/proxy/audit`.
3. **Proxy fast-path** — proxy detector consults the cached policy; gateway
   remains authoritative for refreshes.
4. **Dashboard runtime overlay** — per-pair decision counter, recent denials,
   policy hot-reload status on the runtime tab.

Capability-keyed rules (`agent_a may invoke tool X via agent_b`) are deliberately
deferred to a v2 once pairwise + role tags prove out in production.
