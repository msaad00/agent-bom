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

## Gateway integration

The gateway is the central authority for firewall decisions. Operators run:

```bash
agent-bom gateway serve \
    --upstreams ./gateway-upstreams.yaml \
    --firewall-policy ./firewall.json \
    --firewall-policy-reload-seconds 5
```

This wires the policy file into the gateway lifespan. Hot reload is mtime-based
and skips identical files. Malformed JSON or schema errors surface as
`firewall_runtime.last_error` on `/healthz` without taking the gateway down —
the previous good policy stays loaded.

### `POST /v1/firewall/check`

Server-authoritative decision endpoint. The proxy fast-path will call this
when its local cache is cold or stale; operators can also hit it directly.

Request:

```json
{
  "source_agent": "cursor",
  "target_agent": "snowflake-cli",
  "source_roles": ["trusted"],
  "target_roles": ["data-plane"]
}
```

Response:

```json
{
  "source_agent": "cursor",
  "target_agent": "snowflake-cli",
  "source_roles": ["trusted"],
  "target_roles": ["data-plane"],
  "decision": "deny",
  "effective_decision": "deny",
  "matched_rule": {"source": "cursor", "target": "snowflake-cli", "decision": "deny", "description": "..."},
  "policy": {
    "source": "/var/run/agent-bom/firewall.json",
    "loaded_at": 1714665600.0,
    "default_decision": "allow",
    "enforcement_mode": "enforce",
    "tenant_id": "acme"
  }
}
```

Any non-allow effective decision (i.e. `deny` in enforce mode, `warn` always,
or `deny → warn` under dry-run) emits a `gateway.firewall_decision` audit event
through the configured audit sink. In a normal cluster install that sink fans
out to `/v1/proxy/audit`, so denies and warns flow into the same HMAC-chained
audit table the proxy already writes to.

### `GET /healthz`

The `firewall_runtime` block exposes:

- `source` — file path or `default-allow` when no policy is loaded.
- `source_kind` — `file` or `default-allow`.
- `reload_enabled` / `reload_interval_seconds` / `last_loaded_at` / `last_error`.
- `rule_count`, `default_decision`, `enforcement_mode`, `tenant_id`.

## Proxy fast-path

The MCP proxy is on the hot path of every JSON-RPC call between an MCP host
and an MCP server. Hitting the gateway over HTTP per call would blow the
latency budget, so the proxy uses the `FirewallClient` from
`src/agent_bom/firewall_client.py`:

- per-process **TTL cache** keyed by `(source_agent, target_agent, source_roles, target_roles)`,
- configurable **fail mode** (`open` / `closed`) when the gateway is unreachable
  AND no local policy is configured,
- optional **local policy fallback** (`--firewall-policy <file>`) for air-gapped
  installs or as a degraded-mode policy,
- gateway remains authoritative — the client just caches and degrades.

```bash
agent-bom proxy \
    --firewall-target-id snowflake-cli \
    --firewall-gateway-url https://gateway.internal:8090 \
    --firewall-gateway-token "$AGENT_BOM_PROXY_FIREWALL_GATEWAY_TOKEN" \
    --firewall-cache-ttl-seconds 60 \
    --firewall-fail-mode open \
    -- npx @mcp/server-snowflake
```

Activation rule: the firewall is *only* consulted when `--firewall-target-id`
is set together with at least one of `--firewall-gateway-url` or
`--firewall-policy`. Without a target identity the proxy can't form a
source -> target pair, so the firewall stays inert.

Decision behaviour at the proxy:

- `effective_decision = ALLOW` -> call proceeds.
- `effective_decision = WARN`  -> audited, `metrics.firewall_warn` incremented,
  call proceeds. Useful for soak / dry-run rollouts.
- `effective_decision = DENY`  -> JSON-RPC error returned to the client,
  audited, `metrics.firewall` incremented. Decision reason names the matched
  rule for fast triage.

Fail mode reference:

| `--firewall-fail-mode` | Gateway up | Gateway down, local policy | Gateway down, no local |
|---|---|---|---|
| `open` (default) | gateway authoritative | local evaluator wins | default-allow |
| `closed`         | gateway authoritative | local evaluator wins | default-deny |

The proxy registers its evaluator via `set_firewall_evaluator(fn, target_id=...)`
so tests can swap implementations cleanly. `clear_firewall_evaluator()` restores
the default.

## Roadmap

Four-PR series implementing #982:

1. **Foundation** (PR 1, merged) — schema, loader, evaluator, CLI, tests.
2. **Gateway evaluator** (PR 2, in flight) — gateway loads the policy, evaluates
   via `POST /v1/firewall/check`, hot-reloads, and fans out audit events to the
   `/v1/proxy/audit` HMAC-chained relay. Surfaced in `/healthz` and the
   `agent-bom gateway serve` startup banner. Helm chart `gateway.firewallPolicyPath`.
3. **Proxy fast-path** (this PR) — `FirewallClient` with TTL cache + fail mode +
   local fallback; proxy CLI wires it via `--firewall-target-id` and friends;
   helper `_maybe_block_on_firewall` consulted from both stdio and SSE paths.
4. **Dashboard runtime overlay** — per-pair decision counter, recent denials,
   policy hot-reload status on the runtime tab. `/v1/gateway/stats` extended
   with `firewall_runtime` aggregation.

Capability-keyed rules (`agent_a may invoke tool X via agent_b`) are deliberately
deferred to a v2 once pairwise + role tags prove out in production.
