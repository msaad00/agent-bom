# Open Cost Model (FinOps)

agent-bom attributes LLM API spend to agents, models, and providers so operators
get cost accountability without adding a separate FinOps product. Unlike closed
runtime platforms, the price model is **open and operator-tunable** — every
number is in the repo and overridable.

## How it works

```
OTel GenAI spans ──► token usage ──► open price table ──► per-call cost record
 (gen_ai.usage.*)    (otel_ingest)     (cost_model)         (cost_store, per tenant)
                                                                     │
                                                      rollups + budget posture
                                                                     │
                                  GET /v1/observability/costs · cost_report MCP tool
```

1. **Ingest** — POST OpenTelemetry traces to `POST /v1/traces`. GenAI spans
   (`gen_ai.system`, `gen_ai.request.model`, `gen_ai.usage.input_tokens`,
   `gen_ai.usage.output_tokens`) are parsed by `agent_bom.otel_ingest`.
2. **Price** — `agent_bom.cost_model.compute_cost_usd()` resolves the model to a
   USD-per-1M-token price (longest model-prefix match, provider aliases for
   Azure/Bedrock/Vertex). Unknown models cost `0.0` and are counted as
   `unpriced_calls` rather than failing.
3. **Persist** — per-call `LLMCostRecord`s are stored per tenant
   (`agent_bom.api.cost_store`), deduplicated by `trace_id:span_id`.
4. **Report** — spend rolls up by agent, model, and provider with budget posture.

No prompts, responses, or arguments are read or stored — only token counts and
model identifiers. This preserves the read-only, metadata-only trust posture.

## Price table

List prices (USD per 1,000,000 tokens) captured **2026-06-01** from public
provider pricing. These are conservative list prices, not negotiated rates — see
`agent_bom/cost_model.py` for the full table.

### Overriding prices

Set committed-use or enterprise-discount rates via `AGENT_BOM_COST_MODEL_JSON`:

```bash
export AGENT_BOM_COST_MODEL_JSON='{
  "openai":    {"gpt-4o": {"input_per_mtok": 1.25, "output_per_mtok": 5.0}},
  "anthropic": {"claude-sonnet-4": {"input_per_mtok": 2.4, "output_per_mtok": 12.0}}
}'
```

Overrides win over the built-in table; model keys are matched as prefixes.

## API

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/v1/observability/costs` | Spend by agent/model/provider + budget posture + `forecast` block. Optional `?agent=` scope. |
| `GET`  | `/v1/observability/costs/budget` | Configured cap + current utilization. |
| `PUT`  | `/v1/observability/costs/budget` | Set a tenant or per-agent USD cap. Body: `{"limit_usd": 250.0, "agent": "optional"}`. |
| `GET`  | `/v1/observability/costs/forecast` | Burn rate + projected period spend + budget runway. Optional `?agent=` scope. |

The `cost_report` MCP tool exposes the same spend view to headless agents.

## Forecasting

`GET /v1/observability/costs/forecast` projects spend forward from the
`observed_at` timestamps already on every cost record — no new dependency, math
in `agent_bom.api.cost_forecast`. The same projection is embedded as a
`forecast` block on the costs report.

The burn rate is the higher of the trailing-24h and trailing-7d daily rates
(conservative under acceleration). Fields:

- `burn_rate_usd_per_day` / `burn_rate_basis` — recent daily spend rate and the
  window it came from.
- `projected_period_spend_usd` — extrapolated spend at the end of the current
  calendar-month billing period.
- `days_remaining` / `projected_exhaustion_at` — runway to the configured cap.
- `status` — `ok`, `no_budget`, `budget_exceeded` (runway `0`), `stale`, or
  `insufficient_history` (all projections null on sparse/empty history).

A forecast is **reference only** — it never blocks a call. Enforcement stays in
the relay (`mode: enforce`, above).

## Budgets

A budget is a USD cap, tenant-wide (`agent: ""`) or scoped to one agent. The
report's `budget` block reports `spend_usd`, `remaining_usd`, `utilization`, and
an `exceeded` flag once spend reaches the cap. A per-agent budget falls back to
the tenant-wide cap when none is set for that agent.

### Enforcement (`mode`)

A budget has a `mode`:

- `report` (default) — advisory; surfaced in budget posture only.
- `enforce` — **pre-invocation enforcement**. Once the agent (or tenant) reaches
  the cap, the gateway relay fails subsequent calls closed with JSON-RPC
  `-32001` *before the upstream is touched*, and writes a
  `gateway.budget_exceeded` audit event. A per-agent enforce budget takes
  precedence; otherwise a tenant-wide enforce budget applies.

```bash
# Hard-stop agent "billing-bot" at $50 of spend:
curl -XPUT $API/v1/observability/costs/budget -H "X-API-Key: $KEY" \
  -d '{"agent":"billing-bot","limit_usd":50,"mode":"enforce"}'
```

Enforcement requires the gateway and control plane to share `AGENT_BOM_DB` so the
relay can read accumulated spend.
