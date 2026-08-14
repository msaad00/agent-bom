# Adoption Events

Agent-bom can keep a coarse product-adoption funnel in a local SQLite file.
It is disabled by default and sends nothing to agent-bom maintainers or any
third party.

Enable it explicitly:

```bash
export AGENT_BOM_ADOPTION_EVENTS_ENABLED=1
# Optional; defaults to ~/.agent-bom/adoption-events.sqlite
export AGENT_BOM_ADOPTION_EVENTS_DB=/var/lib/agent-bom/adoption-events.sqlite
```

The funnel records only bounded event names and dimensions: scan completion,
artifact creation, investigation start, verification completion, repeat use,
CI adoption, and control-plane adoption. Allowed dimensions are coarse channel,
outcome, artifact type, and CI-provider classes. Source content, findings,
secrets, credentials, tenant IDs, finding IDs, and customer resource IDs are
rejected before storage.

An authenticated control-plane administrator can inspect the aggregate at
`GET /v1/observability/adoption`. Authenticated contributors can submit only
the same bounded event contract at `POST /v1/observability/adoption/events`;
unknown fields and customer-controlled dimension values fail closed with 422.

Disable collection by unsetting `AGENT_BOM_ADOPTION_EVENTS_ENABLED` or setting
it to `0`. When disabled, no adoption database is created.
