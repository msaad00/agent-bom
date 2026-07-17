# Risk campaigns

Risk campaigns group canonical findings that share one explicit remediation target. Campaign priority is bounded to 10 and exposes its base-risk, exploitability, reachability, and explicit crown-jewel components; missing context contributes no score.

## First command

Use an authenticated, tenant-scoped API request:

```bash
curl -sS "$AGENT_BOM_URL/v1/campaigns" \
  -H "Authorization: Bearer $AGENT_BOM_API_KEY" \
  -H "X-Agent-Bom-Tenant-ID: $AGENT_BOM_TENANT_ID"
```

## Artifact

The response is a bounded `risk-campaigns.v1` artifact with stable campaign and finding IDs, explicit score components, workflow version, completeness flags, and modeled risk-reduction scope. Provisional membership is visible but cannot create or synchronize tickets.

## Next step

Assign an owner and SLA with `PATCH /v1/campaigns/{campaign_id}`, create tickets through a stored ticketing connection, and then call `POST /v1/campaigns/{campaign_id}/verify` with the current workflow `version`. Verification is server-owned: it compares the stable remediation target with a complete current canonical-findings snapshot, returning the current remaining IDs or marking the campaign verified and done.

When remediation removes every current member, the campaign retires from the active list. `GET /v1/campaigns/verification-queue` preserves the tenant-scoped re-verification handoff across reloads and restarts with its durable title, original member count, workflow status, and current version.
