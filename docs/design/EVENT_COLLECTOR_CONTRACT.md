# Design: event/log collector contract (posture change events)

**Status:** Phase 2 — control-plane ingest route shipped; Go forward wired;
Helm Deployment gated by `eventCollector.enabled` (default false).

**Relates to:** [ADR-009](../decisions/009-python-primary-go-sidecar-later.md)
(Python-primary; optional Go sidecar for proven hot paths).

## Lane

**Posture change events** — not CWPP / runtime-evidence ingest.

```text
SQS / queue poll  →  normalize (CloudTrail / EventBridge)  →  POST batch to control plane
                                                              →  Python dispatch / CIS / persist
```

| Lane | Path / owner | Purpose |
|------|----------------|---------|
| Posture change events (this contract) | Go collector → `POST /v1/cloud/connections/events/ingest` | Queue-driven resource-change signals for scoped CIS re-eval |
| Runtime evidence (separate) | `POST /v1/cloud/runtime-evidence/ingest` | CWPP / EDR workload signals (metadata only) |

Do not merge these lanes. The collector never writes CIS findings itself.

## Ownership split

| Concern | Owner |
|---------|--------|
| Bounded queue poll loop (SQS later; stub mode today) | **Go** `runtime/event-collector` |
| Minimal CloudTrail / EventBridge → `CloudChangeEvent` normalize | **Go** (parity with `parse_cloudtrail_event`) |
| Forward batch to control plane (`Authorization: Bearer …`) | **Go** |
| `dispatch_change_event`, connection broker, CIS subset, persist | **Python** control plane |
| Auth, tenant, RBAC, account-bound fail-closed checks | **Python** (on ingest) |

## Control-plane path

```http
POST {control-plane}/v1/cloud/connections/events/ingest
Authorization: Bearer <api-key>
Content-Type: application/json

{
  "events": [
    {
      "provider": "aws",
      "account": "123456789012",
      "region": "us-east-1",
      "resource_type": "s3",
      "resource_id": "my-bucket",
      "action": "PutBucketPolicy",
      "arn": "",
      "raw": { }
    }
  ]
}
```

Auth-by-default (`scan` permission). Each event is matched to a tenant connection
by provider + account (from `role_ref`); unmatched accounts are skipped
fail-closed. Dispatch errors are sanitized in the response.

## Go binary surfaces

- Module: `github.com/msaad00/agent-bom/runtime/event-collector`
- Listen: `--listen :8092` (default)
- Flags: `--control-plane-url`, `--api-key-file`, `--mode stub|sqs`
- `GET /healthz` — liveness
- Dev helper: `POST /v1/normalize/cloudtrail` — body = EventBridge /
  CloudTrail JSON; response = normalized `CloudChangeEvent` or 400
- Dev helper: `POST /v1/forward/cloudtrail` — normalize then POST to
  `{control-plane-url}/v1/cloud/connections/events/ingest`
- `--mode stub`: no AWS SDK calls; process serves health/normalize/forward
- `--mode sqs`: reserved for bounded poll (not wired yet); forward helpers work

## Fail-open / fail-closed

| Layer | Default | Notes |
|-------|---------|-------|
| Normalize | fail-closed | Malformed / unsupported service → skip (no crash) |
| Forward | fail-closed on non-2xx / transport error | Leave message for redelivery when SQS lands; stub has nothing to redrive |
| Account / tenant binding | Python on ingest | Collector does not broaden trust |

## Non-goals

- No dual product (Python edition vs Go edition) — see ADR-009.
- No cloud inventory rewrite into Go.
- No Azure / GCP collectors in Phase 1.
- No moving CIS evaluation into Go.

## Verification

```bash
make event-collector-go-test
# equivalent: cd runtime/event-collector && go test ./...
```

## Code

- Go: [`runtime/event-collector/`](../../runtime/event-collector/)
- Helm: `eventCollector.*` in [`deploy/helm/agent-bom/values.yaml`](../../deploy/helm/agent-bom/values.yaml)
- Python reference normalize / dispatch:
  [`src/agent_bom/cloud/event_ingest.py`](../../src/agent_bom/cloud/event_ingest.py)
