# Design: event/log collector contract (posture change events)

**Status:** Active. This is an **implementation-agnostic HTTP ingest contract**
owned by the Python control plane — any collector that can POST the documented
batch may use it.

The Go reference collector was retired on 2026-07-25: its queue-poll mode was
never wired, no image was published, and `agent_bom.cloud.event_ingest` already
performs bounded polling, account-bound validation, dispatch, and
poison-message handling in Python. See
[ADR-009](../decisions/009-python-primary-go-sidecar-later.md). The route and
its contract are unchanged by that removal.

## Lane

**Posture change events** — not CWPP / runtime-evidence ingest.

```text
SQS / queue poll  →  normalize (CloudTrail / EventBridge)  →  POST batch to control plane
                                                              →  Python dispatch / CIS / persist
```

| Lane | Path / owner | Purpose |
|------|----------------|---------|
| Posture change events (this contract) | any collector → `POST /v1/cloud/connections/events/ingest` | Queue-driven resource-change signals for scoped CIS re-eval |
| Runtime evidence (separate) | `POST /v1/cloud/runtime-evidence/ingest` | CWPP / EDR workload signals (metadata only) |

Do not merge these lanes. The collector never writes CIS findings itself.

## Ownership split

| Concern | Owner |
|---------|--------|
| Bounded queue poll loop | **Python** `agent_bom.cloud.event_ingest` (or your own collector) |
| CloudTrail / EventBridge → `CloudChangeEvent` normalize | **Python** `parse_cloudtrail_event` |
| Forward batch to control plane (`Authorization: Bearer …`) | collector |
| Inbound auth on a collector's own HTTP surface, if it has one | collector |
| `dispatch_change_event`, connection broker, CIS subset, persist | **Python** control plane |
| Tenant, RBAC, account-bound fail-closed checks | **Python** (on ingest) |

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

- Listen: `--listen 127.0.0.1:8092` (default) — loopback only; binding a
  routable address is an explicit operator decision
- Flags: `--control-plane-url`, `--api-key-file`, `--inbound-token-file`,
  `--enable-dev-endpoints`, `--mode stub|sqs`
- `GET /healthz` — liveness; unauthenticated so a kubelet probe works, and it
  returns only `status` and `mode`
- Dev helper: `POST /v1/normalize/cloudtrail` — body = EventBridge /
  CloudTrail JSON; response = normalized `CloudChangeEvent` or 400
- Dev helper: `POST /v1/forward/cloudtrail` — normalize then POST to
  `{control-plane-url}/v1/cloud/connections/events/ingest`
- Both `/v1` helpers are **off by default**. They are served only with
  `--enable-dev-endpoints` **and** `--inbound-token-file`, and each request
  must carry that token (see [Inbound auth](#inbound-auth)).
- `--mode stub`: no AWS SDK calls; process serves health, plus the `/v1`
  helpers when they are explicitly enabled
- `--mode sqs`: reserved for bounded poll (not wired yet). The queue lane —
  not the `/v1` helpers — is the intended production path

## Inbound auth

The collector holds a control-plane API key with `scan` permission and attaches
it to everything it forwards. Any caller able to reach a `/v1` helper therefore
borrows that credential, so the helpers carry their own authentication:

- Callers must send `Authorization: Bearer <token>` matching the contents of
  `--inbound-token-file`. The comparison is constant-time over SHA-256 digests.
- A failed check returns **401 with an empty body** — no detail about the
  collector's configuration, and no forward is attempted.
- The inbound token is a **separate secret from `--api-key-file`**. Startup
  fails if the two flags name the same file or resolve to the same value; an
  ingress credential equal to the egress credential means learning one yields
  the other.

### Fail-closed rules

| Condition | Behavior |
|-----------|----------|
| `--enable-dev-endpoints` not set | `/v1` routes are not registered → 404 |
| `--enable-dev-endpoints` set, no `--inbound-token-file` | Startup fails; the process refuses to serve |
| `--inbound-token-file` present but empty | Startup fails |
| Inbound token equals the egress API key | Startup fails |
| Wrong / missing / non-Bearer credential | 401, empty body, no forward |

Inbound auth is defense in depth, not a substitute for network isolation. When
the collector is deployed on a routable address (a Kubernetes pod IP, where the
kubelet must reach `/healthz`), pair it with a NetworkPolicy that admits only
the intended producer.

## Fail-open / fail-closed

| Layer | Default | Notes |
|-------|---------|-------|
| Collector `/v1` surface | fail-closed | Off unless `--enable-dev-endpoints` **and** `--inbound-token-file`; unauthenticated callers get 401 and no forward |
| Listen address | fail-closed | Loopback by default; exposing it is explicit |
| Normalize | fail-closed | Malformed / unsupported service → skip (no crash) |
| Forward | fail-closed on non-2xx / transport error | Leave message for redelivery when SQS lands; stub has nothing to redrive |
| Account / tenant binding | Python on ingest | Collector does not broaden trust: reaching it requires its own credential, and the control plane still re-derives tenant from auth and rejects events whose account does not match the connection's `role_ref` |

## Non-goals

- No dual product edition — see ADR-009.
- No Azure / GCP collectors yet.
- CIS evaluation stays in the control plane, never in a collector.

## Verification


Post a normalized batch straight at the control plane:

```bash
curl -sS -X POST http://127.0.0.1:8420/v1/cloud/connections/events/ingest \
  -H "Authorization: Bearer $(cat /tmp/agent-bom-api.key)" \
  -H 'Content-Type: application/json' \
  --data @cloud-change-events.json
# without the header → 401, and nothing is dispatched
```

## Code

- Python reference normalize / dispatch:
  [`src/agent_bom/cloud/event_ingest.py`](../../src/agent_bom/cloud/event_ingest.py)
