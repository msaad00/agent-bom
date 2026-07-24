# Design: event/log collector contract (posture change events)

**Status:** Phase 2 — control-plane ingest route shipped; Go forward wired.
The Helm Deployment is gated by both `eventCollector.enabled` and
`eventCollector.image.repository`, and both are empty/false by default, so a
stock install renders no collector objects.

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
| Inbound auth on the collector's own HTTP surface | **Go** (see [Inbound auth](#inbound-auth)) |
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

- Module: `github.com/msaad00/agent-bom/runtime/event-collector`
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

- No dual product (Python edition vs Go edition) — see ADR-009.
- No cloud inventory rewrite into Go.
- No Azure / GCP collectors in Phase 1.
- No moving CIS evaluation into Go.

## Verification

```bash
make event-collector-go-test
# equivalent: cd runtime/event-collector && go test ./...
```

Local run with the dev helpers enabled:

```bash
umask 077 && openssl rand -hex 32 > /tmp/collector-inbound.token

go run ./cmd/event-collector \
  --control-plane-url=http://127.0.0.1:8420 \
  --api-key-file=/tmp/agent-bom-api.key \
  --inbound-token-file=/tmp/collector-inbound.token \
  --enable-dev-endpoints

curl -sS -X POST http://127.0.0.1:8092/v1/forward/cloudtrail \
  -H "Authorization: Bearer $(cat /tmp/collector-inbound.token)" \
  -H 'Content-Type: application/json' \
  --data @cloudtrail-event.json
# → {"status":"forwarded","path":"/v1/cloud/connections/events/ingest"}
# without the header → 401 with an empty body, and nothing is forwarded
```

## Code

- Go: [`runtime/event-collector/`](../../runtime/event-collector/)
- Helm: `eventCollector.*` in [`deploy/helm/agent-bom/values.yaml`](../../deploy/helm/agent-bom/values.yaml)
- Python reference normalize / dispatch:
  [`src/agent_bom/cloud/event_ingest.py`](../../src/agent_bom/cloud/event_ingest.py)
