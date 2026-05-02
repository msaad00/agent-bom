# Discovery envelope (`#2083`)

The **discovery envelope** is the per-run trust contract attached to every
`Agent` that agent-bom discovers. It records *what the scan actually did*
this run: the scan mode, the explicit scope, the IAM/API permissions
exercised, and whether sensitive values were redacted or never collected.

This is distinct from `discovery_provenance` (sanitized record of *where the
asset came from*). Both can coexist on the same `Agent`:

| Field | Purpose |
|---|---|
| `discovery_provenance` | "This Agent was pulled from AWS account 12345 via cloud_pull." |
| `discovery_envelope`   | "This run used cloud_read_only mode, scoped to account/12345 + region/us-east-1, exercised ec2:DescribeInstances + iam:GetRole, redaction_status=central_sanitizer_applied." |

## Schema

```json
{
  "envelope_version": 1,
  "scan_mode": "cloud_read_only",
  "discovery_scope": [
    "aws:account/123456789012",
    "aws:region/us-east-1"
  ],
  "permissions_used": [
    "bedrock-agent:GetAgent",
    "bedrock-agent:ListAgents",
    "sts:GetCallerIdentity"
  ],
  "redaction_status": "central_sanitizer_applied",
  "captured_at": "2026-05-02T20:15:00.000+00:00"
}
```

### Locked vocabulary

`scan_mode` is a locked enum so the trust contract stays reliable:

| Value | Meaning |
|---|---|
| `local_only` | No network egress, no cloud / SaaS read, no runtime probe |
| `cloud_read_only` | Read-only API calls against a cloud provider (AWS, Azure, GCP, …) |
| `saas_read_only` | Read-only API calls against a SaaS surface (Snowflake, Databricks, …) |
| `runtime_probe` | Live MCP server introspection (`tools/list`, `resources/list`, …) |
| `container_local` | Local container scan — image layers, manifests, no runtime probe |
| `endpoint_push` | Endpoint-side discovery pushed into the API; pull-only on the server side |

`redaction_status` is also locked:

| Value | Meaning |
|---|---|
| `never_collected` | The provider deliberately never read the sensitive value |
| `redacted_in_place` | The provider redacted the value before returning it |
| `central_sanitizer_applied` | The shared `agent_bom.security` sanitizer scrubbed the value before storage |
| `not_applicable` | No sensitive values were in scope this run |

### Versioning

`envelope_version` is strict — only `1` is accepted. New producers can bump
it, but `DiscoveryEnvelope.from_dict()` will refuse mismatched versions so
old consumers detect new shapes loudly instead of silently dropping data.

Within a version, unknown enum values fall back to safe defaults
(`scan_mode = local_only`, `redaction_status = not_applicable`) so a
forward-compatible producer doesn't crash an older consumer.

## Producers

Every cloud / SaaS / local provider populates the envelope at the end of
its `discover()` and attaches it to every returned `Agent` via
`attach_envelope_to_agents(...)`. As of PR B the wired set is:

| Provider | `scan_mode` |
|---|---|
| `aws` | `cloud_read_only` |
| `gcp` | `cloud_read_only` |
| `azure` | `cloud_read_only` |
| `coreweave` | `cloud_read_only` |
| `nebius` | `cloud_read_only` |
| `snowflake` | `saas_read_only` |
| `databricks` | `saas_read_only` |
| `mlflow_provider` | `saas_read_only` |
| `wandb_provider` | `saas_read_only` |
| `huggingface` | `saas_read_only` |
| `openai_provider` | `saas_read_only` |
| `ollama` | `local_only` |

A parametric test in `tests/test_discovery_envelope.py` enforces that each
of these providers references the canonical envelope type and uses its
declared `ScanMode`, so a future refactor can't quietly reclass a SaaS
provider as `cloud_read_only` (or vice versa) without the test catching it.

```python
from agent_bom.discovery_envelope import DiscoveryEnvelope, RedactionStatus, ScanMode

envelope = DiscoveryEnvelope(
    scan_mode=ScanMode.CLOUD_READ_ONLY,
    discovery_scope=("aws:account/12345", "aws:region/us-east-1"),
    permissions_used=("ec2:DescribeInstances", "iam:ListRoles"),
    redaction_status=RedactionStatus.CENTRAL_SANITIZER_APPLIED,
)
agent.discovery_envelope = envelope.to_dict()
```

The envelope is stored on `Agent.discovery_envelope` as a plain dict so the
model stays JSON-friendly without dragging the dataclass into the import
path. Consumers can re-hydrate via `DiscoveryEnvelope.from_dict(...)`.

## API + UI surface (PR C)

The envelope rides through the existing `/v1/agents` + `/v1/agents/{name}`
endpoints — `_serialize_agent` calls `asdict(agent)` and the envelope is a
plain dict on the dataclass, so no shape transformation is needed.
TypeScript types in `ui/lib/api-types.ts` carry the canonical
`DiscoveryEnvelope` interface.

The agents page renders a `DiscoveryEnvelopeCard` on each agent's expanded
detail view (mounted only when the envelope is present). The card shows:

- a clear data-residency note ("scan ran inside your environment with
  read-only roles, no findings are sent to agent-bom") so operators
  understand the trust posture without reading docs,
- `scan_mode` + `redaction_status` chips,
- the `discovery_scope` list as compact mono-styled tags,
- the `permissions_used` list collapsed by default with a `<details>`
  summary showing the count,
- the `captured_at` timestamp + envelope version in the footer.

Visual style mirrors the existing `DiscoveryProvenanceTags` block (same
border-radius, same chip pattern) but in emerald to distinguish "trust
contract for this scan" from "where this asset came from" (the sky-blue
provenance card).

## Lock-in matrix (PR D)

`tests/test_discovery_envelope_lock_in.py` runs three invariants against
every wired provider:

1. **Permission shape** — every entry follows a recognised
   `<service>:<action>` / `<service>.<resource>.<verb>` /
   `Microsoft.<svc>/.../verb` shape.
2. **Read-only verbs** — the trailing verb of every permission must be in
   the `_READ_VERBS` allowlist (Get, List, Describe, Search, Read, Select,
   View, Retrieve, Show, Fetch, Scan, watch, GET/HEAD/OPTIONS). A future
   contributor cannot quietly add a write verb (e.g. `s3:PutObject`,
   `compute.instances.delete`) without this matrix failing — and that
   failure is the signal to either drop the verb or have a deliberate
   conversation about why a write permission is being claimed.
3. **Redaction status** — cloud / SaaS providers must declare
   `central_sanitizer_applied`; `local_only` providers (Ollama) declare
   `not_applicable`.

Plus a "no orphan providers" test that walks `agent_bom.cloud.*` and
verifies every module declaring `permissions_used` is also in the matrix
table — so a new provider added in a follow-up PR-B-style change can't
silently bypass the least-privilege check.

## Roadmap

- **PR A (merged)** — schema + Agent model field + AWS producer + tests.
- **PR B (merged)** — provider parity: every cloud / SaaS / local provider
  populates the envelope.
- **PR C (merged)** — API + UI surface; envelope visible in the dashboard.
- **PR D (this PR)** — cross-provider redaction + least-privilege lock-in
  matrix.

#2083 closes with PR D.
