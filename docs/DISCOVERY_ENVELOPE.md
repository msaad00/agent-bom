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

Cloud providers populate the envelope at the end of `discover()` and attach
it to every returned `Agent`. AWS is the canonical example wired in the
foundation PR (#2083 PR A); other providers + connectors follow.

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

## Roadmap

- **PR A (this PR)** — schema + Agent model field + AWS producer + tests.
- PR B — connector + endpoint parity (Snowflake, Databricks, GCP, Azure,
  vector DBs, MLflow, W&B, …) all populate the envelope.
- PR C — UI surface on the agent / source detail view; `/v1/agents` and
  `/v1/discovery/providers` API responses include the envelope.
- PR D — cross-provider redaction + least-privilege test matrix.
