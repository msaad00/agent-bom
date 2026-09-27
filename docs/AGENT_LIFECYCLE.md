# Agent lifecycle and retained BOM history

The lifecycle API retains exact per-agent scan BOMs and records operator-supplied
logical agent → deployment → instance → run references. It is an additive
control-plane registry: existing fleet inventory and identity tokens retain their
current contracts. The BOM profile remains experimental.

## Retain a scan and inspect its history

Use a completed control-plane scan and its exact `canonical_id` / `stable_id`.
The API derives the tenant from authenticated request context. Saving and
registration require `config` permission; reading requires `read` permission.
The deployment's explicit local development no-auth exception still applies.

```python
import os
from agent_bom.client import AgentBomClient

with AgentBomClient(
    base_url="http://127.0.0.1:8422",
    api_key=os.environ["AGENT_BOM_API_KEY"],
) as client:
    saved = client.capture_agent_snapshot("COMPLETED_SCAN_ID", "EXACT_AGENT_ID")
    document = client.get_agent_snapshot(saved["snapshot_id"])
    history = client.agent_lifecycle_history("EXACT_AGENT_ID")
```

Artifact: an immutable `agent-bom.profile/v1` JSON document, its snapshot digest,
and a separate retention receipt. Next: compare two saved snapshot IDs with
`compare_agent_snapshots(before, after)`. `composition_changed` excludes receipt
IDs/times and subject display-name changes; evidence, coverage and subject changes
are reported separately. Component identifiers and relationship basis remain
significant. Unknown composition outside the scan is still unassessed.

The scan evidence panel exposes **Saved BOM history**, **Save this snapshot**,
bounded history pages and comparison of the first two entries on a page. Read
failures and configuration permission failures appear as unavailable evidence.
The API exports complete saved documents independently of the original scan's
retention. A saved snapshot is not removed when its scan record is removed.

## Register explicit lifecycle references

```python
with AgentBomClient(base_url="http://127.0.0.1:8422", api_key=os.environ["AGENT_BOM_API_KEY"]) as client:
    client.register_agent_deployment(
        {
            "deployment_id": "DEPLOYMENT_ID",
            "agent_id": "EXACT_AGENT_ID",
            "snapshot_id": saved["snapshot_id"],
            "version": "DEPLOYMENT_VERSION",
        }
    )
    client.register_agent_instance(
        {
            "instance_id": "INSTANCE_ID",
            "deployment_id": "DEPLOYMENT_ID",
            "identity_id": "LIVE_MANAGED_IDENTITY_ID",
            # Optional timezone-aware expires_at makes this an ephemeral instance.
        }
    )
    run = client.register_agent_run(
        {
            "run_id": "RUN_ID",
            "instance_id": "INSTANCE_ID",
            "conversation_id": "OPTIONAL_OPAQUE_CONVERSATION_REFERENCE",
        }
    )
    client.retire_agent_lifecycle_record("instance", "INSTANCE_ID")
```

A deployment pins one snapshot for the same exact agent. An instance requires an
existing live managed identity for that same tenant and agent, checked at
registration. A run inherits its instance's snapshot and identity; the API checks
that identity again before recording a new run. References cannot be rebound.
The identity store and registry are separate transactions: revocation can race
registration, so this check is not an authorization grant or execution guard.
Runtime enforcement must independently verify current identity and policy.

Every lifecycle receipt says `operator_recorded`. A registry write is not proof
of credential possession, workload execution, access, a successful outcome, or
delegation. Scan identity remains `observed`. Legacy name-only records are not
silently registered. Conversation IDs are opaque references; no chat content is
captured. Run activity remains outside the BOM.

Retirement is terminal. Expiry is evaluated against server time on every new
registration/run operation; no sweeper is required to reject expired instances.
Historic records remain readable after retirement/expiry. Reusing an instance ID
cannot extend its lifetime. New deployments/instances need new explicit IDs.
List other record kinds with `agent_lifecycle_history(agent_id, kind="run")` or
`deployment` / `instance`; pagination is oldest first, at most 200 rows per call.
`history_limit_reached` discloses when the bounded browsing ceiling is reached.

## Persistence, failure and rollback

SQLite is durable by default, single-node, and serializes reference checks and
writes with `BEGIN IMMEDIATE`. PostgreSQL uses the shared application pool,
forced tenant RLS, and a tenant-scoped transaction lock. Run Alembic migrations
before starting an application configured for PostgreSQL. The migration denies
snapshot UPDATE/DELETE to `agent_bom_app` and denies lifecycle DELETE; database
owners and maintenance administrators remain a separate privileged boundary.

Missing, conflicting, cross-agent, expired and retired references fail closed.
Unavailable persistence returns a generic 503; no successful retention receipt
is returned. The API exposes no evidence deletion or overwrite operation.
This is not independently anchored or tamper-proof audit storage. Retention
administration, runtime-to-run attestation and durable containment receipts are
separate capabilities and are not established by registry entries.

The schema is additive. Roll back application binaries while retaining both
lifecycle tables; the migration downgrade deliberately preserves the evidence.
Back up the control-plane database under the operator's normal retention policy.
Explicit `AGENT_BOM_EPHEMERAL_STORE=1` loses these records on restart.
