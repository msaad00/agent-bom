# Snowflake POV deployment runbook

Use this page for a Snowflake-oriented proof of value where agent-bom runs in
the customer's infrastructure and Snowflake/Cortex inventory is collected inside
the operator boundary.

## Scope

The v0.84.1 POV scope is:

- self-hosted API + UI control plane
- operator-owned Postgres-compatible control-plane database
- Snowflake/Cortex operator-pull inventory
- scan, findings, provenance, permissions, graph, and export review
- optional MCP proxy/gateway enforcement for selected MCP traffic

The POV does not include automatic patching or draft PR remediation. Today
agent-bom produces remediation plans and evidence that can be routed into an
existing Dependabot, Renovate, Jira, or AppSec workflow.

## Database options

agent-bom needs a transactional Postgres-compatible control-plane database for
multi-replica API, fleet, policy, graph, and audit state. The Helm chart does
not install a Postgres subchart.

Supported deployment pattern:

- provision the database with the customer's platform tooling
- store `AGENT_BOM_POSTGRES_URL` in a Kubernetes Secret or External Secrets
  backend
- run agent-bom API/UI pods with the database secret mounted as environment
- smoke-test migrations, API startup, graph writes, fleet sync, policy, audit,
  and backup/restore posture

Candidate database services include RDS/Aurora Postgres, Cloud SQL for
PostgreSQL, Azure Database for PostgreSQL, Supabase, Crunchy/EDB, and Snowflake
Postgres. Snowflake Postgres is a good fit for Snowflake-owned environments
when the instance exposes a normal PostgreSQL connection string reachable from
the agent-bom API pods. Treat it as a candidate until the smoke tests above pass
in the target account and region.

## 1. Create the database secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: agent-bom-control-plane-db
  namespace: agent-bom
type: Opaque
stringData:
  AGENT_BOM_POSTGRES_URL: postgresql://agent_bom:REDACTED@postgres.example:5432/agent_bom?sslmode=require
```

Apply it out of band through the operator's secret manager, SOPS, CI secret
store, or External Secrets. Do not commit the real URL.

## 2. Deploy the control plane

For a focused EKS POV with BYO Postgres:

```bash
helm upgrade --install agent-bom deploy/helm/agent-bom \
  --namespace agent-bom --create-namespace \
  -f deploy/helm/agent-bom/examples/eks-mcp-pilot-values.yaml \
  -f deploy/helm/agent-bom/examples/byo-postgres-values.yaml
```

For a production-shaped EKS profile:

```bash
helm upgrade --install agent-bom deploy/helm/agent-bom \
  --namespace agent-bom --create-namespace \
  -f deploy/helm/agent-bom/examples/eks-production-values.yaml
```

Use the Snowflake backend overlay only when the POV explicitly wants selected
agent-bom stores backed by Snowflake warehouse tables. That is separate from
using Snowflake Postgres as the Postgres-compatible control-plane database.

## 3. Verify the control plane

```bash
kubectl -n agent-bom get pods
kubectl -n agent-bom logs deploy/agent-bom-api --tail=100
kubectl -n agent-bom port-forward svc/agent-bom-api 8080:8080

curl -fsS http://127.0.0.1:8080/health
curl -fsS http://127.0.0.1:8080/version
curl -fsS http://127.0.0.1:8080/v1/discovery/providers
curl -fsS http://127.0.0.1:8080/v1/auth/policy
```

For Postgres candidate validation, run at least one scan and confirm API logs
show persistent graph/fleet/policy state without falling back to in-memory
stores.

## 4. Generate Snowflake operator-pull inventory

Run this from the operator environment, not from the agent-bom API pod:

```bash
python examples/operator_pull/snowflake_inventory_adapter.py \
  --account my-org-my-account \
  --authenticator externalbrowser \
  --database AI_PLATFORM \
  --schema PUBLIC \
  --output snowflake-inventory.json
```

Then remove Snowflake credential material from the scanner environment before
handoff:

```bash
unset SNOWFLAKE_PASSWORD SNOWFLAKE_TOKEN SNOWFLAKE_PRIVATE_KEY_PATH
```

## 5. Scan the pushed inventory

Local scan:

```bash
agent-bom agents \
  --inventory snowflake-inventory.json \
  --format json \
  --output snowflake-agent-bom.json
```

CI/SARIF gate:

```bash
agent-bom agents \
  --inventory snowflake-inventory.json \
  --format sarif \
  --output snowflake-agent-bom.sarif \
  --fail-on-severity high
```

Review these evidence fields:

- `discovery_provenance.source_type`
- `permissions_used`
- redacted `cloud_origin`
- MCP server names, transports, tools, packages, and PURLs
- graph path from package or finding to MCP server, agent, tools, and credential
  environment variable names

## 6. Optional runtime enforcement

Use `agent-bom proxy` for selected local/sidecar MCP enforcement. Use
`agent-bom gateway serve` for shared remote MCP traffic that should be governed
from one policy/audit plane.

Do not make the gateway a mandatory choke point for the whole POV. Start with a
small set of MCP traffic where policy enforcement and audit are the evaluation
goal.

## What works today

| Surface | POV status |
|---|---|
| CLI scan and SARIF gate | Works from packaged install |
| API + UI control plane | Deployable with BYO Postgres |
| Fleet and graph | Deployable for controlled POV; smoke-test in buyer env |
| MCP proxy/gateway | Deployable for selected traffic |
| Snowflake/Cortex inventory | Operator-pull adapter exists |
| Provenance and permissions | JSON, UI, SARIF, OCSF, CycloneDX surfaces exist |
| Remediation | Structured plan only |

## Roadmap / do not oversell

| Surface | Current state |
|---|---|
| Draft PR remediation | Roadmap; not part of v0.84.1 |
| Auto-remediation | Roadmap |
| Full Compliance Hub | Roadmap |
| Complete IAM-to-agent traversal | Roadmap |
| Snowflake Postgres certification | Candidate until smoke-tested |

The customer-safe positioning is: agent-bom can run in the customer's
infrastructure with customer-owned database, identity, network, and secrets. It
does not require a hosted agent-bom control plane.
