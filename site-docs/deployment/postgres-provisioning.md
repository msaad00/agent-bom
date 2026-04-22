# Postgres Provisioning Workflow

This page documents the Postgres contract for self-hosted `agent-bom`
operators.

Use this when you are deploying the control plane in your own infra and want to
understand:

- what Postgres is responsible for
- what Terraform or platform automation should provision
- what Helm should own
- what secrets/env vars the chart expects

## What Postgres owns

Postgres is the primary transactional control-plane store for:

- scan jobs
- fleet state
- gateway policy state
- audit log
- API key store
- exceptions
- schedules
- graph state
- trend/baseline history

If you need the widest backend parity today, Postgres is the default.

## What to provision before Helm

Your company platform or the shipped AWS baseline module should provision:

- a Postgres instance or cluster
- network reachability from the `agent-bom` namespace
- a database and application user
- TLS policy according to your platform standard
- secret storage for the connection string
- backup policy and retention

For AWS/EKS, the reference path is:

- [Terraform AWS Baseline](terraform-aws-baseline.md)
- [AWS Company Rollout](aws-company-rollout.md)

## Connection contract

The chart expects:

- `AGENT_BOM_POSTGRES_URL`

Typical shape:

```bash
export AGENT_BOM_POSTGRES_URL="postgresql://agent_bom:***@postgres.internal:5432/agent_bom"
```

Recommended operator practice:

- inject this through `Secret` / `ExternalSecret`
- do not inline it in values files
- treat it as the switch that enables:
  - Postgres transactional stores
  - shared rate limiting in multi-replica deployments
  - tenant-scoped RLS enforcement in the database layer

## How Helm and Postgres relate

Helm should own:

- Deployments
- Services
- HPAs / PDBs
- CronJobs
- product ConfigMaps / Secrets references

Helm should **not** be your primary database provisioning layer.

That split is deliberate:

- company platform teams usually already own database provisioning standards
- destroy/cleanup ownership stays clearer
- the product can deploy into an existing EKS platform cleanly

## Request-to-database tenant flow

For Postgres-backed deployments, a successful authenticated request does this:

1. auth middleware resolves tenant
2. request state carries `tenant_id`
3. middleware binds `app.tenant_id` into the Postgres session
4. Postgres RLS enforces that tenant boundary on protected tables

That means Postgres is not just a passive storage backend; it participates in
tenant enforcement.

## Operational checklist

Before calling the deployment production-ready:

1. confirm `AGENT_BOM_POSTGRES_URL` is injected from a secret source
2. confirm API replicas are using Postgres-backed shared rate limiting
3. confirm audit log backend is Postgres or an explicitly chosen alternative
4. confirm backups and restore workflow exist for the database
5. confirm connection pool sizing matches your endpoint and scan volume

## What this does not try to do

This page does not replace your company’s full database platform standard.

It is intentionally the `agent-bom` contract:

- what the product needs
- what the product assumes
- what the product wires when Postgres is present

If your platform team already provisions Postgres another way, keep that and
just satisfy the same runtime contract.
