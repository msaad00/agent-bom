# Postgres Provisioning Workflow

> **You do not need to read this unless** your platform team is
> provisioning Postgres outside of the reference installer (e.g. with
> custom Terraform, an existing RDS, or a non-default user/role layout).
> The paved-path installers in [Deployment Overview](overview.md) handle
> this for you.

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

- `AGENT_BOM_POSTGRES_URL` for the tenant-bound `agent_bom_app` runtime role
- `AGENT_BOM_POSTGRES_MAINTENANCE_URL` for the separately validated
  `agent_bom_maintenance` role used only inside scoped maintenance operations
- `ALEMBIC_DATABASE_URL` for the migration/admin role; never inject this Secret
  into the API workload

Typical shape:

```bash
export AGENT_BOM_POSTGRES_URL="postgresql://agent_bom_app:***@postgres.internal:5432/agent_bom"
export AGENT_BOM_POSTGRES_MAINTENANCE_URL="postgresql://agent_bom_maintenance:***@postgres.internal:5432/agent_bom"
export ALEMBIC_DATABASE_URL="postgresql://agent_bom:***@postgres.internal:5432/agent_bom"
```

Recommended operator practice:

- inject each identity through its own `Secret` / `ExternalSecret`
- do not inline credentials in values files
- treat the app URL as the switch that enables:
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

The packaged Helm chart therefore has no Postgres subchart dependency. The
production contract is:

1. provision Postgres/RDS with your platform tooling
2. populate three distinct database Secrets: tenant-bound app, scoped
   maintenance, and migration/admin
3. before an upgrade from 0.98.2 or earlier, either let a `CREATEROLE` migration
   principal create/rotate `agent_bom_app` and `agent_bom_maintenance`, or have
   the DBA pre-provision those exact roles with the supplied credentials; the
   API role must never inherit `agent_bom_rls_maintenance`
4. run the packaged migration with all three Secret references; its connection
   identity remains migration/admin while the app and maintenance credentials
   are used only to bootstrap or verify the fixed runtime roles
5. expose only `AGENT_BOM_POSTGRES_URL` and
   `AGENT_BOM_POSTGRES_MAINTENANCE_URL` to the API; expose only the maintenance
   URL to backup jobs with the scoped bypass option
6. install/start the workload profile after migrations complete

For clusters without External Secrets Operator, use the shipped Secret shape as
a starting point:

```bash
cp deploy/helm/agent-bom/examples/postgres-secret.example.yaml /tmp/agent-bom-postgres-secret.yaml
# edit /tmp/agent-bom-postgres-secret.yaml or render it from your secret manager
kubectl apply -f /tmp/agent-bom-postgres-secret.yaml
```

For clusters with External Secrets Operator, use the `production` profile and
replace the `REPLACE_ME_*` remote references in
`deploy/helm/agent-bom/examples/eks-production-values.yaml`.

## Request-to-database tenant flow

For Postgres-backed deployments, a successful authenticated request does this:

1. auth middleware resolves tenant
2. request state carries `tenant_id`
3. middleware binds `app.tenant_id` into the Postgres session
4. Postgres RLS enforces that tenant boundary on protected tables

That means Postgres is not just a passive storage backend; it participates in
tenant enforcement.

## Upgrading a pre-existing Postgres volume (superuser crash-loop)

The RLS role guard refuses to start the API when the connection role has
`SUPERUSER` or `BYPASSRLS`, because either attribute silently voids tenant
isolation. Fresh installs are fine: `deploy/supabase/postgres/init.sql` strips
`SUPERUSER`/`BYPASSRLS` from the `agent_bom` owner and provisions the DML-only
`agent_bom_app` role automatically.

`init.sql` only runs on **first** cluster init (an empty data directory). If you
created your `postgres-data` volume before that de-superuser block shipped, the
`agent_bom` role is still a `SUPERUSER`, and upgrading to a build with the guard
will fail closed on boot — the API pod crash-loops with a
`RlsRolePrivilegeError` and no automatic escape.

Fix it once, on the existing database, before rolling the new image:

```sql
-- run as a superuser against the existing database, one time
ALTER ROLE agent_bom NOSUPERUSER NOBYPASSRLS;
```

Then point `AGENT_BOM_POSTGRES_URL` at the least-privilege `agent_bom_app` role
(the intended production connection role). As a temporary stopgap only — for a
single-tenant or local/dev deployment where tenant isolation is not required —
you may instead set `AGENT_BOM_ALLOW_SUPERUSER_DB=1` to downgrade the hard
failure to a warning. The distinct maintenance login and marker-role validation
remain mandatory even under this acknowledgement. This flag disables database
tenant isolation and is only for disposable single-tenant/local development;
never use it in production or any multi-tenant deployment because it leaves
cross-tenant reads/writes possible.

The trusted-maintenance migration honors that same explicit acknowledgement
for an existing privileged application role, but it never grants the
maintenance marker to the application role or reuses the application pool for
scoped maintenance operations.

## Operational checklist

Before calling the deployment production-ready:

1. confirm app, maintenance, and migration/admin URLs are injected from
   distinct secret sources and only the app + maintenance Secrets reach API pods
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
