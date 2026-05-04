# Backup And Restore Runbook

> **You do not need to read this unless** you are operating the packaged
> Postgres backup CronJob (`controlPlane.backup.enabled=true`) or
> rehearsing a restore. Snowflake-native deployments use the warehouse
> durability and recovery model instead and do not need this page.

This runbook covers the packaged Postgres backup path for self-hosted control
planes. It applies when `controlPlane.backup.enabled=true` in the Helm chart.
Snowflake-native deployments use the warehouse durability and recovery model
instead.

## What Is Backed Up

The backup CronJob runs `pg_dump --format=custom` against
`AGENT_BOM_POSTGRES_URL` and uploads the resulting dump to S3-compatible
storage.

Packaged implementation:

- Helm template: `deploy/helm/agent-bom/templates/controlplane-backup-cronjob.yaml`
- values: `deploy/helm/agent-bom/values.yaml`
- restore script: `deploy/ops/restore-postgres-backup.sh`
- CI proof: `.github/workflows/backup-restore.yml`

## Production Prerequisites

Before enabling the CronJob:

1. Create a dedicated backup bucket with public access blocked.
2. Enable bucket versioning and retention appropriate for your RPO/RTO.
3. Use SSE-KMS for regulated environments.
4. Attach a least-privilege IRSA or workload-identity role to the backup
   service account.
5. Confirm `pg_dump` and `pg_restore` major versions match the Postgres major
   version.
6. Store `AGENT_BOM_POSTGRES_URL` in your secret manager, not inline values.

## Helm Values

Minimal shape:

```yaml
controlPlane:
  backup:
    enabled: true
    schedule: "0 3 * * *"
    serviceAccount:
      annotations:
        eks.amazonaws.com/role-arn: arn:aws:iam::<account-id>:role/agent-bom-backup
    destination:
      bucket: agent-bom-prod-backups
      prefix: agent-bom/postgres
      bucketRegion: "<your-backup-bucket-region>"
      encryption:
        enabled: true
        mode: "aws:kms"
        kmsKeyId: alias/agent-bom-backups
```

Keep `bucketRegion` explicit. Do not rely on example regions for production.

## Manual Backup Check

Confirm the latest backup object exists:

```bash
export AWS_REGION="<your-backup-bucket-region>"
aws s3 ls "s3://agent-bom-prod-backups/agent-bom/postgres/" \
  --region "$AWS_REGION" \
  --recursive \
  --human-readable \
  --summarize
```

Check the CronJob:

```bash
kubectl -n agent-bom get cronjob agent-bom-control-plane-backup
kubectl -n agent-bom get jobs -l app.kubernetes.io/component=control-plane-backup
```

## Restore Drill

Restore into a staging database first. Do not restore directly over production
until incident command has approved the data-loss window.

```bash
export AWS_REGION="<your-backup-bucket-region>"
export BACKUP_URI="s3://agent-bom-prod-backups/agent-bom/postgres/agent-bom-YYYYMMDDTHHMMSSZ.dump"
export RESTORE_POSTGRES_URL="postgresql://agent_bom:REDACTED@staging-postgres:5432/agent_bom"

deploy/ops/restore-postgres-backup.sh \
  "$BACKUP_URI" \
  "$RESTORE_POSTGRES_URL" \
  "$AWS_REGION"
```

Verify tenant-aware tables after restore:

```bash
psql "$RESTORE_POSTGRES_URL" -c "select count(*) from audit_log;"
psql "$RESTORE_POSTGRES_URL" -c "select team_id, count(*) from audit_log group by team_id order by team_id;"
```

Then run the control-plane smoke checks against the restored environment:

```bash
scripts/deploy/verify-eks-reference.sh \
  --cluster-name corp-ai \
  --region "$AWS_REGION" \
  --namespace agent-bom
```

## Production Restore Checklist

- Freeze scan schedules and external pushes before restore.
- Snapshot the current database if it is still reachable.
- Restore to a new database or schema first when time allows.
- Verify row counts, tenant distribution, audit export, and auth key state.
- Point the API deployment at the restored database.
- Restart API, worker, gateway, and UI deployments.
- Re-run health, metrics, and signed compliance evidence checks.
- Record the backup URI, operator, approval, start time, end time, and data
  loss window in the incident record.

## CI Guardrail

The backup workflow seeds synthetic tenant data, dumps it, wipes the database,
restores through the production restore script, and verifies row counts plus
tenant distribution. It runs on backup-script/template changes and weekly to
catch upstream image drift.
