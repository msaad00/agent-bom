# Cloud Security Audit — IAM Offboarding Automation

> Detect IAM created by departed employees, revoke credentials, strip permissions, quarantine — fully automated with Snowflake, EventBridge, and Lambda.

## Architecture

```
                         EXTERNAL DATA SOURCES
 ┌──────────────────────────────────────────────────────────────────────┐
 │                                                                      │
 │  ┌───────────┐  ┌────────────┐  ┌────────────┐  ┌──────────────┐   │
 │  │  Workday  │  │ Snowflake  │  │ Databricks │  │  ClickHouse  │   │
 │  │  (API)    │  │ (SQL/S.I.) │  │ (Unity)    │  │  (SQL)       │   │
 │  └─────┬─────┘  └─────┬──────┘  └─────┬──────┘  └──────┬───────┘   │
 │        └───────────────┴───────┬───────┴─────────────────┘           │
 └────────────────────────────────┼─────────────────────────────────────┘
                                  │  HR termination data
                                  │  + CloudTrail IAM events
                                  ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                  AWS Organization — Security OU Account                │
 │                                                                        │
 │  ┌──────────────────────────────────────────┐                          │
 │  │  Reconciler                              │                          │
 │  │                                          │                          │
 │  │  sources.py → DepartureRecord[]          │                          │
 │  │  change_detect.py → SHA-256 row diff     │                          │
 │  │  export.py → S3 manifest (KMS encrypted) │                          │
 │  └─────────────────┬────────────────────────┘                          │
 │                    │                                                    │
 │                    ▼                                                    │
 │  ┌──────────────────────────┐     ┌─────────────────────────────┐     │
 │  │  S3 Departures Bucket    │────▶│  EventBridge Rule           │     │
 │  │  (KMS, versioned)        │     │  (S3 PutObject trigger)     │     │
 │  └──────────────────────────┘     └──────────────┬──────────────┘     │
 │                                                   │                    │
 │                                   ┌───────────────▼───────────────┐   │
 │                                   │        Step Function           │   │
 │   ┌───── VPC ─────────────────────────────────────────────────┐   │   │
 │   │                                                           │   │   │
 │   │  ┌─────────────────────┐    ┌──────────────────────────┐  │   │   │
 │   │  │ Parser Lambda       │    │ Worker Lambda             │  │   │   │
 │   │  │                     │───▶│                            │  │   │   │
 │   │  │ - Validate manifest │    │ - 13-step IAM cleanup     │  │   │   │
 │   │  │ - Grace period check│    │ - Cross-account STS       │  │   │   │
 │   │  │ - Rehire filtering  │    │ - Multi-cloud workers     │  │   │   │
 │   │  │ - IAM existence     │    │ - Audit to DDB + S3       │  │   │   │
 │   │  │                     │    │                            │  │   │   │
 │   │  │ Parser IAM Role     │    │ Worker IAM Role            │  │   │   │
 │   │  │ (read-only)         │    │ (write, cross-account)     │  │   │   │
 │   │  └─────────────────────┘    └────────────┬─────────────┘  │   │   │
 │   └──────────────────────────────────────────┼─────────────────┘   │   │
 │                                              │                      │   │
 │                 ┌────────────────────────────▼──────────────────┐    │
 │                 │  Target Accounts (via STS AssumeRole)         │    │
 │                 │                                                │    │
 │                 │  1. Revoke all credentials                    │    │
 │                 │  2. Strip all permissions                     │    │
 │                 │  3. Delete IAM user                           │    │
 │                 └──────────────────────────────────────────────┘    │
 │                                                                      │
 │   ┌──────────────────────────────────────────────────────────────┐   │
 │   │  Audit Trail                                                 │   │
 │   │  DynamoDB (per-user) + S3 (execution logs)                   │   │
 │   └──────────────────────────────┬───────────────────────────────┘   │
 └──────────────────────────────────┼───────────────────────────────────┘
                                    │  Remediation logs feed back
                                    ▼
 ┌──────────────────────────────────────────────────────────────────────┐
 │                    EXTERNAL ANALYTICS / DW                            │
 │                                                                      │
 │  ┌───────────┐  ┌────────────┐  ┌────────────┐  ┌──────────────┐   │
 │  │ Snowflake │  │ ClickHouse │  │ Databricks │  │  S3 Archive  │   │
 │  └───────────┘  └────────────┘  └────────────┘  └──────────────┘   │
 │                                                                      │
 │  Remediation history · Posture metrics · Compliance evidence         │
 └──────────────────────────────────────────────────────────────────────┘
```

> **Deployable code**: See [cloud-security](https://github.com/msaad00/cloud-security/tree/main/skills/iam-departures-remediation) for production Lambda code, CloudFormation templates, and multi-cloud workers.

## Data Flow — Step by Step

```
  STEP 1                STEP 2              STEP 3              STEP 4              STEP 5              STEP 6
 ┌─────────┐          ┌─────────┐         ┌──────────┐        ┌──────────┐        ┌──────────┐        ┌──────────┐
 │Snowflake│          │   S3    │         │EventBrdge│        │  Parser  │        │  Worker  │        │ Logs S3  │
 │  Task   │─────────▶│ Bucket  │────────▶│  Rule    │───────▶│  Lambda  │───────▶│  Lambda  │───────▶│ → DW     │
 └─────────┘          └─────────┘         └──────────┘        └──────────┘        └──────────┘        └──────────┘
  Scheduled            JSON/Parquet        S3 PutObject         Parse export        Cross-account       Audit logs
  query joins          departed            triggers rule        Match IAM to        IAM actions on      feed back to
  IAM + HR data        employee IAM        in EventBridge       departed list       target accounts     Snowflake/CH/
                       export                                   Identify targets    Revoke + strip      DBX for analytics
```

### Step 1 — Snowflake Task (Scheduled Query)

A Snowflake Task runs on schedule, joining IAM event data with HR termination records:

```sql
-- Snowflake Task: runs daily, exports departed employee IAM to S3
CREATE OR REPLACE TASK iam_offboarding_export
  WAREHOUSE = 'SECURITY_WH'
  SCHEDULE = 'USING CRON 0 2 * * * America/New_York'  -- 2 AM ET daily
AS
  COPY INTO @offboarding_stage/departed_iam/
  FROM (
    SELECT
        ct.event_time,
        ct.event_name,
        ct.creator_arn,
        ct.target_resource AS iam_resource_arn,
        ct.source_ip_address,
        hr.employee_id,
        hr.employee_name,
        hr.email,
        hr.termination_date,
        hr.department,
        DATEDIFF('day', hr.termination_date, CURRENT_DATE()) AS days_since_termination
    FROM cloudtrail_events ct
    JOIN hr_employees hr
        ON ct.creator_arn LIKE '%' || hr.aws_username || '%'
    WHERE hr.status = 'terminated'
        AND ct.event_name IN (
            'CreateUser', 'CreateRole', 'AttachUserPolicy',
            'CreateAccessKey', 'PutUserPolicy', 'AttachRolePolicy'
        )
        AND ct.target_resource NOT IN (
            SELECT arn FROM known_service_roles  -- exclude service accounts
        )
  )
  FILE_FORMAT = (TYPE = 'PARQUET')
  OVERWRITE = TRUE;
```

> **Why Snowflake?** Historical CloudTrail data is already archived there (or ClickHouse, Databricks — adapt the SQL). The join with HR data is the key: it identifies IAM created by people who no longer work here.

<details>
<summary><b>ClickHouse variant</b></summary>

```sql
-- ClickHouse: same logic, different syntax
SELECT
    ct.event_time,
    ct.event_name,
    ct.creator_arn,
    ct.target_resource AS iam_resource_arn,
    hr.employee_name,
    hr.termination_date,
    dateDiff('day', hr.termination_date, today()) AS days_since_termination
FROM cloudtrail_events ct
JOIN hr_employees hr
    ON ct.creator_arn LIKE concat('%', hr.aws_username, '%')
WHERE hr.status = 'terminated'
    AND ct.event_name IN ('CreateUser', 'CreateRole', 'AttachUserPolicy', 'CreateAccessKey')
    AND ct.target_resource NOT IN (SELECT arn FROM known_service_roles)
INTO OUTFILE 's3://offboarding-bucket/departed_iam/'
FORMAT Parquet;
```

</details>

<details>
<summary><b>Databricks variant</b></summary>

```python
# Databricks: Spark SQL or PySpark
departed_iam = spark.sql("""
    SELECT ct.event_time, ct.event_name, ct.creator_arn,
           ct.target_resource AS iam_resource_arn,
           hr.employee_name, hr.termination_date
    FROM cloudtrail_events ct
    JOIN hr_employees hr ON ct.creator_arn LIKE concat('%', hr.aws_username, '%')
    WHERE hr.status = 'terminated'
      AND ct.event_name IN ('CreateUser', 'CreateRole', 'AttachUserPolicy', 'CreateAccessKey')
""")
departed_iam.write.mode("overwrite").parquet("s3://offboarding-bucket/departed_iam/")
```

</details>

### Step 2 — S3 Bucket (Landing Zone)

The Snowflake Task exports to an S3 bucket. EventBridge picks up the `PutObject` event.

```
  s3://offboarding-bucket/
  └── departed_iam/
      └── YYYY/MM/DD/
          └── data_0_0_0.parquet    <-- Snowflake Task output
```

**Guardrails:**
- Bucket is encrypted (SSE-S3 or SSE-KMS)
- Bucket policy: only Snowflake external stage + Parser Lambda can read
- Versioning enabled for audit trail
- Lifecycle rule: expire after 90 days

### Step 3 — EventBridge Rule

S3 PutObject event triggers the Parser Lambda via EventBridge:

```json
{
  "source": ["aws.s3"],
  "detail-type": ["Object Created"],
  "detail": {
    "bucket": { "name": ["offboarding-bucket"] },
    "object": { "key": [{ "prefix": "departed_iam/" }] }
  }
}
```

### Step 4 — Parser Lambda (Read-Only)

Runs inside a VPC. Has its own IAM Role scoped to read-only.

```
  Parser Lambda
  ├── Reads Parquet from S3
  ├── Validates data schema + freshness
  ├── Deduplicates against previous runs
  ├── Enriches with current IAM state (iam:ListUsers, iam:GetUser)
  ├── Confirms each target IAM resource still exists and is active
  └── Outputs: list of confirmed orphaned IAM resources → invokes Worker Lambda
```

**Parser IAM Role** (least privilege):
```json
{
  "Effect": "Allow",
  "Action": [
    "s3:GetObject",
    "iam:ListUsers",
    "iam:GetUser",
    "iam:ListAccessKeys",
    "iam:GetLoginProfile",
    "lambda:InvokeFunction"
  ],
  "Resource": [
    "arn:aws:s3:::offboarding-bucket/departed_iam/*",
    "arn:aws:iam::*:user/*",
    "arn:aws:lambda:REGION:ACCOUNT:function:worker-lambda"
  ]
}
```

### Step 5 — Worker Lambda (Cross-Account Write)

Takes action on target accounts. Assumes a role in each target account.

```
  Worker Lambda
  ├── For each orphaned IAM resource:
  │   ├── 1. Revoke all credentials (deactivate access keys, delete login profile)
  │   ├── 2. Strip all permissions (detach managed + inline policies)
  │   ├── 3. Quarantine (tag as quarantined, move to quarantine path)
  │   └── 4. Delete (after grace period, or immediately if flagged critical)
  ├── Logs every action to execution Logs S3
  └── Sends SNS notification per remediated resource
```

**Worker IAM Role** (cross-account):
```json
{
  "Effect": "Allow",
  "Action": [
    "sts:AssumeRole"
  ],
  "Resource": [
    "arn:aws:iam::TARGET_ACCOUNT_1:role/OffboardingWorkerRole",
    "arn:aws:iam::TARGET_ACCOUNT_2:role/OffboardingWorkerRole"
  ]
}
```

The assumed role in each target account has:
```json
{
  "Effect": "Allow",
  "Action": [
    "iam:DeactivateAccessKey",
    "iam:DeleteAccessKey",
    "iam:DeleteLoginProfile",
    "iam:DetachUserPolicy",
    "iam:DeleteUserPolicy",
    "iam:RemoveUserFromGroup",
    "iam:TagUser",
    "iam:DeleteUser"
  ],
  "Resource": "arn:aws:iam::*:user/*"
}
```

### Step 6 — Audit Logs → Analytics / Data Warehouse

Lambda execution logs land in S3, then feed back into your data warehouse for historical analytics, compliance evidence, and posture tracking.

```
  Lambda Execution Logs S3
         │
         ├──▶ Snowflake (external stage → COPY INTO remediation_log)
         ├──▶ ClickHouse (S3 table function → INSERT INTO remediation_log)
         ├──▶ Databricks (Auto Loader → Delta table)
         └──▶ S3 archive (Athena queries for ad-hoc analysis)
```

This closes the loop: the same warehouse that sourced the departed employee data now stores the remediation results. You can track:
- **Remediation velocity** — time from termination to IAM cleanup
- **Coverage gaps** — departed employees whose IAM was missed
- **Posture trend** — orphaned IAM count over time
- **Compliance evidence** — auditor-ready logs of every action taken

```sql
-- Snowflake: remediation dashboard query
SELECT
    DATE_TRUNC('week', remediation_time) AS week,
    COUNT(*) AS resources_remediated,
    AVG(DATEDIFF('hour', termination_date, remediation_time)) AS avg_hours_to_remediate
FROM remediation_log
GROUP BY 1
ORDER BY 1 DESC;
```

### Step 7 — Validate with agent-bom

After the workflow completes, validate the security posture:

```bash
# CIS IAM benchmark — verify no orphaned IAM remains
agent-bom scan --aws --aws-region us-east-1 --aws-cis-benchmark

# Scan Lambda functions for CVEs in their own dependencies
agent-bom scan --aws --aws-region us-east-1 \
  --aws-include-lambda \
  --enrich -f json -o post-offboarding.json

# Check blast radius if any orphaned IAM was missed
agent-bom blast-radius --cve CVE-XXXX-YYYY
```

Via MCP tools (Claude Desktop, Cursor, etc.):

```
cis_benchmark(provider="aws", region="us-east-1")
scan()
blast_radius(cve_id="CVE-XXXX-YYYY")
```

## Security Guardrails

| Layer | Guardrail | Implementation |
|-------|-----------|---------------|
| **Data** | Freshness validation | Parser Lambda rejects exports older than 48h |
| **Data** | Schema validation | Parser validates required columns before processing |
| **Network** | VPC isolation | Both Lambdas run inside VPC, no public internet |
| **IAM** | Least privilege | Parser = read-only, Worker = scoped write via AssumeRole |
| **IAM** | Separate roles | Each Lambda has its own IAM role (no shared credentials) |
| **Audit** | Execution logs | Every action logged to S3 + CloudTrail |
| **Safety** | Grace period | Quarantine tag applied before deletion; 30-day grace |
| **Safety** | Dry-run mode | Worker Lambda supports `DRY_RUN=true` env var |
| **Safety** | Exclusion list | `known_service_roles` table prevents service account deletion |
| **Monitoring** | SNS alerts | Every remediation triggers notification to security team |
| **Compliance** | agent-bom | Post-run CIS benchmark validates IAM hygiene |

## Adapting to Your Stack

| Component | Options |
|-----------|---------|
| Data warehouse | Snowflake, ClickHouse, Databricks, BigQuery, Redshift |
| Scheduled export | Snowflake Task, Airflow DAG, dbt job, cron + Python script |
| Event trigger | EventBridge, S3 notification, SQS, SNS |
| Compute | Lambda, Step Functions, Fargate, ECS task |
| Cross-account | STS AssumeRole, AWS Organizations SCP |
| Notification | SNS, Slack webhook, PagerDuty, Teams, email |
| Ticketing | Jira, ServiceNow, Linear, GitHub Issues |
| Validation | agent-bom CIS benchmark, AWS Config rules, custom checks |

## Outputs

| Artifact | Purpose |
|----------|---------|
| S3 Parquet export | Departed employee IAM inventory (reusable) |
| Lambda execution logs (S3) | Full audit trail of every remediation action |
| SNS notifications | Real-time alerts to security team |
| agent-bom CIS report | Post-remediation IAM hygiene validation |
| CloudTrail entries | AWS-native audit of all IAM changes |
