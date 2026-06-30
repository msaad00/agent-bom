# agent-bom one-click AWS scan (CloudFormation)

Deploy a **read-only**, **serverless** agent-bom scan of your AWS account in one
command. The stack provisions an AWS CodeBuild project (no EC2 instance — it runs
even on free-tier-restricted accounts), runs agent-bom's AWS inventory and CIS
benchmark, and publishes HTML / JSON / plaintext reports to a private S3 bucket.

- **Read-only.** The scan role is granted only the AWS-managed `SecurityAudit`
  policy (optionally `ViewOnlyAccess`) plus write access to the single report
  bucket. It cannot change anything in your account.
- **No EC2.** Execution is serverless via CodeBuild. Nothing to patch, no
  instances, no inbound network exposure.
- **No long-lived secrets.** CodeBuild assumes the scoped role at runtime.
- **Cheap.** Small CodeBuild compute, runs in minutes, reports expire after 30
  days by default.

## Deploy

```bash
aws cloudformation deploy \
  --template-file deploy/cloudformation/agent-bom-scan.yaml \
  --stack-name agent-bom-scan \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides Region=us-east-1
```

`CAPABILITY_IAM` is required because the stack creates the scoped read-only scan
role.

## Run a scan

The CodeBuild project does not run on creation. Start an on-demand scan:

```bash
aws codebuild start-build --project-name "$(aws cloudformation describe-stacks \
  --stack-name agent-bom-scan \
  --query 'Stacks[0].Outputs[?OutputKey==`CodeBuildProject`].OutputValue' \
  --output text)"
```

Or enable recurring scans at deploy time (see **Scheduled scans** below).

## Get the reports

```bash
# Resolve the bucket name from stack outputs
BUCKET=$(aws cloudformation describe-stacks --stack-name agent-bom-scan \
  --query 'Stacks[0].Outputs[?OutputKey==`ReportBucketName`].OutputValue' \
  --output text)

# List published reports
aws s3 ls "s3://$BUCKET/aws-scan/" --recursive

# Download them all
aws s3 cp "s3://$BUCKET/aws-scan/" ./agent-bom-reports/ --recursive
```

Each run writes a timestamped prefix `aws-scan/<UTC-timestamp>/` containing:

| File          | Format                                          |
| ------------- | ----------------------------------------------- |
| `report.html` | Rich HTML report                                |
| `report.json` | Machine-readable JSON                            |
| `report.txt`  | Plaintext CLI report (no color)                 |
| `console.log` | Captured colorized console table                |

The stack also emits a `ConsoleUrl` output linking straight to the bucket in the
S3 console.

## Parameters

| Parameter             | Default                                              | Purpose                                                                 |
| --------------------- | ---------------------------------------------------- | ----------------------------------------------------------------------- |
| `Region`              | `us-east-1`                                           | AWS region passed to `agent-bom cloud aws --region`.                    |
| `FailOnSeverity`      | `none`                                                | `none\|low\|medium\|high\|critical` — fail the build at/above severity. |
| `AddViewOnlyAccess`   | `false`                                               | Also attach AWS-managed `ViewOnlyAccess` (still read-only).             |
| `AgentBomSpec`        | `agent-bom[aws]`                                      | pip spec; pin a version e.g. `agent-bom[aws]==0.90.0`.                  |
| `ComputeType`         | `BUILD_GENERAL1_SMALL`                                | CodeBuild compute size.                                                 |
| `PythonImage`         | `aws/codebuild/amazonlinux2-x86_64-standard:5.0`      | Managed CodeBuild image providing Python 3.                            |
| `ReportRetentionDays` | `30`                                                  | Days before report objects expire.                                     |
| `Schedule`            | `false`                                               | Enable an EventBridge rule for recurring scans.                        |
| `ScheduleExpression`  | `rate(7 days)`                                        | Schedule used when `Schedule=true`.                                    |

### Fail-on-severity gate

```bash
aws cloudformation deploy \
  --template-file deploy/cloudformation/agent-bom-scan.yaml \
  --stack-name agent-bom-scan \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides Region=us-east-1 FailOnSeverity=high
```

Reports are always uploaded to S3 *before* the gate runs, so a non-zero build
never loses artifacts.

### Scheduled scans

```bash
aws cloudformation deploy \
  --template-file deploy/cloudformation/agent-bom-scan.yaml \
  --stack-name agent-bom-scan \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides Region=us-east-1 Schedule=true ScheduleExpression="rate(7 days)"
```

## What gets created

| Resource                     | Type                       | Notes                                                       |
| ---------------------------- | -------------------------- | ----------------------------------------------------------- |
| Report bucket                | `AWS::S3::Bucket`          | Private (all public access blocked), SSE-S3, versioned, lifecycle expiry. |
| Bucket policy                | `AWS::S3::BucketPolicy`    | Denies non-TLS access.                                       |
| Scan role                    | `AWS::IAM::Role`           | `SecurityAudit` (+ optional `ViewOnlyAccess`) + write-to-bucket + build logs only. |
| CodeBuild project            | `AWS::CodeBuild::Project`  | Serverless scan, 30-minute timeout, `NO_SOURCE`.            |
| Schedule role + rule         | `AWS::IAM::Role` / `AWS::Events::Rule` | Only when `Schedule=true`.                       |

## Validate the template

```bash
pip install cfn-lint
cfn-lint deploy/cloudformation/agent-bom-scan.yaml
```

## Clean up

```bash
# Empty the bucket first (it is retained on stack delete)
aws s3 rm "s3://$BUCKET/" --recursive
aws cloudformation delete-stack --stack-name agent-bom-scan
aws s3 rb "s3://$BUCKET"
```

The report bucket uses a `Retain` deletion policy so reports survive an
accidental stack delete; remove it manually when you no longer need them.

## Buildspec

The CodeBuild buildspec is inlined in the template (`ScanProject.Source.BuildSpec`).
[`buildspec.yml`](./buildspec.yml) is a readable reference copy kept in sync.
