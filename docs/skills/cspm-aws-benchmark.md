# CSPM — AWS CIS Foundations Benchmark

> Run CIS AWS Foundations v3.0 checks, map controls to compliance frameworks, track posture over time, and remediate findings — using agent-bom as the assessment engine.

## Architecture

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │                        AWS Account(s)                               │
  │                                                                     │
  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
  │  │   IAM    │  │    S3    │  │CloudTrail│  │   VPC    │           │
  │  │ Users    │  │ Buckets  │  │  Trails  │  │ Configs  │           │
  │  │ Roles    │  │ Policies │  │  Logs    │  │ Flow Logs│           │
  │  │ Policies │  │ Encrypt  │  │  Events  │  │ NACLs    │           │
  │  │ MFA      │  │ Versioning│ │  SNS     │  │ SGs      │           │
  │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘           │
  │       │              │             │              │                  │
  │       └──────────────┴──────┬──────┴──────────────┘                  │
  │                             │                                        │
  └─────────────────────────────┼────────────────────────────────────────┘
                                │
                                ▼
                  ┌──────────────────────────┐
                  │      agent-bom           │
                  │  cis_benchmark           │
                  │  (provider="aws")        │
                  │                          │
                  │  18 checks across:       │
                  │  - IAM (7 checks)        │
                  │  - Storage (4 checks)    │
                  │  - Logging (4 checks)    │
                  │  - Networking (3 checks) │
                  └─────────────┬────────────┘
                                │
                  ┌─────────────▼────────────┐
                  │  Compliance Mapping       │
                  │                           │
                  │  CIS AWS v3.0            │
                  │  NIST CSF 2.0            │
                  │  ISO 27001:2022          │
                  │  SOC 2 TSC              │
                  │  PCI DSS 4.0            │
                  └─────────────┬────────────┘
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                   │
              ▼                 ▼                   ▼
        ┌──────────┐    ┌──────────┐       ┌──────────┐
        │  SARIF   │    │  HTML    │       │  JSON    │
        │  (GitHub)│    │Dashboard │       │ (SIEM)   │
        └──────────┘    └──────────┘       └──────────┘
```

## CIS AWS Foundations v3.0 — Controls Map

### IAM Controls (Section 1)

| # | CIS Control | What agent-bom Checks | Severity | NIST CSF | ISO 27001 |
|---|------------|----------------------|----------|----------|-----------|
| 1.1 | MFA on root account | Root account has hardware MFA | CRITICAL | PR.AC-1 | A.8.5 |
| 1.2 | MFA for IAM users | Console users have MFA enabled | HIGH | PR.AC-1 | A.8.5 |
| 1.3 | Credentials unused 45+ days | Access keys + passwords not used in 45 days | MEDIUM | PR.AC-1 | A.5.18 |
| 1.4 | Access keys rotated 90 days | Key age > 90 days flagged | MEDIUM | PR.AC-1 | A.5.17 |
| 1.5 | Password policy strength | Min length, complexity, rotation | MEDIUM | PR.AC-1 | A.5.17 |
| 1.6 | No root access keys | Root account has no access keys | CRITICAL | PR.AC-4 | A.8.2 |
| 1.7 | IAM policies not inline | Users have managed policies, not inline | LOW | PR.AC-4 | A.5.15 |

### Storage Controls (Section 2)

| # | CIS Control | What agent-bom Checks | Severity | NIST CSF | ISO 27001 |
|---|------------|----------------------|----------|----------|-----------|
| 2.1 | S3 bucket encryption | Default encryption enabled (SSE-S3/KMS) | HIGH | PR.DS-1 | A.8.24 |
| 2.2 | S3 bucket logging | Server access logging or CloudTrail S3 events | MEDIUM | DE.AE-3 | A.8.15 |
| 2.3 | S3 public access blocked | Block public access at account + bucket level | CRITICAL | PR.AC-3 | A.8.3 |
| 2.4 | S3 versioning enabled | MFA Delete or versioning on sensitive buckets | MEDIUM | PR.DS-1 | A.8.13 |

### Logging Controls (Section 3)

| # | CIS Control | What agent-bom Checks | Severity | NIST CSF | ISO 27001 |
|---|------------|----------------------|----------|----------|-----------|
| 3.1 | CloudTrail enabled | Multi-region trail with management events | CRITICAL | DE.AE-3 | A.8.15 |
| 3.2 | CloudTrail log validation | Log file integrity validation enabled | HIGH | PR.DS-6 | A.8.15 |
| 3.3 | CloudTrail S3 not public | Trail S3 bucket has no public access | CRITICAL | PR.AC-3 | A.8.3 |
| 3.4 | CloudWatch alarms | Alarms for unauthorized API calls, root usage | MEDIUM | DE.CM-1 | A.8.16 |

### Networking Controls (Section 4)

| # | CIS Control | What agent-bom Checks | Severity | NIST CSF | ISO 27001 |
|---|------------|----------------------|----------|----------|-----------|
| 4.1 | No unrestricted SSH | Security groups block 0.0.0.0/0 on port 22 | HIGH | PR.AC-5 | A.8.20 |
| 4.2 | No unrestricted RDP | Security groups block 0.0.0.0/0 on port 3389 | HIGH | PR.AC-5 | A.8.20 |
| 4.3 | VPC flow logs enabled | Flow logs active on all VPCs | MEDIUM | DE.CM-1 | A.8.16 |

## Running the Assessment

### Quick check (single region)

```bash
agent-bom scan --aws --aws-region us-east-1 --aws-cis-benchmark
```

### Full assessment (multi-region + enrichment)

```bash
# All regions with CVE enrichment + compliance mapping
for region in us-east-1 us-west-2 eu-west-1 ap-southeast-1; do
  agent-bom scan --aws --aws-region $region \
    --aws-cis-benchmark \
    --enrich \
    -f json -o cis-aws-$region.json
done
```

### Via MCP tool

```
cis_benchmark(provider="aws", region="us-east-1")
```

### CI/CD gate

```yaml
- name: CIS AWS Benchmark
  run: |
    agent-bom scan --aws --aws-region us-east-1 \
      --aws-cis-benchmark \
      --fail-on-severity high \
      -f sarif -o cis-results.sarif -q

- name: Upload to GitHub Security
  if: always()
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: cis-results.sarif
```

## Remediation Playbook

### Critical findings — fix immediately

```
  FINDING: Root account has access keys
  ──────────────────────────────────────
  WHY:     Root keys = unlimited blast radius. Compromised root = full account takeover.
  FIX:     aws iam delete-access-key --user-name root --access-key-id AKIA...
  VERIFY:  agent-bom scan --aws --aws-cis-benchmark | grep "root_access_keys"
```

```
  FINDING: S3 bucket publicly accessible
  ──────────────────────────────────────
  WHY:     Public S3 = data exfiltration. #1 source of cloud data breaches.
  FIX:     aws s3api put-public-access-block --bucket NAME \
             --public-access-block-configuration \
             BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
  VERIFY:  agent-bom scan --aws --aws-cis-benchmark | grep "s3_public"
```

### High findings — fix within 48h

<details>
<summary><b>IAM users without MFA</b></summary>

```bash
# List users without MFA
aws iam list-users --query 'Users[*].UserName' --output text | \
  while read user; do
    mfa=$(aws iam list-mfa-devices --user-name "$user" --query 'MFADevices' --output text)
    [ -z "$mfa" ] && echo "NO MFA: $user"
  done

# Enforce MFA via IAM policy
# Attach a policy that denies all actions except MFA setup when MFA is not present
```

</details>

<details>
<summary><b>Stale access keys (> 90 days)</b></summary>

```bash
# Find stale keys
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d | \
  awk -F',' '$11 != "N/A" && $11 < "'$(date -d "-90 days" +%Y-%m-%d)'" {print $1, $11}'

# Deactivate stale keys
aws iam update-access-key --user-name USER --access-key-id AKIA... --status Inactive
```

</details>

<details>
<summary><b>Unrestricted SSH/RDP</b></summary>

```bash
# Find security groups with 0.0.0.0/0 on port 22 or 3389
aws ec2 describe-security-groups \
  --filters Name=ip-permission.from-port,Values=22 \
            Name=ip-permission.cidr-ip,Values=0.0.0.0/0 \
  --query 'SecurityGroups[*].[GroupId,GroupName]' --output table

# Revoke the rule
aws ec2 revoke-security-group-ingress --group-id sg-XXX \
  --protocol tcp --port 22 --cidr 0.0.0.0/0
```

</details>

## Posture Metrics

Track these metrics over time (export to ClickHouse, Snowflake, or any SIEM):

| Metric | Formula | Target |
|--------|---------|--------|
| CIS Pass Rate | `passed_checks / total_checks * 100` | > 90% |
| Critical Findings | Count of CRITICAL severity findings | 0 |
| Mean Time to Remediate | Avg days from finding to fix | < 7 days |
| IAM MFA Coverage | `users_with_mfa / total_console_users * 100` | 100% |
| Stale Key Count | Access keys > 90 days old | 0 |
| Public S3 Buckets | Buckets with public access | 0 |
| CloudTrail Coverage | Regions with active trails | 100% |

```bash
# Export metrics to ClickHouse via agent-bom analytics
export AGENT_BOM_CLICKHOUSE_URL="clickhouse://user:pass@host:8123/security"
agent-bom scan --aws --aws-cis-benchmark --enrich -f json -o cis-results.json
agent-bom analytics-query --query "cis_trend" --days 90
```

## Outputs

| Artifact | Purpose |
|----------|---------|
| CIS benchmark results (JSON) | Machine-readable findings per control |
| SARIF report | GitHub Security tab integration |
| HTML dashboard | Visual posture overview for stakeholders |
| Posture metrics | Time-series tracking in SIEM/warehouse |
