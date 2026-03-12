# CSPM — GCP CIS Foundations Benchmark

> GCP CIS Foundations v3.0 assessment with controls mapping, Vertex AI security, and posture tracking — preparation skill for when agent-bom ships native GCP CIS checks.

## Architecture

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │                         GCP Project                                 │
  │                                                                     │
  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
  │  │  IAM &   │  │  Cloud   │  │  Cloud   │  │  VPC     │           │
  │  │  Service │  │  Storage │  │  Logging │  │  Network │           │
  │  │  Accounts│  │  Buckets │  │  + Audit │  │  Firewall│           │
  │  │  Roles   │  │  IAM     │  │  Sinks   │  │  Rules   │           │
  │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘           │
  │       │              │             │              │                  │
  │       └──────────────┴──────┬──────┴──────────────┘                  │
  └─────────────────────────────┼────────────────────────────────────────┘
                                │
                                ▼
                  ┌──────────────────────────┐
                  │      agent-bom           │
                  │  cis_benchmark           │
                  │  (provider="gcp")        │
                  │                          │
                  │  + scan --gcp            │
                  │  (Vertex AI, Cloud Run,  │
                  │   Cloud Functions, GKE)  │
                  └─────────────┬────────────┘
                                │
              ┌─────────────────┼─────────────────┐
              ▼                 ▼                   ▼
        ┌──────────┐    ┌──────────┐       ┌──────────┐
        │  SARIF   │    │  HTML    │       │  JSON    │
        └──────────┘    └──────────┘       └──────────┘
```

## CIS GCP Foundations v3.0 — Controls Map

### IAM Controls (Section 1)

| # | CIS Control | Check | Severity | NIST CSF |
|---|------------|-------|----------|----------|
| 1.1 | Corp credentials (Cloud Identity/Workspace) | No personal Gmail accounts for IAM | HIGH | PR.AC-1 |
| 1.2 | MFA enforced org-wide | Organization policy requires MFA | CRITICAL | PR.AC-1 |
| 1.3 | No service account keys | Prefer Workload Identity Federation | HIGH | PR.AC-1 |
| 1.4 | Service account key rotation | Keys rotated within 90 days | MEDIUM | PR.AC-1 |
| 1.5 | No user-managed SA keys for default SAs | Default compute/app engine SAs keyless | HIGH | PR.AC-4 |
| 1.6 | No project-wide SSH keys | Restrict SSH to instance-level | MEDIUM | PR.AC-5 |
| 1.7 | SA impersonation limited | `iam.serviceAccountTokenCreator` scoped | HIGH | PR.AC-4 |

### Cloud Storage Controls (Section 2)

| # | CIS Control | Check | Severity | NIST CSF |
|---|------------|-------|----------|----------|
| 2.1 | Uniform bucket-level access | No legacy ACL, uniform IAM only | HIGH | PR.AC-3 |
| 2.2 | Bucket retention policy | Retention lock on compliance-critical buckets | MEDIUM | PR.DS-1 |
| 2.3 | No public buckets | `allUsers`/`allAuthenticatedUsers` not granted | CRITICAL | PR.AC-3 |
| 2.4 | CMEK encryption | Customer-managed encryption keys on sensitive data | MEDIUM | PR.DS-1 |

### Logging Controls (Section 3)

| # | CIS Control | Check | Severity | NIST CSF |
|---|------------|-------|----------|----------|
| 3.1 | Audit logging enabled | Data Access audit logs for all services | CRITICAL | DE.AE-3 |
| 3.2 | Log sinks configured | Org-level sink to Cloud Storage / BigQuery | HIGH | DE.AE-3 |
| 3.3 | Log bucket retention | Logs retained for minimum 365 days | MEDIUM | DE.AE-5 |
| 3.4 | Alert policies | Alerts for IAM changes, firewall changes, route changes | MEDIUM | DE.CM-1 |

### Networking Controls (Section 4)

| # | CIS Control | Check | Severity | NIST CSF |
|---|------------|-------|----------|----------|
| 4.1 | No default network | Default VPC deleted in all projects | MEDIUM | PR.AC-5 |
| 4.2 | No unrestricted SSH/RDP | Firewall rules block 0.0.0.0/0 on 22/3389 | HIGH | PR.AC-5 |
| 4.3 | VPC flow logs enabled | Flow logs on all subnets | MEDIUM | DE.CM-1 |
| 4.4 | Private Google Access | Subnets use Private Google Access for GCP APIs | MEDIUM | PR.AC-5 |
| 4.5 | SSL policies on load balancers | TLS 1.2+ enforced, no weak ciphers | HIGH | PR.DS-2 |

### Vertex AI Controls (GCP-Specific)

| # | Control | Check | Severity |
|---|---------|-------|----------|
| V.1 | Model endpoint auth | Endpoints require IAM authentication | CRITICAL |
| V.2 | VPC-SC for Vertex | Vertex AI services inside VPC Service Controls | HIGH |
| V.3 | CMEK for training data | Training datasets encrypted with CMEK | MEDIUM |
| V.4 | Model registry audit | Model versions tracked with lineage | MEDIUM |
| V.5 | No public endpoints | Vertex AI endpoints not exposed to internet | CRITICAL |

## Running the Assessment

### GCP discovery + benchmark (current)

```bash
# Discover Vertex AI, Cloud Run, Cloud Functions, GKE
agent-bom scan --gcp --gcp-project my-project-id --enrich

# When GCP CIS checks ship:
agent-bom scan --gcp --gcp-project my-project-id --gcp-cis-benchmark
```

### Via MCP tool

```
# Current: discovery scan
scan()

# When GCP CIS ships:
cis_benchmark(provider="gcp", project="my-project-id")
```

### Manual assessment (until native checks ship)

Use `gcloud` to verify controls that agent-bom doesn't yet check natively:

<details>
<summary><b>IAM checks via gcloud</b></summary>

```bash
# 1.1 Check for personal Gmail accounts
gcloud projects get-iam-policy $PROJECT_ID --format=json | \
  jq '.bindings[].members[]' | grep -i "gmail.com" && echo "FAIL: Personal accounts found"

# 1.3 List service account keys (should be empty for Workload Identity)
gcloud iam service-accounts list --project=$PROJECT_ID --format="value(email)" | \
  while read sa; do
    keys=$(gcloud iam service-accounts keys list --iam-account=$sa \
      --managed-by=user --format="value(name)" 2>/dev/null)
    [ -n "$keys" ] && echo "FAIL: $sa has user-managed keys"
  done

# 1.2 Check MFA enforcement (requires Admin SDK or manual check in Workspace Admin)
echo "CHECK: Verify MFA enforcement in Google Workspace Admin > Security > 2SV"
```

</details>

<details>
<summary><b>Storage + Logging checks via gcloud</b></summary>

```bash
# 2.3 Check for public buckets
gsutil ls -p $PROJECT_ID | while read bucket; do
  acl=$(gsutil iam get $bucket 2>/dev/null)
  echo "$acl" | grep -q "allUsers\|allAuthenticatedUsers" && echo "FAIL: Public: $bucket"
done

# 3.1 Check audit logging
gcloud projects get-iam-policy $PROJECT_ID --format=json | \
  jq '.auditConfigs // "NONE"'

# 4.3 Check VPC flow logs
gcloud compute networks subnets list --project=$PROJECT_ID --format=json | \
  jq '.[] | select(.logConfig.enable != true) | .name' | \
  while read subnet; do echo "FAIL: No flow logs: $subnet"; done
```

</details>

## Remediation Playbook

### Critical findings

```
  FINDING: Vertex AI endpoint publicly accessible
  ────────────────────────────────────────────────
  WHY:     Public model endpoints = prompt injection surface + data exfiltration risk
  FIX:     gcloud ai endpoints update ENDPOINT_ID --region=REGION \
             --clear-traffic-split  # Remove public routing
           # Then: configure VPC-SC perimeter for Vertex AI
  VERIFY:  gcloud ai endpoints describe ENDPOINT_ID --region=REGION --format=json | jq '.network'
```

```
  FINDING: Public Cloud Storage bucket
  ─────────────────────────────────────
  FIX:     gsutil iam ch -d allUsers gs://BUCKET_NAME
           gsutil iam ch -d allAuthenticatedUsers gs://BUCKET_NAME
  VERIFY:  gsutil iam get gs://BUCKET_NAME | grep -c "allUsers"  # should be 0
```

## Posture Metrics

| Metric | Target |
|--------|--------|
| CIS Pass Rate | > 90% |
| Service Accounts with User Keys | 0 |
| Public Buckets | 0 |
| Subnets without Flow Logs | 0 |
| Vertex AI Endpoints without VPC-SC | 0 |
| Audit Logging Coverage | 100% of services |

## Outputs

| Artifact | Purpose |
|----------|---------|
| GCP scan results (JSON) | Vertex AI, Cloud Run, GKE inventory |
| CIS assessment (JSON) | Per-control pass/fail (when native checks ship) |
| SARIF report | GitHub Security tab |
| Posture metrics | Time-series for SIEM/dashboard |
