# agent-bom Provisioning Scripts

Read-only, least-privilege provisioning for each cloud provider.
**Zero write access. Credentials never stored by agent-bom.**

---

## Security Model (applies to all providers)

| Principle | Implementation |
|---|---|
| **Agentless** | No persistent process — scan runs and exits |
| **Read-only** | Metadata and usage views only. Never touches data rows |
| **Zero credential storage** | Env vars only, never written to disk or DB |
| **Ephemeral tokens** | AWS STS, Azure AD, GCP ADC, Snowflake JWT (60s expiry) |
| **Least privilege** | Minimum permissions per provider, documented and auditable |
| **Zero trust** | Every call authenticated; no implicit session trust |
| **Instant revocation** | Disable user/role/service account to cut access in seconds |

---

## AWS (EC2 + EKS + GPU workloads)

### 1. Create the IAM policy

```bash
aws iam create-policy \
  --policy-name agent-bom-scanner \
  --policy-document file://aws_readonly_policy.json
```

### 2. Create an IAM role (preferred over IAM user)

```bash
aws iam create-role \
  --role-name agent-bom-scanner \
  --assume-role-policy-document '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Allow",
      "Principal":{"Service":"ec2.amazonaws.com"},
      "Action":"sts:AssumeRole"
    }]
  }'

aws iam attach-role-policy \
  --role-name agent-bom-scanner \
  --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/agent-bom-scanner
```

### 3. Set up EKS RBAC (for GPU + K8s workload scanning)

```bash
kubectl apply -f aws_eks_rbac.yaml

# Map the IAM role into EKS aws-auth
eksctl create iamidentitymapping \
  --cluster <CLUSTER_NAME> \
  --region <REGION> \
  --arn arn:aws:iam::<ACCOUNT_ID>:role/agent-bom-scanner \
  --username agent-bom \
  --group agent-bom-readonly
```

### 4. Scan GPU + EKS workloads

```bash
# Discover AI agents + Bedrock + SageMaker + Lambda
export AWS_REGION=us-east-1
agent-bom scan --aws --aws-include-eks

# Scan GPU nodes + containers (NVIDIA CUDA, resource requests)
agent-bom scan --gpu-scan --gpu-k8s-context <EKS_CONTEXT>

# Full scan: cloud discovery + GPU + container images
agent-bom scan --aws --aws-include-eks --gpu-scan --image <ECR_IMAGE>
```

**What gets scanned on EKS+GPU:**
- NVIDIA GPU-requesting pods (`nvidia.com/gpu` resource)
- CUDA base image CVEs
- DCGM exporter endpoints (unauthenticated exposure check)
- MCP server pods (label `mcp.io/server=true` or image signals)
- SageMaker training job packages
- Bedrock agent action groups → Lambda → package CVEs

**Credentials needed:** None if running on an EC2 instance with the IAM role attached.
For CI/CD: short-lived STS credentials via `aws sts assume-role`.

---

## Azure (AKS + Azure ML + Cognitive Services)

### 1. Create the custom role

```bash
# Replace <YOUR_SUBSCRIPTION_ID> in azure_readonly_role.json first
az role definition create --role-definition azure_readonly_role.json
```

### 2. Assign to a Managed Identity (no credentials — recommended)

```bash
# Create managed identity
az identity create --name agent-bom-scanner --resource-group <RG>

# Get the principal ID
PRINCIPAL_ID=$(az identity show --name agent-bom-scanner --resource-group <RG> --query principalId -o tsv)

# Assign the custom role
az role assignment create \
  --role "agent-bom Scanner" \
  --assignee $PRINCIPAL_ID \
  --scope /subscriptions/<SUBSCRIPTION_ID>
```

### 3. Scan

```bash
# Managed Identity (no credentials needed when running in Azure)
agent-bom scan --azure

# Service Principal (CI/CD)
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...   # or use certificate auth
export AZURE_SUBSCRIPTION_ID=...
agent-bom scan --azure
```

---

## GCP (GKE + Vertex AI + Cloud Run)

### 1. Create the custom role

```bash
gcloud iam roles create agentBomScanner \
  --project=YOUR_PROJECT_ID \
  --file=gcp_readonly_role.yaml
```

### 2. Create a service account + assign role

```bash
gcloud iam service-accounts create agent-bom-scanner \
  --display-name="agent-bom security scanner"

gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:agent-bom-scanner@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --role="projects/YOUR_PROJECT_ID/roles/agentBomScanner"
```

### 3. Use Workload Identity (no key files — recommended for GKE)

```bash
# Bind Kubernetes service account to GCP service account
gcloud iam service-accounts add-iam-policy-binding \
  agent-bom-scanner@YOUR_PROJECT_ID.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:YOUR_PROJECT_ID.svc.id.goog[security/agent-bom]"
```

### 4. Scan

```bash
# Application Default Credentials (gcloud auth application-default login)
export GOOGLE_CLOUD_PROJECT=YOUR_PROJECT_ID
agent-bom scan --gcp
```

---

## Snowflake (Cortex + Notebooks + UDFs + CIS Benchmark)

See `snowflake_readonly.sql` — run as ACCOUNTADMIN.

```bash
# After running the SQL script:
export SNOWFLAKE_ACCOUNT=myorg-myaccount
export SNOWFLAKE_USER=AGENT_BOM_SVC
export SNOWFLAKE_PRIVATE_KEY_PATH=~/.snowflake/agent_bom_key.p8
agent-bom scan --snowflake --snowflake-cis-benchmark --cortex-observability
```

---

## Credential Best Practices (all providers)

1. **Never use long-lived keys in CI/CD** — use OIDC federation (GitHub Actions → AWS/GCP/Azure natively supports this, no secrets stored)
2. **Rotate keys every 90 days** — AWS IAM Access Analyzer, Azure AD, and GCP have built-in rotation alerts
3. **Scope to minimum regions** — add `"Condition": {"StringEquals": {"aws:RequestedRegion": ["us-east-1"]}}` to AWS policies
4. **Use separate credentials per environment** — dev/staging/prod each get their own role
5. **Audit what we actually called** — CloudTrail / Azure Monitor / GCP Audit Logs record every API call agent-bom makes

---

## GitHub Actions — Zero Stored Credentials (OIDC)

The cleanest CI/CD path — no secrets stored anywhere:

```yaml
# .github/workflows/agent-bom-scan.yml
permissions:
  id-token: write   # Required for OIDC
  contents: read

steps:
  - name: Configure AWS credentials (OIDC — no stored keys)
    uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::<ACCOUNT_ID>:role/agent-bom-scanner
      aws-region: us-east-1

  - name: Run agent-bom scan
    run: agent-bom scan --aws --aws-include-eks --gpu-scan
```

Docs:
- AWS OIDC: https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services
- Azure OIDC: https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/configuring-openid-connect-in-azure
- GCP OIDC: https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/configuring-openid-connect-in-google-cloud-platform
