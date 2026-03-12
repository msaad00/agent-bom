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

## AWS

Covers: EC2, ECS, EKS, Lambda, Bedrock, SageMaker, ECR, CloudTrail, GPU instances.

EKS is an AWS-managed Kubernetes service — it uses IAM for cluster-level auth and
Kubernetes RBAC for pod-level auth. Both are required.

### 1. Create the IAM policy

```bash
aws iam create-policy \
  --policy-name agent-bom-scanner \
  --policy-document file://aws_readonly_policy.json
```

### 2. Create an IAM role (preferred over long-lived IAM user keys)

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

### 3. Set up EKS Kubernetes RBAC (required for pod + GPU workload scanning)

EKS has two auth layers: IAM (cluster access) + K8s RBAC (resource access).
Both are needed to scan running workloads.

```bash
# K8s RBAC: get/list/watch on pods, nodes, GPU resources, MCP CRDs
kubectl apply -f aws_eks_clusterrole.yaml
kubectl apply -f aws_eks_rolebinding.yaml

# Map the IAM role into EKS so it binds to the ClusterRole above
eksctl create iamidentitymapping \
  --cluster <CLUSTER_NAME> \
  --region <REGION> \
  --arn arn:aws:iam::<ACCOUNT_ID>:role/agent-bom-scanner \
  --username agent-bom \
  --group agent-bom-readonly
```

Docs:
- IAM → EKS mapping: https://docs.aws.amazon.com/eks/latest/userguide/add-user-role.html
- EKS Pod Identity (no long-lived keys): https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html

### 4. Scan AWS services

```bash
export AWS_REGION=us-east-1

# Discover: Bedrock agents, SageMaker endpoints, Lambda functions, ECS tasks
agent-bom scan --aws

# + EKS workloads (pods, deployments, MCP server pods)
agent-bom scan --aws --aws-include-eks

# + GPU nodes (NVIDIA CUDA CVEs, DCGM exposure, gpu resource requests)
agent-bom scan --aws --aws-include-eks --gpu-scan

# + Container image CVEs from ECR
agent-bom scan --aws --aws-include-eks --gpu-scan --image <ECR_URI>

# K8s MCP server discovery only
agent-bom scan --k8s-mcp --k8s-namespace <NS>
```

**What gets scanned:**

| Service | What agent-bom reads |
|---|---|
| Bedrock | Agent definitions, action groups, Lambda ARNs |
| Lambda | Function config, layers, runtime packages |
| SageMaker | Endpoints, models, notebook instances, training jobs |
| ECS | Running task images → CVE scan |
| EKS pods | Image names, GPU resource requests, MCP labels |
| EKS nodes | GPU capacity/allocatable, node labels |
| EC2 | Instance types (GPU family: p3/p4/g4/g5), AMI IDs |
| ECR | Image layers → package extraction → CVEs |
| CloudTrail | Recent API events for activity timeline |

**Credentials needed:** None if running on EC2/EKS with the IAM role attached (instance metadata service).
For CI/CD: short-lived STS tokens via OIDC (see GitHub Actions section below).

---

## Azure

Covers: AKS (Azure Kubernetes Service), Azure ML, Container Instances, Cognitive Services, ACR.

AKS is Azure's managed Kubernetes service — the custom role covers both ARM-level
cluster discovery and AKS credential retrieval for K8s API access.

### 1. Create the custom role

```bash
# Replace <YOUR_SUBSCRIPTION_ID> in azure_readonly_role.json first
az role definition create --role-definition azure_readonly_role.json
```

### 2. Assign to a Managed Identity (no credentials — recommended)

```bash
az identity create --name agent-bom-scanner --resource-group <RG>

PRINCIPAL_ID=$(az identity show --name agent-bom-scanner \
  --resource-group <RG> --query principalId -o tsv)

az role assignment create \
  --role "agent-bom Scanner" \
  --assignee $PRINCIPAL_ID \
  --scope /subscriptions/<SUBSCRIPTION_ID>
```

Docs: https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview

### 3. Scan Azure services

```bash
# Managed Identity (no credentials when running in Azure)
agent-bom scan --azure

# Service Principal (CI/CD)
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...   # or certificate: AZURE_CLIENT_CERTIFICATE_PATH
export AZURE_SUBSCRIPTION_ID=...
agent-bom scan --azure
```

**What gets scanned:** AKS clusters + node pools, Azure ML workspaces + endpoints + models, Container Instances, Cognitive Services deployments, ACR images.

---

## GCP

Covers: GKE (Google Kubernetes Engine), Vertex AI, Cloud Run, Cloud Functions, Artifact Registry.

GKE uses GCP IAM for cluster auth and Kubernetes RBAC internally. Workload Identity
Federation eliminates the need for service account key files entirely.

### 1. Create the custom role

```bash
gcloud iam roles create agentBomScanner \
  --project=YOUR_PROJECT_ID \
  --file=gcp_readonly_role.yaml
```

### 2. Create service account + assign role

```bash
gcloud iam service-accounts create agent-bom-scanner \
  --display-name="agent-bom security scanner"

gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:agent-bom-scanner@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --role="projects/YOUR_PROJECT_ID/roles/agentBomScanner"
```

### 3. Workload Identity (GKE — no key files)

```bash
gcloud iam service-accounts add-iam-policy-binding \
  agent-bom-scanner@YOUR_PROJECT_ID.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:YOUR_PROJECT_ID.svc.id.goog[security/agent-bom]"
```

Docs: https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity

### 4. Scan GCP services

```bash
export GOOGLE_CLOUD_PROJECT=YOUR_PROJECT_ID
agent-bom scan --gcp
```

**What gets scanned:** GKE clusters + node pools, Vertex AI endpoints + models + notebooks + pipeline jobs, Cloud Run services, Cloud Functions, Artifact Registry images.

---

## Snowflake

Covers: Cortex agents, notebooks, UDFs, stored procedures, Streamlit apps, Snowpark packages, CIS benchmark, governance.

### 1. Run the provisioning SQL (as ACCOUNTADMIN — one-time)

```bash
# Review snowflake_readonly.sql first, then run:
snow sql -f snowflake_readonly.sql
```

### 2. Generate key pair (no password ever set)

```bash
openssl genrsa -out ~/.snowflake/agent_bom_key.p8 2048
openssl rsa -in ~/.snowflake/agent_bom_key.p8 -pubout -out agent_bom_key.pub
# Paste content of agent_bom_key.pub into the ALTER USER line in snowflake_readonly.sql
```

### 3. Scan Snowflake services

```bash
export SNOWFLAKE_ACCOUNT=myorg-myaccount
export SNOWFLAKE_USER=AGENT_BOM_SVC
export SNOWFLAKE_PRIVATE_KEY_PATH=~/.snowflake/agent_bom_key.p8

# Full Snowflake scan
agent-bom scan --snowflake --snowflake-cis-benchmark --cortex-observability
```

Docs: https://docs.snowflake.com/en/user-guide/key-pair-auth

---

## Credential Best Practices (all providers)

1. **Never use long-lived keys in CI/CD** — use OIDC federation (GitHub Actions supports AWS/GCP/Azure natively — zero stored secrets)
2. **Rotate keys every 90 days** — AWS IAM Access Analyzer, Azure Entra ID, and GCP have built-in rotation reminders
3. **Scope to minimum regions** — add `"Condition": {"StringEquals": {"aws:RequestedRegion": ["us-east-1"]}}` to AWS policies
4. **Separate credentials per environment** — dev/staging/prod each get their own role with their own audit trail
5. **Audit what agent-bom called** — CloudTrail / Azure Monitor / GCP Audit Logs / Snowflake QUERY_HISTORY record every API call made

---

## GitHub Actions — Zero Stored Credentials (OIDC)

No secrets stored anywhere. GitHub exchanges a short-lived OIDC token for cloud credentials at runtime.

```yaml
# .github/workflows/agent-bom-scan.yml
permissions:
  id-token: write   # Required for OIDC token exchange
  contents: read

steps:
  - name: Configure AWS credentials via OIDC (no stored keys)
    uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::<ACCOUNT_ID>:role/agent-bom-scanner
      aws-region: us-east-1

  - name: Scan AWS + EKS + GPU workloads
    run: agent-bom scan --aws --aws-include-eks --gpu-scan
```

OIDC setup docs:
- AWS: https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services
- Azure: https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/configuring-openid-connect-in-azure
- GCP: https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/configuring-openid-connect-in-google-cloud-platform
