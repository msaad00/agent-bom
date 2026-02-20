# Cloud Security Audit

> Multi-cloud AI asset discovery and vulnerability assessment across AWS, Azure, GCP, Snowflake, Databricks, and Nebius.

## Goal

Discover every AI agent, model endpoint, MCP server, container workload, and serverless function across your cloud accounts. Scan all discovered assets for CVEs, map blast radius, and produce an actionable remediation plan with OWASP LLM Top 10 + MITRE ATLAS threat tagging.

## Prerequisites

```bash
pip install 'agent-bom[cloud]'  # All cloud SDKs
# Or install individual providers:
pip install 'agent-bom[aws]'
pip install 'agent-bom[snowflake]'
pip install 'agent-bom[azure]'
pip install 'agent-bom[gcp]'
pip install 'agent-bom[databricks]'
pip install 'agent-bom[nebius]'
```

Authenticate with each provider's standard credential chain before running scans.

## Steps

### 1. Pre-flight Check

Verify credentials and see what APIs will be called:

```bash
# AWS
agent-bom scan --aws --aws-region us-east-1 --dry-run

# Snowflake
agent-bom scan --snowflake --dry-run

# All providers
agent-bom scan --aws --azure --gcp --snowflake --databricks --nebius --dry-run
```

Review the API list. No data is read during `--dry-run`.

### 2. AWS Deep Scan

AWS has the deepest discovery surface. Start with the defaults, then expand:

```bash
# Phase 1: Bedrock agents, ECS containers, SageMaker endpoints
agent-bom scan --aws --aws-region us-east-1 --enrich -f json -o aws-phase1.json
```

Review results. Then add deeper sources:

```bash
# Phase 2: Add Lambda functions + EKS clusters + Step Functions
agent-bom scan --aws --aws-region us-east-1 \
  --aws-include-lambda \
  --aws-include-eks \
  --aws-include-step-functions \
  --enrich -f json -o aws-phase2.json
```

**Decision point**: If EC2 instances run AI workloads (tagged):

```bash
# Phase 3: EC2 instances filtered by tag
agent-bom scan --aws --aws-region us-east-1 \
  --aws-include-ec2 --aws-ec2-tag "Team=ml-platform" \
  --enrich -f json -o aws-ec2.json
```

For multi-region, repeat with each region:

```bash
for region in us-east-1 us-west-2 eu-west-1; do
  agent-bom scan --aws --aws-region $region \
    --aws-include-lambda --aws-include-eks \
    --enrich -f json -o aws-$region.json
done
```

### 3. Snowflake Deep Scan

Snowflake discovery covers the full Cortex AI stack automatically:

```bash
agent-bom scan --snowflake --enrich -f json -o snowflake-audit.json
```

This discovers:
- **Cortex Agents** — agentic orchestration systems
- **Native MCP Servers** — with YAML tool spec parsing; `SYSTEM_EXECUTE_SQL` tools flagged as HIGH-RISK
- **Query History Audit** — catches `CREATE MCP SERVER` and `CREATE AGENT` from query logs
- **Custom Tools** — functions and procedures with language annotation
- **Cortex Search Services** — semantic search endpoints
- **Snowpark Packages** — installed Python/Java packages
- **Streamlit Apps** — deployed Streamlit applications

**Decision point**: If `SYSTEM_EXECUTE_SQL` tools are found, flag them for immediate review — these allow arbitrary SQL execution through MCP.

### 4. Azure Scan

```bash
agent-bom scan --azure --azure-subscription <sub-id> --enrich -f json -o azure-audit.json
```

Discovers AI Foundry agents and Container Apps.

### 5. GCP Scan

```bash
agent-bom scan --gcp --gcp-project <project-id> --enrich -f json -o gcp-audit.json
```

Discovers Vertex AI endpoints and Cloud Run services.

### 6. Databricks Scan

```bash
agent-bom scan --databricks --enrich -f json -o databricks-audit.json
```

Discovers cluster libraries (PyPI/Maven) and model serving endpoints.

### 7. Nebius GPU Cloud Scan

```bash
agent-bom scan --nebius --nebius-project-id <project> --enrich -f json -o nebius-audit.json
```

Discovers Managed K8s clusters and container services.

### 8. CoreWeave / GPU K8s Clusters

CoreWeave and other K8s-native GPU clouds use standard Kubernetes:

```bash
# CoreWeave
agent-bom scan --k8s --context=coreweave-cluster --all-namespaces --enrich -f json -o coreweave-audit.json

# Any GPU K8s cluster (Lambda Labs, Paperspace, self-managed)
agent-bom scan --k8s --context=<cluster-context> --all-namespaces --enrich
```

### 9. Unified Multi-Cloud Scan

Combine all providers in a single scan for a unified AI-BOM:

```bash
agent-bom scan \
  --aws --aws-region us-east-1 --aws-include-lambda --aws-include-eks --aws-include-step-functions \
  --snowflake \
  --azure --azure-subscription <sub-id> \
  --gcp --gcp-project <project-id> \
  --databricks \
  --nebius --nebius-project-id <project> \
  --k8s --all-namespaces \
  --enrich \
  -f html -o cloud-security-report.html
```

### 10. Policy Enforcement

Apply security policies to fail on violations:

```bash
agent-bom scan [your cloud flags] \
  --policy policy.json \
  --fail-on-severity high \
  --fail-on-kev \
  --enrich -f sarif -o results.sarif
```

Example policy file:

```json
[
  {"id": "no-unverified-high", "unverified_server": true, "severity_gte": "HIGH", "action": "fail"},
  {"id": "warn-excessive-agency", "min_tools": 6, "action": "warn"},
  {"id": "block-kev", "severity_gte": "CRITICAL", "action": "fail"}
]
```

### 11. Compare Against Baseline

Track drift between scans:

```bash
# Save first scan as baseline
agent-bom scan [your cloud flags] --enrich --save -f json -o baseline.json

# Later: compare against baseline
agent-bom scan [your cloud flags] --enrich --baseline baseline.json -f json -o current.json
```

New vulnerabilities, new agents, and removed assets are highlighted in the diff.

## Outputs

| Artifact | Purpose |
|----------|---------|
| Per-cloud JSON reports | Detailed per-provider inventory |
| `cloud-security-report.html` | Interactive dashboard with severity donut + blast radius chart + dependency graph |
| `results.sarif` | Upload to GitHub Security tab |
| Baseline diff | Track security posture drift over time |

## Architecture

```
     AWS          Snowflake       Azure        GCP       Databricks     Nebius      CoreWeave
      │               │            │           │             │            │            │
      │  Bedrock       │  Cortex    │  AI       │  Vertex     │  Clusters  │  K8s       │  K8s
      │  Lambda        │  MCP Svr   │  Foundry  │  Cloud Run  │  Serving   │  Containers│  Pods
      │  EKS           │  Search    │  Cont.App │             │            │            │
      │  StepFn        │  Snowpark  │           │             │            │            │
      │  EC2           │  Streamlit │           │             │            │            │
      │  ECS           │  History   │           │             │            │            │
      │  SageMaker     │  Tools     │           │             │            │            │
      └───────┬────────┴─────┬──────┴─────┬─────┴──────┬──────┴──────┬─────┴──────┬─────┘
              │              │            │            │             │            │
              └──────────────┴────────────┴────────────┴─────────────┴────────────┘
                                                │
                                    ┌───────────▼────────────┐
                                    │   agent-bom Enrichment  │
                                    │  OSV → NVD → EPSS → KEV │
                                    │  OWASP LLM + MITRE ATLAS│
                                    └───────────┬────────────┘
                                                │
                                    ┌───────────▼────────────┐
                                    │   Unified AI-BOM Report │
                                    │   Blast Radius + Graph   │
                                    │   Remediation Plan       │
                                    └────────────────────────┘
```
