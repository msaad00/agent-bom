# Deployment & Scalability Architecture

## Overview

agent-bom is one product with multiple deployable surfaces: local CLI, CI
scanner, container image, self-hosted API/UI, fleet sync, proxy, gateway, MCP
server mode, and Snowflake-specific compatibility views. This document covers
the maintained deployment shapes. For the canonical chooser, start with
[`site-docs/deployment/overview.md`](../site-docs/deployment/overview.md).

---

## Architecture Overview

### How agent-bom Works

```
┌─────────────────────────────────────────┐
│  agent-bom (AI supply-chain scanner)    │
│  ├─ Discovers MCP/AI agent configs      │
│  ├─ Extracts packages (+ transitive)    │
│  ├─ Scans for vulnerabilities (OSV)     │
│  ├─ Enriches with NVD/EPSS/KEV          │
│  ├─ Calculates blast radius             │
│  └─ Outputs AI-BOM (JSON/CycloneDX)     │
└─────────────────────────────────────────┘
```

**Key Difference**: agent-bom is purpose-built for **AI agents and MCP servers**, not generic software packages. It understands AI-specific blast radius (credentials, tools, multi-agent exposure).

### API Scale Notes

When `AGENT_BOM_POSTGRES_URL` is configured, the API now shares critical control-plane state across replicas instead of keeping it process-local:

- scan jobs
- fleet data
- schedules
- API keys and exceptions
- audit log and trend history
- API rate limiting buckets

That keeps auth, tenant isolation, auditability, and request throttling consistent when `agent-bom serve` is deployed behind a load balancer.

---

## Deployment Patterns

### 1. Local CLI (Current)

**Use case**: Developer workstations, ad-hoc scanning

```bash
# Install locally
pip install agent-bom

# Scan local MCP configs
agent-bom agents --enrich --output report.json
```

**Pros**: Simple, no infrastructure needed
**Cons**: Manual execution, not automated

---

### 2. Docker Container

**Use case**: CI/CD pipelines, reproducible scans, air-gapped environments

#### Dockerfile

```dockerfile
FROM python:3.11-slim

# Install agent-bom
RUN pip install --no-cache-dir agent-bom

# Set working directory
WORKDIR /workspace

# Default command
ENTRYPOINT ["agent-bom"]
CMD ["agents", "--help"]
```

#### Usage

```bash
# Build image
docker build -t agent-bom:latest .

# Scan mounted directory
docker run --rm \
  -v $(pwd):/workspace \
  -v ~/.config:/home/abom/.config:ro \
  agent-bom:latest agents --enrich --output /workspace/report.json

# Scan with environment variables
docker run --rm \
  -e NVD_API_KEY=your-key \
  -e SNOWFLAKE_ACCOUNT=myaccount \
  -v $(pwd):/workspace \
  agent-bom:latest agents --enrich
```

**Pros**: Portable, reproducible, version-locked
**Cons**: Requires Docker runtime

---

### 3. CI/CD Integration

**Use case**: Automated security scanning in build pipelines

#### GitHub Actions

```yaml
name: AI-BOM Security Scan

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install agent-bom
        run: pip install agent-bom

      - name: Scan MCP servers
        env:
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
        run: |
          agent-bom agents --enrich \
            --format json \
            --output ai-bom.json

      - name: Check for critical vulnerabilities
        run: |
          python -c "
          import json
          with open('ai-bom.json') as f:
              data = json.load(f)
          critical = sum(1 for br in data.get('blast_radii', [])
                        if br.get('risk_score', 0) >= 9.0)
          if critical > 0:
              print(f'❌ Found {critical} critical vulnerabilities!')
              exit(1)
          "

      - name: Upload AI-BOM artifact
        uses: actions/upload-artifact@v3
        with:
          name: ai-bom
          path: ai-bom.json
```

#### GitLab CI

```yaml
ai-bom-scan:
  image: python:3.11-slim
  stage: security
  script:
    - pip install agent-bom
    - agent-bom agents --enrich --output ai-bom.json
  artifacts:
    reports:
      cyclonedx: ai-bom.json
    paths:
      - ai-bom.json
    expire_in: 30 days
  only:
    - main
    - merge_requests
```

#### Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('AI-BOM Scan') {
            steps {
                sh 'pip install agent-bom'
                sh 'agent-bom agents --enrich --output ai-bom.json'

                script {
                    def report = readJSON file: 'ai-bom.json'
                    def critical = report.blast_radii.count { it.risk_score >= 9.0 }
                    if (critical > 0) {
                        error("Found ${critical} critical vulnerabilities!")
                    }
                }

                archiveArtifacts artifacts: 'ai-bom.json'
            }
        }
    }
}
```

**Pros**: Automated, fail builds on critical issues
**Cons**: Requires CI/CD platform access

---

### 4. Kubernetes CronJob (Enterprise)

**Use case**: Continuous monitoring of production AI infrastructure

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: agent-bom-scanner
  namespace: security
spec:
  schedule: "0 */6 * * *"  # Every 6 hours
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: agent-bom
            image: agent-bom:latest
            args:
              - agents
              - --enrich
              - --format
              - json
              - --output
              - /output/ai-bom.json
            env:
            - name: NVD_API_KEY
              valueFrom:
                secretKeyRef:
                  name: agent-bom-secrets
                  key: nvd-api-key
            - name: SNOWFLAKE_ACCOUNT
              valueFrom:
                configMapKeyRef:
                  name: agent-bom-config
                  key: snowflake-account
            volumeMounts:
            - name: config-volume
              mountPath: /home/abom/.config
              readOnly: true
            - name: output-volume
              mountPath: /output
          volumes:
          - name: config-volume
            configMap:
              name: mcp-configs
          - name: output-volume
            persistentVolumeClaim:
              claimName: ai-bom-reports
          restartPolicy: OnFailure
```

**Pros**: Scheduled, persistent, scalable
**Cons**: Kubernetes expertise required

For the maintained Helm chart in `deploy/helm/agent-bom/`, the runtime monitor DaemonSet now includes liveness, readiness, and startup probes by default when enabled, can optionally expose a Prometheus Operator `ServiceMonitor` for `/metrics`, can optionally create an `Ingress` and `PodDisruptionBudget` for the monitor service, and ships with an explicit `NetworkPolicy` egress baseline for DNS plus outbound web traffic instead of `allow-all` egress.

---

## ❄️ Snowflake Integration

> **Note**: agent-bom integrates with Snowflake for **scanning Cortex Agents,
> CoCo skills, Snowpark resources, and Snowflake-hosted app surfaces**.
> The primary shipped web UI remains the packaged Next.js dashboard. The
> Streamlit path below is a Snowflake-specific compatibility / native-view
> option, not the default product dashboard.

### Reference Architecture

```
              Snowflake Account
┌─────────────────────────────────────┐
│  Snowpark Container Service         │
│  ┌─────────────────┐                │
│  │ agent-bom API   │─writes─► Tables│
│  │ (port 8422)     │                │
│  └─────────────────┘                │
│                                     │
│  Streamlit in Snowflake             │
│  ┌─────────────────┐                │
│  │ SiS Dashboard   │─reads──► Tables│
│  └─────────────────┘                │
└─────────────────────────────────────┘
```

### Quick Start

1. **Run setup SQL** — creates database, tables, image repo, compute pool, and service:
   ```bash
   snowsql -f deploy/snowflake/setup.sql
   ```

2. **Build and push the container image**:
   ```bash
   docker build -f deploy/docker/Dockerfile.snowpark -t agent-bom-snowpark:latest .
   docker tag agent-bom-snowpark:latest \
     <account>.registry.snowflakecomputing.com/agent_bom/public/agent_bom_repo/agent-bom:latest
   docker push <account>.registry.snowflakecomputing.com/agent_bom/public/agent_bom_repo/agent-bom:latest
   ```

   Enterprise networks can use the same proxy and custom-CA contract as the other maintained images:
   `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, and `PIP_CERT`.

3. **Optional: deploy the Snowflake-native Streamlit view** — upload `deploy/snowflake/streamlit_app.py` and `deploy/snowflake/environment.yml` via the Snowflake web UI (Streamlit > + Streamlit App).

### Authentication

The Snowflake stores auto-detect auth method:

| Env Var | Method |
|---------|--------|
| `SNOWFLAKE_PRIVATE_KEY_PATH` | Key-pair auth (preferred for CI/CD and service accounts) |
| `SNOWFLAKE_AUTHENTICATOR` | Auth method: `externalbrowser` (SSO, default), `oauth`, `snowflake_jwt` |
| `SNOWFLAKE_PASSWORD` | **Deprecated** — emits warning. Migrate to key-pair or SSO |

Additional env vars: `SNOWFLAKE_ACCOUNT`, `SNOWFLAKE_USER`, `SNOWFLAKE_DATABASE` (default: `AGENT_BOM`), `SNOWFLAKE_SCHEMA` (default: `PUBLIC`).

### Tables

| Table | Purpose |
|-------|---------|
| `scan_jobs` | Scan job persistence (status, results as VARIANT) |
| `fleet_agents` | Fleet agent lifecycle (trust scores, states) |
| `gateway_policies` | Runtime MCP gateway policies |
| `policy_audit_log` | Policy enforcement audit trail |

---

## 🌐 Remote Scanning Architectures

### Fleet and endpoint scanning

```
┌──────────────────────────────────────────┐
│  agent-bom API + UI                      │
└───────────────┬──────────────────────────┘
                │ HTTPS API
        ┌───────┴────────┬────────────┐
        ▼                ▼            ▼
    ┌───────┐      ┌───────┐    ┌───────┐
    │ VM 1  │      │ VM 2  │    │ VM N  │
    │┌──────┴┐     │┌──────┴┐   │┌──────┴┐
    ││agent │      ││agent │    ││agent │
    │└──────┘      │└──────┘    │└──────┘
    └───────┘      └───────┘    └───────┘
```

Use `agent-bom fleet`, `agent-bom proxy-bootstrap`, or pushed fleet ingest for
managed endpoint rollout. There is no shipped `agent-bom agents --remote ssh://`
mode; use SSH or device-management tooling only as an external transport for
running the normal CLI or onboarding bundle on the endpoint.

### API-Based Cloud Scanning

```python
# Scan Snowflake Cortex via API (uses SSO by default)
agent-bom agents --snowflake-account myaccount \
               --snowflake-user myuser

# Or with key-pair auth (CI/CD)
SNOWFLAKE_PRIVATE_KEY_PATH=~/.ssh/sf_key.p8 \
agent-bom agents --snowflake-account myaccount --snowflake-user myuser

# Scan AWS Bedrock via API
agent-bom agents --aws-region us-east-1 \
               --aws-profile production

# Scan Azure OpenAI via API
agent-bom agents --azure-subscription-id xxx \
               --azure-resource-group rg-ai
```

**No VM access required** — uses cloud provider APIs to:
1. List AI agents/models
2. Fetch agent configurations
3. Extract package dependencies
4. Scan for vulnerabilities

---

## 📊 Scalability Patterns

### 1. Batch Processing (Large Fleets)

**Problem**: Scanning 1,000+ VMs takes hours
**Solution**: Parallel batch processing

```python
from concurrent.futures import ThreadPoolExecutor

def scan_vm_fleet(vm_list):
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(scan_vm, vm) for vm in vm_list]
        results = [f.result() for f in futures]
    return aggregate_results(results)
```

### 2. Incremental Scanning

**Problem**: Re-scanning everything is wasteful
**Solution**: Track changes, only scan deltas

```bash
# Store fingerprint of last scan
agent-bom agents --output /var/lib/agent-bom/baseline.json

# Next scan: compare to baseline
agent-bom agents --baseline /var/lib/agent-bom/baseline.json \
               --output /var/lib/agent-bom/delta.json
```

### 3. Distributed Scanning (Map-Reduce)

**Architecture**:
```
┌─────────────────────────────────────────┐
│  Coordinator (Airflow/Temporal)         │
└───────────┬────────────────────────────┬┘
            │ Map                        │ Reduce
    ┌───────┴──────┐           ┌────────┴────────┐
    ▼              ▼           ▼                 ▼
┌────────┐    ┌────────┐   ┌──────────────┐  ┌──────┐
│Worker 1│    │Worker N│   │  Aggregator  │  │ SIEM │
│VM 1-100│    │VM N-X  │   │ (merge BOM)  │  │ SOAR │
└────────┘    └────────┘   └──────────────┘  └──────┘
```

**Example with Airflow**:
```python
from airflow import DAG
from airflow.operators.python import PythonOperator

def scan_batch(vm_batch):
    # Scan VMs 1-100, 101-200, etc.
    pass

dag = DAG('agent_bom_scan', schedule_interval='@daily')

tasks = []
for i in range(0, 1000, 100):  # 10 batches of 100 VMs
    task = PythonOperator(
        task_id=f'scan_batch_{i}',
        python_callable=scan_batch,
        op_args=[vms[i:i+100]]
    )
    tasks.append(task)

# Merge results
merge = PythonOperator(task_id='merge', python_callable=merge_results)
tasks >> merge
```

### 4. Caching and Rate Limit Optimization

**Problem**: 1,000 VMs × 50 packages = 50,000 OSV API calls
**Solution**: Deduplicate and cache

```python
# Deduplicate packages across all VMs
unique_packages = deduplicate([pkg for vm in vms for pkg in vm.packages])

# Batch query OSV (100 per request)
cached_results = load_cache()
new_packages = [p for p in unique_packages if p not in cached_results]

if new_packages:
    results = batch_query_osv(new_packages)
    save_cache(results)
```

**Cache storage**: Redis, DynamoDB, or local SQLite

---

## 🔐 Security Considerations

### 1. Credential Management

```bash
# Use environment variables (not CLI args)
export NVD_API_KEY=xxx
export SNOWFLAKE_PRIVATE_KEY_PATH=~/.ssh/snowflake_key.p8

agent-bom agents --enrich

# In Kubernetes, mount keys through Secrets, External Secrets, or IRSA-backed
# secret managers and expose only the required environment variables.
```

### 2. Network Isolation

```yaml
# Kubernetes NetworkPolicy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: agent-bom-scanner
spec:
  podSelector:
    matchLabels:
      app: agent-bom
  policyTypes:
  - Egress
  egress:
  - to:  # Allow only OSV, NVD, EPSS, CISA APIs
    - ipBlock:
        cidr: 0.0.0.0/0
    ports:
    - protocol: TCP
      port: 443
```

### 3. RBAC and Audit Logging

Use the self-hosted API for authenticated operator workflows. The API enforces
API-key/OIDC/SAML auth, RBAC, tenant propagation, rate limiting, and audit
logging; proxy and gateway runtime events are posted back to the same audit
surface.

---

## 📈 Performance and Scale Evidence

Use the measured performance docs instead of release-plan estimates:

- [`docs/PERFORMANCE_BENCHMARKS.md`](PERFORMANCE_BENCHMARKS.md)
- [`docs/perf/`](perf/)
- [`site-docs/deployment/performance-and-sizing.md`](../site-docs/deployment/performance-and-sizing.md)

For large API deployments, configure Postgres-backed stores so scan jobs, fleet
state, schedules, API keys, audit, graph, and rate limiting survive API replica
rotation and stay tenant-scoped.

---

## 📋 Key Capabilities

| Feature | agent-bom |
|---------|-----------|
| AI agent config discovery | ✅ (29 first-class client types + dynamic/project surfaces) |
| MCP server support | ✅ |
| Transitive deps | ✅ |
| Blast radius (AI-specific) | ✅ |
| EPSS/KEV enrichment | ✅ |
| Container scanning | ✅ |
| Cloud API scanning | ✅ (AWS, Azure, GCP, Snowflake, Databricks) |
| Open source | ✅ |
| CycloneDX output | ✅ |

---

## 💡 Summary

agent-bom scales from local CLI to enterprise infrastructure by:

1. **Containerization**: Docker images for portability
2. **CI/CD Integration**: GitHub Actions, GitLab CI, Jenkins
3. **Cloud-Native**: Kubernetes CronJobs and Helm-managed control-plane deployments
4. **Remote Inventory**: fleet sync, pushed ingest, and cloud APIs
5. **Performance**: Caching, batching, parallelization

agent-bom can be deployed anywhere — CLI, Docker, CI/CD, Kubernetes, Snowflake, or as an MCP server — specialized for AI agent infrastructure security.
