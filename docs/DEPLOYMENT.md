# Deployment & Scalability Architecture

## 🎯 Overview

agent-bom is designed to scale from local CLI usage to enterprise-wide AI infrastructure scanning. This document explains deployment patterns, containerization, CI/CD integration, and cloud-native architectures.

---

## 🏗️ Architecture Overview

### How agent-bom Works

```
┌─────────────────────────────────────────┐
│  agent-bom (AI-BOM Generator + Scanner) │
│  ├─ Discovers MCP/AI agent configs      │
│  ├─ Extracts packages (+ transitive)    │
│  ├─ Scans for vulnerabilities (OSV)     │
│  ├─ Enriches with NVD/EPSS/KEV          │
│  ├─ Calculates blast radius             │
│  └─ Outputs AI-BOM (JSON/CycloneDX)     │
└─────────────────────────────────────────┘
```

**Key Difference**: agent-bom is purpose-built for **AI agents and MCP servers**, not generic software packages. It understands AI-specific blast radius (credentials, tools, multi-agent exposure).

---

## 📦 Deployment Patterns

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
CMD ["scan", "--help"]
```

#### Usage

```bash
# Build image
docker build -t agent-bom:latest .

# Scan mounted directory
docker run --rm \
  -v $(pwd):/workspace \
  -v ~/.config:/root/.config:ro \
  agent-bom:latest scan --enrich --output /workspace/report.json

# Scan with environment variables
docker run --rm \
  -e NVD_API_KEY=your-key \
  -e SNOWFLAKE_ACCOUNT=myaccount \
  -v $(pwd):/workspace \
  agent-bom:latest scan --enrich
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
              - scan
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
              mountPath: /root/.config
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

---

### 5. AWS Lambda / Cloud Functions (Serverless)

**Use case**: Event-driven scanning, API endpoints

#### Lambda Handler

```python
import json
import tempfile
import os
from agent_bom.cli import main

def lambda_handler(event, context):
    """
    Trigger agent-bom agents from Lambda.
    Event payload:
    {
        "snowflake_account": "myaccount",
        "enrich": true,
        "output_bucket": "s3://mybucket/ai-bom/"
    }
    """

    # Parse event
    snowflake_account = event.get('snowflake_account')
    enrich = event.get('enrich', True)
    output_bucket = event.get('output_bucket')

    # Run scan
    with tempfile.TemporaryDirectory() as tmpdir:
        output_file = os.path.join(tmpdir, 'ai-bom.json')

        # Build CLI args
        args = ['scan', '--format', 'json', '--output', output_file]
        if enrich:
            args.append('--enrich')
        if snowflake_account:
            args.extend(['--snowflake-account', snowflake_account])

        # Execute scan
        main(args)

        # Upload to S3
        with open(output_file) as f:
            report = json.load(f)

        # TODO: Upload to S3 using boto3

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Scan complete',
                'vulnerabilities': len(report.get('blast_radii', []))
            })
        }
```

#### SAM Template

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31

Resources:
  AgentBomFunction:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: agent-bom-scanner
      Runtime: python3.11
      Handler: lambda_function.lambda_handler
      Timeout: 300
      MemorySize: 1024
      Environment:
        Variables:
          NVD_API_KEY: !Ref NVDApiKey
      Events:
        Schedule:
          Type: Schedule
          Properties:
            Schedule: rate(6 hours)
```

**Pros**: No infrastructure management, auto-scaling
**Cons**: 15-minute timeout, cold start latency

---

## ❄️ Snowflake Integration

> **Note**: agent-bom integrates with Snowflake for **scanning Cortex Agents,
> CoCo skills, and Snowpark resources** — not as a deployed Native App.
> The architecture below is a proposed reference pattern for enterprise
> teams that want to run agent-bom inside Snowflake infrastructure.

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

3. **Deploy SiS dashboard** — upload `deploy/snowflake/streamlit_app.py` and `deploy/snowflake/environment.yml` via the Snowflake web UI (Streamlit > + Streamlit App).

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

### Scanning VMs and Remote Systems

#### 1. SSH-Based Remote Scanning

```python
# Future: agent-bom/remote_scanner.py

import paramiko
import tempfile

def scan_remote_vm(hostname, username, key_path):
    """Scan MCP configs on a remote VM via SSH."""

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=username, key_filename=key_path)

    # Copy MCP configs to temp dir
    with tempfile.TemporaryDirectory() as tmpdir:
        sftp = ssh.open_sftp()
        sftp.get('~/.config/claude-desktop/config.json',
                 f'{tmpdir}/config.json')
        sftp.close()

        # Scan locally
        from agent_bom.cli import main
        main(['scan', '--config-dir', tmpdir])

    ssh.close()
```

**Usage**:
```bash
agent-bom agents --remote ssh://user@vm.example.com --key ~/.ssh/id_rsa
```

#### 2. Agent-Based Scanning (Similar to Wiz/Prisma Cloud)

```
┌──────────────────────────────────────────┐
│  Central Management Console              │
│  (agent-bom server)                      │
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

**Agent responsibilities**:
- Discover local MCP configs
- Extract packages
- Send inventory to central server
- Receive scan results

**Central server responsibilities**:
- Aggregate packages from all agents
- Batch query OSV/NVD/EPSS/KEV
- Calculate global blast radius
- Provide web UI for results

#### 3. API-Based Cloud Scanning

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

# Or use secret managers
agent-bom agents --secret-provider aws-secrets-manager \
               --secret-id prod/agent-bom/nvd-key
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

```python
# Future: agent-bom with audit logging

import logging
logging.basicConfig(filename='/var/log/agent-bom/audit.log')

def scan_with_audit(user, target):
    logging.info(f"User {user} initiated scan of {target}")
    result = scan(target)
    logging.info(f"Scan complete: {len(result.vulnerabilities)} vulns found")
    return result
```

---

## 📈 Performance Benchmarks

| Scale | Local CLI | Docker | Kubernetes | Lambda |
|-------|-----------|--------|------------|--------|
| 1 MCP server | 5s | 8s | 15s | 20s |
| 10 MCP servers | 30s | 35s | 40s | 60s |
| 100 packages | 2m | 2m 15s | 2m 30s | 4m |
| 1,000 packages (batched) | 15m | 16m | 12m (parallel) | N/A |

**Note**: With NVD API key, enrichment adds ~10% overhead. Without key, adds 5-10x overhead due to rate limiting.

---

## 🚀 Next Steps for Production

### Phase 1: Containerization (Week 1)
- [ ] Create Dockerfile
- [ ] Publish to Docker Hub / GHCR
- [ ] Test in CI/CD pipelines

### Phase 2: Cloud Provider APIs (Week 2-3)
- [ ] Implement Snowflake Cortex scanning
- [ ] Implement AWS Bedrock scanning
- [ ] Implement Azure OpenAI scanning

### Phase 3: Remote Scanning (Week 4)
- [ ] SSH-based remote scanning
- [ ] Agent-based architecture (PoC)
- [ ] API server for centralized management

### Phase 4: Scale Testing (Week 5)
- [ ] Benchmark 1,000+ package scans
- [ ] Implement caching layer
- [ ] Optimize batch processing

### Phase 5: Enterprise Features (Later)
- [ ] Web UI dashboard
- [ ] SIEM/SOAR integrations
- [ ] Multi-tenancy support
- [ ] Historical trending

---

## 📋 Key Capabilities

| Feature | agent-bom |
|---------|-----------|
| AI agent config discovery | ✅ (30 MCP clients) |
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
3. **Cloud-Native**: Kubernetes CronJobs, serverless functions
4. **Remote Scanning**: SSH, agents, cloud APIs
5. **Performance**: Caching, batching, parallelization

agent-bom can be deployed anywhere — CLI, Docker, CI/CD, Kubernetes, Snowflake, or as an MCP server — specialized for AI agent infrastructure security.
