# Output Format Comparison & Deployment Models

## Overview

Agent-BOM supports three output formats:
1. **Console (Rich)** - Human-readable terminal output with colors and tables
2. **JSON** - Custom AI-BOM format optimized for agent trust chain analysis
3. **CycloneDX 1.6** - Industry-standard SBOM format for interoperability

---

## Format Comparison

### JSON Format (agent-bom native)

**Structure:**
```json
{
  "ai_bom_version": "0.1.0",
  "generated_at": "2026-02-17T01:27:12.571273",
  "summary": {
    "total_agents": 2,
    "total_mcp_servers": 8,
    "total_packages": 8,
    "total_vulnerabilities": 0,
    "critical_findings": 0
  },
  "agents": [
    {
      "name": "claude-desktop",
      "type": "claude-desktop",
      "config_path": "/Users/mohamedsaad/...",
      "mcp_servers": [
        {
          "name": "filesystem",
          "command": "npx",
          "args": ["-y", "@modelcontextprotocol/server-filesystem"],
          "has_credentials": false,
          "credential_env_vars": [],
          "packages": [
            {
              "name": "@modelcontextprotocol/server-filesystem",
              "version": "2026.1.14",
              "ecosystem": "npm",
              "purl": "pkg:npm/@modelcontextprotocol/server-filesystem@2026.1.14",
              "is_direct": true,
              "dependency_depth": 0,
              "vulnerabilities": []
            }
          ]
        }
      ]
    }
  ]
}
```

**Key Features:**
- **Agent-centric hierarchy**: Agent → MCP Server → Package → Vulnerability
- **Trust chain preserved**: Shows exact command invocation and credential exposure
- **Blast radius analysis**: Easy to trace impact from vulnerability back to agent
- **Credential tracking**: `has_credentials` and `credential_env_vars` for risk assessment
- **Dependency depth**: Track transitive dependencies with `dependency_depth`
- **Custom fields**: AI-specific metadata not available in standard SBOM formats

**Best for:**
- AI security analysis
- Trust chain visualization
- Credential exposure analysis
- Custom integrations with security tools
- Programmatic consumption by other tools

---

### CycloneDX 1.6 Format (industry standard)

**Structure:**
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:93c3ad9d-c3ef-4650-887b-a9942367e8ad",
  "metadata": {
    "timestamp": "2026-02-17T01:23:24.477745",
    "tools": {
      "components": [
        {
          "type": "application",
          "name": "agent-bom",
          "version": "0.1.0",
          "purl": "pkg:pypi/agent-bom@0.1.0"
        }
      ]
    },
    "properties": [
      {"name": "agent-bom:total-agents", "value": "2"},
      {"name": "agent-bom:total-mcp-servers", "value": "8"},
      {"name": "agent-bom:total-vulnerabilities", "value": "14"}
    ]
  },
  "components": [
    {
      "type": "application",
      "bom-ref": "agent:claude-desktop",
      "name": "claude-desktop",
      "version": "unknown"
    },
    {
      "type": "library",
      "bom-ref": "pkg:npm/@modelcontextprotocol/server-filesystem@2026.1.14",
      "name": "@modelcontextprotocol/server-filesystem",
      "version": "2026.1.14",
      "purl": "pkg:npm/@modelcontextprotocol/server-filesystem@2026.1.14"
    }
  ],
  "dependencies": [
    {
      "ref": "agent:claude-desktop",
      "dependsOn": ["mcp:filesystem"]
    },
    {
      "ref": "mcp:filesystem",
      "dependsOn": ["pkg:npm/@modelcontextprotocol/server-filesystem@2026.1.14"]
    }
  ],
  "vulnerabilities": [
    {
      "bom-ref": "vuln:GHSA-xxxx-yyyy-zzzz",
      "id": "GHSA-xxxx-yyyy-zzzz",
      "source": {"name": "OSV", "url": "https://osv.dev"},
      "ratings": [
        {
          "source": {"name": "NVD"},
          "score": 7.5,
          "severity": "high",
          "method": "CVSSv31",
          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
        }
      ],
      "cwes": [400],
      "description": "Vulnerability description...",
      "published": "2024-01-15T00:00:00Z",
      "affects": [
        {
          "ref": "pkg:npm/@modelcontextprotocol/server-filesystem@2026.1.14",
          "versions": [
            {"version": "2026.1.14", "status": "affected"}
          ]
        }
      ]
    }
  ]
}
```

**Key Features:**
- **Standard compliance**: Works with any SBOM-compatible tool (Dependency-Track, Grype, etc.)
- **Component-based**: Flat structure with dependency graph
- **Vulnerability standard**: Uses CycloneDX vulnerability schema
- **Tool interoperability**: Import into SBOM management platforms
- **PURL support**: Package URL standard for universal package identification
- **Regulatory compliance**: Meets SBOM requirements (EO 14028, etc.)

**Best for:**
- Compliance reporting
- Integration with existing SBOM tools
- Regulatory requirements
- Tool chain interoperability
- Enterprise SBOM management platforms

---

## Enrichment: OSV + NVD + EPSS + CISA KEV

### How Enrichment Works

When you run with `--enrich` flag:

```bash
agent-bom scan --format json --enrich --output enriched.json
```

**Enrichment Pipeline:**

1. **OSV.dev Query** (Primary vulnerability source)
   - Aggregates data from NVD, GitHub Advisory, PyPI Advisory, etc.
   - Provides CVE IDs, GHSA IDs, aliases, affected versions
   - Returns fix versions when available
   - Rate limit: None (public API)

2. **NVD API Query** (Enhanced CVSS details)
   - Fetches official CVE records
   - Provides detailed CVSS v3.1 scores and vectors
   - CWE categorization
   - Detailed descriptions and references
   - Rate limit: 5 req/30s (no key), 50 req/30s (with API key)

3. **EPSS API Query** (Exploit prediction)
   - Exploitation Probability Score System
   - Predicts likelihood of vulnerability exploitation
   - Updated daily based on real-world exploitation data
   - Rate limit: None (public API)

4. **CISA KEV Check** (Known exploited vulnerabilities)
   - Official US government catalog
   - Confirms active exploitation in the wild
   - Cached for 24 hours to reduce lookups
   - Highest priority indicator
   - Rate limit: None (public data)

### Enriched Vulnerability Example

```json
{
  "id": "GHSA-8r34-jx8r-hm8f",
  "aliases": ["CVE-2024-12345"],
  "summary": "Prototype pollution in package-name",
  "details": "A prototype pollution vulnerability exists...",
  "severity": "HIGH",
  "cvss_score": 7.5,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
  "cwe_ids": ["CWE-1321"],
  "affected_package": "pkg:npm/package-name@1.2.3",
  "fixed_versions": ["1.2.4", "2.0.0"],
  "published": "2024-01-15T10:30:00Z",
  "modified": "2024-01-16T08:15:00Z",
  "references": [
    {
      "type": "ADVISORY",
      "url": "https://github.com/advisories/GHSA-8r34-jx8r-hm8f"
    },
    {
      "type": "FIX",
      "url": "https://github.com/owner/repo/commit/abc123"
    }
  ],
  "enrichment": {
    "nvd": {
      "cve_id": "CVE-2024-12345",
      "cvss_v31": {
        "base_score": 7.5,
        "base_severity": "HIGH",
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "attack_vector": "NETWORK",
        "attack_complexity": "LOW",
        "privileges_required": "NONE",
        "user_interaction": "NONE",
        "scope": "UNCHANGED",
        "confidentiality_impact": "NONE",
        "integrity_impact": "HIGH",
        "availability_impact": "NONE"
      },
      "cwe": ["CWE-1321"],
      "published_date": "2024-01-15T10:30:00.000Z",
      "last_modified_date": "2024-01-16T08:15:00.000Z"
    },
    "epss": {
      "score": 0.00234,
      "percentile": 0.52,
      "probability": "0.23%",
      "risk_level": "LOW"
    },
    "cisa_kev": {
      "is_known_exploited": false,
      "date_added": null,
      "due_date": null,
      "required_action": null
    }
  },
  "remediation": {
    "recommendation": "Upgrade to version 1.2.4 or later",
    "fixed_in": ["1.2.4", "2.0.0"],
    "workaround": "No workaround available - upgrade required"
  }
}
```

### Fix Version Determination

**OSV API provides fix information in `ranges` field:**

```json
{
  "ranges": [
    {
      "type": "ECOSYSTEM",
      "events": [
        {"introduced": "0"},
        {"fixed": "1.2.4"}
      ]
    }
  ]
}
```

**agent-bom extracts fixed versions:**
- Parses `fixed` events from ranges
- Displays as "Fix: 1.2.4+" or "Fix: Not available"
- Shows multiple fix versions for different version ranges
- Includes fix commit URLs when available

**When no fix exists:**
```json
{
  "fixed_versions": [],
  "remediation": {
    "recommendation": "No fix available - monitor for updates",
    "workaround": "Implement input validation as temporary mitigation"
  }
}
```

---

## Discovery Models

### 1. Auto-Discovery (Current Default)

**How it works:**
- Scans predefined configuration locations for AI agents
- Parses MCP server configurations automatically
- No manual input required

**Supported agents:**
- **Claude Desktop**: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS), `~/.config/Claude/claude_desktop_config.json` (Linux)
- **Cursor**: `~/.cursor/mcp.json`
- **Cline**: `~/.cline/mcp.json`
- **Windsurf**: `~/.windsurf/mcp.json`
- **Continue**: `~/.continue/config.json`

**Example:**
```bash
# Auto-discovers all agents on the system
agent-bom scan

# Auto-discovers and enriches
agent-bom scan --enrich
```

**Pros:**
- Zero configuration required
- Discovers all installed agents automatically
- Always up-to-date with current configurations
- Easy for developers and security teams

**Cons:**
- Requires file system access to config directories
- May not work in sandboxed environments
- Only discovers known agent types

---

### 2. Manual Inventory Submission

**How it works:**
- Users provide JSON inventory of agents and MCP servers
- Useful for custom agents or non-standard configurations
- Supports air-gapped environments

**Example inventory format:**
```json
{
  "agents": [
    {
      "name": "custom-agent",
      "type": "custom",
      "mcp_servers": [
        {
          "name": "internal-mcp",
          "command": "python",
          "args": ["-m", "internal_mcp"],
          "env": {
            "API_KEY": "xxx"
          }
        }
      ]
    }
  ]
}
```

**Usage:**
```bash
# Scan from manual inventory
agent-bom scan --inventory inventory.json --enrich
```

**Pros:**
- Works with any agent type
- Supports custom/proprietary agents
- Air-gapped environment support
- Full control over what gets scanned

**Cons:**
- Requires manual maintenance
- Inventory can become stale
- More effort to maintain

---

### 3. API-Based Discovery (Future Enhancement)

**How it works:**
- Agent management platforms expose API
- agent-bom queries API for active agents
- Centralized inventory management

**Example:**
```bash
# Query from agent management API
agent-bom scan --api-url https://agent-mgmt.company.com/api/agents
```

**Use cases:**
- Enterprise agent management platforms
- Cloud-based agent orchestration
- Real-time agent inventory
- Integration with CMDB/asset management

---

## Cloud & VM Deployment Models

### AWS Integration Patterns

#### 1. **Scheduled Lambda Scanning** (Serverless)

**Architecture:**
```
EventBridge (cron) → Lambda → Read configs from S3/EFS → Scan → Store results in S3/DynamoDB
```

**Setup:**
```yaml
# serverless.yml
functions:
  scanAgents:
    handler: scan_handler.lambda_handler
    runtime: python3.11
    timeout: 300
    environment:
      S3_BUCKET: agent-configs
      RESULTS_TABLE: agent-bom-results
    events:
      - schedule: cron(0 2 * * ? *)  # Daily at 2 AM
    layers:
      - arn:aws:lambda:us-east-1:xxx:layer:agent-bom:1
```

**Lambda handler:**
```python
import boto3
import json
from agent_bom import scan_agents

def lambda_handler(event, context):
    s3 = boto3.client('s3')

    # Download agent configs from S3
    configs = []
    response = s3.list_objects_v2(Bucket='agent-configs', Prefix='agents/')
    for obj in response['Contents']:
        config = s3.get_object(Bucket='agent-configs', Key=obj['Key'])
        configs.append(json.loads(config['Body'].read()))

    # Scan
    results = scan_agents(configs, enrich=True)

    # Store results
    s3.put_object(
        Bucket='agent-bom-results',
        Key=f"scans/{datetime.now().isoformat()}.json",
        Body=json.dumps(results)
    )

    # Send alerts if critical vulnerabilities found
    if results['summary']['critical_findings'] > 0:
        sns = boto3.client('sns')
        sns.publish(
            TopicArn='arn:aws:sns:us-east-1:xxx:security-alerts',
            Subject='Critical vulnerabilities in AI agents',
            Message=json.dumps(results['summary'])
        )

    return {'statusCode': 200, 'body': 'Scan completed'}
```

**Pros:**
- No infrastructure to manage
- Pay-per-scan pricing
- Scales automatically
- Easy to schedule

**Cons:**
- 15-minute timeout limit
- Cold start latency
- Limited to scanning configs in S3/EFS

---

#### 2. **EC2/ECS Agent-Based Scanning**

**Architecture:**
```
EC2 instance with agent-bom installed → Scans local configs → Reports to central API/S3
```

**Install on EC2:**
```bash
# User data script
#!/bin/bash
pip install agent-bom

# Create scan script
cat > /usr/local/bin/scan-agents.sh <<'EOF'
#!/bin/bash
agent-bom scan --format json --enrich --output /tmp/scan-result.json
aws s3 cp /tmp/scan-result.json s3://agent-bom-results/$(hostname)/$(date +%Y%m%d-%H%M%S).json
EOF

chmod +x /usr/local/bin/scan-agents.sh

# Schedule with cron
echo "0 2 * * * /usr/local/bin/scan-agents.sh" | crontab -
```

**ECS Task Definition:**
```json
{
  "family": "agent-bom-scanner",
  "taskRoleArn": "arn:aws:iam::xxx:role/agent-bom-task-role",
  "containerDefinitions": [
    {
      "name": "scanner",
      "image": "agent-bom:latest",
      "command": ["scan", "--format", "json", "--enrich", "--output", "/results/scan.json"],
      "mountPoints": [
        {
          "sourceVolume": "agent-configs",
          "containerPath": "/root/.config/Claude"
        }
      ]
    }
  ],
  "volumes": [
    {
      "name": "agent-configs",
      "efsVolumeConfiguration": {
        "fileSystemId": "fs-xxxxx",
        "rootDirectory": "/agent-configs"
      }
    }
  ]
}
```

**Pros:**
- Scans actual running agent configurations
- Can access local file systems
- Full control over execution environment
- Works with any agent deployment

**Cons:**
- Infrastructure to manage
- Higher cost than Lambda
- Requires IAM roles and permissions

---

#### 3. **Bedrock/SageMaker Agent Scanning** (API-based)

**Architecture:**
```
API Gateway → Lambda → List Bedrock Agents → Extract dependencies → Scan → Store results
```

**Scan Bedrock agents:**
```python
import boto3
from agent_bom import scan_bedrock_agents

def scan_bedrock():
    bedrock = boto3.client('bedrock-agent')

    # List all agents
    agents = bedrock.list_agents()

    # For each agent, get action groups and knowledge bases
    results = []
    for agent in agents['agentSummaries']:
        agent_id = agent['agentId']

        # Get action groups (may contain Lambda functions with dependencies)
        action_groups = bedrock.list_agent_action_groups(agentId=agent_id)

        # Get knowledge bases
        kb_associations = bedrock.list_agent_knowledge_bases(agentId=agent_id)

        # Scan dependencies
        scan_result = scan_bedrock_agents(agent_id, action_groups, kb_associations)
        results.append(scan_result)

    return results
```

**Pros:**
- Cloud-native scanning for managed AI services
- No agent configuration file access needed
- Integrates with AWS API
- Automated discovery

**Cons:**
- Limited to AWS Bedrock agents
- May not capture all dependencies
- Requires Bedrock API permissions

---

### Azure Integration

**Azure Functions + Storage:**
```bash
# Similar to Lambda, triggered by Timer
func init --python agent-bom-scanner
cd agent-bom-scanner
func new --name ScanAgents --template "Timer trigger"
```

**Azure VM with Azure DevOps Pipeline:**
```yaml
# azure-pipelines.yml
schedules:
  - cron: "0 2 * * *"
    displayName: Daily scan
    branches:
      include:
        - main

jobs:
  - job: ScanAgents
    pool:
      vmImage: 'ubuntu-latest'
    steps:
      - script: |
          pip install agent-bom
          agent-bom scan --format cyclonedx --output sbom.cdx.json --enrich
        displayName: 'Scan for vulnerabilities'

      - task: PublishBuildArtifacts@1
        inputs:
          pathToPublish: 'sbom.cdx.json'
          artifactName: 'sbom'
```

---

### GCP Integration

**Cloud Functions + Cloud Scheduler:**
```python
# main.py
import functions_framework
from google.cloud import storage

@functions_framework.http
def scan_agents(request):
    # Download configs from Cloud Storage
    storage_client = storage.Client()
    bucket = storage_client.bucket('agent-configs')

    # Scan
    results = run_scan()

    # Upload results
    blob = bucket.blob(f'scans/{datetime.now().isoformat()}.json')
    blob.upload_from_string(json.dumps(results))

    return 'Scan completed', 200
```

---

## Deployment Decision Matrix

| Scenario | Recommended Approach | Why |
|----------|---------------------|-----|
| Local development | Auto-discovery | Simple, no config needed |
| CI/CD pipeline | Docker container | Reproducible, isolated |
| VM fleet | Agent-based (EC2/VM) | Scans actual configs on each VM |
| Kubernetes cluster | CronJob | Native to K8s, scales well |
| Serverless (AWS) | Lambda + EventBridge | Cost-effective, managed |
| Enterprise platform | API-based discovery | Centralized, real-time |
| Air-gapped | Manual inventory | No external connectivity |
| Compliance audit | CycloneDX export | Standard format |
| Security monitoring | Enriched JSON + SIEM | Full context for analysis |

---

## Validation & Verification

### 1. Validate Output Format

**CycloneDX validation:**
```bash
# Install validator
npm install -g @cyclonedx/cyclonedx-cli

# Validate
cyclonedx-cli validate --input-file /tmp/sbom.cdx.json
```

**JSON schema validation:**
```python
import jsonschema
import json

# Load schema and SBOM
with open('ai-bom-schema.json') as f:
    schema = json.load(f)

with open('/tmp/sbom.json') as f:
    sbom = json.load(f)

# Validate
jsonschema.validate(instance=sbom, schema=schema)
print("✓ Valid AI-BOM JSON")
```

### 2. Verify Vulnerability Data

**Cross-reference with OSV.dev:**
```bash
# Check if vulnerability ID exists
curl "https://api.osv.dev/v1/vulns/GHSA-xxxx-yyyy-zzzz"

# Query by package
curl -X POST "https://api.osv.dev/v1/query" \
  -d '{"package": {"name": "package-name", "ecosystem": "npm"}, "version": "1.2.3"}'
```

**Cross-reference with NVD:**
```bash
# Check CVE
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-12345"
```

### 3. Import into SBOM Tools

**Dependency-Track:**
```bash
# Upload CycloneDX SBOM
curl -X POST "http://dependency-track/api/v1/bom" \
  -H "X-API-Key: $API_KEY" \
  -F "project=agent-bom" \
  -F "bom=@/tmp/sbom.cdx.json"
```

**Grype:**
```bash
# Scan SBOM with Grype
grype sbom:/tmp/sbom.cdx.json
```

---

## Summary

| Question | Answer |
|----------|--------|
| **What formats do we output?** | Console (rich), JSON (custom AI-BOM), CycloneDX 1.6 (standard) |
| **Do we get OSV and NVD enrichment?** | Yes, with `--enrich` flag. Also includes EPSS and CISA KEV |
| **How are fix versions determined?** | Extracted from OSV API `ranges.events.fixed` field |
| **Discovery vs submission?** | Default: Auto-discovery from agent configs. Also supports manual inventory JSON |
| **AWS/cloud integration?** | Lambda (scheduled), EC2/ECS (agent-based), Bedrock API (cloud-native). Similar for Azure/GCP |
| **How to validate results?** | CycloneDX validator, JSON schema, cross-reference with OSV/NVD APIs, import into SBOM tools |

---

**Generated by agent-bom v0.1.0**
