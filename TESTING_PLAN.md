# Testing & Validation Plan

## 🎯 Testing Goals

1. **Validate current logic** - Ensure what works actually works
2. **Identify gaps** - Find what needs implementation
3. **End-to-end scenarios** - Test real-world use cases
4. **Pre-launch checklist** - Fix critical issues before announcement

---

## ✅ What Works RIGHT NOW

### 1. **MCP Discovery**
```bash
# Test discovery
agent-bom where

# Expected: Shows paths for Claude Desktop, Cursor, etc.
```

**What it does**:
- Scans known config locations for each platform
- Parses JSON configs to extract MCP server definitions
- Works for: Claude Desktop, Cursor, Windsurf, Cline, project configs

### 2. **Package Extraction**
```bash
# Test with your local MCP servers
agent-bom inventory
```

**What it extracts**:
- ✅ npm: `package-lock.json` → all dependencies (direct + transitive from lock)
- ✅ pip: `requirements.txt`, `Pipfile.lock`, `pyproject.toml`
- ✅ Go: `go.sum`
- ✅ Cargo: `Cargo.lock`
- ✅ npx/uvx: Detects package from command args

### 3. **Transitive Resolution** (NEW!)
```bash
# Test with MCP server using npx
agent-bom scan --transitive --max-depth 3
```

**How it works**:
1. Finds `npx @some/package` in MCP config
2. Queries npm registry API for package metadata
3. Recursively resolves dependencies
4. Scans ALL packages (direct + transitive)

**Example**:
```
npx @modelcontextprotocol/server-filesystem
  ├─ express@4.18.2 (direct)
  │   ├─ body-parser@1.20.1 (transitive, depth=1)
  │   ├─ cookie@0.5.0 (transitive, depth=1)
  │   └─ ... (47 more transitive deps)
  └─ axios@1.6.0 (direct)
      ├─ follow-redirects@1.15.0 (transitive, depth=1)
      └─ form-data@4.0.0 (transitive, depth=1)
```

### 4. **Vulnerability Scanning**
```bash
# Full scan with vulns
agent-bom scan --format json --output report.json
```

**How CVE matching works**:
```
Package → OSV.dev API → Vulnerabilities
```

**OSV.dev provides**:
- CVE IDs (e.g., CVE-2024-1234)
- GHSA IDs (e.g., GHSA-xxxx-xxxx-xxxx)
- Severity (CVSS-based)
- Fixed versions
- References to NVD, GitHub, npm advisories

**Example API call**:
```json
POST https://api.osv.dev/v1/querybatch
{
  "queries": [
    {
      "package": {"name": "express", "ecosystem": "npm"},
      "version": "4.18.2"
    }
  ]
}
```

**Response**:
```json
{
  "results": [{
    "vulns": [{
      "id": "GHSA-rv95-896h-c2vc",
      "aliases": ["CVE-2024-29041"],
      "summary": "Express.js Open Redirect in malformed URLs",
      "severity": [{
        "type": "CVSS_V3",
        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
      }],
      "affected": [{
        "package": {"name": "express", "ecosystem": "npm"},
        "ranges": [{
          "events": [
            {"introduced": "0"},
            {"fixed": "4.19.0"}
          ]
        }]
      }],
      "references": [
        {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-29041"},
        {"url": "https://github.com/expressjs/express/security/advisories/GHSA-rv95-896h-c2vc"}
      ]
    }]
  }]
}
```

**Our processing**:
1. Parse OSV response
2. Extract CVE aliases
3. Map to CVSS severity (CRITICAL/HIGH/MEDIUM/LOW)
4. Store in `Package.vulnerabilities[]`
5. Calculate blast radius

### 5. **Blast Radius Analysis**
```
Vulnerability → Package → MCP Server → Agents → Credentials
```

**Risk scoring**:
```python
base_score = severity_score  # 8.0 for CRITICAL, 6.0 for HIGH, etc.
agent_factor = min(num_agents * 0.5, 2.0)
cred_factor = min(num_credentials * 0.3, 1.5)
tool_factor = min(num_tools * 0.1, 1.0)

risk_score = min(base_score + agent_factor + cred_factor + tool_factor, 10.0)
```

**Example**:
```
CVE-2024-1234 in express@4.18.2
  └─ Used by: database-server (MCP)
      ├─ Credentials: DB_PASSWORD, API_KEY
      ├─ Tools: query_database, update_schema
      └─ Agents: claude-desktop, cursor, windsurf (3 agents)

Risk Score: 8.0 (CRITICAL) + 1.5 (3 agents) + 0.6 (2 creds) + 0.2 (2 tools) = 10.0
```

---

## ❌ What DOESN'T Work Yet

### 1. **Snowflake Cortex Scanning**
```bash
# This will NOT work:
agent-bom scan --snowflake-account myaccount
```

**Why**: Not implemented yet!

**What's needed**:
1. Install Snowflake Python connector: `pip install snowflake-connector-python`
2. Add authentication (username/password or OAuth)
3. Query Cortex agents:
   ```sql
   SELECT agent_name, agent_config
   FROM INFORMATION_SCHEMA.CORTEX_AGENTS
   ```
4. Parse agent configs (similar to MCP JSON parsing)
5. Extract package dependencies
6. Scan as normal

**Implementation estimate**: 2-3 days

**Would you be able to test?**: YES, if you have:
- Snowflake account with Cortex enabled
- Credentials (username/password or key-pair)
- At least one Cortex agent deployed

### 2. **AWS Bedrock / Azure / Google ADK**
**Status**: Not implemented

**Needs**:
- AWS SDK (boto3) for Bedrock
- Azure SDK for OpenAI Service
- Google Cloud SDK for ADK
- API calls to list agents
- Parse agent manifests

### 3. **Direct NVD API Integration**
**Status**: Using OSV.dev (which aggregates NVD)

**To add NVD directly**:
```python
import httpx

async def query_nvd(cve_id: str):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers={"apiKey": NVD_API_KEY})
        return response.json()
```

**Benefit**: Richer metadata, more accurate CVSS scores

### 4. **Dependency Graph Visualization**
**Status**: Not implemented

**Needs**:
- Generate DOT format or D3.js JSON
- Render with Graphviz or Mermaid
- Interactive web view

**Example output** (Mermaid):
```mermaid
graph TB
    A[claude-desktop] --> B[database-server]
    B --> C[express@4.18.2]
    B --> D[pg@8.11.0]
    C --> E[body-parser@1.20.1]
    C --> F[cookie@0.5.0]

    style C fill:#ff0000
    style E fill:#ffff00
```

---

## 🧪 Test Plan

### Phase 1: Local Testing (Your Machine)

**Prerequisites**:
```bash
pip install -e ".[dev]"
agent-bom --version
```

**Test 1: Discovery**
```bash
agent-bom where
# Expected: Shows MCP client config paths
# Check: Do you have Claude Desktop or Cursor installed?
```

**Test 2: Inventory**
```bash
agent-bom inventory
# Expected: Lists MCP servers + packages
# Check: Do you have MCP servers configured?
```

**Test 3: Vulnerability Scan**
```bash
agent-bom scan
# Expected: Finds vulnerabilities in packages
# Check: Are packages extracted? Are vulns detected?
```

**Test 4: Transitive Resolution**
```bash
agent-bom scan --transitive --max-depth 3
# Expected: Resolves nested dependencies for npx packages
# Check: Do you have npx-based MCP servers?
```

**Test 5: Export Formats**
```bash
agent-bom scan --format json --output test.json
agent-bom scan --format cyclonedx --output test.cdx.json

# Validate
python3 -m json.tool test.json
python3 -m json.tool test.cdx.json
```

### Phase 2: Account Testing (Snowflake, AWS, etc.)

**Snowflake Test Scenario**:
```
Given: Snowflake account with Cortex agents
When: agent-bom scan --snowflake-account myaccount --snowflake-user myuser
Then: Should discover agents, extract packages, scan for vulns
```

**Current status**: ❌ Not implemented

**To implement**:
1. Create `src/agent_bom/discovery/snowflake.py`
2. Add Snowflake connector
3. Query Cortex agents
4. Parse and scan

**Would you like me to implement this?**

### Phase 3: Accuracy Testing

**Test vulnerable package detection**:
```bash
# Create test MCP server with known vulns
mkdir test-server
cd test-server
npm init -y
npm install express@4.18.2 axios@1.6.0

# Run scan
agent-bom scan

# Expected: Should detect CVE-2024-29041 in express
```

**Test false positive rate**:
```bash
# Install patched versions
npm install express@4.19.0 axios@1.7.4

# Run scan
agent-bom scan

# Expected: Should show 0 vulnerabilities
```

---

## 📋 Pre-Launch Checklist

Before announcing agent-bom, ensure:

- [ ] **Core functionality works**
  - [ ] Discovery finds MCP configs
  - [ ] Package extraction accurate
  - [ ] Transitive resolution works for npx/uvx
  - [ ] OSV.dev integration returns correct CVEs
  - [ ] Blast radius calculated properly

- [ ] **Output formats valid**
  - [ ] Console output readable
  - [ ] JSON schema consistent
  - [ ] CycloneDX passes validation

- [ ] **Documentation complete**
  - [ ] README has clear examples
  - [ ] ROADMAP shows future plans
  - [ ] CONTRIBUTING guides developers

- [ ] **Tests pass**
  - [ ] Unit tests for parsers
  - [ ] Integration tests for scanners
  - [ ] End-to-end scenarios

- [ ] **Known limitations documented**
  - [ ] Snowflake not supported yet
  - [ ] Cloud providers pending
  - [ ] NVD direct integration future

---

## 🚀 Next Steps

### Option A: Test Current Features
1. Run on your machine
2. Scan your MCP servers
3. Validate vulnerability detection
4. Identify issues

### Option B: Implement Snowflake
1. Add Snowflake connector
2. Query Cortex agents
3. Test on your account
4. Validate end-to-end

### Option C: Add CI/CD
1. GitHub Actions for tests
2. Automated linting (ruff)
3. Publish to PyPI on release
4. Security scanning with Snyk

**What would you like to prioritize?**
