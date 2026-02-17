# Scanner Internals: How agent-bom Actually Works

**Last Updated:** 2026-02-17

---

## 🎯 Complete Data Flow

```
User Command
    ↓
agent-bom scan --transitive --enrich
    ↓
┌──────────────────────────────────────────────────────────────┐
│ PHASE 1: DISCOVERY                                            │
│ File: src/agent_bom/discovery/__init__.py                   │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│ 1. Scan config directories:                                  │
│    • ~/.config/Claude/claude_desktop_config.json            │
│    • ~/.cursor/mcp.json                                      │
│    • ~/.cline/mcp.json, ~/.windsurf/mcp.json, etc.          │
│                                                               │
│ 2. ✅ Security validation (NEW):                             │
│    validate_json_file(config_path)                           │
│    • Check file size < 10MB (DoS prevention)                 │
│    • Safe JSON parsing (no code execution)                   │
│    • Path traversal prevention                               │
│                                                               │
│ 3. Parse each config file:                                   │
│    config_data = json.load(file)                             │
│    mcp_servers = config_data["mcpServers"]                   │
│                                                               │
│ 4. ✅ Validate each MCP server (NEW):                        │
│    validate_mcp_server_config(server_def)                    │
│    • validate_command() - Only allow safe commands           │
│    • validate_arguments() - Block shell injection            │
│    • validate_environment() - Block dangerous env vars       │
│    • Skip insecure servers with warning                      │
│                                                               │
│ OUTPUT: List[Agent]                                          │
│         ├── Agent(claude-desktop)                            │
│         │   └── MCPServer(github, filesystem, ...)          │
│         └── Agent(cursor)                                    │
│             └── MCPServer(slack, postgres, ...)              │
└──────────────────────────────────────────────────────────────┘
    ↓
┌──────────────────────────────────────────────────────────────┐
│ PHASE 2: PACKAGE EXTRACTION                                  │
│ File: src/agent_bom/parsers/__init__.py                     │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│ For each MCP server:                                         │
│                                                               │
│ 1. Extract package from command:                             │
│    command: "npx"                                            │
│    args: ["-y", "@modelcontextprotocol/server-github"]      │
│    ↓                                                         │
│    Package: @modelcontextprotocol/server-github             │
│    Ecosystem: npm                                            │
│    Version: "latest" (to be resolved)                        │
│                                                               │
│ 2. For uvx/Python packages:                                  │
│    command: "uvx"                                            │
│    args: ["mcp-server-fetch"]                                │
│    ↓                                                         │
│    Package: mcp-server-fetch                                 │
│    Ecosystem: pypi                                           │
│    Version: "latest" (to be resolved)                        │
│                                                               │
│ OUTPUT: List[Package] (with version="latest")               │
└──────────────────────────────────────────────────────────────┘
    ↓
┌──────────────────────────────────────────────────────────────┐
│ PHASE 3: VERSION RESOLUTION                                  │
│ File: src/agent_bom/resolver.py                             │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│ For each package:                                            │
│                                                               │
│ ┌────────────────────────────────────────────────────────┐  │
│ │ NPM PACKAGES                                            │  │
│ │ Source: registry.npmjs.org                              │  │
│ └────────────────────────────────────────────────────────┘  │
│                                                               │
│ 1. Query npm registry:                                       │
│    GET https://registry.npmjs.org/{package}                  │
│                                                               │
│    Example:                                                  │
│    GET https://registry.npmjs.org/@modelcontextprotocol/server-github
│                                                               │
│ 2. Response (JSON):                                          │
│    {                                                         │
│      "name": "@modelcontextprotocol/server-github",         │
│      "dist-tags": {                                          │
│        "latest": "2025.4.8"    ← Resolve "latest" to this   │
│      },                                                      │
│      "versions": {                                           │
│        "2025.4.8": {                                         │
│          "dependencies": {                                   │
│            "@modelcontextprotocol/sdk": "^1.0.1",          │
│            "@octokit/rest": "^20.0.0",                      │
│            "dotenv": "^16.0.0"                              │
│          }                                                   │
│        }                                                     │
│      }                                                       │
│    }                                                         │
│                                                               │
│ 3. Extract:                                                  │
│    ✅ Resolved version: "2025.4.8"                          │
│    ✅ Dependencies: [@modelcontextprotocol/sdk, ...]        │
│                                                               │
│ ┌────────────────────────────────────────────────────────┐  │
│ │ PYPI PACKAGES                                           │  │
│ │ Source: pypi.org                                        │  │
│ └────────────────────────────────────────────────────────┘  │
│                                                               │
│ 1. Query PyPI:                                               │
│    GET https://pypi.org/pypi/{package}/json                 │
│                                                               │
│    Example:                                                  │
│    GET https://pypi.org/pypi/mcp-server-fetch/json          │
│                                                               │
│ 2. Response (JSON):                                          │
│    {                                                         │
│      "info": {                                               │
│        "name": "mcp-server-fetch",                          │
│        "version": "2025.4.7",  ← Latest version             │
│        "requires_dist": [                                    │
│          "httpx>=0.25.0",                                   │
│          "beautifulsoup4>=4.12.0",                          │
│          "pydantic>=2.0"                                     │
│        ]                                                     │
│      }                                                       │
│    }                                                         │
│                                                               │
│ 3. Extract:                                                  │
│    ✅ Resolved version: "2025.4.7"                          │
│    ✅ Dependencies: [httpx, beautifulsoup4, pydantic]       │
│                                                               │
│ OUTPUT: List[Package] (with resolved versions)              │
└──────────────────────────────────────────────────────────────┘
    ↓
┌──────────────────────────────────────────────────────────────┐
│ PHASE 4: TRANSITIVE RESOLUTION (if --transitive)            │
│ File: src/agent_bom/transitive.py                           │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│ For each direct dependency:                                  │
│                                                               │
│ 1. Recursively fetch dependencies:                           │
│                                                               │
│    @modelcontextprotocol/server-github @ 2025.4.8           │
│        ↓ Query npm registry for this version                │
│        ├── @modelcontextprotocol/sdk @ 1.0.1 (depth 1)     │
│        │   ↓ Query npm registry                             │
│        │   ├── zod @ 3.23.8 (depth 2)                       │
│        │   ├── raw-body @ 3.0.0 (depth 2)                   │
│        │   │   ↓ Query npm registry                         │
│        │   │   ├── bytes @ 3.1.2 (depth 3)                  │
│        │   │   ├── unpipe @ 1.0.0 (depth 3)                 │
│        │   │   ├── iconv-lite @ 0.6.3 (depth 3)             │
│        │   │   └── http-errors @ 2.0.0 (depth 3)            │
│        │   └── content-type @ 1.0.5 (depth 2)               │
│        ├── @octokit/rest @ 20.0.2 (depth 1)                │
│        │   ↓ Query npm registry                             │
│        │   ├── @octokit/core @ 5.0.0 (depth 2)              │
│        │   │   ↓ Query npm registry                         │
│        │   │   ├── @octokit/auth-token @ 4.0.0 (depth 3)   │
│        │   │   ├── @octokit/graphql @ 7.0.2 (depth 3)       │
│        │   │   └── ... (depth 3)                            │
│        │   └── ... (depth 2)                                │
│        └── dotenv @ 16.3.1 (depth 1)                        │
│                                                               │
│ 2. Cycle detection:                                          │
│    visited = {}                                              │
│    if (package, version) in visited:                         │
│        skip  # Already processed                             │
│                                                               │
│ 3. Depth limiting:                                           │
│    if current_depth > max_depth:                             │
│        stop  # Prevent infinite recursion                    │
│                                                               │
│ OUTPUT: List[Package] (direct + transitive)                 │
│         • Direct dependencies: 8 packages                    │
│         • Transitive dependencies: 716 packages              │
│         • Total: 724 packages                                │
└──────────────────────────────────────────────────────────────┘
    ↓
┌──────────────────────────────────────────────────────────────┐
│ PHASE 5: VULNERABILITY SCANNING                              │
│ File: src/agent_bom/scanners/__init__.py                    │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│ ┌────────────────────────────────────────────────────────┐  │
│ │ OSV.dev API (Primary Source)                            │  │
│ │ URL: https://api.osv.dev                                │  │
│ │ Rate Limit: None                                        │  │
│ │ Cache: None (always fresh)                              │  │
│ └────────────────────────────────────────────────────────┘  │
│                                                               │
│ For each package:                                            │
│                                                               │
│ 1. Query OSV.dev:                                            │
│    POST https://api.osv.dev/v1/query                         │
│    {                                                         │
│      "package": {                                            │
│        "name": "@modelcontextprotocol/sdk",                 │
│        "ecosystem": "npm"                                    │
│      },                                                      │
│      "version": "1.0.1"                                      │
│    }                                                         │
│                                                               │
│ 2. Response (JSON):                                          │
│    {                                                         │
│      "vulns": [                                              │
│        {                                                     │
│          "id": "GHSA-8r9q-7v3w-x5j4",                       │
│          "summary": "Path traversal in SDK",                │
│          "details": "A path traversal vulnerability...",    │
│          "severity": [                                       │
│            {                                                 │
│              "type": "CVSS_V3",                             │
│              "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/..."   │
│            }                                                 │
│          ],                                                  │
│          "affected": [                                       │
│            {                                                 │
│              "package": {...},                              │
│              "ranges": [                                     │
│                {                                             │
│                  "type": "ECOSYSTEM",                       │
│                  "events": [                                │
│                    {"introduced": "0"},                     │
│                    {"fixed": "1.0.2"}  ← FIX VERSION!       │
│                  ]                                           │
│                }                                             │
│              ]                                               │
│            }                                                 │
│          ],                                                  │
│          "references": [                                     │
│            {                                                 │
│              "type": "ADVISORY",                            │
│              "url": "https://github.com/advisories/..."     │
│            },                                                │
│            {                                                 │
│              "type": "FIX",                                 │
│              "url": "https://github.com/.../commit/..."     │
│            }                                                 │
│          ],                                                  │
│          "database_specific": {                             │
│            "cwe_ids": ["CWE-22"],                           │
│            "github_reviewed": true                          │
│          }                                                   │
│        }                                                     │
│      ]                                                       │
│    }                                                         │
│                                                               │
│ 3. Extract vulnerability data:                               │
│    ✅ ID: GHSA-8r9q-7v3w-x5j4                               │
│    ✅ Severity: Based on CVSS                                │
│    ✅ Fix version: 1.0.2 (from ranges.events.fixed)        │
│    ✅ CWE: CWE-22 (Path Traversal)                          │
│    ✅ References: Advisory + Fix commit URLs                 │
│                                                               │
│ OUTPUT: List[Vulnerability] with fix versions               │
└──────────────────────────────────────────────────────────────┘
    ↓
┌──────────────────────────────────────────────────────────────┐
│ PHASE 6: ENRICHMENT (if --enrich)                           │
│ File: src/agent_bom/enrichment.py                           │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│ For each vulnerability:                                      │
│                                                               │
│ ┌────────────────────────────────────────────────────────┐  │
│ │ A. NVD API (CVE Details)                                │  │
│ │ URL: https://services.nvd.nist.gov/rest/json/cves/2.0  │  │
│ │ Rate Limit: 50 req/30s (with API key)                  │  │
│ │ Cache: 24 hours                                         │  │
│ └────────────────────────────────────────────────────────┘  │
│                                                               │
│ 1. If vulnerability has CVE ID:                              │
│    GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-12345
│                                                               │
│ 2. Response:                                                 │
│    {                                                         │
│      "cve": {                                                │
│        "id": "CVE-2024-12345",                              │
│        "metrics": {                                          │
│          "cvssMetricV31": [{                                │
│            "cvssData": {                                     │
│              "baseScore": 7.5,                              │
│              "baseSeverity": "HIGH",                        │
│              "vectorString": "CVSS:3.1/AV:N/AC:L/...",     │
│              "attackVector": "NETWORK",                     │
│              "attackComplexity": "LOW",                     │
│              "privilegesRequired": "NONE",                  │
│              "userInteraction": "NONE",                     │
│              "scope": "UNCHANGED",                          │
│              "confidentialityImpact": "NONE",               │
│              "integrityImpact": "HIGH",                     │
│              "availabilityImpact": "NONE"                   │
│            }                                                 │
│          }]                                                  │
│        },                                                    │
│        "weaknesses": [{                                      │
│          "description": [{                                   │
│            "value": "CWE-22"                                │
│          }]                                                  │
│        }]                                                    │
│      }                                                       │
│    }                                                         │
│                                                               │
│ 3. Extract:                                                  │
│    ✅ CVSS Score: 7.5                                        │
│    ✅ CVSS Severity: HIGH                                    │
│    ✅ CVSS Vector: Full breakdown                            │
│    ✅ CWE: CWE-22                                            │
│                                                               │
│ ┌────────────────────────────────────────────────────────┐  │
│ │ B. EPSS API (Exploit Prediction)                        │  │
│ │ URL: https://api.first.org/data/v1/epss                │  │
│ │ Rate Limit: None                                        │  │
│ │ Cache: 24 hours                                         │  │
│ │ Updates: Daily (midnight UTC)                           │  │
│ └────────────────────────────────────────────────────────┘  │
│                                                               │
│ 1. Query EPSS:                                               │
│    GET https://api.first.org/data/v1/epss?cve=CVE-2024-12345│
│                                                               │
│ 2. Response:                                                 │
│    {                                                         │
│      "data": [{                                              │
│        "cve": "CVE-2024-12345",                             │
│        "epss": "0.00234",      ← 0.234% probability         │
│        "percentile": "0.52"    ← 52nd percentile            │
│      }]                                                      │
│    }                                                         │
│                                                               │
│ 3. Extract:                                                  │
│    ✅ EPSS Score: 0.00234 (0.234% exploitation probability) │
│    ✅ Percentile: 52nd percentile                            │
│    ✅ Risk Level: LOW (< 1% probability)                     │
│                                                               │
│ ┌────────────────────────────────────────────────────────┐  │
│ │ C. CISA KEV (Known Exploited)                           │  │
│ │ URL: https://www.cisa.gov/sites/default/files/feeds/   │  │
│ │      known_exploited_vulnerabilities.json               │  │
│ │ Rate Limit: None                                        │  │
│ │ Cache: 24 hours                                         │  │
│ │ Updates: Weekly (Thursdays)                             │  │
│ └────────────────────────────────────────────────────────┘  │
│                                                               │
│ 1. Download KEV catalog (once, then cache):                 │
│    GET https://www.cisa.gov/.../known_exploited_vulnerabilities.json
│                                                               │
│ 2. Response:                                                 │
│    {                                                         │
│      "vulnerabilities": [                                    │
│        {                                                     │
│          "cveID": "CVE-2024-54321",                         │
│          "vendorProject": "...",                            │
│          "product": "...",                                   │
│          "dateAdded": "2024-01-15",                         │
│          "shortDescription": "...",                         │
│          "requiredAction": "Apply updates..."               │
│        },                                                    │
│        ...                                                   │
│      ]                                                       │
│    }                                                         │
│                                                               │
│ 3. Check if CVE is in catalog:                               │
│    is_known_exploited = "CVE-2024-12345" in [v["cveID"] ...]│
│                                                               │
│ 4. Extract:                                                  │
│    ✅ KEV Status: false (not in catalog = not exploited)    │
│    ✅ Date Added: N/A                                        │
│    ✅ Required Action: N/A                                   │
│                                                               │
│ OUTPUT: Enriched vulnerabilities with:                      │
│         • CVSS scores + vectors                              │
│         • EPSS exploitation probability                      │
│         • KEV known exploitation status                      │
│         • CWE categories                                     │
│         • Fix versions (from OSV)                            │
│         • Remediation recommendations                        │
└──────────────────────────────────────────────────────────────┘
    ↓
┌──────────────────────────────────────────────────────────────┐
│ PHASE 7: TYING DATA TOGETHER                                 │
│ File: src/agent_bom/scanners/__init__.py                    │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│ Create the trust chain:                                      │
│                                                               │
│ Agent ← has → MCP Server ← has → Package ← has → Vulnerability
│                                                               │
│ Example:                                                     │
│                                                               │
│ claude-desktop (Agent)                                       │
│   ├── github (MCP Server)                                    │
│   │   ├── @modelcontextprotocol/server-github@2025.4.8     │
│   │   ├── @modelcontextprotocol/sdk@1.0.1 (transitive)     │
│   │   │   └── GHSA-8r9q-7v3w-x5j4 (Vulnerability)           │
│   │   │       ├── Severity: HIGH                            │
│   │   │       ├── CVSS: 7.5                                 │
│   │   │       ├── EPSS: 0.234% probability                  │
│   │   │       ├── KEV: Not exploited                        │
│   │   │       ├── CWE: CWE-22 (Path Traversal)              │
│   │   │       ├── Fix: Upgrade to 1.0.2                     │
│   │   │       └── Blast Radius:                             │
│   │   │           ├── Affects: claude-desktop (agent)       │
│   │   │           ├── Via: github (MCP server)              │
│   │   │           ├── Has credentials: YES (GITHUB_TOKEN)   │
│   │   │           └── Risk: CRITICAL                        │
│   │   └── ... more packages                                 │
│   └── filesystem (MCP Server)                                │
│       └── ...                                                │
│                                                               │
│ OUTPUT: Complete trust chain with vulnerability mapping     │
└──────────────────────────────────────────────────────────────┘
    ↓
┌──────────────────────────────────────────────────────────────┐
│ PHASE 8: OUTPUT GENERATION                                   │
│ File: src/agent_bom/output/__init__.py                      │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│ Generate output in requested format:                         │
│                                                               │
│ ┌─ Console (Rich) ────────────────────────────────────────┐ │
│ │ • Formatted tables with colors                           │ │
│ │ • Blast radius analysis                                  │ │
│ │ • Summary statistics                                     │ │
│ │ • ✅ Secrets redacted via sanitize_env_vars()           │ │
│ └──────────────────────────────────────────────────────────┘ │
│                                                               │
│ ┌─ JSON (Custom AI-BOM) ──────────────────────────────────┐ │
│ │ {                                                        │ │
│ │   "ai_bom_version": "0.1.0",                            │ │
│ │   "generated_at": "2026-02-17T...",                     │ │
│ │   "summary": {...},                                      │ │
│ │   "agents": [                                            │ │
│ │     {                                                    │ │
│ │       "name": "claude-desktop",                         │ │
│ │       "mcp_servers": [                                   │ │
│ │         {                                                │ │
│ │           "name": "github",                             │ │
│ │           "packages": [                                  │ │
│ │             {                                            │ │
│ │               "name": "@modelcontextprotocol/sdk",     │ │
│ │               "version": "1.0.1",                       │ │
│ │               "vulnerabilities": [                      │ │
│ │                 {                                        │ │
│ │                   "id": "GHSA-8r9q-7v3w-x5j4",         │ │
│ │                   "severity": "HIGH",                   │ │
│ │                   "cvss_score": 7.5,                    │ │
│ │                   "epss_score": 0.00234,                │ │
│ │                   "is_known_exploited": false,          │ │
│ │                   "fixed_versions": ["1.0.2"],   ← FIX  │ │
│ │                   "remediation": "Upgrade to 1.0.2+"    │ │
│ │                 }                                        │ │
│ │               ]                                          │ │
│ │             }                                            │ │
│ │           ]                                              │ │
│ │         }                                                │ │
│ │       ]                                                  │ │
│ │     }                                                    │ │
│ │   ]                                                      │ │
│ │ }                                                        │ │
│ └──────────────────────────────────────────────────────────┘ │
│                                                               │
│ ┌─ CycloneDX 1.6 (Standard SBOM) ─────────────────────────┐ │
│ │ • Industry-standard format                               │ │
│ │ • Compatible with Dependency-Track, Grype, etc.          │ │
│ │ • Includes components, dependencies, vulnerabilities     │ │
│ │ • Fix versions in vulnerability objects                  │ │
│ └──────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
    ↓
Final Output
```

---

## 📊 Data Sources Summary

| Source | Purpose | API Endpoint | Data Returned |
|--------|---------|--------------|---------------|
| **npm registry** | Package metadata | `registry.npmjs.org/{package}` | Version, dependencies |
| **PyPI** | Package metadata | `pypi.org/pypi/{package}/json` | Version, dependencies |
| **OSV.dev** | Vulnerabilities | `api.osv.dev/v1/query` | CVE/GHSA IDs, severity, **fix versions**, CWE |
| **NVD** | CVE details | `services.nvd.nist.gov/rest/json/cves/2.0` | CVSS scores, vectors, CWE |
| **EPSS** | Exploit prediction | `api.first.org/data/v1/epss` | Exploitation probability |
| **CISA KEV** | Known exploits | `cisa.gov/.../known_exploited_vulnerabilities.json` | Exploitation confirmation |

---

## ✅ Fix Version Sources

### Where Fix Versions Come From

**OSV.dev provides fix versions in the `affected` field:**

```json
{
  "vulns": [{
    "id": "GHSA-xxxx-yyyy-zzzz",
    "affected": [{
      "package": {"name": "package-name"},
      "ranges": [{
        "type": "ECOSYSTEM",
        "events": [
          {"introduced": "0"},
          {"fixed": "1.2.4"}  ← This is the fix version!
        ]
      }]
    }]
  }]
}
```

**Our code extracts it:**

```python
# src/agent_bom/scanners/__init__.py
def extract_fixed_versions(vuln: dict) -> list[str]:
    """Extract fixed versions from OSV vulnerability data."""
    fixed_versions = []
    for affected in vuln.get("affected", []):
        for range_item in affected.get("ranges", []):
            for event in range_item.get("events", []):
                if "fixed" in event:
                    fixed_versions.append(event["fixed"])
    return fixed_versions
```

**Output includes fix versions:**

```json
{
  "vulnerabilities": [{
    "id": "GHSA-xxxx-yyyy-zzzz",
    "fixed_versions": ["1.2.4", "2.0.0"],
    "remediation": {
      "recommendation": "Upgrade to version 1.2.4 or later",
      "fixed_in": ["1.2.4", "2.0.0"],
      "workaround": "No workaround - upgrade required"
    }
  }]
}
```

---

## 🔒 Security Validations Applied

| Phase | Validation | Function | Purpose |
|-------|-----------|----------|---------|
| **Discovery** | JSON file | `validate_json_file()` | DoS prevention, safe parsing |
| **Discovery** | MCP config | `validate_mcp_server_config()` | Block malicious servers |
| **Discovery** | Command | `validate_command()` | Only allow safe executables |
| **Discovery** | Arguments | `validate_arguments()` | Block shell injection |
| **Discovery** | Environment | `validate_environment()` | Block dangerous env vars |
| **Resolution** | URL | `validate_url()` | HTTPS only |
| **Resolution** | Package name | `validate_package_name()` | Prevent injection |
| **Output** | Secrets | `sanitize_env_vars()` | Redact credentials |

---

## 🧪 CI/CD Integration

### Automated in GitHub Actions

Every PR and push to main runs:

1. **Security Scan**
   - `pip-audit` - Dependency vulnerabilities
   - `bandit` - Static security analysis
   - `safety` - Vulnerability database check

2. **Code Quality**
   - `ruff` - Linting
   - `mypy` - Type checking

3. **Tests**
   - Unit tests (Python 3.10, 3.11, 3.12, 3.13)
   - Integration tests

4. **Dogfooding**
   - Scan test MCP configs with agent-bom itself
   - Verify scanner works end-to-end

5. **Quality Gate**
   - Fail if > 5 fixable CVEs
   - Fail if HIGH severity code issues
   - Fail if build fails

6. **PR Comment**
   - Auto-comment with scan results
   - Show summary of vulnerabilities found

---

## 🔄 Integration with Other Tools

### Can Integrate With

**✅ Dependency-Track:**
```bash
agent-bom scan --format cyclonedx --output sbom.cdx.json
curl -X POST "https://dtrack.company.com/api/v1/bom" \
  -F "bom=@sbom.cdx.json"
```

**✅ Grype:**
```bash
agent-bom scan --format cyclonedx --output sbom.cdx.json
grype sbom:sbom.cdx.json
```

**✅ Snyk:**
```bash
# Snyk can scan agent-bom itself
snyk test --file=pyproject.toml
```

**✅ Custom Tools:**
```bash
# JSON output for custom parsing
agent-bom scan --format json --output sbom.json
jq '.agents[].mcp_servers[].packages[].vulnerabilities[]' sbom.json
```

### But We Have Our Own Scanner

**Why have our own?**

1. ✅ **AI-specific**: Maps vulnerabilities to agents (Grype doesn't know about agents)
2. ✅ **Trust chain**: Shows Agent → MCP → Package → Vulnerability
3. ✅ **Credential exposure**: Detects risky combinations (vuln + credentials)
4. ✅ **Blast radius**: Shows impact across agents
5. ✅ **MCP-aware**: Understands npx/uvx package resolution

**Other tools complement us:**
- Grype: Additional vulnerability sources
- Snyk: License checking, additional CVE data
- Dependency-Track: SBOM management, tracking over time

---

## 📝 Summary

### What agent-bom Does

1. ✅ **Discovers** AI agents (Claude, Cursor, etc.) automatically
2. ✅ **Extracts** MCP server packages (npm, PyPI, Go, Cargo)
3. ✅ **Resolves** versions from registries (npmjs.org, pypi.org)
4. ✅ **Scans** for vulnerabilities (OSV.dev)
5. ✅ **Enriches** with security data (NVD, EPSS, CISA KEV)
6. ✅ **Provides fix versions** (from OSV ranges.events.fixed)
7. ✅ **Maps trust chain** (Agent → MCP → Package → Vuln)
8. ✅ **Detects credential exposure** (env vars + vulnerabilities)
9. ✅ **Validates security** (command, args, env, paths)
10. ✅ **Outputs** in multiple formats (Console, JSON, CycloneDX)

### What We Use (External)

- **npm registry** - Package metadata
- **PyPI** - Package metadata
- **OSV.dev** - Vulnerabilities + fix versions
- **NVD** - CVSS scores
- **EPSS** - Exploit prediction
- **CISA KEV** - Known exploitation

### What We Built (Our Scanner)

- ✅ 315 lines of security validation code
- ✅ AI agent discovery
- ✅ MCP server parsing
- ✅ Transitive dependency resolution
- ✅ Trust chain mapping
- ✅ Blast radius analysis
- ✅ Credential exposure detection
- ✅ Multiple output formats
- ✅ CI/CD integration

---

**Generated by:** agent-bom development team
**Date:** 2026-02-17
**Scanner Version:** 0.1.0
