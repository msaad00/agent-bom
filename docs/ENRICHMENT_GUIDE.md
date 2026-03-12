# Vulnerability Enrichment Guide

## 🎯 What Was Added

agent-bom now enriches vulnerability data with **three critical sources**:

1. **NVD** (National Vulnerability Database) - CWE mappings, publish dates
2. **EPSS** (Exploit Prediction Scoring System) - Probability of exploitation
3. **CISA KEV** (Known Exploited Vulnerabilities) - Actively exploited CVEs

---

## 🚀 Usage

### Basic Scan (OSV only)
```bash
agent-bom scan
```

### **Enhanced Scan with Enrichment**
```bash
agent-bom scan --enrich
```

### With NVD API Key (Recommended)
```bash
# Set API key as environment variable
export NVD_API_KEY="your-api-key-here"
agent-bom scan --enrich

# Or pass directly
agent-bom scan --enrich --nvd-api-key="your-api-key-here"
```

**Get NVD API Key**: https://nvd.nist.gov/developers/request-an-api-key

---

## 📊 What You Get

### Without Enrichment (Default)
```
Risk  Vuln ID              Package          Severity  Agents  Creds  Fix
8.3   GHSA-xxxx-xxxx       axios@1.6.0      critical  3       2      1.7.4
```

### With Enrichment (--enrich)
```
Risk  Vuln ID              Package          Severity  EPSS   KEV  Agents  Creds  Fix
10.0  CVE-2024-1234       express@4.18.2   critical  85%    🔥   3       2      4.19.0
8.3   CVE-2024-5678       axios@1.6.0      high      45%    —    2       1      1.7.4
6.0   CVE-2024-9012       lodash@4.17.20   medium    12%    —    1       0      4.17.21
```

**Legend**:
- **EPSS**: Exploit probability (higher = more likely to be exploited)
  - 🔴 70%+ = High risk
  - 🟡 30-69% = Medium risk
  - ⚪ <30% = Low risk
- **KEV**: 🔥 = In CISA Known Exploited Vulnerabilities catalog (CRITICAL!)

---

## 🔍 Enrichment Details

### 1. EPSS (Exploit Prediction Scoring System)

**What it is**: Machine learning model that predicts the probability a CVE will be exploited in the next 30 days.

**Data source**: https://api.first.org/data/v1/epss

**Example**:
```json
{
  "cve": "CVE-2024-1234",
  "epss": 0.85,        // 85% probability of exploitation
  "percentile": 0.98,   // In top 2% of all CVEs
  "date": "2024-02-15"
}
```

**Use case**: Prioritize patching based on actual exploit likelihood, not just severity.

---

### 2. CISA KEV (Known Exploited Vulnerabilities)

**What it is**: Official US government catalog of CVEs actively exploited in the wild.

**Data source**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

**Significance**: If a CVE is in KEV, **it's being actively exploited right now** → patch IMMEDIATELY!

**Example**:
```json
{
  "cveID": "CVE-2024-1234",
  "vulnerabilityName": "Express.js RCE",
  "dateAdded": "2024-02-15",
  "dueDate": "2024-03-07",  // Remediation deadline for federal agencies
  "requiredAction": "Apply updates per vendor instructions"
}
```

**Remediation SLA**: Federal agencies must patch KEV vulnerabilities within 21 days.

---

### 3. NVD (National Vulnerability Database)

**What it is**: NIST's comprehensive CVE database with detailed metadata.

**Data source**: https://services.nvd.nist.gov/rest/json/cves/2.0

**Provides**:
- **CWE IDs**: Common Weakness Enumeration (e.g., CWE-79 = XSS)
- **Publish dates**: When the CVE was first disclosed
- **Last modified**: When metadata was updated
- **CVSS vectors**: Detailed attack complexity metrics

**Example**:
```json
{
  "id": "CVE-2024-1234",
  "published": "2024-02-15T10:00:00.000",
  "lastModified": "2024-02-16T14:30:00.000",
  "weaknesses": [
    {"type": "Primary", "description": [{"value": "CWE-79"}]}
  ]
}
```

---

## 📈 Risk Scoring with Enrichment

Base risk score is enhanced based on enrichment data:

```
base_score = CVSS severity (CRITICAL=8.0, HIGH=6.0, etc.)
epss_boost = +2.0 if EPSS > 70%, +1.0 if EPSS > 30%
kev_boost = +2.0 if in CISA KEV
agent_factor = +0.5 per affected agent (max +2.0)
cred_factor = +0.3 per exposed credential (max +1.5)

final_risk_score = min(base_score + epss_boost + kev_boost + agent_factor + cred_factor, 10.0)
```

**Example**:
```
CVE-2024-1234 in express@4.18.2:
- CVSS: CRITICAL (8.0)
- EPSS: 85% → +2.0
- CISA KEV: YES → +2.0
- 3 agents → +1.5
- 2 credentials → +0.6
= 8.0 + 2.0 + 2.0 + 1.5 + 0.6 = 14.1 → capped at 10.0
```

---

## 🔄 Rate Limits

### EPSS API
- **Limit**: None (public, no auth required)
- **Batch size**: 100 CVEs per request
- **Response time**: ~200ms

### CISA KEV
- **Limit**: None (static JSON file)
- **Updates**: Daily
- **Cache**: Refreshed every 24 hours

### NVD API
- **Without API key**: 5 requests per 30 seconds (slow!)
- **With API key**: 50 requests per 30 seconds (10x faster)
- **Recommendation**: Always use API key for production

**Rate limiting logic**:
```python
if no_api_key and num_requests > 5:
    await asyncio.sleep(6)  # Wait 6 seconds every 5 requests
```

---

## 💡 Best Practices

### 1. Always Use Enrichment for Production Scans
```bash
# DO THIS
agent-bom scan --enrich --format json --output production-bom.json

# NOT THIS (missing critical context)
agent-bom scan --format json --output production-bom.json
```

### 2. Get NVD API Key
Free registration: https://nvd.nist.gov/developers/request-an-api-key

Add to your environment:
```bash
# Add to ~/.bashrc or ~/.zshrc
export NVD_API_KEY="your-key-here"
```

### 3. Prioritize by KEV First, Then EPSS
```
Priority 1: is_kev = true              → Patch ASAP (active exploitation!)
Priority 2: epss_score > 0.7           → Patch within 7 days (high probability)
Priority 3: severity = CRITICAL        → Patch within 30 days
Priority 4: epss_score > 0.3           → Patch within 60 days
Priority 5: severity = HIGH/MEDIUM     → Patch when convenient
```

### 4. Monitor KEV Catalog
CISA adds new CVEs weekly. Re-scan regularly:
```bash
# Daily production scan
0 2 * * * agent-bom scan --enrich --output /var/log/agent-bom/daily-$(date +\%Y\%m\%d).json
```

---

## 📋 JSON Output Schema

Enhanced vulnerability object:
```json
{
  "id": "CVE-2024-1234",
  "summary": "Express.js Remote Code Execution",
  "severity": "critical",
  "cvss_score": 9.8,
  "fixed_version": "4.19.0",
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],

  // ENRICHMENT DATA
  "epss_score": 0.85,
  "epss_percentile": 98.5,
  "is_kev": true,
  "kev_date_added": "2024-02-15",
  "kev_due_date": "2024-03-07",
  "exploitability": "HIGH",
  "cwe_ids": ["CWE-94"],
  "nvd_published": "2024-02-15T10:00:00.000",
  "nvd_modified": "2024-02-16T14:30:00.000"
}
```

---

## 🧪 Testing Enrichment

```bash
# Test with transitive deps + enrichment
agent-bom scan --transitive --enrich

# Export enriched data
agent-bom scan --enrich --format json --output enriched-test.json

# Verify enrichment worked
python3 -c "import json; d=json.load(open('enriched-test.json')); print('EPSS:', any('epss_score' in v for p in d['agents'][0]['mcp_servers'][0]['packages'] for v in p['vulnerabilities']))"
```

---

## ⚠️ Known Limitations

1. **NVD Rate Limiting**: Without API key, enrichment is slow (6 seconds per 5 CVEs)
2. **EPSS Coverage**: Not all CVEs have EPSS scores (only ~80% coverage)
3. **KEV Scope**: CISA KEV is US-focused; may miss region-specific exploits
4. **API Availability**: Requires internet connection; offline mode not supported yet

---

## OpenSSF Scorecard Enrichment

The `--scorecard` flag enriches packages with [OpenSSF Scorecard](https://scorecard.dev/) scores from `api.securityscorecards.dev`. Scorecard measures the security health of open source projects across 18 checks (Code-Review, Maintained, Vulnerabilities, etc.).

```bash
agent-bom scan --scorecard                    # enrich packages with scorecard data
agent-bom scan --enrich --scorecard -f json   # full enrichment + scorecard
```

**How it works:**
- Packages with a known GitHub source repo get their scorecard fetched
- Scores range from 0.0 (worst) to 10.0 (best)
- Low scores amplify blast radius risk: `< 3.0` = +0.75 risk, `< 5.0` = +0.5, `< 7.0` = +0.25
- Console output shows `SC:X.X` badges (green/yellow/red) per package
- JSON output includes `scorecard_score` and individual `scorecard_checks`

**No API key required.** The OpenSSF Scorecard API is free and public.

---

## Malicious Package Detection

agent-bom automatically detects known malicious packages from the [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) dataset (via OSV.dev `MAL-` prefixed IDs) and flags potential typosquats of 57 popular npm/PyPI packages.

**MAL- prefix detection:** Any vulnerability with an ID starting with `MAL-` (e.g., `MAL-2024-1234`) automatically flags the package as malicious. These appear as skull badges in console output and `is_malicious: true` in JSON.

**Typosquat detection:** Package names are compared against popular packages using sequence matching. A similarity ratio >= 85% triggers a warning (e.g., `expresss` flagged as typosquat of `express`).

No additional flags needed — malicious detection runs automatically during every scan.
