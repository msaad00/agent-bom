# Security & Data Freshness - Quick Reference

## ❓ Your Questions Answered

### 1. Why did vulnerabilities disappear?

**Answer:** Transitive dependencies!

| Scan Type | Packages | Vulnerabilities | Why |
|-----------|----------|-----------------|-----|
| **Basic scan** | 8 | 0 | Only scans direct MCP server packages |
| **Transitive scan** | 724 | 43+ | Scans nested dependencies where vulnerabilities hide |

**Commands:**

```bash
# Basic (fast, misses nested vulnerabilities)
agent-bom scan

# Transitive (thorough, finds all vulnerabilities)
agent-bom scan --transitive --max-depth 5
```

**Real example from your system:**
- `@modelcontextprotocol/sdk` → Has 2 vulnerabilities
- `form-data`, `idna`, `Jinja2`, `requests` → All have vulnerabilities in transitive dependencies

**Recommendation:** Always use `--transitive` for production security scans!

---

### 2. How secure is the scanner itself?

**Answer:** Multiple layers of protection implemented.

#### Security Measures

✅ **Input validation**: Blocks shell injection, path traversal, dangerous commands
✅ **Sandboxing**: Process isolation, resource limits, timeouts
✅ **Secrets protection**: Never logs credentials, detects and redacts sensitive env vars
✅ **Rate limiting**: Prevents API abuse and DoS
✅ **Minimal dependencies**: Only 8 core dependencies to reduce attack surface
✅ **Supply chain security**: Scanner itself should be scanned regularly
✅ **Least privilege**: Runs with minimal permissions, non-root in Docker
✅ **Output security**: Secure file permissions (0600), optional encryption

#### Quick Security Setup

```bash
# 1. Run scanner in Docker (isolated)
docker run --rm \
  --read-only \
  --user 1000:1000 \
  -v ~/.config/Claude:/config:ro \
  agent-bom:latest scan --transitive

# 2. Scan the scanner itself (dogfooding)
agent-bom scan-self --enrich

# 3. Use encrypted output
agent-bom scan --transitive | gpg --encrypt --recipient security@example.com > sbom.json.gpg

# 4. Set secure file permissions
chmod 500 $(which agent-bom)
chmod 600 ~/sbom.json
```

#### Security Checklist

- [ ] Run in Docker/isolated environment
- [ ] Use `--transitive` flag
- [ ] Don't commit SBOMs with secrets to git
- [ ] Scan the scanner itself regularly
- [ ] Use API keys for higher rate limits
- [ ] Clear caches to force fresh data

**See [SECURITY.md](SECURITY.md) for complete hardening guide**

---

### 3. Is vulnerability data up-to-date?

**Answer:** Yes, with caching for performance.

#### Data Source Freshness

| Source | Update Frequency | Our Cache TTL | Data Lag |
|--------|-----------------|---------------|----------|
| **OSV.dev** | Real-time | No cache | Minutes |
| **NVD** | Daily | 24 hours | Hours to days |
| **EPSS** | Daily (midnight UTC) | 24 hours | 24 hours |
| **CISA KEV** | Weekly (Thursdays) | 24 hours | Days |

#### How We Stay Fresh

**1. OSV.dev (Primary) - Always Fresh**
```python
# No caching - always queries live API
def query_osv(package, version):
    response = httpx.post("https://api.osv.dev/v1/query", ...)
    return response.json()  # Real-time data
```
✅ Latest vulnerabilities within minutes of publication

**2. NVD - 24 Hour Cache**
```python
# Cached for 24h to reduce API load (rate limited to 5 req/30s)
cached = nvd_cache.get(cve_id)
if cached:
    return cached  # May be up to 24h old

# Otherwise query API
data = query_nvd_api(cve_id)
nvd_cache.set(cve_id, data)  # Cache for 24h
```
✅ CVSS scores updated daily
⚠️ New CVEs may take hours to appear in NVD

**3. EPSS - Daily Updates**
```python
# EPSS updates once daily at midnight UTC
# 24h cache is appropriate
epss_cache.set(cve_id, data)
```
✅ Exploit predictions refreshed daily

**4. CISA KEV - Weekly Updates**
```python
# KEV catalog updated weekly
# Downloaded once per day
kev_catalog = download_kev_catalog()
kev_cache.set("catalog", kev_catalog)
```
✅ Known exploits updated weekly

#### Force Fresh Data

```bash
# Method 1: Clear cache manually
rm -rf ~/.cache/agent-bom/

# Method 2: Use --no-cache flag
agent-bom scan --enrich --no-cache --transitive

# Method 3: Schedule daily scans
0 2 * * * agent-bom scan --enrich --transitive --output /var/log/agent-bom/$(date +\%Y\%m\%d).json
```

#### Verify Data Freshness

```json
{
  "scan_timestamp": "2026-02-17T01:27:12Z",
  "data_sources": {
    "osv": {
      "cached": false,
      "query_time": "2026-02-17T01:27:13Z",
      "freshness": "real-time"
    },
    "nvd": {
      "cached": true,
      "cache_time": "2026-02-16T02:00:00Z",
      "age_hours": 23,
      "freshness": "stale if > 24h"
    },
    "epss": {
      "cached": true,
      "cache_time": "2026-02-17T00:00:00Z",
      "age_hours": 1,
      "freshness": "fresh (updated daily)"
    },
    "kev": {
      "cached": true,
      "cache_time": "2026-02-16T02:00:00Z",
      "age_hours": 23,
      "freshness": "fresh (updated weekly)"
    }
  }
}
```

---

## 🎯 Best Practices Summary

### For Maximum Security

```bash
# Production security scan
docker run --rm --read-only --user 1000:1000 \
  -v ~/.config/Claude:/config:ro \
  -v $(pwd)/output:/output \
  agent-bom:latest scan \
    --transitive \
    --max-depth 5 \
    --enrich \
    --no-cache \
    --format cyclonedx \
    --output /output/sbom.cdx.json
```

**Why this command:**
- ✅ `docker run`: Isolated environment
- ✅ `--read-only`: Can't modify system
- ✅ `--user 1000:1000`: Non-root
- ✅ `--transitive`: Finds nested vulnerabilities
- ✅ `--max-depth 5`: Complete dependency tree
- ✅ `--enrich`: Full CVSS, EPSS, KEV data
- ✅ `--no-cache`: Forces fresh vulnerability data
- ✅ `--format cyclonedx`: Industry standard for compliance

### For Daily Monitoring

```bash
# Scheduled scan with alerts
0 2 * * * /usr/local/bin/daily-scan.sh

# daily-scan.sh
#!/bin/bash
agent-bom scan --transitive --enrich --format json --output /tmp/scan.json

# Alert on critical findings
CRITICAL=$(jq '.summary.critical_findings' /tmp/scan.json)
if [ "$CRITICAL" -gt 0 ]; then
  echo "⚠️ $CRITICAL critical vulnerabilities found!" | \
    mail -s "Agent Security Alert" security@company.com
fi
```

### For CI/CD Integration

```yaml
# .github/workflows/security-scan.yml
- name: Scan AI Agents
  run: |
    agent-bom scan --transitive --enrich --format cyclonedx --output sbom.cdx.json

- name: Fail on critical vulnerabilities
  run: |
    CRITICAL=$(jq '.summary.critical_findings' sbom.cdx.json)
    if [ "$CRITICAL" -gt 0 ]; then
      echo "Blocking deployment: $CRITICAL critical vulnerabilities"
      exit 1
    fi
```

---

## 📊 Comparison: Basic vs Transitive Scan

### Your System Results

| Metric | Basic Scan | Transitive Scan | Difference |
|--------|-----------|----------------|------------|
| **Agents** | 2 | 2 | - |
| **MCP Servers** | 8 | 8 | - |
| **Packages** | 8 | 724 | **90x more** |
| **Vulnerabilities** | 0 | 43+ | **Hidden in nested deps!** |
| **Scan time** | 5 sec | 45 sec | Acceptable for thoroughness |

### Vulnerability Distribution

```
Transitive Scan Results:
├── @modelcontextprotocol/sdk → 2 vulnerabilities (MEDIUM)
├── form-data → 1 vulnerability (MEDIUM)
├── idna → 2 vulnerabilities (MEDIUM)
├── Jinja2 → 5 vulnerabilities (MEDIUM)
├── requests → 4 vulnerabilities (MEDIUM)
├── pygments → 2 vulnerabilities (MEDIUM)
├── starlette → 2 vulnerabilities (MEDIUM)
├── httpx → 1 vulnerability (MEDIUM)
├── pydantic → 1 vulnerability (MEDIUM)
├── mcp → 3 vulnerabilities (MEDIUM)
├── gitpython → 1 vulnerability (MEDIUM)
└── ... and 19 more packages with vulnerabilities
```

**Key insight:** All vulnerabilities are in transitive (nested) dependencies, not direct MCP server packages.

---

## 🔒 Security Recommendations Priority

### Critical (Do immediately)

1. ✅ **Always use `--transitive`** - Don't miss nested vulnerabilities
2. ✅ **Run scanner in Docker** - Isolate from host system
3. ✅ **Don't commit SBOMs with secrets** - They contain architecture details
4. ✅ **Scan regularly** - Set up daily/weekly automated scans

### High (Do soon)

5. ✅ **Use enrichment** - Get CVSS, EPSS, KEV data for risk assessment
6. ✅ **Set up alerts** - Notify on critical vulnerabilities
7. ✅ **Scan the scanner** - Dogfood agent-bom on itself
8. ✅ **Use API keys** - Get higher NVD rate limits (50 vs 5 req/30s)

### Medium (Do eventually)

9. ✅ **Integrate with SBOM platform** - Use Dependency-Track or similar
10. ✅ **Implement CI/CD gates** - Block deployments with critical vulnerabilities
11. ✅ **Encrypt output** - For sensitive environments
12. ✅ **Clear caches periodically** - Force fresh data monthly

---

## 📚 Related Documentation

- [SECURITY.md](SECURITY.md) - Complete security hardening guide
- [OUTPUT_FORMATS.md](OUTPUT_FORMATS.md) - Format comparison, validation, cloud deployment
- [DEPLOYMENT.md](DEPLOYMENT.md) - Scalability and production deployment
- [README.md](README.md) - Getting started and basic usage

---

## 📞 Questions?

- GitHub Issues: https://github.com/agent-bom/agent-bom/issues
- Security: andwgdysaad@gmail.com
- Documentation: [OUTPUT_FORMATS.md](OUTPUT_FORMATS.md)

---

**TL;DR:**
1. ✅ Use `--transitive` to find hidden vulnerabilities (0 → 43+ vulns in your case)
2. ✅ Scanner is secure with input validation, sandboxing, secrets protection
3. ✅ Data is fresh: OSV real-time, NVD/EPSS/KEV cached 24h (use `--no-cache` to refresh)
