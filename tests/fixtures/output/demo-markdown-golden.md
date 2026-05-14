# agent-bom Scan Report

**Generated**: 2026-01-01 12:00:00 UTC
**Version**: agent-bom v0.70.6

## Summary

| Metric | Count |
|--------|-------|
| Agents discovered | 1 |
| MCP servers | 1 |
| Packages scanned | 1 |
| Vulnerabilities | 4 |
| Policy/security findings | 0 |
| Critical | 1 |
| High | 1 |
| Medium | 1 |
| Low | 1 |

## Findings

| Severity | CVE | Package | Version | Fix | CVSS | EPSS | KEV | CWE | Tags | Source | Agents |
|----------|-----|---------|---------|-----|------|------|-----|-----|------|--------|--------|
| **CRITICAL** | CVE-2024-0001 | lodash | 4.17.20 | 4.17.21 | 9.8 | - | - | CWE-1321 | - | - | 1 |
| **HIGH** | CVE-2024-0002 | requests | 2.28.0 | 2.31.0 | 7.5 | - | - | - | - | - | 1 |
| **MEDIUM** | CVE-2024-0003 | express | 4.18.0 | 4.17.21 | 5.3 | - | - | - | - | - | 1 |
| **LOW** | CVE-2024-0004 | debug | 4.3.0 | 4.17.21 | 2.1 | - | - | - | - | - | 1 |

## Exposure Paths

| Rank | Risk | Severity | Path | Proof | Fix |
|------|------|----------|------|-------|-----|
| #1 | 0.0 | CRITICAL | lodash@4.17.20 -> CVE-2024-0001 | 1 affected agent(s) | Upgrade lodash to 4.17.21 |
| #2 | 0.0 | HIGH | requests@2.28.0 -> CVE-2024-0002 | 1 affected agent(s) | Upgrade requests to 2.31.0 |
| #3 | 0.0 | MEDIUM | express@4.18.0 -> CVE-2024-0003 | 1 affected agent(s) | Upgrade express to 4.17.21 |
| #4 | 0.0 | LOW | debug@4.3.0 -> CVE-2024-0004 | 1 affected agent(s) | Upgrade debug to 4.17.21 |

## Critical & High Findings

### CVE-2024-0001 — lodash@4.17.20

> Test vulnerability

- **Severity**: CRITICAL
- **CVSS**: 9.8
- **Fix**: Upgrade to 4.17.21
- **CWE**: CWE-1321
- **Affected agents**: claude

### CVE-2024-0002 — requests@2.28.0

> Test vulnerability

- **Severity**: HIGH
- **CVSS**: 7.5
- **Fix**: Upgrade to 2.31.0
- **Affected agents**: claude

---
*Scanned by [agent-bom](https://github.com/msaad00/agent-bom) v0.70.6*
