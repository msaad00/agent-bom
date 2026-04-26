# ADR-001: OSV as primary vulnerability source

## Status

Accepted

## Context

agent-bom needs a vulnerability database to check packages against known CVEs.
Options considered:

1. **NVD (National Vulnerability Database)** — comprehensive but rate-limited API,
   requires API key for reasonable throughput, CPE matching is complex
2. **OSV.dev** — open, no API key required, ecosystem-native identifiers (GHSA, PYSEC),
   supports batch queries, maintained by Google
3. **Snyk** — commercial API, requires token, good data quality but vendor lock-in
4. **GitHub Advisory Database (GHSA)** — good for npm/PyPI but limited ecosystem coverage

## Decision

Use **OSV.dev** as the primary vulnerability source with NVD and GHSA as
supplemental enrichment sources.

- OSV provides the initial vulnerability match (package name + version → advisories)
- NVD enriches with CVSS scores, CWE IDs, and reference links (90-day cache)
- EPSS enriches with exploit probability scores (30-day cache)
- CISA KEV flags known-exploited vulnerabilities (24-hour cache)
- Snyk is available as an optional source via `--snyk-token`

## Consequences

### Positive

- No API key required for basic scanning — zero-config experience
- Batch query support keeps scan times fast (one HTTP call per ecosystem)
- Ecosystem-native IDs reduce false positives vs CPE matching
- Multi-source enrichment gives comprehensive risk context

### Negative

- OSV coverage for some ecosystems (C/C++, system packages) is thinner than NVD
- NVD enrichment adds latency (mitigated by 90-day disk cache)
- No single source has complete coverage — users may see different results from other vulnerability scanners
