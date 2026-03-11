# ADR-002: OSV-First Vulnerability Strategy

**Status:** Accepted
**Date:** 2026-03-11

## Context

Vulnerability scanning requires a reliable, comprehensive, and freely accessible
data source. Options include maintaining a proprietary database (like Trivy's
trivy-db or Grype's grype-db), using the NVD directly, or using aggregator APIs.

We need to balance scan accuracy, offline capability, speed, and maintenance
burden for an open-source project with no dedicated data engineering team.

## Decision

Use **OSV.dev** as the primary vulnerability data source, with supplemental
sources layered on top:

1. **OSV** (primary) — Free API, covers npm/PyPI/Go/Maven/Cargo/etc., maintained
   by Google, no auth required, PURL-native queries
2. **GHSA** (supplemental) — GitHub Security Advisories for additional coverage
3. **NVD** (enrichment) — CVSS scores, CWE mappings, 90-day response cache
4. **EPSS** (enrichment) — Exploit prediction scores, 30-day cache
5. **CISA KEV** (enrichment) — Known Exploited Vulnerabilities, 24-hour cache
6. **NVIDIA advisories** (supplemental) — For GPU/CUDA/TensorRT packages

**Alternatives considered:**

1. *Own vuln DB (like Trivy)* — Best for offline/speed, but requires continuous
   data pipeline maintenance, storage, and distribution infrastructure. Planned
   for future (see gap analysis) but not justified at current scale.
2. *NVD-only* — Comprehensive but slow (rate-limited API), requires CPE
   matching instead of PURL, and has known coverage gaps for non-CVE advisories.
3. *Snyk/commercial API* — Good data quality but introduces vendor lock-in and
   cost for an open-source project.

## Consequences

- **Positive:** Zero infrastructure cost. No database to maintain or distribute.
- **Positive:** PURL-native queries match our package model directly.
- **Positive:** Multi-source enrichment (NVD + EPSS + KEV) provides depth that
  single-source solutions lack.
- **Trade-off:** Requires network access for scanning. Air-gapped environments
  cannot scan without a future local DB feature.
- **Trade-off:** API rate limits affect scan speed for large dependency trees.
  Caching mitigates this but doesn't eliminate it.
- **Future:** A local SQLite-backed cache of OSV/NVD/EPSS data is the planned
  path to offline scanning and 10x faster lookups. This would complement, not
  replace, the API-first approach.
