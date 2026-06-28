# ADR-002: OSV-First Vulnerability Strategy

**Status:** Accepted
**Date:** 2026-03-11

## Context

Vulnerability scanning requires a reliable, comprehensive, and freely accessible
data source. Options include maintaining a proprietary vulnerability database,
using the NVD directly, or using aggregator APIs.

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
7. **Alpine secdb** (distro) — Authoritative apk per-branch secfix data
8. **Debian Security Tracker** (distro) — Authoritative per-release status and
   backported fix versions for Debian/`deb` packages. OSV drops releases once they
   reach end-of-life, so its bulk export carries no `debian:10` (buster) rows and
   misses the `+debNuX` backports distro maintainers actually shipped. The tracker
   records, per *source* package and per release, whether each CVE is resolved
   (with the exact backported fix), open (no-dsa / won't-fix / EOL — suppressed by
   default, restored with `AGENT_BOM_INCLUDE_UNFIXED=1`), or undetermined. Two
   feeds with an identical JSON shape are ingested by `db update --source debian`:
   the main tracker for supported releases and the Extended LTS tracker for the
   end-of-life releases (buster/Debian 10) the main feed has pruned. Tracker rows
   share OSV's `DEBIAN-CVE-*` identifier so they merge by id and the backport wins
   per release; OSV remains the fallback where the tracker has no entry.

**Alternatives considered:**

1. *Own vuln DB* — Best for offline/speed, but requires continuous
   data pipeline maintenance, storage, and distribution infrastructure. Planned
   for future (see gap analysis) but not justified at current scale.
2. *NVD-only* — Comprehensive but slow (rate-limited API), requires CPE
   matching instead of PURL, and has known coverage gaps for non-CVE advisories.
3. *Commercial vulnerability APIs* — Good data quality but introduce vendor lock-in
   and per-token cost for an open-source project.

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
