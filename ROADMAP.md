# Roadmap

This document outlines the planned direction for agent-bom over the next
12 months. Items are grouped by theme, not strict timeline. Priority is
informed by user feedback, security landscape changes, and contributor
availability.

For the full backlog, see [open issues](https://github.com/msaad00/agent-bom/issues).

---

## Scanner depth

| Item | Issue | Status |
|------|-------|--------|
| OSV ecosystem expansion — Maven, Go, Ruby, .NET real-world vuln validation | [#545](https://github.com/msaad00/agent-bom/issues/545) | Planned |
| Gradle, NuGet, PHP Composer lock-file parsers | [#524](https://github.com/msaad00/agent-bom/issues/524) | Planned |
| SBOM ingest depth — CycloneDX 1.6 + SPDX 3.0 round-trip fidelity | [#546](https://github.com/msaad00/agent-bom/issues/546) | Planned |
| Notebook cell + prompt + CoCo code scanning (SQL/Python SAST) | [#554](https://github.com/msaad00/agent-bom/issues/554) | Planned |
| Code poisoning detection across AI skill files and generated code | [#548](https://github.com/msaad00/agent-bom/issues/548) | Planned |

## Runtime & proxy

| Item | Issue | Status |
|------|-------|--------|
| CoCo proxy depth (SQL injection + Cortex model tracking) | [#547](https://github.com/msaad00/agent-bom/issues/547) | Done |
| TLS termination for SSE proxy mode | [#556](https://github.com/msaad00/agent-bom/issues/556) | Planned |
| Proxy live traffic view — animated flow, blocked counter, alert timeline | [#468](https://github.com/msaad00/agent-bom/issues/468) | Planned |

## Multi-cloud

| Item | Issue | Status |
|------|-------|--------|
| Unified `--cloud all` single scan across 12 providers | [#540](https://github.com/msaad00/agent-bom/issues/540) | Planned |
| Cross-cloud compliance view — unified CIS/framework dashboard | [#541](https://github.com/msaad00/agent-bom/issues/541) | Planned |
| Cross-cloud drift detection — config change monitoring | [#542](https://github.com/msaad00/agent-bom/issues/542) | Planned |
| Fleet-wide CIS benchmark aggregation | [#543](https://github.com/msaad00/agent-bom/issues/543) | Planned |

## Quality & testing

| Item | Issue | Status |
|------|-------|--------|
| Raise test coverage floor to 80% + add test_cli.py | [#529](https://github.com/msaad00/agent-bom/issues/529) | Planned |
| Zero-dep scanner end-to-end verification | [#549](https://github.com/msaad00/agent-bom/issues/549) | Planned |

## Output & reporting

| Item | Issue | Status |
|------|-------|--------|
| PDF export for scan reports | [#555](https://github.com/msaad00/agent-bom/issues/555) | Planned |
| Dashboard home — risk heatmap, trend sparklines, MTTR gauge | [#463](https://github.com/msaad00/agent-bom/issues/463) | Planned |

## Community & governance

| Item | Status |
|------|--------|
| OpenSSF Best Practices Silver badge | In progress |
| First external committer onboarding | Seeking contributors |
| Security audit (pre-v1.0) | Planned |

---

## Completed (recent)

| Item | Version |
|------|---------|
| CoCo proxy depth — SQL injection + Cortex model tracking | v0.69.0 |
| Snowflake Notebook discovery + ACCESS_HISTORY governance | v0.69.0 |
| Output format compliance (SARIF fingerprints, CDX bom-ref, SPDX 3.0) | v0.69.0 |
| Cloud provider pagination (OpenAI, HuggingFace, MLflow, W&B) | v0.69.0 |
| CLI refactor — 6,262-line monolith → 11 focused modules | v0.69.0 |
| OpenSSF Scorecard Dangerous-Workflow fix | v0.69.0 |
| EPSS batch pagination + KEV stale cache fix | v0.68.1 |

---

This roadmap is updated with each release. To suggest a feature, open a
[GitHub issue](https://github.com/msaad00/agent-bom/issues/new).
