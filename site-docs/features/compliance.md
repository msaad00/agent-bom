# Compliance Frameworks

agent-bom maps scan findings to 15 tag-mapped security and compliance frameworks and exposes OWASP AISVS as benchmark evidence.

Framework catalogs are pinned in-repo by default so scans stay deterministic,
offline-friendly, and reproducible. Catalog refreshes can happen out of band;
the scan hot path does not fetch MITRE or other framework data at runtime.

## Supported frameworks

| Framework | Module | Focus |
|-----------|--------|-------|
| OWASP LLM Top 10 | `owasp.py` | LLM-specific risks |
| OWASP Agentic Security | `owasp_agentic.py` | Agent autonomy risks |
| OWASP MCP Top 10 | `owasp_mcp.py` | MCP protocol risks |
| MITRE ATLAS | `atlas.py` | Adversarial ML tactics |
| EU AI Act | `eu_ai_act.py` | EU regulatory compliance |
| NIST AI RMF | `nist_ai_rmf.py` | AI risk management |
| NIST CSF | `nist_csf.py` | Cybersecurity framework |
| SOC 2 | `soc2.py` | Trust service criteria |
| ISO 27001 | `iso_27001.py` | Information security |
| CIS Controls | `cis_controls.py` | Security best practices |
| CMMC 2.0 | `cmmc.py` | Defense contractor practices |
| NIST 800-53 | `nist_800_53.py` | Federal security controls |
| FedRAMP Moderate | `fedramp.py` | Federal cloud baseline |
| PCI DSS | `pci_dss.py` | Payment data controls |

## Benchmark surfaces

| Benchmark | Module | Focus |
|-----------|--------|-------|
| OWASP AISVS v1.0 | `cloud/aisvs_benchmark.py` | AI security verification checks |

## Usage

```bash
# Single framework
agent-bom agents --compliance

# Compliance evidence export
agent-bom agents --compliance --compliance-export nist-ai-rmf
```

## CIS Benchmarks (cloud)

```bash
# AWS CIS Foundations v3.0
agent-bom cloud aws --cis

# Snowflake CIS v1.0
agent-bom agents --snowflake --snowflake-cis-benchmark
```

Requires cloud credentials (AWS_PROFILE or SNOWFLAKE_ACCOUNT/USER/PASSWORD).
