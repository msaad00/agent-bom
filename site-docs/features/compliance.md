# Compliance Frameworks

agent-bom maps scan findings to 10 security and compliance frameworks.

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

## Usage

```bash
# Single framework
agent-bom scan --compliance owasp-llm

# Multiple frameworks
agent-bom scan --compliance owasp-llm,eu-ai-act

# All frameworks
agent-bom scan --compliance all
```

## CIS Benchmarks (cloud)

```bash
# AWS CIS Foundations v3.0
agent-bom cis-benchmark --provider aws

# Snowflake CIS v1.0
agent-bom cis-benchmark --provider snowflake
```

Requires cloud credentials (AWS_PROFILE or SNOWFLAKE_ACCOUNT/USER/PASSWORD).
