---
name: agent-bom-compliance
description: >-
  AI compliance and policy engine — evaluate scan results against OWASP LLM Top 10,
  MITRE ATLAS, EU AI Act, NIST AI RMF, and custom policy-as-code rules. Generate
  SBOMs in CycloneDX or SPDX format. Use when the user mentions compliance checking,
  security policy enforcement, SBOM generation, or regulatory frameworks.
version: 0.59.3
license: Apache-2.0
compatibility: >-
  Requires Python 3.11+. Install via pipx or pip. No external dependencies,
  API keys, or network access required.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/agent-bom
  source: https://github.com/msaad00/agent-bom
  pypi: https://pypi.org/project/agent-bom/
  scorecard: https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom
  tests: 6194
  install:
    pipx: agent-bom
    pip: agent-bom
  openclaw:
    requires:
      bins: []
      env: []
      credentials: none
    credential_policy: "Zero credentials required. All compliance evaluation runs locally on scan data already in memory."
    optional_env: []
    optional_bins: []
    emoji: "\U00002705"
    homepage: https://github.com/msaad00/agent-bom
    source: https://github.com/msaad00/agent-bom
    license: Apache-2.0
    os:
      - darwin
      - linux
      - windows
    data_flow: "Purely local. Evaluates scan results already in memory against bundled compliance rules. Zero network calls, zero file reads beyond user-provided SBOMs."
    file_reads:
      - "user-provided SBOM files (CycloneDX/SPDX JSON)"
    file_writes: []
    network_endpoints: []
    telemetry: false
    persistence: false
    privilege_escalation: false
    always: false
    autonomous_invocation: restricted
---

# agent-bom-compliance — AI Compliance & Policy Engine

Evaluate AI infrastructure scan results against security frameworks and enforce
policy-as-code rules. Generate SBOMs in standard formats.

## Install

```bash
pipx install agent-bom
agent-bom compliance        # run compliance check on latest scan
agent-bom generate-sbom     # generate CycloneDX SBOM
```

## Tools (4)

| Tool | Description |
|------|-------------|
| `compliance` | OWASP LLM/Agentic Top 10, EU AI Act, MITRE ATLAS, NIST AI RMF |
| `policy_check` | Evaluate results against custom security policy (17 conditions) |
| `cis_benchmark` | Run CIS benchmark checks against cloud accounts |
| `generate_sbom` | Generate SBOM (CycloneDX or SPDX format) |

## Supported Frameworks

- **OWASP LLM Top 10** (2025) — prompt injection, supply chain, data leakage
- **OWASP Agentic Top 10** — tool poisoning, rug pulls, credential theft
- **MITRE ATLAS** — adversarial ML threat framework
- **EU AI Act** — risk classification, transparency, SBOM requirements
- **NIST AI RMF** — govern, map, measure, manage lifecycle
- **CIS Foundations** — AWS and Snowflake benchmarks

## Example Workflows

```
# Run compliance check
compliance(frameworks=["owasp_llm", "eu_ai_act"])

# Enforce custom policy
policy_check(policy={"max_critical": 0, "max_high": 5})

# Generate SBOM
generate_sbom(format="cyclonedx")
```

## Privacy & Data Handling

All compliance evaluation runs **locally on scan data already in memory**.
No files are read from disk (except user-provided SBOMs). No network calls.
No credentials needed.

## Verification

- **Source**: [github.com/msaad00/agent-bom](https://github.com/msaad00/agent-bom) (Apache-2.0)
- **6,100+ tests** with CodeQL + OpenSSF Scorecard
- **No telemetry**: Zero tracking, zero analytics
