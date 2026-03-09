---
name: agent-bom-compliance
description: >-
  AI compliance and policy engine — evaluate scan results against OWASP LLM Top 10,
  MITRE ATLAS, EU AI Act, NIST AI RMF, and custom policy-as-code rules. Generate
  SBOMs in CycloneDX or SPDX format. Use when the user mentions compliance checking,
  security policy enforcement, SBOM generation, or regulatory frameworks.
version: 0.63.2
license: Apache-2.0
compatibility: >-
  Requires Python 3.11+. Install via pipx or pip. No credentials required for
  OWASP/NIST/EU AI Act evaluation. CIS benchmark checks optionally use cloud
  SDK credentials (AWS/Azure/GCP/Snowflake) if provided.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/agent-bom
  source: https://github.com/msaad00/agent-bom
  pypi: https://pypi.org/project/agent-bom/
  scorecard: https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom
  tests: 3480
  install:
    pipx: agent-bom
    pip: agent-bom
  openclaw:
    requires:
      bins: []
      env: []
      credentials: none
    credential_policy: "Zero credentials required for OWASP/NIST/EU AI Act compliance and SBOM generation. CIS benchmark checks (AWS, Azure, GCP, Snowflake) optionally accept cloud credentials — only used locally to call cloud APIs, never transmitted elsewhere."
    optional_env:
      - name: AWS_PROFILE
        purpose: "AWS CIS benchmark checks — uses boto3 with your local AWS profile"
        required: false
      - name: AZURE_TENANT_ID
        purpose: "Azure CIS benchmark checks (azure-mgmt-* SDK)"
        required: false
      - name: AZURE_CLIENT_ID
        purpose: "Azure CIS benchmark checks — service principal client ID"
        required: false
      - name: AZURE_CLIENT_SECRET
        purpose: "Azure CIS benchmark checks — service principal secret"
        required: false
      - name: GOOGLE_APPLICATION_CREDENTIALS
        purpose: "GCP CIS benchmark checks (google-cloud-* SDK)"
        required: false
      - name: SNOWFLAKE_ACCOUNT
        purpose: "Snowflake CIS benchmark checks"
        required: false
      - name: SNOWFLAKE_USER
        purpose: "Snowflake CIS benchmark checks"
        required: false
      - name: SNOWFLAKE_PASSWORD
        purpose: "Snowflake CIS benchmark checks"
        required: false
    optional_bins: []
    emoji: "\U00002705"
    homepage: https://github.com/msaad00/agent-bom
    source: https://github.com/msaad00/agent-bom
    license: Apache-2.0
    os:
      - darwin
      - linux
      - windows
    data_flow: "Purely local for OWASP/NIST/EU AI Act/MITRE/SBOM features. CIS benchmark checks call cloud provider APIs (AWS/Azure/GCP/Snowflake) using locally configured credentials — no data is stored or transmitted beyond the cloud provider's own API. Zero file reads beyond user-provided SBOMs."
    file_reads:
      - "user-provided SBOM files (CycloneDX/SPDX JSON)"
      - "user-provided policy files (YAML/JSON policy-as-code)"
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
- **CIS Foundations** — AWS, Azure v3.0, GCP v3.0, Snowflake benchmarks

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
- **3,400+ tests** with CodeQL + OpenSSF Scorecard
- **No telemetry**: Zero tracking, zero analytics
