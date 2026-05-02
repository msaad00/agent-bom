---
name: agent-bom-discover-azure
description: >-
  Discover Azure-hosted AI agent and MCP-relevant assets from the operator's
  environment, emit canonical agent-bom inventory JSON, and scan it without
  giving agent-bom long-lived Azure credentials. Use when a user asks to
  inventory Azure OpenAI, Container Apps, AKS, Functions, ML, or agentic Azure
  infrastructure as canonical inventory.
version: 0.84.6
license: Apache-2.0
compatibility: >-
  Requires Python 3.11+, agent-bom installed from this repository or PyPI, and
  operator-controlled Azure read-only credentials from Azure CLI, workload
  identity, managed identity, or service principal.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/agent-bom
  source: https://github.com/msaad00/agent-bom
  pypi: https://pypi.org/project/agent-bom/
  openclaw:
    requires:
      bins:
        - python
      env: []
      credentials: azure-read-only
    credential_policy: "Use the operator's existing Azure identity chain. Prefer Azure CLI, workload identity, managed identity, or short-lived service principal credentials. Do not ask users to paste client secrets. Do not print credential values."
    optional_env:
      - AZURE_SUBSCRIPTION_ID
      - AZURE_TENANT_ID
      - AZURE_CLIENT_ID
      - AZURE_CLIENT_SECRET
      - AZURE_AUTHORITY_HOST
    optional_bins:
      - az
    emoji: "search"
    homepage: https://github.com/msaad00/agent-bom
    source: https://github.com/msaad00/agent-bom
    license: Apache-2.0
    os:
      - darwin
      - linux
      - windows
    credential_handling: "Credentials stay in the operator environment. The skill invokes Azure SDK discovery locally and writes canonical inventory JSON with source_type=skill_invoked_pull. agent-bom receives sanitized inventory only when the operator explicitly scans or pushes that inventory."
    data_flow: "Operator Azure subscription -> read-only Azure SDK calls -> canonical inventory JSON -> optional local agent-bom inventory scan. No agent-bom-hosted service is required. Credential-like values are redacted before persistence/export."
    file_reads:
      - "~/.azure/azureProfile.json"
      - "~/.azure/config"
      - "~/.azure/msal_token_cache.json"
    file_writes:
      - "operator-selected inventory JSON output path"
    network_endpoints:
      - url: "https://login.microsoftonline.com"
        purpose: "Azure identity token exchange when the selected credential flow needs it"
        auth: true
      - url: "https://management.azure.com"
        purpose: "Azure Resource Manager and service inventory"
        auth: true
      - url: "https://*.cognitiveservices.azure.com"
        purpose: "Azure AI and OpenAI service metadata where available"
        auth: true
    telemetry: false
    persistence: false
    privilege_escalation: false
    always: false
    autonomous_invocation: restricted
---

# agent-bom-discover-azure

Use this skill to collect Azure AI and workload inventory as schema-valid
agent-bom inventory. Default to discover-only: write JSON to an
operator-selected path and stop.

## Guardrails

- Use only operator-approved Azure subscriptions and read-only identities.
- Do not request or display raw `AZURE_CLIENT_SECRET`, access tokens, or
  connection strings.
- Do not modify Azure resources. This workflow is discovery-only.
- Write inventory only to a path the operator chose.
- Treat AI-generated prose as non-authoritative; schema-validated inventory JSON
  is the evidence.

## Workflow

```bash
python examples/operator_pull/azure_inventory_adapter.py \
  --subscription-id "$AZURE_SUBSCRIPTION_ID" \
  --source azure-skill-invoked \
  --discovery-method skill_invoked_pull \
  --output azure-inventory.json
```

Scan only when the operator asks for findings:

```bash
agent-bom agents --inventory azure-inventory.json --format json --output agent-bom-azure-findings.json
```

## Evidence Contract

The emitted inventory carries `discovery_provenance.source_type:
skill_invoked_pull`, `observed_via: skill_invoked_pull, azure_sdk`, sanitized
`metadata.permissions_used`, and redacted credential material. If schema
validation fails, stop and fix the inventory instead of scanning a best-effort
summary.
