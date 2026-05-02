---
name: agent-bom-discover-gcp
description: >-
  Discover GCP-hosted AI agent and MCP-relevant assets from the operator's
  environment, emit canonical agent-bom inventory JSON, and scan it without
  giving agent-bom long-lived GCP credentials. Use when a user asks to
  inventory Vertex AI, Cloud Run, Cloud Functions, GKE, or agentic GCP
  infrastructure as canonical inventory.
version: 0.84.6
license: Apache-2.0
compatibility: >-
  Requires Python 3.11+, agent-bom installed from this repository or PyPI, and
  operator-controlled GCP read-only credentials from ADC, workload identity, or
  a scoped service account.
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
      credentials: gcp-read-only
    credential_policy: "Use the operator's existing Application Default Credentials, workload identity, or short-lived service account credentials. Do not ask users to paste service account JSON into chat. Do not print credential values."
    optional_env:
      - GOOGLE_APPLICATION_CREDENTIALS
      - GOOGLE_CLOUD_PROJECT
      - CLOUDSDK_CONFIG
    optional_bins:
      - gcloud
    emoji: "search"
    homepage: https://github.com/msaad00/agent-bom
    source: https://github.com/msaad00/agent-bom
    license: Apache-2.0
    os:
      - darwin
      - linux
      - windows
    credential_handling: "Credentials stay in the operator environment. The skill invokes GCP SDK discovery locally and writes canonical inventory JSON with source_type=skill_invoked_pull. agent-bom receives sanitized inventory only when the operator explicitly scans or pushes that inventory."
    data_flow: "Operator GCP project -> read-only Google API calls -> canonical inventory JSON -> optional local agent-bom inventory scan. No agent-bom-hosted service is required. Credential-like values are redacted before persistence/export."
    file_reads:
      - "~/.config/gcloud/configurations/config_default"
      - "~/.config/gcloud/application_default_credentials.json"
      - "~/.config/gcloud/credentials.db"
      - "operator-selected service account JSON when GOOGLE_APPLICATION_CREDENTIALS is set"
    file_writes:
      - "operator-selected inventory JSON output path"
    network_endpoints:
      - url: "https://cloudresourcemanager.googleapis.com"
        purpose: "Project and resource inventory"
        auth: true
      - url: "https://aiplatform.googleapis.com"
        purpose: "Vertex AI inventory"
        auth: true
      - url: "https://run.googleapis.com"
        purpose: "Cloud Run inventory"
        auth: true
      - url: "https://cloudfunctions.googleapis.com"
        purpose: "Cloud Functions inventory"
        auth: true
      - url: "https://container.googleapis.com"
        purpose: "GKE inventory"
        auth: true
    telemetry: false
    persistence: false
    privilege_escalation: false
    always: false
    autonomous_invocation: restricted
---

# agent-bom-discover-gcp

Use this skill to collect GCP AI and workload inventory as schema-valid
agent-bom inventory. Default to discover-only: write JSON to an
operator-selected path and stop.

## Guardrails

- Use only operator-approved projects and read-only credentials.
- Do not request or display service account private keys, OAuth refresh tokens,
  or bearer tokens.
- Do not modify GCP resources. This workflow is discovery-only.
- Write inventory only to a path the operator chose.
- Treat AI-generated prose as non-authoritative; schema-validated inventory JSON
  is the evidence.

## Workflow

```bash
python examples/operator_pull/gcp_inventory_adapter.py \
  --project "$GOOGLE_CLOUD_PROJECT" \
  --region us-central1 \
  --source gcp-skill-invoked \
  --discovery-method skill_invoked_pull \
  --output gcp-inventory.json
```

Scan only when the operator asks for findings:

```bash
agent-bom agents --inventory gcp-inventory.json --format json --output agent-bom-gcp-findings.json
```

## Evidence Contract

The emitted inventory carries `discovery_provenance.source_type:
skill_invoked_pull`, `observed_via: skill_invoked_pull, gcp_sdk`, sanitized
`metadata.permissions_used`, and redacted credential material. If schema
validation fails, stop and fix the inventory instead of scanning a best-effort
summary.
