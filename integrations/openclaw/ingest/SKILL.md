---
name: agent-bom-ingest
description: >-
  Validate and ingest operator-pushed agent-bom inventory JSON from AWS, Azure,
  GCP, Snowflake, CMDB, or endpoint collectors. Use when a user has canonical
  inventory JSON and wants local findings, graph, policy, provenance, or
  auditor-ready exports without giving agent-bom direct cloud credentials.
version: 0.83.4
license: Apache-2.0
compatibility: >-
  Requires Python 3.11+ and agent-bom 0.83.4+. Inventory must conform to the
  packaged inventory.schema.json contract.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/agent-bom
  source: https://github.com/msaad00/agent-bom
  pypi: https://pypi.org/project/agent-bom/
  openclaw:
    requires:
      bins:
        - agent-bom
      env: []
      credentials: none
    credential_policy: "No cloud credentials are required. Optional control-plane push uses an operator-provided agent-bom API token; never ask users to paste that token into chat and never print it."
    optional_env:
      - AGENT_BOM_API_KEY
      - AGENT_BOM_PUSH_URL
    optional_bins: []
    emoji: "inbox"
    homepage: https://github.com/msaad00/agent-bom
    source: https://github.com/msaad00/agent-bom
    license: Apache-2.0
    os:
      - darwin
      - linux
      - windows
    credential_handling: "Inventory is schema-validated before it is trusted. Env var values, URL credentials, launch arguments, discovery_provenance, permissions_used, and security intelligence pass through the sanitizer/redaction contract before display/export."
    data_flow: "Operator-generated inventory JSON -> packaged inventory.schema.json validation -> local agent-bom scan/graph/export. Optional push to an operator-owned control plane goes only to the URL the operator provided."
    file_reads:
      - "operator-selected inventory JSON file"
      - "packaged agent_bom/data/inventory.schema.json"
    file_writes:
      - "operator-selected JSON/SARIF/HTML/Markdown export path"
    network_endpoints:
      - url: "operator-provided AGENT_BOM_PUSH_URL"
        purpose: "Optional push into the operator-owned agent-bom control plane"
        auth: true
        optional: true
      - url: "https://api.osv.dev/v1"
        purpose: "Optional package vulnerability lookup during local scan"
        auth: false
        optional: true
      - url: "https://api.github.com/advisories"
        purpose: "Optional GitHub Advisory enrichment during local scan"
        auth: false
        optional: true
    telemetry: false
    persistence: false
    privilege_escalation: false
    always: false
    autonomous_invocation: restricted
---

# agent-bom-ingest

Use this skill when the operator already produced canonical inventory JSON with
an operator-pull adapter, endpoint collector, CMDB export, or AI-agent workflow.
The default path is local validation plus local scan/export.

## Guardrails

- Validate inventory with the packaged schema before treating it as evidence.
- Require `discovery_provenance` and `permissions_used` where the source claims
  cloud/operator-pushed discovery.
- Require a trustworthy `discovery_provenance.source_type` such as
  `operator_pushed_inventory` or `skill_invoked_pull`; do not infer it from
  prose.
- Do not invent provenance, permissions, cloud scopes, or credential posture.
- Do not push to a control plane unless the operator provides the destination
  URL and auth method explicitly.
- Do not print raw tokens, URL credentials, private keys, or env var values.

## Workflow

Validate first:

```bash
agent-bom inventory validate inventory.json
```

Scan locally:

```bash
agent-bom agents --inventory inventory.json --format json --output agent-bom-findings.json
```

Choose output by consumer:

- SARIF for CI/code-scanning gates
- JSON for graph, API, and automation
- HTML or Markdown for human review
- CycloneDX/SPDX for SBOM consumers

## Evidence Contract

Valid inventory preserves `discovery_provenance`, `permissions_used`,
`cloud_origin`, redaction state, package identity, server identity, tools, and
security intelligence. If the inventory is malformed or missing required trust
fields, stop and ask the operator to regenerate it rather than scanning a
best-effort summary.
