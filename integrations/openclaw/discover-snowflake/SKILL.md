---
name: agent-bom-discover-snowflake
description: >-
  Discover Snowflake Cortex, Snowpark, notebook, Streamlit, MCP, and
  AI-observability assets from the operator's environment, emit canonical
  agent-bom inventory JSON, and scan it without giving agent-bom long-lived
  Snowflake credentials. Use when a user asks to inventory Snowflake AI or
  Cortex infrastructure as canonical inventory.
version: 0.86.0
license: Apache-2.0
compatibility: >-
  Requires Python 3.11+, agent-bom installed with the snowflake extra, and
  operator-controlled Snowflake read-only credentials. Prefer SSO, OAuth, or
  key-pair auth over passwords.
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
      credentials: snowflake-read-only
    credential_policy: "Use the operator's existing Snowflake SSO, OAuth, or key-pair auth context. Prefer SNOWFLAKE_PRIVATE_KEY_PATH or SNOWFLAKE_AUTHENTICATOR over SNOWFLAKE_PASSWORD. Do not ask users to paste passwords, private keys, or OAuth tokens into chat."
    optional_env:
      - SNOWFLAKE_ACCOUNT
      - SNOWFLAKE_USER
      - SNOWFLAKE_AUTHENTICATOR
      - SNOWFLAKE_PRIVATE_KEY_PATH
      - SNOWFLAKE_PRIVATE_KEY_PASSPHRASE
      - SNOWFLAKE_TOKEN
      - SNOWFLAKE_WAREHOUSE
      - SNOWFLAKE_DATABASE
      - SNOWFLAKE_SCHEMA
      - SNOWFLAKE_ROLE
    optional_bins:
      - snow
      - snowsql
    emoji: "search"
    homepage: https://github.com/msaad00/agent-bom
    source: https://github.com/msaad00/agent-bom
    license: Apache-2.0
    os:
      - darwin
      - linux
      - windows
    credential_handling: "Credentials stay in the operator environment. The skill invokes Snowflake discovery locally and writes canonical inventory JSON with source_type=skill_invoked_pull. agent-bom receives sanitized inventory only when the operator explicitly scans or pushes that inventory."
    data_flow: "Operator Snowflake account -> read-only Snowflake queries/API calls -> canonical inventory JSON -> optional local agent-bom inventory scan. No agent-bom-hosted service is required. Credential-like values are redacted before persistence/export."
    file_reads:
      - "~/.snowflake/connections.toml"
      - "~/.snowflake/config.toml"
      - "operator-selected private key path when SNOWFLAKE_PRIVATE_KEY_PATH is set"
    file_writes:
      - "operator-selected inventory JSON output path"
    network_endpoints:
      - url: "https://{account}.snowflakecomputing.com"
        purpose: "Snowflake inventory, Cortex, query history, and AI observability discovery"
        auth: true
      - url: "https://*.snowflakecomputing.com"
        purpose: "Snowflake regional and organization account endpoints selected by the operator"
        auth: true
    telemetry: false
    persistence: false
    privilege_escalation: false
    always: false
    autonomous_invocation: restricted
---

# agent-bom-discover-snowflake

Use this skill to collect Snowflake AI and workload inventory as schema-valid
agent-bom inventory. Default to discover-only: write JSON to an
operator-selected path and stop.

## Guardrails

- Use only operator-approved Snowflake accounts, warehouses, databases, and
  read-only roles.
- Prefer SSO, OAuth, or key-pair auth. Do not request or display
  `SNOWFLAKE_PASSWORD`, private key contents, passphrases, or OAuth tokens.
- Do not modify Snowflake resources. This workflow is discovery-only.
- Write inventory only to a path the operator chose.
- Treat AI-generated prose as non-authoritative; schema-validated inventory JSON
  is the evidence.

## Workflow

```bash
python examples/operator_pull/snowflake_inventory_adapter.py \
  --account "$SNOWFLAKE_ACCOUNT" \
  --user "$SNOWFLAKE_USER" \
  --authenticator snowflake_jwt \
  --source snowflake-skill-invoked \
  --discovery-method skill_invoked_pull \
  --output snowflake-inventory.json
```

Scan only when the operator asks for findings:

```bash
agent-bom agents --inventory snowflake-inventory.json --format json --output agent-bom-snowflake-findings.json
```

## Evidence Contract

The emitted inventory carries `discovery_provenance.source_type:
skill_invoked_pull`, `observed_via: skill_invoked_pull, snowflake_sdk`,
sanitized `metadata.permissions_used`, and redacted credential material. If
schema validation fails, stop and fix the inventory instead of scanning a
best-effort summary.
