# Installing agent-bom as a Snowflake Native App

Run the entire agent-bom AI-supply-chain security stack inside your own Snowflake AI Data Cloud — no data leaves your account. This guide walks the install end-to-end, from manifest review through customer-bound table grants through dashboard access.

## What you get

- **15-framework compliance posture** — SOC 2, ISO 27001, FedRAMP, EU AI Act, NIST AI RMF, NIST CSF, OWASP LLM/MCP/Agentic, MITRE ATLAS, CIS Controls, CMMC, NIST 800-53, PCI DSS — automatically classifying findings from your existing scanner outputs
- **Inventory + blast radius** across structured cloud asset tables, semi-structured event JSON, and unstructured stages (notebooks, IaC, model artifacts, prompt corpora)
- **Wiz-shaped dashboard** — Next.js with React Flow graph viz, hosted on Snowpark Container Services inside your account
- **Audit log** with HMAC chain, OCSF-shaped events, customer-owned (we cannot read it)
- **Zero data egress by default** — only customer-approved advisory feeds (OSV / KEV / EPSS / GHSA) reach outbound

## Prerequisites

- Snowflake account on `STANDARD` edition or higher
- `ACCOUNTADMIN` role for the install + initial bindings (after install, app is operated by a less-privileged role)
- Optional: corporate VPN egress IP block(s) for the dashboard network policy

## 1 — Review the manifest

Before clicking install, review what agent-bom asks for:

- [`deploy/snowflake/native-app/manifest.yml`](../../deploy/snowflake/native-app/manifest.yml) — privileges, references, EAIs
- [`deploy/snowflake/native-app/scripts/setup.sql`](../../deploy/snowflake/native-app/scripts/setup.sql) — the install-time DDL
- [`deploy/snowflake/native-app/scripts/customer_grants_template.sql`](../../deploy/snowflake/native-app/scripts/customer_grants_template.sql) — the GRANTs you'll be asked to bind

The trust contract:

| What we ask for | What we DON'T ask for |
|---|---|
| `CREATE COMPUTE POOL` (run our containers) | USAGE on any of your databases |
| `CREATE SERVICE`, `BIND SERVICE ENDPOINT` | Schema-level grants |
| `SELECT` on tables YOU bind at install | Any write privilege on your tables |
| `READ` on stages YOU bind at install | `MANAGE GRANTS`, `ACCOUNTADMIN` access |
| Outbound HTTPS to OSV/KEV/EPSS/GHSA (per-EAI consent) | Any other outbound network |

## 2 — Install from the Marketplace

```sql
-- One-line Marketplace install (TBD once listing approved):
CALL SNOWFLAKE.LOCAL.NATIVE_APPS.INSTALL_FROM_MARKETPLACE('agent-bom');
```

Or manually via the dev path:

```sql
-- Upload the app package, create the application
CREATE APPLICATION PACKAGE agent_bom_pkg;
ALTER APPLICATION PACKAGE agent_bom_pkg ADD VERSION v0_85 USING '@agent_bom_stage/v0_85';
CREATE APPLICATION agent_bom FROM APPLICATION PACKAGE agent_bom_pkg USING VERSION v0_85;
```

## 3 — Bind your tables (the customer-approved access)

The install UI walks you through binding each `references:` declaration in the manifest to actual objects in your account:

| Reference | What it's for | Example bindings |
|---|---|---|
| `cloud_asset_tables` | Inventory + blast radius | `CLOUDQUERY.AWS_RESOURCES`, `CLOUDQUERY.AZURE_RESOURCES`, `CLOUDQUERY.GCP_RESOURCES`, `CLOUDQUERY.SNOWFLAKE_OBJECTS` |
| `iam_tables` | Credential blast radius | `CLOUDQUERY.AWS_IAM_USERS`, `CLOUDQUERY.AWS_IAM_ROLES`, `IDENTITY.SCIM_USERS` |
| `vuln_tables` | 15-framework re-classification of existing findings | `SECURITY.CSPM_FINDINGS`, `SECURITY.CONTAINER_VULNS`, `SECURITY.CODE_FINDINGS` |
| `log_tables` | (Optional) runtime correlation | `LOGS.OCSF_EVENTS`, `LOGS.AWS_CLOUDTRAIL`, `LOGS.SNOWFLAKE_QUERY_HISTORY` |
| `artifact_stages` | Notebook / IaC / model artifact scanning | `SCANS.NOTEBOOKS_STAGE`, `SCANS.IAC_STAGE`, `SCANS.MODEL_ARTIFACTS_STAGE` |

You bind only what you want agent-bom to see. Unbound references → that scan path is unavailable in the dashboard.

See [`customer_grants_template.sql`](../../deploy/snowflake/native-app/scripts/customer_grants_template.sql) for the canonical example.

## 4 — Approve the External Access Integrations (advisory feeds)

agent-bom needs OSV / KEV / EPSS / GHSA to enrich findings with vulnerability metadata. These are the **only** outbound calls; each is gated by a per-feed EAI you toggle in the install UI.

If you want fully air-gapped (no outbound network at all): leave all four EAIs OFF. agent-bom still scans + classifies; CVE enrichment is just less complete.

## 5 — (Recommended) Set a network policy

Restrict where the dashboard can be reached from. Templates in [`network_policies.sql`](../../deploy/snowflake/native-app/scripts/network_policies.sql):

```sql
-- Apply the recommended SOC default
@deploy/snowflake/native-app/scripts/network_policies.sql
ALTER APPLICATION agent_bom SET CONFIGURATION network_policy_name = 'AGENT_BOM_SOC_DEFAULT';
```

## 6 — (Optional) Set up a service user with key-pair auth

If you want to push scan data into the app from CI/CD or external orchestration, create a dedicated service user with key-pair auth. Template: [`auth_keypair_setup.sql`](../../deploy/snowflake/native-app/scripts/auth_keypair_setup.sql).

```bash
# Generate the key-pair locally
openssl genrsa -out agent_bom_svc_rsa.pem 2048
openssl rsa -in agent_bom_svc_rsa.pem -pubout -out agent_bom_svc_rsa.pub

# Run the setup script (paste the .pub contents into the script first)
snow sql -f deploy/snowflake/native-app/scripts/auth_keypair_setup.sql

# Test the connection
export SNOWFLAKE_USER=agent_bom_svc
export SNOWFLAKE_PRIVATE_KEY_PATH=/secrets/agent_bom_svc_rsa.pem
export SNOWFLAKE_ACCOUNT=<your_account>
agent-bom snowflake test-connection
```

## 7 — Trigger your first scan

```sql
-- Manual scan
CALL agent_bom.core.trigger_scan();

-- Or enable the auto-scan task (default 6h interval)
ALTER TASK agent_bom.core.auto_scan_task RESUME;
```

## 8 — Open the dashboard

The dashboard URL is exposed via the Native App's service endpoint. From Snowsight:

1. Apps → agent-bom → Services → `agent_bom_api`
2. Click the public URL
3. Authenticate with your Snowflake SSO

## What to verify after install

```sql
-- Confirm zero account-level grants leaked through
USE ROLE agent_bom.app_user;
SHOW GRANTS TO APPLICATION ROLE agent_bom.app_user;

-- Confirm the read-only contract on bound objects
SHOW GRANTS ON DATABASE YOUR_DB;  -- should show NO grants to APPLICATION agent_bom

-- Confirm EAI scope (only the four advisory feeds)
SHOW EXTERNAL ACCESS INTEGRATIONS LIKE 'AGENT_BOM_%';
```

## Uninstall

```sql
DROP APPLICATION agent_bom CASCADE;
DROP APPLICATION PACKAGE agent_bom_pkg;
```

This removes the app's compute pool, services, schemas, and all data agent-bom collected. **Customer-bound tables/stages are untouched** — they were never owned by the app.

## Related

- [Identity and naming contract](../IDENTITY_AND_NAMING_CONTRACT.md) — what's fixed vs customer-controlled
- [Policy precedence](../POLICY_PRECEDENCE.md) — firewall / gateway / proxy / CLI layering
- [Runtime reference](../RUNTIME_REFERENCE.md) — five runtime surfaces map
- Native App epic: [#2214](https://github.com/msaad00/agent-bom/issues/2214)
