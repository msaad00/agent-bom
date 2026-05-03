-- =============================================================================
-- agent-bom Native App: Customer-Approved GRANTs Template
-- =============================================================================
-- BEFORE installing agent-bom from the Marketplace, the customer DBA reviews
-- this script to see exactly what tables/stages the app will be able to read.
--
-- During install, the Native App's `references:` UI lets the customer bind
-- THESE objects (or their own equivalents) to the references declared in
-- manifest.yml. This script is the canonical example of what to bind.
--
-- agent-bom never receives:
--   • USAGE on a database
--   • Schema-level grants
--   • Any write privilege on customer tables
--   • Access to objects the customer hasn't explicitly bound
--
-- Run as ACCOUNTADMIN to verify what GRANTs would be issued. Comment lines
-- you don't want; uncomment what you do.
-- =============================================================================

-- ─── Identifying the application role agent-bom uses ─────────────────────────
-- Once installed, agent-bom's worker SQL runs under:
--   APPLICATION ROLE agent_bom.app_user
--
-- All GRANTs below should target this application role.

-- ─── 1. Cloud asset inventory tables ─────────────────────────────────────────
-- Bind these to the `cloud_asset_tables` reference in the install UI.
-- Replace YOUR_DB.YOUR_SCHEMA.* with the actual table names you've landed.
GRANT SELECT ON TABLE YOUR_DB.CLOUDQUERY.AWS_RESOURCES         TO APPLICATION agent_bom;
GRANT SELECT ON TABLE YOUR_DB.CLOUDQUERY.AZURE_RESOURCES       TO APPLICATION agent_bom;
GRANT SELECT ON TABLE YOUR_DB.CLOUDQUERY.GCP_RESOURCES         TO APPLICATION agent_bom;
GRANT SELECT ON TABLE YOUR_DB.CLOUDQUERY.SNOWFLAKE_OBJECTS     TO APPLICATION agent_bom;

-- ─── 2. IAM / identity tables ────────────────────────────────────────────────
-- Bind these to the `iam_tables` reference.
GRANT SELECT ON TABLE YOUR_DB.CLOUDQUERY.AWS_IAM_USERS         TO APPLICATION agent_bom;
GRANT SELECT ON TABLE YOUR_DB.CLOUDQUERY.AWS_IAM_ROLES         TO APPLICATION agent_bom;
GRANT SELECT ON TABLE YOUR_DB.CLOUDQUERY.AWS_IAM_POLICIES      TO APPLICATION agent_bom;
GRANT SELECT ON TABLE YOUR_DB.IDENTITY.AZURE_AD_USERS          TO APPLICATION agent_bom;
GRANT SELECT ON TABLE YOUR_DB.IDENTITY.SCIM_USERS              TO APPLICATION agent_bom;

-- ─── 3. Vulnerability / scanner output tables ────────────────────────────────
-- Bind these to the `vuln_tables` reference. Anything you've landed from
-- existing CSPM / container-scan / code-scan / SIEM tooling.
GRANT SELECT ON TABLE YOUR_DB.SECURITY.CSPM_FINDINGS           TO APPLICATION agent_bom;
GRANT SELECT ON TABLE YOUR_DB.SECURITY.CONTAINER_VULNS         TO APPLICATION agent_bom;
GRANT SELECT ON TABLE YOUR_DB.SECURITY.CODE_FINDINGS           TO APPLICATION agent_bom;

-- ─── 4. Event / log tables (optional) ────────────────────────────────────────
-- Bind these to the `log_tables` reference. Only needed if you want
-- runtime-correlation (set enable_runtime_correlation = true in app config).
-- GRANT SELECT ON TABLE YOUR_DB.LOGS.OCSF_EVENTS              TO APPLICATION agent_bom;
-- GRANT SELECT ON TABLE YOUR_DB.LOGS.AWS_CLOUDTRAIL           TO APPLICATION agent_bom;
-- GRANT SELECT ON TABLE YOUR_DB.LOGS.SNOWFLAKE_QUERY_HISTORY  TO APPLICATION agent_bom;

-- ─── 5. Stages with unstructured artifacts ───────────────────────────────────
-- Bind these to the `artifact_stages` reference. agent-bom uses the same
-- IaC, notebook, dataset-card, and skill parsers it uses on local filesystems
-- — only here the input is a Snowflake stage.
GRANT READ ON STAGE YOUR_DB.SCANS.NOTEBOOKS_STAGE              TO APPLICATION agent_bom;
GRANT READ ON STAGE YOUR_DB.SCANS.IAC_STAGE                    TO APPLICATION agent_bom;
GRANT READ ON STAGE YOUR_DB.SCANS.MODEL_ARTIFACTS_STAGE        TO APPLICATION agent_bom;
GRANT READ ON STAGE YOUR_DB.SCANS.PROMPT_CORPORA_STAGE         TO APPLICATION agent_bom;

-- ─── 6. Verify what agent-bom CAN see ────────────────────────────────────────
-- After install + binding, run as the application role to confirm the
-- least-privilege contract:
--   USE ROLE agent_bom.app_user;
--   SHOW GRANTS TO APPLICATION ROLE agent_bom.app_user;
--
-- Expected: SELECT on bound tables, READ on bound stages, USAGE on the
-- application's own schemas. NO usage on YOUR_DB, NO grants on unbound
-- objects, NO write privileges anywhere outside the app's own schema.
-- =============================================================================
