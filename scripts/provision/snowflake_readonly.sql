-- agent-bom Snowflake read-only provisioning script
-- Zero write access. Metadata only. Customer data rows never read.
--
-- Run as ACCOUNTADMIN (one-time setup by your Snowflake admin).
-- agent-bom never executes this script — your admin reviews and runs it.
--
-- Docs:
--   https://docs.snowflake.com/en/user-guide/security-access-control-overview
--   https://docs.snowflake.com/en/user-guide/key-pair-auth
--   https://docs.snowflake.com/en/user-guide/oauth-intro

-- ─── Step 1: Create the scanner role ────────────────────────────────────────
CREATE ROLE IF NOT EXISTS AGENT_BOM_READONLY
  COMMENT = 'Read-only role for agent-bom AI infrastructure security scanning';

-- ─── Step 2: Grant read access to Snowflake metadata views ──────────────────
-- IMPORTED PRIVILEGES on the SNOWFLAKE DB gives access to:
--   ACCOUNT_USAGE.QUERY_HISTORY          → activity timeline
--   ACCOUNT_USAGE.ACCESS_HISTORY         → governance audit
--   ACCOUNT_USAGE.GRANTS_TO_ROLES        → privilege analysis
--   ACCOUNT_USAGE.FUNCTIONS              → UDF discovery
--   ACCOUNT_USAGE.PROCEDURES             → stored proc discovery
--   ACCOUNT_USAGE.CORTEX_AGENT_REGISTRY  → Cortex agent inventory
--   ACCOUNT_USAGE.CORTEX_AGENT_USAGE_HISTORY → observability/health
--   INFORMATION_SCHEMA.*                 → package metadata, notebook cells
-- No customer warehouse data is accessible via these views.
GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE AGENT_BOM_READONLY;

-- ─── Step 3: Create the service account user (no password — key-pair only) ──
CREATE USER IF NOT EXISTS AGENT_BOM_SVC
  DEFAULT_ROLE = AGENT_BOM_READONLY
  DEFAULT_WAREHOUSE = AGENT_BOM_WH
  COMMENT = 'agent-bom read-only scan service account — no password, key-pair auth only'
  DISABLED = FALSE;

GRANT ROLE AGENT_BOM_READONLY TO USER AGENT_BOM_SVC;

-- ─── Step 4: Register the public key (key-pair auth — no password ever) ─────
-- Generate your key pair locally (never share the private key):
--
--   openssl genrsa -out ~/.snowflake/agent_bom_key.p8 2048
--   openssl rsa -in ~/.snowflake/agent_bom_key.p8 -pubout -out agent_bom_key.pub
--   # Copy the content of agent_bom_key.pub (without -----BEGIN/END----- lines)
--
-- Then register:
ALTER USER AGENT_BOM_SVC SET RSA_PUBLIC_KEY='<PASTE_PUBLIC_KEY_CONTENT_HERE>';

-- Key rotation (zero-downtime):
--   ALTER USER AGENT_BOM_SVC SET RSA_PUBLIC_KEY_2='<NEW_KEY>';   -- register new
--   ALTER USER AGENT_BOM_SVC UNSET RSA_PUBLIC_KEY;               -- retire old
--   ALTER USER AGENT_BOM_SVC SET RSA_PUBLIC_KEY='<NEW_KEY>';     -- promote
--   ALTER USER AGENT_BOM_SVC UNSET RSA_PUBLIC_KEY_2;             -- clean up

-- ─── Step 5: (Optional) Restrict access by IP ────────────────────────────────
-- Replace with your CI/CD runner IP range or office egress IPs.
CREATE NETWORK POLICY IF NOT EXISTS AGENT_BOM_NETWORK_POLICY
  ALLOWED_IP_LIST = ('10.0.0.0/8')   -- replace with your IPs
  COMMENT = 'Restrict agent-bom scanner to known egress IPs';

ALTER USER AGENT_BOM_SVC SET NETWORK_POLICY = AGENT_BOM_NETWORK_POLICY;

-- ─── Step 6: (Optional) Create a minimal warehouse ───────────────────────────
-- XS warehouse, auto-suspend after 60 seconds of inactivity.
CREATE WAREHOUSE IF NOT EXISTS AGENT_BOM_WH
  WAREHOUSE_SIZE = XSMALL
  AUTO_SUSPEND = 60
  AUTO_RESUME = TRUE
  INITIALLY_SUSPENDED = TRUE
  COMMENT = 'agent-bom scan warehouse — XS, auto-suspend 60s';

GRANT USAGE ON WAREHOUSE AGENT_BOM_WH TO ROLE AGENT_BOM_READONLY;

-- ─── Usage ───────────────────────────────────────────────────────────────────
-- Run the scanner with key-pair auth (no password):
--
--   export SNOWFLAKE_ACCOUNT=myorg-myaccount
--   export SNOWFLAKE_USER=AGENT_BOM_SVC
--   export SNOWFLAKE_PRIVATE_KEY_PATH=~/.snowflake/agent_bom_key.p8
--   agent-bom scan --snowflake --snowflake-cis-benchmark --cortex-observability
--
-- Or with SSO (browser popup, no stored credentials):
--   export SNOWFLAKE_ACCOUNT=myorg-myaccount
--   export SNOWFLAKE_USER=you@company.com
--   export SNOWFLAKE_AUTHENTICATOR=externalbrowser
--   agent-bom scan --snowflake

-- ─── Revocation ──────────────────────────────────────────────────────────────
-- Instantly revoke all access:
--   ALTER USER AGENT_BOM_SVC SET DISABLED = TRUE;
--   REVOKE ROLE AGENT_BOM_READONLY FROM USER AGENT_BOM_SVC;
