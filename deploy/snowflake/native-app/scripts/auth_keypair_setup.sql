-- =============================================================================
-- agent-bom Native App: Service-User Key-Pair Auth Setup
-- =============================================================================
-- Out-of-box script for the customer to create a dedicated service user that
-- can push scan data into the agent-bom Native App from CLI tooling, CI/CD,
-- or external orchestration.
--
-- Snowflake recommends key-pair auth for service users (no password rotation,
-- no MFA prompts, audit-trail friendly). This script creates one such user
-- with the minimum role set the agent-bom CLI needs.
--
-- Run as ACCOUNTADMIN. Replace placeholders before executing.
--
-- Generate the key-pair locally first (one-time):
--   openssl genrsa -out agent_bom_svc_rsa.pem 2048
--   openssl rsa -in agent_bom_svc_rsa.pem -pubout -out agent_bom_svc_rsa.pub
--   # Strip the BEGIN/END markers + newlines from the .pub file when pasting below
-- =============================================================================

-- ─── 1. Service role (least privilege) ───────────────────────────────────────
CREATE ROLE IF NOT EXISTS agent_bom_svc_role
    COMMENT = 'agent-bom service role — pushes scan data into the Native App';

-- agent-bom Native App grants APPLICATION ROLE app_user to this role.
-- (Run AFTER installing the app from the Marketplace.)
-- GRANT APPLICATION ROLE agent_bom.app_user TO ROLE agent_bom_svc_role;

-- ─── 2. Service user with key-pair auth ──────────────────────────────────────
CREATE USER IF NOT EXISTS agent_bom_svc
    LOGIN_NAME = 'agent_bom_svc'
    DISPLAY_NAME = 'agent-bom service'
    DEFAULT_ROLE = agent_bom_svc_role
    DEFAULT_WAREHOUSE = COMPUTE_WH
    -- Paste the contents of agent_bom_svc_rsa.pub between the markers
    -- (without BEGIN/END lines and with newlines stripped):
    RSA_PUBLIC_KEY = '<PASTE_BASE64_PUBLIC_KEY_HERE>'
    -- Optional: pre-stage the second key for zero-downtime rotation
    -- RSA_PUBLIC_KEY_2 = '<PASTE_NEXT_KEY_FOR_ROTATION>'
    MUST_CHANGE_PASSWORD = FALSE
    DISABLED = FALSE
    COMMENT = 'agent-bom service user — key-pair auth only, no password';

GRANT ROLE agent_bom_svc_role TO USER agent_bom_svc;

-- ─── 3. Bind the service user to a network policy (recommended) ──────────────
-- Restricts where the service can authenticate from. Combine with
-- network_policies.sql templates above.
-- ALTER USER agent_bom_svc SET NETWORK_POLICY = AGENT_BOM_SOC_DEFAULT;

-- ─── 4. Audit + verification ─────────────────────────────────────────────────
-- Verify the service user was created with key-pair auth:
SHOW USERS LIKE 'agent_bom_svc';
DESC USER agent_bom_svc;

-- Verify role grants:
SHOW GRANTS TO USER agent_bom_svc;
SHOW GRANTS TO ROLE agent_bom_svc_role;

-- ─── 5. CLI connection test ──────────────────────────────────────────────────
-- From the agent-bom CLI (run on a machine with the private key):
--   export SNOWFLAKE_USER=agent_bom_svc
--   export SNOWFLAKE_PRIVATE_KEY_PATH=/secrets/agent_bom_svc_rsa.pem
--   export SNOWFLAKE_ACCOUNT=<your_account>
--   agent-bom snowflake test-connection
--
-- Successful connect prints:
--   ✓ key-pair auth: agent_bom_svc -> agent_bom_svc_role
--   ✓ Native App reachable: agent_bom (v0.85.0)
--   ✓ app_user role granted
-- =============================================================================
