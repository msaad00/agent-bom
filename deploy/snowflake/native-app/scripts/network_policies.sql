-- =============================================================================
-- agent-bom Native App: Network Policy Templates
-- =============================================================================
-- Out-of-box recommendations for restricting where the agent-bom dashboard +
-- API endpoints can be reached from. Run as ACCOUNTADMIN BEFORE installing
-- the app, then set `network_policy_name` in the app's configuration to bind.
--
-- Snowflake docs: https://docs.snowflake.com/en/user-guide/network-policies
-- =============================================================================

-- ─── Template 1 — corporate VPN only ─────────────────────────────────────────
-- Replace the placeholder ranges with your corporate egress IP block.
-- Most enterprises route security tooling through VPN; least-privilege default.
CREATE OR REPLACE NETWORK POLICY agent_bom_vpn_only
    ALLOWED_IP_LIST = (
        '203.0.113.0/24'      -- example: corporate VPN egress (RFC 5737 placeholder)
        -- ,'198.51.100.0/24' -- add additional ranges here
    )
    BLOCKED_IP_LIST = ()
    COMMENT = 'agent-bom dashboard ingress — restricted to corporate VPN';

-- ─── Template 2 — bastion host only ──────────────────────────────────────────
-- For air-gapped environments where every Snowflake-facing connection
-- comes from a known bastion / jump-box.
CREATE OR REPLACE NETWORK POLICY agent_bom_bastion_only
    ALLOWED_IP_LIST = (
        '192.0.2.10/32'  -- example: bastion-prod.your-corp.io
    )
    BLOCKED_IP_LIST = ()
    COMMENT = 'agent-bom dashboard ingress — single bastion host only';

-- ─── Template 3 — corporate + on-call (recommended SOC default) ──────────────
-- Combines VPN ranges with a small on-call jump-box list. Recommended for
-- SOC use cases — keeps tier-1 analysts able to reach the dashboard during
-- incident response without requiring an active VPN session.
CREATE OR REPLACE NETWORK POLICY agent_bom_soc_default
    ALLOWED_IP_LIST = (
        '203.0.113.0/24',     -- corporate VPN
        '192.0.2.10/32',      -- on-call bastion 1
        '192.0.2.11/32'       -- on-call bastion 2
    )
    BLOCKED_IP_LIST = ()
    COMMENT = 'agent-bom dashboard ingress — corporate VPN + on-call bastions';

-- ─── Bind to the Native App ──────────────────────────────────────────────────
-- After installing the app:
--   ALTER APPLICATION AGENT_BOM SET CONFIGURATION network_policy_name = 'AGENT_BOM_SOC_DEFAULT';
--
-- Or apply at the account level (affects ALL services in the account):
--   ALTER ACCOUNT SET NETWORK_POLICY = AGENT_BOM_SOC_DEFAULT;
--
-- See docs/snowflake-native-app/INSTALL.md for the full walkthrough.
