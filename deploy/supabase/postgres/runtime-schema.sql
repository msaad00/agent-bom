-- Additive schema for stores that historically created their Postgres objects
-- from API process startup. This file is safe to replay. Keep readiness marker
-- rows last: their presence means every preceding DDL statement committed.

-- Incident-edge keyset indexes match the migration-owned graph paging path.
DO $$
DECLARE previous_graph_bypass TEXT := current_setting('app.bypass_rls', true);
BEGIN
  IF to_regclass('public.graph_snapshots') IS NOT NULL THEN
    ALTER TABLE graph_snapshots ADD COLUMN IF NOT EXISTS snapshot_generation TEXT NOT NULL DEFAULT '';
    ALTER TABLE graph_snapshots ADD COLUMN IF NOT EXISTS read_revision TEXT NOT NULL DEFAULT '';
    PERFORM set_config('app.bypass_rls', '1', true);
    UPDATE graph_snapshots SET snapshot_generation=replace(gen_random_uuid()::text, '-', '') WHERE snapshot_generation='';
    UPDATE graph_snapshots SET read_revision=replace(gen_random_uuid()::text, '-', '') WHERE read_revision='';
    PERFORM set_config('app.bypass_rls', COALESCE(previous_graph_bypass, '0'), true);
  END IF;
  IF to_regclass('public.graph_edges') IS NOT NULL THEN
    CREATE INDEX IF NOT EXISTS idx_pg_adjacency_out ON graph_edges
      (tenant_id, scan_id, source_id COLLATE "C", target_id COLLATE "C", relationship COLLATE "C");
    CREATE INDEX IF NOT EXISTS idx_pg_adjacency_in ON graph_edges
      (tenant_id, scan_id, target_id COLLATE "C", source_id COLLATE "C", relationship COLLATE "C");
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS control_plane_schema_versions (
  component TEXT PRIMARY KEY, version INTEGER NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Cross-tenant access is authorized by both a scoped session flag and a
-- database role that the runtime app principal must never inherit.
CREATE OR REPLACE FUNCTION public.abom_rls_bypass()
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $$
  SELECT COALESCE(NULLIF(current_setting('app.bypass_rls', true), ''), '0') = '1'
     AND pg_has_role(session_user, 'agent_bom_rls_maintenance', 'MEMBER')
$$;

-- Complete the migration-owned shape of tables that already exist in the
-- historical baseline but previously relied on API bootstrap for newer
-- columns and indexes.
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS scim_subject_id TEXT;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS owner TEXT;
-- Stable principal binding: deprovisioning a subject revokes every key keyed to
-- its principal_id (not its free-form display name). Backfill mirrors
-- create_api_key_record precedence (scim_subject_id -> owner).
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS principal_id TEXT;
UPDATE api_keys SET principal_id = COALESCE(NULLIF(scim_subject_id, ''), NULLIF(owner, '')) WHERE principal_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_api_keys_scim_subject ON api_keys(team_id,scim_subject_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_owner ON api_keys(team_id,owner);
CREATE INDEX IF NOT EXISTS idx_api_keys_principal ON api_keys(team_id,principal_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_team_action_ts ON audit_log(team_id,action,timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_team_resource_ts ON audit_log(team_id,resource text_pattern_ops,timestamp DESC);
-- Hash-chain fork guard (#3665-class): at most one row may link to any predecessor
-- per tenant, so concurrent appends across uvicorn --workers N cannot fork the chain.
-- Mirrors PostgresAuditLog._ensure_fork_guard_index; must live in the migration-owned
-- schema because the runtime store's _init_tables() early-returns when Postgres is authoritative.
CREATE UNIQUE INDEX IF NOT EXISTS audit_log_team_prevsig_uniq ON audit_log(team_id,prev_signature);
ALTER TABLE fleet_agents ADD COLUMN IF NOT EXISTS canonical_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_fleet_canonical_id ON fleet_agents(canonical_id);
CREATE INDEX IF NOT EXISTS idx_fleet_tenant_state_trust_name ON fleet_agents(tenant_id,lifecycle_state,trust_score DESC,name);
CREATE INDEX IF NOT EXISTS idx_fleet_tenant_name_lower ON fleet_agents(tenant_id,LOWER(name));
CREATE TABLE IF NOT EXISTS fleet_endpoints (tenant_id TEXT NOT NULL,endpoint_id TEXT NOT NULL,completeness TEXT NOT NULL,updated_at TEXT NOT NULL,data JSONB NOT NULL,PRIMARY KEY(tenant_id,endpoint_id));
CREATE INDEX IF NOT EXISTS idx_fleet_endpoints_tenant_updated ON fleet_endpoints(tenant_id,updated_at DESC,endpoint_id);
CREATE INDEX IF NOT EXISTS idx_pg_jobs_team_created ON scan_jobs(team_id,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_team_status ON scan_jobs(team_id,status);
CREATE INDEX IF NOT EXISTS idx_pg_jobs_batch ON scan_jobs(team_id,batch_id,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pg_jobs_parent ON scan_jobs(team_id,parent_job_id,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pg_jobs_schedule ON scan_jobs(team_id,schedule_id,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sched_tenant_due ON scan_schedules(tenant_id,enabled,next_run);
CREATE TABLE IF NOT EXISTS access_review_campaigns (campaign_id TEXT NOT NULL, tenant_id TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, due_at TEXT NOT NULL DEFAULT '', data TEXT NOT NULL, PRIMARY KEY (tenant_id,campaign_id));
CREATE TABLE IF NOT EXISTS access_review_items (item_id TEXT NOT NULL, campaign_id TEXT NOT NULL, tenant_id TEXT NOT NULL, subject_id TEXT NOT NULL, decision TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant_id,item_id));
CREATE INDEX IF NOT EXISTS idx_access_review_campaigns_tenant ON access_review_campaigns(tenant_id,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_access_review_items_campaign ON access_review_items(tenant_id,campaign_id);

CREATE TABLE IF NOT EXISTS agent_identities (identity_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, status TEXT NOT NULL, issued_at TEXT NOT NULL, data TEXT NOT NULL);
ALTER TABLE agent_identities ADD COLUMN IF NOT EXISTS agent_id TEXT NOT NULL DEFAULT '';
UPDATE agent_identities SET agent_id = TRIM(data::jsonb ->> 'agent_id') WHERE agent_id = '' AND data::jsonb ->> 'agent_id' IS NOT NULL;
CREATE TABLE IF NOT EXISTS agent_identity_jit_grants (grant_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, identity_id TEXT NOT NULL, tool_name TEXT NOT NULL, status TEXT NOT NULL, requested_at TEXT NOT NULL, expires_at TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS agent_conditional_access_policies (policy_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, status TEXT NOT NULL, priority INTEGER NOT NULL, created_at TEXT NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_agent_identities_tenant ON agent_identities(tenant_id,status);
CREATE INDEX IF NOT EXISTS idx_agent_identities_hash ON agent_identities(token_hash);
CREATE INDEX IF NOT EXISTS idx_agent_identities_agent ON agent_identities(tenant_id,agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_identity_jit_lookup ON agent_identity_jit_grants(tenant_id,identity_id,tool_name,status,expires_at);
CREATE INDEX IF NOT EXISTS idx_agent_conditional_access_tenant ON agent_conditional_access_policies(tenant_id,status,priority);

CREATE TABLE IF NOT EXISTS ai_system_blueprints (tenant_id TEXT NOT NULL, blueprint_id TEXT NOT NULL, name TEXT NOT NULL, updated_at TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(tenant_id,blueprint_id));
CREATE TABLE IF NOT EXISTS ai_system_blueprint_versions (tenant_id TEXT NOT NULL, blueprint_id TEXT NOT NULL, version INTEGER NOT NULL, version_id TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(tenant_id,blueprint_id,version));
CREATE INDEX IF NOT EXISTS idx_ai_system_blueprints_tenant ON ai_system_blueprints(tenant_id,updated_at DESC,blueprint_id);
CREATE INDEX IF NOT EXISTS idx_ai_system_blueprint_versions_lookup ON ai_system_blueprint_versions(tenant_id,blueprint_id,version DESC);

CREATE TABLE IF NOT EXISTS auth_session_attempts (key TEXT NOT NULL, attempted_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS revoked_session_nonces (nonce TEXT PRIMARY KEY, expires_at TIMESTAMPTZ NOT NULL);
CREATE INDEX IF NOT EXISTS auth_session_attempts_key_attempted_at_idx ON auth_session_attempts(key,attempted_at);
CREATE INDEX IF NOT EXISTS auth_session_attempts_attempted_at_idx ON auth_session_attempts(attempted_at);
CREATE INDEX IF NOT EXISTS revoked_session_nonces_expires_at_idx ON revoked_session_nonces(expires_at);

CREATE TABLE IF NOT EXISTS managed_trial_invitations (
  invitation_id TEXT PRIMARY KEY,
  token_digest TEXT NOT NULL UNIQUE CHECK (token_digest ~ '^[0-9a-f]{64}$'),
  email TEXT NOT NULL,
  tenant_id TEXT NOT NULL REFERENCES teams(team_id) ON DELETE CASCADE,
  state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','accepted','expired','revoked')),
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  accepted_at TIMESTAMPTZ,
  verified_subject TEXT,
  CHECK (expires_at > created_at),
  CHECK (
    (state = 'accepted' AND accepted_at IS NOT NULL AND verified_subject IS NOT NULL)
    OR (state IN ('pending','expired') AND accepted_at IS NULL AND verified_subject IS NULL)
    OR state = 'revoked'
  )
);
CREATE INDEX IF NOT EXISTS idx_managed_trial_invitations_tenant_state ON managed_trial_invitations(tenant_id,state,expires_at);
CREATE TABLE IF NOT EXISTS managed_trial_tenants (
  tenant_id TEXT PRIMARY KEY,
  state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active','suspended','expired','deleted')),
  created_at TIMESTAMPTZ NOT NULL,
  trial_ends_at TIMESTAMPTZ NOT NULL,
  cleanup_after TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  cleanup_attempts INTEGER NOT NULL DEFAULT 0 CHECK (cleanup_attempts >= 0),
  cleanup_error TEXT,
  cleanup_completed_at TIMESTAMPTZ,
  CHECK (trial_ends_at >= created_at),
  CHECK (cleanup_after >= trial_ends_at),
  CHECK ((state = 'deleted' AND cleanup_completed_at IS NOT NULL) OR state <> 'deleted')
);
CREATE INDEX IF NOT EXISTS idx_managed_trial_tenants_due ON managed_trial_tenants(state,trial_ends_at,cleanup_after);

CREATE TABLE IF NOT EXISTS runtime_observations (tenant_id TEXT NOT NULL, observation_id TEXT NOT NULL, session_id TEXT NOT NULL, observed_at TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(tenant_id,observation_id));
CREATE TABLE IF NOT EXISTS runtime_sessions (tenant_id TEXT NOT NULL, session_id TEXT NOT NULL, last_seen TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(tenant_id,session_id));
CREATE INDEX IF NOT EXISTS idx_runtime_observations_tenant_session_time ON runtime_observations(tenant_id,session_id,observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_runtime_sessions_tenant_last_seen ON runtime_sessions(tenant_id,last_seen DESC);
CREATE TABLE IF NOT EXISTS gateway_activity_events (tenant_id TEXT NOT NULL,event_id TEXT NOT NULL,ingest_ordinal BIGINT NOT NULL,event_timestamp TIMESTAMPTZ NOT NULL,ingested_at TIMESTAMPTZ NOT NULL,event_digest TEXT NOT NULL,data TEXT NOT NULL,PRIMARY KEY(tenant_id,event_id));
CREATE TABLE IF NOT EXISTS gateway_activity_sequences (tenant_id TEXT PRIMARY KEY,next_ordinal BIGINT NOT NULL CHECK(next_ordinal >= 1));
CREATE TABLE IF NOT EXISTS gateway_activity_tombstones (tenant_id TEXT NOT NULL,event_id TEXT NOT NULL,event_digest TEXT NOT NULL,pruned_ordinal BIGINT NOT NULL,PRIMARY KEY(tenant_id,event_id));
CREATE UNIQUE INDEX IF NOT EXISTS idx_gateway_activity_events_tenant_ordinal ON gateway_activity_events(tenant_id,ingest_ordinal);
CREATE INDEX IF NOT EXISTS idx_gateway_activity_events_tenant_event_time ON gateway_activity_events(tenant_id,event_timestamp,((data::jsonb)->>'event_type'),((data::jsonb)->>'reason_code'));
CREATE INDEX IF NOT EXISTS idx_gateway_activity_tombstones_tenant_ordinal ON gateway_activity_tombstones(tenant_id,pruned_ordinal);
CREATE TABLE IF NOT EXISTS runtime_workload_evidence (
  tenant_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  account_id TEXT NOT NULL,
  workload_ref TEXT NOT NULL,
  dedup_key TEXT NOT NULL,
  workload_id TEXT NOT NULL,
  signal_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  observed_at TIMESTAMPTZ NOT NULL,
  source_id TEXT NOT NULL,
  source_kind TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  PRIMARY KEY(tenant_id,provider,account_id,workload_ref,dedup_key)
);
CREATE INDEX IF NOT EXISTS idx_runtime_workload_evidence_tenant_observed_dedup
  ON runtime_workload_evidence(tenant_id,observed_at DESC,dedup_key DESC);
DROP INDEX IF EXISTS idx_runtime_workload_evidence_tenant_time;

CREATE TABLE IF NOT EXISTS scim_users (tenant_id TEXT NOT NULL,user_id TEXT NOT NULL,external_id TEXT,user_name TEXT NOT NULL,active BOOLEAN NOT NULL DEFAULT TRUE,updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),data JSONB NOT NULL,PRIMARY KEY(tenant_id,user_id));
CREATE TABLE IF NOT EXISTS scim_groups (tenant_id TEXT NOT NULL,group_id TEXT NOT NULL,external_id TEXT,display_name TEXT NOT NULL,updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),data JSONB NOT NULL,PRIMARY KEY(tenant_id,group_id));
CREATE INDEX IF NOT EXISTS idx_scim_users_lookup ON scim_users(tenant_id,user_name,external_id);
CREATE INDEX IF NOT EXISTS idx_scim_groups_lookup ON scim_groups(tenant_id,display_name,external_id);

CREATE TABLE IF NOT EXISTS idempotency_keys (endpoint TEXT NOT NULL,tenant_id TEXT NOT NULL,source_id TEXT NOT NULL,idempotency_key TEXT NOT NULL,request_hash TEXT NOT NULL DEFAULT '',response_json TEXT NOT NULL,created_at TEXT NOT NULL,reservation_owner TEXT NOT NULL DEFAULT '',lease_expires_at TEXT NOT NULL DEFAULT '',PRIMARY KEY(endpoint,tenant_id,source_id,idempotency_key));
CREATE INDEX IF NOT EXISTS idx_idempotency_created_at ON idempotency_keys(created_at);
CREATE TABLE IF NOT EXISTS proxy_replay_log (row_id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,captured_at TIMESTAMPTZ NOT NULL DEFAULT now(),not_after TIMESTAMPTZ NOT NULL,record JSONB NOT NULL);
CREATE INDEX IF NOT EXISTS idx_replay_not_after ON proxy_replay_log(not_after);
CREATE INDEX IF NOT EXISTS idx_replay_tenant ON proxy_replay_log(tenant_id);

CREATE TABLE IF NOT EXISTS tenant_quota_overrides (tenant_id TEXT PRIMARY KEY,updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),data JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS tenant_graph_retention_overrides (tenant_id TEXT PRIMARY KEY,updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),retention_days INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS tenant_score_config_overrides (tenant_id TEXT PRIMARY KEY,updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS graph_scenarios (id TEXT NOT NULL,tenant_id TEXT NOT NULL,base_scan_id TEXT NOT NULL,revision INTEGER NOT NULL CHECK(revision >= 1),name TEXT NOT NULL,description TEXT NOT NULL DEFAULT '',operations JSONB NOT NULL,assumptions JSONB NOT NULL DEFAULT '[]'::jsonb,created_by TEXT NOT NULL DEFAULT '',provenance JSONB NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(id,tenant_id));
CREATE INDEX IF NOT EXISTS idx_graph_scenarios_tenant_updated ON graph_scenarios(tenant_id,updated_at DESC,id DESC);

CREATE TABLE IF NOT EXISTS mcp_client_configs (config_id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,name TEXT NOT NULL,profile_id TEXT NOT NULL,created_at TEXT NOT NULL,revoked BOOLEAN NOT NULL DEFAULT FALSE,data TEXT NOT NULL,identity_id TEXT NOT NULL DEFAULT '',issuer TEXT NOT NULL DEFAULT '',environment TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled','revoked')),revision INTEGER NOT NULL DEFAULT 1 CHECK(revision >= 1),updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'));
CREATE INDEX IF NOT EXISTS idx_mcp_client_configs_tenant ON mcp_client_configs(tenant_id,created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_client_configs_active_identity ON mcp_client_configs (tenant_id, identity_id) WHERE identity_id IS NOT NULL AND btrim(identity_id) <> '' AND status = 'active' AND revoked = FALSE;
CREATE INDEX IF NOT EXISTS idx_mcp_client_configs_identity_history ON mcp_client_configs (tenant_id, identity_id, updated_at DESC) WHERE identity_id IS NOT NULL AND btrim(identity_id) <> '';
CREATE TABLE IF NOT EXISTS model_provider_keys (provider_key_id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,provider TEXT NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL,data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS model_virtual_keys (virtual_key_id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,provider_key_id TEXT NOT NULL,token_hash TEXT NOT NULL UNIQUE,status TEXT NOT NULL,issued_at TEXT NOT NULL,data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_model_provider_keys_tenant ON model_provider_keys(tenant_id,created_at);
CREATE INDEX IF NOT EXISTS idx_model_virtual_keys_tenant ON model_virtual_keys(tenant_id,issued_at);
CREATE INDEX IF NOT EXISTS idx_model_virtual_keys_hash ON model_virtual_keys(token_hash);

-- Simple JSON-record stores.
CREATE TABLE IF NOT EXISTS risk_campaign_workflows (tenant_id TEXT NOT NULL,campaign_id TEXT NOT NULL,owner TEXT,sla_due_at TEXT,state TEXT NOT NULL,verification_status TEXT NOT NULL,title TEXT NOT NULL DEFAULT '',member_ids TEXT NOT NULL DEFAULT '[]',membership_fingerprint TEXT NOT NULL DEFAULT '',generation INTEGER NOT NULL DEFAULT 1,active BOOLEAN NOT NULL DEFAULT TRUE,version INTEGER NOT NULL DEFAULT 1,updated_at TEXT NOT NULL,PRIMARY KEY(tenant_id,campaign_id));
CREATE INDEX IF NOT EXISTS idx_risk_campaign_workflows_tenant_state ON risk_campaign_workflows(tenant_id,state,updated_at DESC);
CREATE TABLE IF NOT EXISTS governance_audit_log (seq BIGSERIAL PRIMARY KEY,action_id TEXT NOT NULL,tenant_id TEXT NOT NULL,action TEXT NOT NULL,observed_at TEXT NOT NULL,record_hash TEXT NOT NULL,prev_hash TEXT NOT NULL DEFAULT '',data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_governance_audit_tenant ON governance_audit_log(tenant_id,seq);
CREATE UNIQUE INDEX IF NOT EXISTS uq_governance_audit_tenant_action ON governance_audit_log(tenant_id,action_id);
CREATE UNIQUE INDEX IF NOT EXISTS governance_audit_log_tenant_prevhash_uniq ON governance_audit_log(tenant_id,prev_hash);
CREATE TABLE IF NOT EXISTS scan_dispatch_queue (job_id TEXT PRIMARY KEY REFERENCES scan_jobs(job_id) ON DELETE CASCADE,tenant_id TEXT NOT NULL,created_at TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',claimed_by TEXT,lease_expires_at TEXT);
CREATE INDEX IF NOT EXISTS idx_dispatch_pending ON scan_dispatch_queue(status,created_at);
ALTER TABLE scan_dispatch_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_dispatch_queue FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scan_dispatch_queue_tenant_isolation ON scan_dispatch_queue;
DROP POLICY IF EXISTS scan_dispatch_queue_maintenance ON scan_dispatch_queue;
CREATE POLICY scan_dispatch_queue_tenant_isolation ON scan_dispatch_queue
  FOR ALL
  USING (tenant_id = public.abom_current_tenant())
  WITH CHECK (tenant_id = public.abom_current_tenant());
DO $queue_rls$
BEGIN
 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_rls_maintenance') THEN
   CREATE POLICY scan_dispatch_queue_maintenance ON scan_dispatch_queue
     FOR ALL TO agent_bom_rls_maintenance
     USING (public.abom_rls_bypass())
     WITH CHECK (public.abom_rls_bypass());
 END IF;
END $queue_rls$;

-- Current application schemas for connection/source/credential records.
CREATE TABLE IF NOT EXISTS cloud_connections (id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,provider TEXT NOT NULL,display_name TEXT NOT NULL,role_ref TEXT NOT NULL,external_id_encrypted TEXT NOT NULL DEFAULT '',regions TEXT NOT NULL DEFAULT '[]',status TEXT NOT NULL DEFAULT 'pending',status_detail TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,updated_at TEXT NOT NULL,last_scan_at TEXT,last_scan_id TEXT,scan_interval_minutes INTEGER,auth_params TEXT NOT NULL DEFAULT '{}',last_event_at TEXT,inventory_scope TEXT NOT NULL DEFAULT 'account',scan_mode TEXT NOT NULL DEFAULT 'full',auto_scan_on_create BOOLEAN NOT NULL DEFAULT TRUE,capability_probe_status TEXT NOT NULL DEFAULT 'not_run',verified_capabilities TEXT NOT NULL DEFAULT '[]');
CREATE INDEX IF NOT EXISTS idx_cloud_connections_tenant ON cloud_connections(tenant_id,created_at);
CREATE INDEX IF NOT EXISTS idx_cloud_connections_schedulable ON cloud_connections(scan_interval_minutes,last_scan_at);
CREATE TABLE IF NOT EXISTS ticketing_connections (id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,provider TEXT NOT NULL,transport TEXT NOT NULL,auth_method TEXT NOT NULL,display_name TEXT NOT NULL,endpoint TEXT NOT NULL DEFAULT '',secret_encrypted TEXT NOT NULL DEFAULT '',auth_params TEXT NOT NULL DEFAULT '{}',status TEXT NOT NULL DEFAULT 'pending',status_detail TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_ticketing_connections_tenant ON ticketing_connections(tenant_id,created_at);
CREATE TABLE IF NOT EXISTS ticket_links (id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,connection_id TEXT NOT NULL,dedupe_key TEXT NOT NULL,provider TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'open',external_id TEXT NOT NULL DEFAULT '',key TEXT NOT NULL DEFAULT '',url TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,updated_at TEXT NOT NULL,UNIQUE (tenant_id,connection_id,dedupe_key));
CREATE INDEX IF NOT EXISTS idx_ticket_links_tenant ON ticket_links(tenant_id,created_at);
CREATE TABLE IF NOT EXISTS control_plane_sources (source_id TEXT PRIMARY KEY,enabled INTEGER DEFAULT 1,tenant_id TEXT NOT NULL DEFAULT 'default',updated_at TEXT NOT NULL,data JSONB NOT NULL);
CREATE INDEX IF NOT EXISTS idx_control_plane_sources_tenant_updated ON control_plane_sources(tenant_id,updated_at DESC);
CREATE TABLE IF NOT EXISTS credential_refs (credential_ref_id TEXT PRIMARY KEY,enabled INTEGER DEFAULT 1,tenant_id TEXT NOT NULL DEFAULT 'default',updated_at TEXT NOT NULL,data JSONB NOT NULL);
CREATE INDEX IF NOT EXISTS idx_credential_refs_tenant_updated ON credential_refs(tenant_id,updated_at DESC);

-- Audit-chain checkpoint is separated from the append-only audit rows.
CREATE TABLE IF NOT EXISTS audit_chain_checkpoint (tenant_id TEXT PRIMARY KEY,entry_count BIGINT NOT NULL DEFAULT 0,head_signature TEXT NOT NULL DEFAULT '',updated_at TEXT NOT NULL DEFAULT '');

CREATE TABLE IF NOT EXISTS compliance_hub_findings (tenant_id TEXT NOT NULL,finding_id TEXT NOT NULL,ingested_at TEXT NOT NULL,source TEXT NOT NULL,applicable_frameworks_csv TEXT NOT NULL DEFAULT '',payload JSONB NOT NULL,ordinal BIGSERIAL NOT NULL,effective_reach_score DOUBLE PRECISION NOT NULL DEFAULT 0,origin TEXT NOT NULL DEFAULT '',severity TEXT NOT NULL DEFAULT '',severity_rank INTEGER NOT NULL DEFAULT 0,cvss_score DOUBLE PRECISION NOT NULL DEFAULT 0,scan_id TEXT NOT NULL DEFAULT '',PRIMARY KEY(tenant_id,finding_id));
CREATE TABLE IF NOT EXISTS hub_overview_revisions (tenant_id TEXT PRIMARY KEY,revision BIGINT NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_order ON compliance_hub_findings(tenant_id,ordinal);
CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_origin_reach ON compliance_hub_findings(tenant_id,origin,effective_reach_score DESC,ordinal);
CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_origin ON compliance_hub_findings(tenant_id,origin);
CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_origin_severity ON compliance_hub_findings(tenant_id,origin,severity_rank DESC,ordinal);
CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_origin_cvss ON compliance_hub_findings(tenant_id,origin,cvss_score DESC,ordinal);
CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_origin_severity_cvss ON compliance_hub_findings(tenant_id,origin,severity_rank,cvss_score DESC,ordinal);
CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_reach_all ON compliance_hub_findings(tenant_id,effective_reach_score DESC,ordinal);
CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_cvss_all ON compliance_hub_findings(tenant_id,cvss_score DESC,ordinal);
CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_severity_all ON compliance_hub_findings(tenant_id,severity_rank DESC,ordinal);
CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_severity_ci ON compliance_hub_findings(tenant_id,LOWER(severity)) WHERE severity <> '';
CREATE INDEX IF NOT EXISTS idx_hub_findings_tenant_scan ON compliance_hub_findings(tenant_id,scan_id) WHERE scan_id <> '';
CREATE TABLE IF NOT EXISTS hub_findings_current (tenant_id TEXT NOT NULL,canonical_id TEXT NOT NULL,first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'open',severity TEXT NOT NULL DEFAULT '',severity_rank INTEGER NOT NULL DEFAULT 0,cvss_score DOUBLE PRECISION NOT NULL DEFAULT 0,effective_reach_score DOUBLE PRECISION NOT NULL DEFAULT 0,scan_count INTEGER NOT NULL DEFAULT 1,resolved_at TEXT,reopened_at TEXT,updated_at TEXT NOT NULL,payload JSONB NOT NULL,ledger_finding_id TEXT,origin TEXT NOT NULL DEFAULT '',scan_id TEXT NOT NULL DEFAULT '',ledger_ordinal BIGINT NOT NULL DEFAULT 9223372036854775807,PRIMARY KEY(tenant_id,canonical_id));
CREATE TABLE IF NOT EXISTS hub_findings_current_observations (tenant_id TEXT NOT NULL,canonical_id TEXT NOT NULL,scan_id TEXT NOT NULL,observed_at TEXT NOT NULL,PRIMARY KEY(tenant_id,canonical_id,scan_id));
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_last_seen ON hub_findings_current(tenant_id,last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_reach ON hub_findings_current(tenant_id,effective_reach_score DESC,last_seen DESC,canonical_id);
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_cvss ON hub_findings_current(tenant_id,cvss_score DESC,last_seen DESC,canonical_id);
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_severity ON hub_findings_current(tenant_id,severity_rank DESC,last_seen DESC,canonical_id);
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_origin_cvss ON hub_findings_current(tenant_id,origin,cvss_score DESC,last_seen DESC,canonical_id);
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_ordinal ON hub_findings_current(tenant_id,ledger_ordinal ASC,first_seen ASC,canonical_id);
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_severity_reach ON hub_findings_current(tenant_id,LOWER(severity),effective_reach_score DESC,last_seen DESC,canonical_id) WHERE severity <> '';
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_severity_cvss ON hub_findings_current(tenant_id,LOWER(severity),cvss_score DESC,last_seen DESC,canonical_id) WHERE severity <> '';
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_open_reach ON hub_findings_current(tenant_id,effective_reach_score DESC,last_seen DESC,canonical_id) WHERE status IN ('open','reopened');
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_scan ON hub_findings_current(tenant_id,scan_id) WHERE scan_id <> '';
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_severity_ci ON hub_findings_current(tenant_id,LOWER(severity)) WHERE severity <> '';
-- Findings pages order text tie-breakers by code point (COLLATE "C"); only these twins serve that ORDER BY.
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_reach_c ON hub_findings_current(tenant_id,effective_reach_score DESC,last_seen COLLATE "C" DESC,canonical_id COLLATE "C" ASC);
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_cvss_c ON hub_findings_current(tenant_id,cvss_score DESC,last_seen COLLATE "C" DESC,canonical_id COLLATE "C" ASC);
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_severity_c ON hub_findings_current(tenant_id,severity_rank DESC,last_seen COLLATE "C" DESC,canonical_id COLLATE "C" ASC);
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_origin_cvss_c ON hub_findings_current(tenant_id,origin,cvss_score DESC,last_seen COLLATE "C" DESC,canonical_id COLLATE "C" ASC);
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_ordinal_c ON hub_findings_current(tenant_id,ledger_ordinal ASC,first_seen COLLATE "C" ASC,canonical_id COLLATE "C" ASC);
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_severity_reach_c ON hub_findings_current(tenant_id,LOWER(severity),effective_reach_score DESC,last_seen COLLATE "C" DESC,canonical_id COLLATE "C" ASC) WHERE severity <> '';
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_severity_cvss_c ON hub_findings_current(tenant_id,LOWER(severity),cvss_score DESC,last_seen COLLATE "C" DESC,canonical_id COLLATE "C" ASC) WHERE severity <> '';
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_open_reach_c ON hub_findings_current(tenant_id,effective_reach_score DESC,last_seen COLLATE "C" DESC,canonical_id COLLATE "C" ASC) WHERE status IN ('open','reopened');
CREATE TABLE IF NOT EXISTS hub_cve_intel (tenant_id TEXT NOT NULL,cve_id TEXT NOT NULL,payload JSONB NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(tenant_id,cve_id));
CREATE TABLE IF NOT EXISTS hub_framework_refs (tenant_id TEXT NOT NULL,framework_ref TEXT NOT NULL,payload JSONB NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(tenant_id,framework_ref));
CREATE TABLE IF NOT EXISTS agent_bom_hub_backfills (name TEXT PRIMARY KEY,completed_at TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS export_schedules (
 schedule_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
 enabled BOOLEAN NOT NULL DEFAULT TRUE, next_run TEXT, data JSONB NOT NULL,
 PRIMARY KEY (tenant_id, schedule_id)
);
CREATE INDEX IF NOT EXISTS idx_export_sched_due ON export_schedules(enabled, next_run, schedule_id);

CREATE TABLE IF NOT EXISTS export_destinations (
 id TEXT NOT NULL, tenant_id TEXT NOT NULL, kind TEXT NOT NULL,
 display_name TEXT NOT NULL, config JSONB NOT NULL DEFAULT '{}'::jsonb,
 secret_encrypted TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending',
 status_detail TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 last_run_at TEXT, last_run_status TEXT, PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS idx_export_dest_tenant ON export_destinations(tenant_id, created_at);

-- Apply identical FORCE RLS policy semantics to all tenant-owned additions.
DO $rls$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'access_review_campaigns','access_review_items','agent_identities','agent_identity_jit_grants','agent_conditional_access_policies',
    'ai_system_blueprints','ai_system_blueprint_versions','runtime_observations','runtime_sessions','gateway_activity_events','gateway_activity_sequences',
    'gateway_activity_tombstones','runtime_workload_evidence','scim_users','scim_groups',
    'export_schedules','export_destinations','idempotency_keys','proxy_replay_log','tenant_quota_overrides','tenant_graph_retention_overrides','tenant_score_config_overrides','graph_scenarios',
    'mcp_client_configs','model_provider_keys','model_virtual_keys','risk_campaign_workflows','governance_audit_log','cloud_connections','ticketing_connections','ticket_links',
    'control_plane_sources','credential_refs','audit_chain_checkpoint','managed_trial_invitations','managed_trial_tenants','compliance_hub_findings','hub_overview_revisions','hub_findings_current',
    'hub_findings_current_observations','hub_cve_intel','hub_framework_refs','fleet_endpoints'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname=current_schema() AND tablename=t AND policyname=t||'_tenant_isolation') THEN
      EXECUTE format('CREATE POLICY %I ON %I USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant()) WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())',t||'_tenant_isolation',t);
    END IF;
  END LOOP;
END $rls$;

-- Grants are explicit because ALTER DEFAULT PRIVILEGES is owner-specific on BYO
-- Postgres. The migration remains valid when the packaged app role is absent.
DO $grant$
BEGIN
 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_app') THEN
   GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO agent_bom_app;
   GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO agent_bom_app;
 END IF;
 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_rls_maintenance') THEN
   GRANT USAGE ON SCHEMA public TO agent_bom_rls_maintenance;
   GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO agent_bom_rls_maintenance;
   GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO agent_bom_rls_maintenance;
 END IF;
END $grant$;

-- Database-owned authority for short-lived tenant-binding claims. Runtime
-- roles receive no table privileges; the app may call only the locked-down
-- verifier. Active RLS continues using app.tenant_id until the later surface
-- and lock-in stages deploy claim issuance everywhere.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS public.agent_bom_tenant_binding_keys (
  key_id TEXT PRIMARY KEY CHECK (key_id ~ '^[0-9a-f]{64}$'),
  key_material BYTEA NOT NULL CHECK (octet_length(key_material) >= 32),
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE OR REPLACE FUNCTION public.abom_verify_tenant_binding_claim(
  p_tenant_id TEXT,
  p_issued_at BIGINT,
  p_nonce TEXT,
  p_signature TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
  v_now BIGINT := floor(extract(epoch FROM clock_timestamp()))::BIGINT;
  v_canonical TEXT;
  v_verified BOOLEAN := FALSE;
BEGIN
  IF p_tenant_id IS NULL
     OR p_tenant_id = ''
     OR p_tenant_id <> btrim(p_tenant_id)
     OR lower(p_tenant_id) IN ('admin', 'analyst', 'viewer', 'system', '__system__')
     OR p_issued_at IS NULL
     OR p_issued_at > v_now + 30
     OR p_issued_at < v_now - 30
     OR p_nonce IS NULL
     OR p_nonce !~ '^[0-9a-f]{32}$'
     OR p_signature IS NULL
     OR p_signature !~ '^[0-9a-f]{64}$'
  THEN
    RETURN FALSE;
  END IF;

  v_canonical := 'v1:' || encode(convert_to(p_tenant_id, 'UTF8'), 'hex')
                 || ':' || p_issued_at::TEXT || ':' || p_nonce;

  SELECT EXISTS (
    SELECT 1
      FROM public.agent_bom_tenant_binding_keys
     WHERE enabled
       AND encode(
             public.hmac(convert_to(v_canonical, 'UTF8'), key_material, 'sha256'),
             'hex'
           ) = p_signature
  ) INTO v_verified;

  RETURN COALESCE(v_verified, FALSE);
END
$function$;

REVOKE ALL ON TABLE public.agent_bom_tenant_binding_keys FROM PUBLIC;
REVOKE ALL ON FUNCTION public.abom_verify_tenant_binding_claim(TEXT, BIGINT, TEXT, TEXT) FROM PUBLIC;

DO $tenant_binding_roles$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_app') THEN
    EXECUTE 'REVOKE ALL ON TABLE public.agent_bom_tenant_binding_keys FROM agent_bom_app';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.abom_verify_tenant_binding_claim(TEXT, BIGINT, TEXT, TEXT) TO agent_bom_app';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_readonly') THEN
    EXECUTE 'REVOKE ALL ON TABLE public.agent_bom_tenant_binding_keys FROM agent_bom_readonly';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_rls_maintenance') THEN
    EXECUTE 'REVOKE ALL ON TABLE public.agent_bom_tenant_binding_keys FROM agent_bom_rls_maintenance';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_maintenance') THEN
    EXECUTE 'REVOKE ALL ON TABLE public.agent_bom_tenant_binding_keys FROM agent_bom_maintenance';
  END IF;
END
$tenant_binding_roles$;

-- Readiness markers: deliberately last.
INSERT INTO control_plane_schema_versions(component,version,updated_at)
SELECT component,1,now() FROM unnest(ARRAY[
 'scan_jobs','api_keys','exceptions','audit_log','trend_history','gateway_policies','schedules','sources','credential_refs','llm_costs',
 'cloud_connections','compliance_hub','access_review_campaigns','risk_campaign_workflows','fleet','scan_cache','identity_scim',
 'tenant_quotas','tenant_graph_retention','idempotency','proxy_replay_log','rate_limits',
 'shared_auth_state','managed_trial_invitations','managed_trial_tenants','governance_audit_log','ai_system_blueprints','model_provider_keys','tenant_score_config',
 'ticketing_connections','graph_scenarios','export_schedules','export_destinations'
]) component
ON CONFLICT(component) DO UPDATE SET version=excluded.version,updated_at=excluded.updated_at;
INSERT INTO control_plane_schema_versions(component,version,updated_at)
VALUES ('compliance_hub',2,now())
ON CONFLICT(component) DO UPDATE SET version=excluded.version,updated_at=excluded.updated_at;
INSERT INTO control_plane_schema_versions(component,version,updated_at)
VALUES ('runtime_workload_evidence',2,now())
ON CONFLICT(component) DO UPDATE SET version=excluded.version,updated_at=excluded.updated_at;
INSERT INTO control_plane_schema_versions(component,version,updated_at)
VALUES ('runtime_events',2,now())
ON CONFLICT(component) DO UPDATE SET version=excluded.version,updated_at=excluded.updated_at;
INSERT INTO control_plane_schema_versions(component,version,updated_at)
VALUES ('mcp_client_configs',2,now())
ON CONFLICT(component) DO UPDATE SET version=excluded.version,updated_at=excluded.updated_at;
INSERT INTO control_plane_schema_versions(component,version,updated_at)
VALUES ('agent_identities',2,now())
ON CONFLICT(component) DO UPDATE SET version=GREATEST(control_plane_schema_versions.version,excluded.version),updated_at=excluded.updated_at;

-- Preserve older readiness until the full graph v4 migration exists; never
-- downgrade its marker on replay. Ownership and committed read tokens require v6.
UPDATE control_plane_schema_versions SET version=6,updated_at=now()
WHERE component='graph' AND version>=4 AND version<6
  AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public'
              AND table_name='graph_snapshots' AND column_name='snapshot_generation')
  AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public'
              AND table_name='graph_snapshots' AND column_name='read_revision');

-- Immutable BOM history and operator-recorded lifecycle.
CREATE TABLE IF NOT EXISTS agent_lifecycle_records (
    tenant_id TEXT NOT NULL, kind TEXT NOT NULL, record_id TEXT NOT NULL,
    agent_id TEXT NOT NULL, recorded_at TEXT NOT NULL, data TEXT NOT NULL,
    PRIMARY KEY (tenant_id, kind, record_id)
);
CREATE INDEX IF NOT EXISTS idx_agent_lifecycle_history
    ON agent_lifecycle_records (tenant_id, kind, agent_id, recorded_at, record_id);
CREATE TABLE IF NOT EXISTS agent_bom_snapshots (
    tenant_id TEXT NOT NULL, snapshot_id TEXT NOT NULL, document TEXT NOT NULL,
    PRIMARY KEY (tenant_id, snapshot_id)
);
ALTER TABLE agent_lifecycle_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_lifecycle_records FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='public'
                   AND tablename='agent_lifecycle_records' AND policyname='agent_lifecycle_records_tenant_isolation') THEN
        CREATE POLICY agent_lifecycle_records_tenant_isolation ON agent_lifecycle_records
            USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
            WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
    END IF;
END $$;
ALTER TABLE agent_bom_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_bom_snapshots FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='public'
                   AND tablename='agent_bom_snapshots' AND policyname='agent_bom_snapshots_tenant_isolation') THEN
        CREATE POLICY agent_bom_snapshots_tenant_isolation ON agent_bom_snapshots
            USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
            WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
    END IF;
END $$;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_app') THEN
        GRANT SELECT, INSERT, UPDATE ON agent_lifecycle_records TO agent_bom_app;
        GRANT SELECT, INSERT ON agent_bom_snapshots TO agent_bom_app;
        REVOKE DELETE ON agent_lifecycle_records FROM agent_bom_app;
        REVOKE UPDATE, DELETE ON agent_bom_snapshots FROM agent_bom_app;
    END IF;
END $$;
INSERT INTO control_plane_schema_versions(component,version,updated_at)
VALUES ('agent_lifecycle',1,now())
ON CONFLICT(component) DO UPDATE SET version=GREATEST(control_plane_schema_versions.version,excluded.version),updated_at=excluded.updated_at;

-- Durable MCP result paging across workers and replicas.
CREATE TABLE IF NOT EXISTS mcp_scan_results (
    tenant_id TEXT NOT NULL, result_id TEXT NOT NULL, owner_digest TEXT NOT NULL,
    created_at DOUBLE PRECISION NOT NULL, expires_at DOUBLE PRECISION NOT NULL,
    data TEXT NOT NULL, PRIMARY KEY (tenant_id, result_id)
);
CREATE INDEX IF NOT EXISTS idx_mcp_result_expiry
    ON mcp_scan_results (tenant_id, expires_at, result_id);
CREATE INDEX IF NOT EXISTS idx_mcp_result_order
    ON mcp_scan_results (tenant_id, created_at DESC, result_id DESC);
ALTER TABLE mcp_scan_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_scan_results FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='public'
                   AND tablename='mcp_scan_results' AND policyname='mcp_scan_results_tenant_isolation') THEN
        CREATE POLICY mcp_scan_results_tenant_isolation ON mcp_scan_results
            USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
            WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
    END IF;
END $$;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_app') THEN
        GRANT SELECT, INSERT, DELETE ON mcp_scan_results TO agent_bom_app;
    END IF;
END $$;
INSERT INTO control_plane_schema_versions(component,version,updated_at)
VALUES ('mcp_scan_results',1,now())
ON CONFLICT(component) DO UPDATE SET
    version=GREATEST(control_plane_schema_versions.version,excluded.version),
    updated_at=excluded.updated_at;

-- Durable provider-neutral side-scan lifecycle state.
CREATE TABLE IF NOT EXISTS side_scan_execution_state (
    execution_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, provider TEXT NOT NULL,
    account_id TEXT NOT NULL, target_id TEXT NOT NULL, idempotency_key TEXT NOT NULL,
    state_version INTEGER NOT NULL, cleanup_status TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL, payload_json TEXT NOT NULL,
    UNIQUE (tenant_id, provider, account_id, target_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_side_scan_cleanup ON side_scan_execution_state (tenant_id, cleanup_status, updated_at);
CREATE INDEX IF NOT EXISTS idx_side_scan_recent ON side_scan_execution_state (tenant_id, updated_at DESC, execution_id DESC);
ALTER TABLE side_scan_execution_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE side_scan_execution_state FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='public'
                   AND tablename='side_scan_execution_state' AND policyname='side_scan_execution_state_tenant_isolation') THEN
        CREATE POLICY side_scan_execution_state_tenant_isolation ON side_scan_execution_state
            USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
            WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_app') THEN
        GRANT SELECT, INSERT, UPDATE ON side_scan_execution_state TO agent_bom_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_rls_maintenance') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON side_scan_execution_state TO agent_bom_rls_maintenance;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_readonly') THEN
        GRANT SELECT ON side_scan_execution_state TO agent_bom_readonly;
    END IF;
END $$;
INSERT INTO control_plane_schema_versions(component,version,updated_at)
VALUES ('side_scan_lifecycle',1,now())
ON CONFLICT(component) DO UPDATE SET
    version=GREATEST(control_plane_schema_versions.version,excluded.version), updated_at=excluded.updated_at;

ALTER TABLE exceptions ADD COLUMN IF NOT EXISTS approval_version INTEGER NOT NULL DEFAULT 0;
UPDATE control_plane_schema_versions SET version=2,updated_at=now() WHERE component='exceptions' AND version < 2;
-- Suppression decision author for four-eyes approval (migration 20261007_03).
ALTER TABLE exceptions ADD COLUMN IF NOT EXISTS decided_by TEXT NOT NULL DEFAULT '';
UPDATE control_plane_schema_versions SET version=3,updated_at=now() WHERE component='exceptions' AND version < 3;

-- Committed job evidence revisions (migration 20261006_01).

DO $job_revision_schema$
BEGIN
LOCK TABLE public.scan_jobs IN SHARE ROW EXCLUSIVE MODE;
CREATE TABLE IF NOT EXISTS public.job_overview_revisions (
    tenant_id TEXT PRIMARY KEY CHECK (length(btrim(tenant_id)) > 0),
    generation TEXT NOT NULL DEFAULT gen_random_uuid()::text,
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0)
);
ALTER TABLE public.job_overview_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.job_overview_revisions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS job_overview_revisions_tenant_isolation ON public.job_overview_revisions;
CREATE POLICY job_overview_revisions_tenant_isolation ON public.job_overview_revisions
    USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
    WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());

CREATE OR REPLACE FUNCTION public.abom_bump_job_revision() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF TG_OP <> 'DELETE' THEN
        INSERT INTO public.job_overview_revisions (tenant_id, revision) VALUES (NEW.team_id, 1)
        ON CONFLICT (tenant_id) DO UPDATE SET revision = job_overview_revisions.revision + 1;
    END IF;
    IF TG_OP = 'DELETE' OR (TG_OP = 'UPDATE' AND OLD.team_id IS DISTINCT FROM NEW.team_id) THEN
        INSERT INTO public.job_overview_revisions (tenant_id, revision) VALUES (OLD.team_id, 1)
        ON CONFLICT (tenant_id) DO UPDATE SET revision = job_overview_revisions.revision + 1;
    END IF;
    RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS scan_jobs_evidence_revision ON public.scan_jobs;
CREATE TRIGGER scan_jobs_evidence_revision AFTER INSERT OR UPDATE OR DELETE ON public.scan_jobs
    FOR EACH ROW EXECUTE FUNCTION public.abom_bump_job_revision();

DO $$
DECLARE previous_bypass TEXT := current_setting('app.bypass_rls', true);
BEGIN
    PERFORM set_config('app.bypass_rls', '1', true);
    INSERT INTO public.job_overview_revisions (tenant_id, revision)
        SELECT DISTINCT team_id, 1 FROM public.scan_jobs ON CONFLICT (tenant_id) DO NOTHING;
    PERFORM set_config('app.bypass_rls', COALESCE(previous_bypass, '0'), true);
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON public.job_overview_revisions TO agent_bom_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_rls_maintenance') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON public.job_overview_revisions TO agent_bom_rls_maintenance;
    END IF;
END $$;
END $job_revision_schema$;

INSERT INTO control_plane_schema_versions(component,version,updated_at) VALUES ('scan_jobs',3,now())
ON CONFLICT(component) DO UPDATE SET version=GREATEST(control_plane_schema_versions.version,excluded.version),updated_at=excluded.updated_at;

-- Shared evidence registries (20261007_01).
CREATE TABLE IF NOT EXISTS public.kspm_cluster_posture (tenant_id TEXT NOT NULL CHECK (length(btrim(tenant_id)) > 0), data JSONB NOT NULL, run_id TEXT NOT NULL, cluster_ref TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(tenant_id,run_id));
CREATE INDEX IF NOT EXISTS idx_kspm_cluster_posture_tenant ON public.kspm_cluster_posture (tenant_id);
ALTER TABLE public.kspm_cluster_posture ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.kspm_cluster_posture FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS kspm_cluster_posture_tenant_isolation ON public.kspm_cluster_posture;
CREATE POLICY kspm_cluster_posture_tenant_isolation ON public.kspm_cluster_posture USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant()) WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON public.kspm_cluster_posture TO agent_bom_app, agent_bom_rls_maintenance;
INSERT INTO control_plane_schema_versions(component,version,updated_at) VALUES ('kspm_cluster_posture',1,now()) ON CONFLICT(component) DO UPDATE SET version=GREATEST(control_plane_schema_versions.version,1);
CREATE TABLE IF NOT EXISTS public.mcp_observations (tenant_id TEXT NOT NULL CHECK (length(btrim(tenant_id)) > 0), data JSONB NOT NULL, observation_id TEXT NOT NULL, server_canonical_id TEXT NOT NULL, server_name TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY (tenant_id, observation_id));
CREATE INDEX IF NOT EXISTS idx_mcp_observations_tenant ON public.mcp_observations (tenant_id);
ALTER TABLE public.mcp_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mcp_observations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS mcp_observations_tenant_isolation ON public.mcp_observations;
CREATE POLICY mcp_observations_tenant_isolation ON public.mcp_observations USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant()) WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON public.mcp_observations TO agent_bom_app, agent_bom_rls_maintenance;
INSERT INTO control_plane_schema_versions(component,version,updated_at) VALUES ('mcp_observations',1,now()) ON CONFLICT(component) DO UPDATE SET version=GREATEST(control_plane_schema_versions.version,1);
CREATE TABLE IF NOT EXISTS public.skills_scan_run (tenant_id TEXT NOT NULL CHECK (length(btrim(tenant_id)) > 0), data JSONB NOT NULL, run_id TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (tenant_id, run_id));
CREATE INDEX IF NOT EXISTS idx_skills_scan_run_tenant ON public.skills_scan_run (tenant_id);
ALTER TABLE public.skills_scan_run ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.skills_scan_run FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS skills_scan_run_tenant_isolation ON public.skills_scan_run;
CREATE POLICY skills_scan_run_tenant_isolation ON public.skills_scan_run USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant()) WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON public.skills_scan_run TO agent_bom_app, agent_bom_rls_maintenance;
INSERT INTO control_plane_schema_versions(component,version,updated_at) VALUES ('skills_scan_run',1,now()) ON CONFLICT(component) DO UPDATE SET version=GREATEST(control_plane_schema_versions.version,1);
CREATE TABLE IF NOT EXISTS public.issue_mappings (tenant_id TEXT NOT NULL CHECK (length(btrim(tenant_id)) > 0), data JSONB NOT NULL, mapping_id TEXT NOT NULL, target_kind TEXT NOT NULL, target_id TEXT NOT NULL, provider TEXT NOT NULL, PRIMARY KEY (tenant_id, mapping_id), UNIQUE(tenant_id,target_kind,target_id,provider));
CREATE INDEX IF NOT EXISTS idx_issue_mappings_tenant ON public.issue_mappings (tenant_id);
ALTER TABLE public.issue_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.issue_mappings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS issue_mappings_tenant_isolation ON public.issue_mappings;
CREATE POLICY issue_mappings_tenant_isolation ON public.issue_mappings USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant()) WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON public.issue_mappings TO agent_bom_app, agent_bom_rls_maintenance;
INSERT INTO control_plane_schema_versions(component,version,updated_at) VALUES ('issue_mappings',1,now()) ON CONFLICT(component) DO UPDATE SET version=GREATEST(control_plane_schema_versions.version,1);
CREATE TABLE IF NOT EXISTS public.dataset_versions (tenant_id TEXT NOT NULL CHECK (length(btrim(tenant_id)) > 0), data JSONB NOT NULL, dataset_id TEXT NOT NULL, version_id TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (tenant_id, dataset_id, version_id));
CREATE INDEX IF NOT EXISTS idx_dataset_versions_tenant ON public.dataset_versions (tenant_id);
ALTER TABLE public.dataset_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dataset_versions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS dataset_versions_tenant_isolation ON public.dataset_versions;
CREATE POLICY dataset_versions_tenant_isolation ON public.dataset_versions USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant()) WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON public.dataset_versions TO agent_bom_app, agent_bom_rls_maintenance;
INSERT INTO control_plane_schema_versions(component,version,updated_at) VALUES ('dataset_versions',1,now()) ON CONFLICT(component) DO UPDATE SET version=GREATEST(control_plane_schema_versions.version,1);
CREATE TABLE IF NOT EXISTS public.evaluation_runs (tenant_id TEXT NOT NULL CHECK (length(btrim(tenant_id)) > 0), data JSONB NOT NULL, evaluation_id TEXT NOT NULL, dataset_id TEXT, created_at TEXT NOT NULL, PRIMARY KEY (tenant_id, evaluation_id));
CREATE INDEX IF NOT EXISTS idx_evaluation_runs_tenant ON public.evaluation_runs (tenant_id);
ALTER TABLE public.evaluation_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.evaluation_runs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS evaluation_runs_tenant_isolation ON public.evaluation_runs;
CREATE POLICY evaluation_runs_tenant_isolation ON public.evaluation_runs USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant()) WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON public.evaluation_runs TO agent_bom_app, agent_bom_rls_maintenance;
INSERT INTO control_plane_schema_versions(component,version,updated_at) VALUES ('evaluation_runs',1,now()) ON CONFLICT(component) DO UPDATE SET version=GREATEST(control_plane_schema_versions.version,1);
CREATE TABLE IF NOT EXISTS public.webhook_subscriptions (tenant_id TEXT NOT NULL CHECK (length(btrim(tenant_id)) > 0), data JSONB NOT NULL, subscription_id TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (tenant_id, subscription_id));
CREATE INDEX IF NOT EXISTS idx_webhook_subscriptions_tenant ON public.webhook_subscriptions (tenant_id);
ALTER TABLE public.webhook_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.webhook_subscriptions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS webhook_subscriptions_tenant_isolation ON public.webhook_subscriptions;
CREATE POLICY webhook_subscriptions_tenant_isolation ON public.webhook_subscriptions USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant()) WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON public.webhook_subscriptions TO agent_bom_app, agent_bom_rls_maintenance;
INSERT INTO control_plane_schema_versions(component,version,updated_at) VALUES ('webhook_subscriptions',1,now()) ON CONFLICT(component) DO UPDATE SET version=GREATEST(control_plane_schema_versions.version,1);
CREATE TABLE IF NOT EXISTS public.drift_incidents (tenant_id TEXT NOT NULL CHECK (length(btrim(tenant_id)) > 0), data JSONB NOT NULL, incident_id TEXT NOT NULL, resolved BOOLEAN NOT NULL, last_detected_at TEXT NOT NULL, PRIMARY KEY (tenant_id, incident_id));
CREATE INDEX IF NOT EXISTS idx_drift_incidents_tenant ON public.drift_incidents (tenant_id);
ALTER TABLE public.drift_incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.drift_incidents FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS drift_incidents_tenant_isolation ON public.drift_incidents;
CREATE POLICY drift_incidents_tenant_isolation ON public.drift_incidents USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant()) WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON public.drift_incidents TO agent_bom_app, agent_bom_rls_maintenance;
INSERT INTO control_plane_schema_versions(component,version,updated_at) VALUES ('drift_incidents',1,now()) ON CONFLICT(component) DO UPDATE SET version=GREATEST(control_plane_schema_versions.version,1);


CREATE TABLE IF NOT EXISTS public.campaign_evidence_state (
    tenant_id TEXT PRIMARY KEY CHECK (length(btrim(tenant_id)) > 0),
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0),
    reconciled_revision BIGINT NOT NULL DEFAULT 0 CHECK (reconciled_revision >= 0)
);
CREATE INDEX IF NOT EXISTS idx_campaign_evidence_pending ON public.campaign_evidence_state(tenant_id)
    WHERE revision != reconciled_revision;
ALTER TABLE public.campaign_evidence_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.campaign_evidence_state FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS campaign_evidence_state_tenant_isolation ON public.campaign_evidence_state;
CREATE POLICY campaign_evidence_state_tenant_isolation ON public.campaign_evidence_state
    USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
    WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON public.campaign_evidence_state TO agent_bom_app, agent_bom_rls_maintenance;
CREATE OR REPLACE FUNCTION public.abom_queue_campaign_evidence() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        INSERT INTO public.campaign_evidence_state(tenant_id,revision) VALUES (OLD.tenant_id,1)
        ON CONFLICT(tenant_id) DO UPDATE SET revision=campaign_evidence_state.revision+1;
    ELSE
        INSERT INTO public.campaign_evidence_state(tenant_id,revision) VALUES (NEW.tenant_id,1)
        ON CONFLICT(tenant_id) DO UPDATE SET revision=campaign_evidence_state.revision+1;
    END IF;
    RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS job_campaign_evidence ON public.job_overview_revisions;
CREATE TRIGGER job_campaign_evidence AFTER INSERT OR UPDATE OR DELETE ON public.job_overview_revisions
    FOR EACH ROW EXECUTE FUNCTION public.abom_queue_campaign_evidence();
DROP TRIGGER IF EXISTS hub_campaign_evidence ON public.hub_overview_revisions;
CREATE TRIGGER hub_campaign_evidence AFTER INSERT OR UPDATE OR DELETE ON public.hub_overview_revisions
    FOR EACH ROW EXECUTE FUNCTION public.abom_queue_campaign_evidence();
DO $$
DECLARE previous_bypass TEXT := current_setting('app.bypass_rls', true);
BEGIN
    PERFORM set_config('app.bypass_rls','1',true);
    INSERT INTO public.campaign_evidence_state(tenant_id,revision)
        SELECT tenant_id,1 FROM public.job_overview_revisions
        UNION SELECT tenant_id,1 FROM public.hub_overview_revisions ON CONFLICT DO NOTHING;
    PERFORM set_config('app.bypass_rls',COALESCE(previous_bypass,'0'),true);
END $$;
INSERT INTO control_plane_schema_versions(component,version,updated_at)
    VALUES ('campaign_evidence_state',1,now()) ON CONFLICT(component) DO NOTHING;

-- Materialized scan finding snapshots (ADR-015, migration 20261010_01).
CREATE TABLE IF NOT EXISTS scan_snapshot_jobs (
    tenant_id TEXT NOT NULL CHECK (length(btrim(tenant_id)) > 0),
    job_id TEXT NOT NULL,
    scope_key TEXT NOT NULL,
    authority_evidence_at TEXT NOT NULL,
    authority_completed_at TEXT NOT NULL,
    authoritative BOOLEAN NOT NULL,
    incomplete_reasons TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    row_schema_version INTEGER NOT NULL,
    row_count INTEGER NOT NULL,
    materialized_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, job_id)
);
CREATE INDEX IF NOT EXISTS idx_scan_snapshot_jobs_completed ON scan_snapshot_jobs (completed_at);
CREATE TABLE IF NOT EXISTS scan_snapshot_rows (
    tenant_id TEXT NOT NULL CHECK (length(btrim(tenant_id)) > 0),
    job_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    finding_identity TEXT NOT NULL,
    canonical_id TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT '',
    payload TEXT NOT NULL,
    PRIMARY KEY (tenant_id, job_id, ordinal)
);
CREATE INDEX IF NOT EXISTS idx_scan_snapshot_rows_job ON scan_snapshot_rows (tenant_id, job_id);
CREATE INDEX IF NOT EXISTS idx_scan_snapshot_rows_canonical ON scan_snapshot_rows (tenant_id, canonical_id) WHERE canonical_id <> '';
ALTER TABLE scan_snapshot_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_snapshot_jobs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scan_snapshot_jobs_tenant_isolation ON scan_snapshot_jobs;
CREATE POLICY scan_snapshot_jobs_tenant_isolation ON scan_snapshot_jobs USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant()) WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON scan_snapshot_jobs TO agent_bom_app, agent_bom_rls_maintenance;
ALTER TABLE scan_snapshot_rows ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_snapshot_rows FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scan_snapshot_rows_tenant_isolation ON scan_snapshot_rows;
CREATE POLICY scan_snapshot_rows_tenant_isolation ON scan_snapshot_rows USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant()) WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
GRANT SELECT, INSERT, UPDATE, DELETE ON scan_snapshot_rows TO agent_bom_app, agent_bom_rls_maintenance;
INSERT INTO control_plane_schema_versions(component,version,updated_at) VALUES ('scan_snapshots',1,now()) ON CONFLICT(component) DO UPDATE SET version=GREATEST(control_plane_schema_versions.version,1);
