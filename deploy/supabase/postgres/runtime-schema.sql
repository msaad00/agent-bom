-- Additive schema for stores that historically created their Postgres objects
-- from API process startup. This file is safe to replay. Keep readiness marker
-- rows last: their presence means every preceding DDL statement committed.

CREATE TABLE IF NOT EXISTS control_plane_schema_versions (
  component TEXT PRIMARY KEY, version INTEGER NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Complete the migration-owned shape of tables that already exist in the
-- historical baseline but previously relied on API bootstrap for newer
-- columns and indexes.
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS scim_subject_id TEXT;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS owner TEXT;
CREATE INDEX IF NOT EXISTS idx_api_keys_scim_subject ON api_keys(team_id,scim_subject_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_owner ON api_keys(team_id,owner);
CREATE INDEX IF NOT EXISTS idx_audit_log_team_action_ts ON audit_log(team_id,action,timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_team_resource_ts ON audit_log(team_id,resource text_pattern_ops,timestamp DESC);
ALTER TABLE fleet_agents ADD COLUMN IF NOT EXISTS canonical_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_fleet_canonical_id ON fleet_agents(canonical_id);
CREATE INDEX IF NOT EXISTS idx_fleet_tenant_state_trust_name ON fleet_agents(tenant_id,lifecycle_state,trust_score DESC,name);
CREATE INDEX IF NOT EXISTS idx_fleet_tenant_name_lower ON fleet_agents(tenant_id,LOWER(name));
CREATE INDEX IF NOT EXISTS idx_pg_jobs_team_created ON scan_jobs(team_id,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pg_jobs_batch ON scan_jobs(team_id,batch_id,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pg_jobs_parent ON scan_jobs(team_id,parent_job_id,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pg_jobs_schedule ON scan_jobs(team_id,schedule_id,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sched_tenant_due ON scan_schedules(tenant_id,enabled,next_run);
CREATE TABLE IF NOT EXISTS access_review_campaigns (campaign_id TEXT NOT NULL, tenant_id TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, due_at TEXT NOT NULL DEFAULT '', data TEXT NOT NULL, PRIMARY KEY (tenant_id,campaign_id));
CREATE TABLE IF NOT EXISTS access_review_items (item_id TEXT NOT NULL, campaign_id TEXT NOT NULL, tenant_id TEXT NOT NULL, subject_id TEXT NOT NULL, decision TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (tenant_id,item_id));
CREATE INDEX IF NOT EXISTS idx_access_review_campaigns_tenant ON access_review_campaigns(tenant_id,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_access_review_items_campaign ON access_review_items(tenant_id,campaign_id);

CREATE TABLE IF NOT EXISTS agent_identities (identity_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, status TEXT NOT NULL, issued_at TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS agent_identity_jit_grants (grant_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, identity_id TEXT NOT NULL, tool_name TEXT NOT NULL, status TEXT NOT NULL, requested_at TEXT NOT NULL, expires_at TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS agent_conditional_access_policies (policy_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, status TEXT NOT NULL, priority INTEGER NOT NULL, created_at TEXT NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_agent_identities_tenant ON agent_identities(tenant_id,status);
CREATE INDEX IF NOT EXISTS idx_agent_identities_hash ON agent_identities(token_hash);
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

CREATE TABLE IF NOT EXISTS runtime_observations (tenant_id TEXT NOT NULL, observation_id TEXT NOT NULL, session_id TEXT NOT NULL, observed_at TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(tenant_id,observation_id));
CREATE TABLE IF NOT EXISTS runtime_sessions (tenant_id TEXT NOT NULL, session_id TEXT NOT NULL, last_seen TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(tenant_id,session_id));
CREATE INDEX IF NOT EXISTS idx_runtime_observations_tenant_session_time ON runtime_observations(tenant_id,session_id,observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_runtime_sessions_tenant_last_seen ON runtime_sessions(tenant_id,last_seen DESC);

CREATE TABLE IF NOT EXISTS scim_users (tenant_id TEXT NOT NULL,user_id TEXT NOT NULL,external_id TEXT,user_name TEXT NOT NULL,active BOOLEAN NOT NULL DEFAULT TRUE,updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),data JSONB NOT NULL,PRIMARY KEY(tenant_id,user_id));
CREATE TABLE IF NOT EXISTS scim_groups (tenant_id TEXT NOT NULL,group_id TEXT NOT NULL,external_id TEXT,display_name TEXT NOT NULL,updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),data JSONB NOT NULL,PRIMARY KEY(tenant_id,group_id));
CREATE INDEX IF NOT EXISTS idx_scim_users_lookup ON scim_users(tenant_id,user_name,external_id);
CREATE INDEX IF NOT EXISTS idx_scim_groups_lookup ON scim_groups(tenant_id,display_name,external_id);

CREATE TABLE IF NOT EXISTS idempotency_keys (endpoint TEXT NOT NULL,tenant_id TEXT NOT NULL,source_id TEXT NOT NULL,idempotency_key TEXT NOT NULL,request_hash TEXT NOT NULL DEFAULT '',response_json TEXT NOT NULL,created_at TEXT NOT NULL,PRIMARY KEY(endpoint,tenant_id,source_id,idempotency_key));
CREATE INDEX IF NOT EXISTS idx_idempotency_created_at ON idempotency_keys(created_at);
CREATE TABLE IF NOT EXISTS proxy_replay_log (row_id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,captured_at TIMESTAMPTZ NOT NULL DEFAULT now(),not_after TIMESTAMPTZ NOT NULL,record JSONB NOT NULL);
CREATE INDEX IF NOT EXISTS idx_replay_not_after ON proxy_replay_log(not_after);
CREATE INDEX IF NOT EXISTS idx_replay_tenant ON proxy_replay_log(tenant_id);

CREATE TABLE IF NOT EXISTS tenant_quota_overrides (tenant_id TEXT PRIMARY KEY,updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),data JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS tenant_graph_retention_overrides (tenant_id TEXT PRIMARY KEY,updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),retention_days INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS tenant_score_config_overrides (tenant_id TEXT PRIMARY KEY,updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),data TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS mcp_client_configs (config_id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,name TEXT NOT NULL,profile_id TEXT NOT NULL,created_at TEXT NOT NULL,revoked BOOLEAN NOT NULL DEFAULT FALSE,data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_mcp_client_configs_tenant ON mcp_client_configs(tenant_id,created_at);
CREATE TABLE IF NOT EXISTS model_provider_keys (provider_key_id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,provider TEXT NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL,data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS model_virtual_keys (virtual_key_id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,provider_key_id TEXT NOT NULL,token_hash TEXT NOT NULL UNIQUE,status TEXT NOT NULL,issued_at TEXT NOT NULL,data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_model_provider_keys_tenant ON model_provider_keys(tenant_id,created_at);
CREATE INDEX IF NOT EXISTS idx_model_virtual_keys_tenant ON model_virtual_keys(tenant_id,issued_at);
CREATE INDEX IF NOT EXISTS idx_model_virtual_keys_hash ON model_virtual_keys(token_hash);

-- Simple JSON-record stores.
CREATE TABLE IF NOT EXISTS risk_campaign_workflows (tenant_id TEXT NOT NULL,campaign_id TEXT NOT NULL,owner TEXT,sla_due_at TEXT,state TEXT NOT NULL,verification_status TEXT NOT NULL,title TEXT NOT NULL DEFAULT '',member_ids TEXT NOT NULL DEFAULT '[]',membership_fingerprint TEXT NOT NULL DEFAULT '',generation INTEGER NOT NULL DEFAULT 1,active BOOLEAN NOT NULL DEFAULT TRUE,version INTEGER NOT NULL DEFAULT 1,updated_at TEXT NOT NULL,PRIMARY KEY(tenant_id,campaign_id));
CREATE INDEX IF NOT EXISTS idx_risk_campaign_workflows_tenant_state ON risk_campaign_workflows(tenant_id,state,updated_at DESC);
CREATE TABLE IF NOT EXISTS governance_audit_log (seq BIGSERIAL PRIMARY KEY,action_id TEXT NOT NULL,tenant_id TEXT NOT NULL,action TEXT NOT NULL,observed_at TEXT NOT NULL,record_hash TEXT NOT NULL,data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_governance_audit_tenant ON governance_audit_log(tenant_id,seq);
CREATE UNIQUE INDEX IF NOT EXISTS uq_governance_audit_tenant_action ON governance_audit_log(tenant_id,action_id);
CREATE TABLE IF NOT EXISTS scan_dispatch_queue (job_id TEXT PRIMARY KEY REFERENCES scan_jobs(job_id) ON DELETE CASCADE,tenant_id TEXT NOT NULL,created_at TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',claimed_by TEXT,lease_expires_at TEXT);
CREATE INDEX IF NOT EXISTS idx_dispatch_pending ON scan_dispatch_queue(status,created_at);

-- Current application schemas for connection/source/credential records.
CREATE TABLE IF NOT EXISTS cloud_connections (id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,provider TEXT NOT NULL,display_name TEXT NOT NULL,role_ref TEXT NOT NULL,external_id_encrypted TEXT NOT NULL DEFAULT '',regions TEXT NOT NULL DEFAULT '[]',status TEXT NOT NULL DEFAULT 'pending',status_detail TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,updated_at TEXT NOT NULL,last_scan_at TEXT,last_scan_id TEXT,scan_interval_minutes INTEGER,auth_params TEXT NOT NULL DEFAULT '{}',last_event_at TEXT);
CREATE INDEX IF NOT EXISTS idx_cloud_connections_tenant ON cloud_connections(tenant_id,created_at);
CREATE INDEX IF NOT EXISTS idx_cloud_connections_schedulable ON cloud_connections(scan_interval_minutes,last_scan_at);
CREATE TABLE IF NOT EXISTS control_plane_sources (source_id TEXT PRIMARY KEY,enabled INTEGER DEFAULT 1,tenant_id TEXT NOT NULL DEFAULT 'default',updated_at TEXT NOT NULL,data JSONB NOT NULL);
CREATE INDEX IF NOT EXISTS idx_control_plane_sources_tenant_updated ON control_plane_sources(tenant_id,updated_at DESC);
CREATE TABLE IF NOT EXISTS credential_refs (credential_ref_id TEXT PRIMARY KEY,enabled INTEGER DEFAULT 1,tenant_id TEXT NOT NULL DEFAULT 'default',updated_at TEXT NOT NULL,data JSONB NOT NULL);
CREATE INDEX IF NOT EXISTS idx_credential_refs_tenant_updated ON credential_refs(tenant_id,updated_at DESC);

-- Audit-chain checkpoint is separated from the append-only audit rows.
CREATE TABLE IF NOT EXISTS audit_chain_checkpoint (tenant_id TEXT PRIMARY KEY,entry_count BIGINT NOT NULL DEFAULT 0,head_signature TEXT NOT NULL DEFAULT '',updated_at TEXT NOT NULL DEFAULT '');

CREATE TABLE IF NOT EXISTS compliance_hub_findings (tenant_id TEXT NOT NULL,finding_id TEXT NOT NULL,ingested_at TEXT NOT NULL,source TEXT NOT NULL,applicable_frameworks_csv TEXT NOT NULL DEFAULT '',payload JSONB NOT NULL,ordinal BIGSERIAL NOT NULL,effective_reach_score DOUBLE PRECISION NOT NULL DEFAULT 0,origin TEXT NOT NULL DEFAULT '',severity TEXT NOT NULL DEFAULT '',severity_rank INTEGER NOT NULL DEFAULT 0,cvss_score DOUBLE PRECISION NOT NULL DEFAULT 0,PRIMARY KEY(tenant_id,finding_id));
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
CREATE TABLE IF NOT EXISTS hub_cve_intel (tenant_id TEXT NOT NULL,cve_id TEXT NOT NULL,payload JSONB NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(tenant_id,cve_id));
CREATE TABLE IF NOT EXISTS hub_framework_refs (tenant_id TEXT NOT NULL,framework_ref TEXT NOT NULL,payload JSONB NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(tenant_id,framework_ref));
CREATE TABLE IF NOT EXISTS agent_bom_hub_backfills (name TEXT PRIMARY KEY,completed_at TEXT NOT NULL);

-- Apply identical FORCE RLS policy semantics to all tenant-owned additions.
DO $rls$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'access_review_campaigns','access_review_items','agent_identities','agent_identity_jit_grants','agent_conditional_access_policies',
    'ai_system_blueprints','ai_system_blueprint_versions','runtime_observations','runtime_sessions','scim_users','scim_groups',
    'idempotency_keys','proxy_replay_log','tenant_quota_overrides','tenant_graph_retention_overrides','tenant_score_config_overrides',
    'mcp_client_configs','model_provider_keys','model_virtual_keys','risk_campaign_workflows','governance_audit_log','cloud_connections',
    'control_plane_sources','credential_refs','audit_chain_checkpoint','compliance_hub_findings','hub_findings_current',
    'hub_findings_current_observations','hub_cve_intel','hub_framework_refs'
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
END $grant$;

-- Readiness markers: deliberately last.
INSERT INTO control_plane_schema_versions(component,version,updated_at)
SELECT component,1,now() FROM unnest(ARRAY[
 'scan_jobs','api_keys','exceptions','audit_log','trend_history','gateway_policies','schedules','sources','credential_refs','llm_costs',
 'cloud_connections','compliance_hub','access_review_campaigns','risk_campaign_workflows','fleet','graph','scan_cache','identity_scim',
 'agent_identities','runtime_events','tenant_quotas','tenant_graph_retention','idempotency','proxy_replay_log','rate_limits',
 'shared_auth_state','governance_audit_log','ai_system_blueprints','mcp_client_configs','model_provider_keys','tenant_score_config'
]) component
ON CONFLICT(component) DO UPDATE SET version=excluded.version,updated_at=excluded.updated_at;
