"""Immutable campaign evidence queue DDL shared by migration and bootstrap."""

POSTGRES_CAMPAIGN_EVIDENCE_V1 = """
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
"""
