"""Version-one PostgreSQL job revision DDL shared by bootstrap and migration.

Keep this migration contract immutable; later schema changes need a new version.
Revision rows survive job and tenant deletion so empty estates invalidate caches.
"""

from typing import TYPE_CHECKING

from agent_bom.api.postgres_common import _tenant_connection
from agent_bom.api.store import _require_tenant_scope

if TYPE_CHECKING:
    from psycopg_pool import ConnectionPool


def read_postgres_job_revision(pool: "ConnectionPool", tenant_id: str) -> str:
    """Read the committed tenant token without decoding scan-job payloads."""
    _require_tenant_scope(tenant_id, False, "PostgresJobStore.overview_evidence_revision()")
    with _tenant_connection(pool) as conn:
        row = conn.execute("SELECT generation, revision FROM job_overview_revisions WHERE tenant_id=%s", (tenant_id,)).fetchone()
    return f"{row[0]}:{row[1]}" if row is not None else "empty"


POSTGRES_JOB_REVISIONS_V1 = """
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
"""
