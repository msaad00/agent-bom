"""Add the database-owned verifier for signed tenant-binding claims.

The shared application role may set any two-part custom GUC, so
``app.tenant_id`` cannot by itself be an identity boundary.  This migration
adds the key authority and verifier needed for a later application rollout.
It intentionally does not replace ``abom_current_tenant`` yet: issuers,
database keys, and runtime session binding must be deployed and observed
before RLS starts rejecting unsigned sessions.

Revision ID: 20260819_01
Revises: 20260818_01
"""

from __future__ import annotations

from alembic import op

revision = "20260819_01"
down_revision = "20260818_01"
branch_labels = None
depends_on = None


_AUTHORITY_DDL = r"""
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS public.agent_bom_tenant_binding_keys (
  key_id TEXT PRIMARY KEY CHECK (key_id ~ '^[0-9a-f]{64}$'),
  key_material BYTEA NOT NULL CHECK (octet_length(key_material) >= 32),
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

COMMENT ON TABLE public.agent_bom_tenant_binding_keys IS
  'Schema-owner-only HMAC keys used to verify bounded tenant-binding claims';

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
  )
    INTO v_verified;

  RETURN COALESCE(v_verified, FALSE);
END
$function$;

REVOKE ALL ON TABLE public.agent_bom_tenant_binding_keys FROM PUBLIC;
REVOKE ALL ON FUNCTION public.abom_verify_tenant_binding_claim(TEXT, BIGINT, TEXT, TEXT) FROM PUBLIC;

DO $roles$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_app') THEN
    EXECUTE 'REVOKE ALL ON TABLE public.agent_bom_tenant_binding_keys FROM agent_bom_app';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.abom_verify_tenant_binding_claim(TEXT, BIGINT, TEXT, TEXT) TO agent_bom_app';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_readonly') THEN
    EXECUTE 'REVOKE ALL ON TABLE public.agent_bom_tenant_binding_keys FROM agent_bom_readonly';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_rls_maintenance') THEN
    EXECUTE 'REVOKE ALL ON TABLE public.agent_bom_tenant_binding_keys FROM agent_bom_rls_maintenance';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_maintenance') THEN
    EXECUTE 'REVOKE ALL ON TABLE public.agent_bom_tenant_binding_keys FROM agent_bom_maintenance';
  END IF;
END
$roles$;
"""


def upgrade() -> None:
    op.execute(_AUTHORITY_DDL)


def downgrade() -> None:
    # Forward-only: removing the verifier or its rotation keys before the
    # application/RLS stages are rolled back would fail open or strand active
    # sessions.  Preserve the authority and require an explicit forward fix.
    raise NotImplementedError("tenant-binding authority downgrade is intentionally forward-only")
