"""Add secret-minimal managed-trial invitations.

Revision ID: 20260724_03
Revises: 20260724_02
"""

from __future__ import annotations

from alembic import op

revision = "20260724_03"
down_revision = "20260724_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS managed_trial_invitations (
            invitation_id TEXT PRIMARY KEY,
            token_digest TEXT NOT NULL UNIQUE CHECK (token_digest ~ '^[0-9a-f]{64}$'),
            email TEXT NOT NULL,
            tenant_id TEXT NOT NULL REFERENCES teams(team_id) ON DELETE CASCADE,
            state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'accepted', 'expired', 'revoked')),
            created_at TIMESTAMPTZ NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            accepted_at TIMESTAMPTZ,
            CHECK (expires_at > created_at),
            CHECK (
                (state = 'accepted' AND accepted_at IS NOT NULL)
                OR (state IN ('pending', 'expired') AND accepted_at IS NULL)
                OR state = 'revoked'
            )
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_managed_trial_invitations_tenant_state "
        "ON managed_trial_invitations(tenant_id, state, expires_at)"
    )
    op.execute("ALTER TABLE managed_trial_invitations ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE managed_trial_invitations FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        DO $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1 FROM pg_policies
            WHERE schemaname = current_schema()
              AND tablename = 'managed_trial_invitations'
              AND policyname = 'managed_trial_invitations_tenant_isolation'
          ) THEN
            CREATE POLICY managed_trial_invitations_tenant_isolation ON managed_trial_invitations
              USING (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant())
              WITH CHECK (public.abom_rls_bypass() OR tenant_id = public.abom_current_tenant());
          END IF;
        END $$
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
          IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_app') THEN
            GRANT SELECT, INSERT, UPDATE, DELETE ON managed_trial_invitations TO agent_bom_app;
          END IF;
        END $$
        """
    )
    op.execute(
        """
        INSERT INTO control_plane_schema_versions(component, version, updated_at)
        VALUES ('managed_trial_invitations', 1, now())
        ON CONFLICT(component) DO UPDATE SET
            version = EXCLUDED.version,
            updated_at = EXCLUDED.updated_at
        """
    )


def downgrade() -> None:
    # Invitation records are security/audit state. Preserve them on rollback.
    pass
