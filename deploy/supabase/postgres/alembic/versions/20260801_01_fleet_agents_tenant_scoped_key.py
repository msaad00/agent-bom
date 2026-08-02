"""Key ``fleet_agents`` by tenant so one customer cannot squat another's agent.

``fleet_agents`` was ``PRIMARY KEY (agent_id)`` with no tenant component, while
the store upserts ``ON CONFLICT (agent_id) DO UPDATE``.  Postgres locates the
conflicting row through the unique index, which is *not* RLS-filtered, so the
``DO UPDATE`` targets a row the second tenant cannot see and the write is
rejected by the row-level security policy.  ``canonical_ids.canonical_agent_id``
derives IDs as a UUIDv5 over content with no tenant component, so two customers
running a stock agent of the same type collide on sight and the first to
register wins permanently.

Why the composite key rather than the ``20260729_01`` trigger idiom
──────────────────────────────────────────────────────────────────
``policy_audit_log.entry_id`` is a write-side dedup key whose caller-visible
value is read back from ``logical_entry_id``/the JSON payload, so rewriting the
physical key was invisible to readers.  ``fleet_agents.agent_id`` is the
*lookup* key: ``get``/``delete``/``update_state``/the ``/v1/fleet/{agent_id}``
route all address rows by it.  Rewriting it into a tenant-derived physical value
would keep a mixed-version fleet writing happily while silently handing old
replicas opaque IDs that no longer resolve — trading a loud failure for a quiet
wrong answer.

Rolling-deploy note (deliberate, not an oversight): a replica still running the
old ``ON CONFLICT (agent_id)`` SQL cannot infer a composite arbiter index and
will error on agent registration until it is replaced.  That is a loud,
transient, self-healing failure of one write path, against a permanent silent
denial of service to every tenant after the first.  Reads on old replicas are
unaffected — they are already tenant-scoped.

Revision ID: 20260801_01
Revises: 20260731_01
"""

from __future__ import annotations

from alembic import op

revision = "20260801_01"
down_revision = "20260731_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.exec_driver_sql("SELECT to_regclass('public.fleet_agents')").scalar() is None:
        return

    already_scoped = bind.exec_driver_sql(
        """
        SELECT EXISTS (
            SELECT 1
              FROM pg_index x
              JOIN pg_attribute a ON a.attrelid = x.indrelid AND a.attnum = ANY (x.indkey)
             WHERE x.indrelid = 'public.fleet_agents'::regclass
               AND x.indisprimary
               AND a.attname = 'tenant_id'
        )
        """
    ).scalar()
    if already_scoped:
        return

    # A row without a tenant cannot participate in a tenant-scoped key, and RLS
    # would never have matched it anyway.
    op.execute("UPDATE fleet_agents SET tenant_id = 'default' WHERE tenant_id IS NULL")

    # Build the replacement key without holding a write lock for the duration.
    with op.get_context().autocommit_block():
        op.execute("CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_fleet_agents_tenant_agent ON fleet_agents(tenant_id, agent_id)")

    # Swapping the primary key needs the exclusive lock anyway; the table is a
    # small governance ledger, and the index above is already built so the lock
    # is held only for the catalog swap.
    op.execute(
        """
        DO $$
        DECLARE
            had_rls BOOLEAN;
            had_force_rls BOOLEAN;
        BEGIN
            LOCK TABLE fleet_agents IN ACCESS EXCLUSIVE MODE;

            SELECT relrowsecurity, relforcerowsecurity
              INTO had_rls, had_force_rls
              FROM pg_class
             WHERE oid = 'public.fleet_agents'::regclass;

            -- The migration owner must see every tenant while re-keying. The
            -- table lock prevents runtime access and the prior RLS posture is
            -- restored before commit.
            IF had_rls THEN
                ALTER TABLE fleet_agents DISABLE ROW LEVEL SECURITY;
            END IF;

            ALTER TABLE fleet_agents ALTER COLUMN tenant_id SET NOT NULL;
            ALTER TABLE fleet_agents ALTER COLUMN tenant_id SET DEFAULT 'default';

            IF EXISTS (
                SELECT 1 FROM pg_constraint
                 WHERE conrelid = 'public.fleet_agents'::regclass
                   AND contype = 'p'
            ) THEN
                ALTER TABLE fleet_agents DROP CONSTRAINT fleet_agents_pkey;
            END IF;

            ALTER TABLE fleet_agents
                ADD CONSTRAINT fleet_agents_pkey PRIMARY KEY USING INDEX uq_fleet_agents_tenant_agent;

            COMMENT ON CONSTRAINT fleet_agents_pkey ON fleet_agents IS
                'Tenant-scoped fleet identity; agent_id is unique within a tenant, never across the estate';

            IF had_rls THEN
                ALTER TABLE fleet_agents ENABLE ROW LEVEL SECURITY;
            END IF;
            IF had_force_rls THEN
                ALTER TABLE fleet_agents FORCE ROW LEVEL SECURITY;
            END IF;
        END
        $$
        """
    )


def downgrade() -> None:
    raise NotImplementedError(
        "Tenant-scoped fleet identity is forward-only: once two tenants hold the same agent_id, "
        "restoring the global key would have to discard one of them."
    )
