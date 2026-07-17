"""Align graph snapshot JSON columns with the application TEXT contract.

Revision ID: 20260717_03
Revises: 20260717_02
"""

from __future__ import annotations

from alembic import op

revision = "20260717_03"
down_revision = "20260717_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Existing installations may have either TEXT (application bootstrap) or
    # JSONB (init.sql/Alembic bootstrap). ``::text`` preserves both forms as
    # valid JSON text, and each statement is safe to replay.
    op.execute("""
        ALTER TABLE graph_snapshots
            ALTER COLUMN risk_summary DROP DEFAULT,
            ALTER COLUMN risk_summary TYPE TEXT USING risk_summary::text,
            ALTER COLUMN risk_summary SET DEFAULT '{}'
    """)
    op.execute("""
        ALTER TABLE graph_snapshots
            ALTER COLUMN analysis_status DROP DEFAULT,
            ALTER COLUMN analysis_status TYPE TEXT USING analysis_status::text,
            ALTER COLUMN analysis_status SET DEFAULT '{}'
    """)
    op.execute("UPDATE graph_snapshots SET analysis_status = '{}' WHERE analysis_status IS NULL")
    op.execute("ALTER TABLE graph_snapshots ALTER COLUMN analysis_status SET NOT NULL")


def downgrade() -> None:
    op.execute("""
        ALTER TABLE graph_snapshots
            ALTER COLUMN risk_summary DROP DEFAULT,
            ALTER COLUMN risk_summary TYPE JSONB USING
                CASE WHEN risk_summary IS NULL THEN NULL
                     WHEN btrim(risk_summary) = '' THEN '{}'::jsonb
                     ELSE risk_summary::jsonb END,
            ALTER COLUMN risk_summary SET DEFAULT '{}'::jsonb
    """)
    op.execute("""
        ALTER TABLE graph_snapshots
            ALTER COLUMN analysis_status DROP DEFAULT,
            ALTER COLUMN analysis_status TYPE JSONB USING
                CASE WHEN analysis_status IS NULL OR btrim(analysis_status) = '' THEN '{}'::jsonb
                     ELSE analysis_status::jsonb END,
            ALTER COLUMN analysis_status SET DEFAULT '{}'::jsonb,
            ALTER COLUMN analysis_status SET NOT NULL
    """)
