"""Extend the hub observations partition runway to a full year.

``20260705_01`` provisioned only a ``behind=1 / ahead=2`` window at migration
time, so a head database carried roughly three months of runway. Nothing at
runtime can extend it: ``init.sql`` grants ``agent_bom_app`` USAGE but revokes
CREATE on schema ``public``, ``agent_bom_maintenance`` is equally DML-only, and
the children are owned by the migration role. Once the last provisioned month
elapsed, every current-dated hub ingest failed permanently with HTTP 500.

This tops the runway up to at least 12 months ahead. The same helper also runs
after every ``alembic upgrade`` (see ``alembic/env.py``) so each deploy tops the
runway up instead of it being fixed once.

Each new child gets ``ENABLE``/``FORCE ROW LEVEL SECURITY`` plus the tenant
isolation policy — partition children do not inherit them, and skipping that
would reopen the cross-tenant hole ``20260729_03`` closed.

Revision ID: 20260731_01
Revises: 20260730_02
"""

from __future__ import annotations

import sys
from pathlib import Path

from alembic import op

revision = "20260731_01"
down_revision = "20260730_02"
branch_labels = None
depends_on = None

_REPO_ROOT = Path(__file__).resolve().parents[5]
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agent_bom.api.hub_observations_partition import (  # noqa: E402
    provision_observation_partition_runway,
)


def upgrade() -> None:
    bind = op.get_bind()
    # The shared helper uses psycopg's ``execute(sql, tuple)`` contract; unwrap
    # the DBAPI connection while retaining Alembic's transaction (as 20260705_01).
    provision_observation_partition_runway(bind.connection.driver_connection)


def downgrade() -> None:
    # Deliberately irreversible: dropping provisioned future partitions would
    # discard ingested observations and re-create the ingest cliff.
    pass
