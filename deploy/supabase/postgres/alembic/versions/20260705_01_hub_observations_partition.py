"""Partition hub_findings_current_observations by observed_at (#3463).

Foundation migration for monthly RANGE partitions. Safe to run on databases
that already use the partitioned parent (no-op). Existing unpartitioned tables
are converted via the shared ``migrate_observations_to_partitioned`` helper.

Follow-up: wire automatic partition creation on every ingest path and add
operator runbook for large-table maintenance windows.
"""

from __future__ import annotations

import sys
from pathlib import Path

from alembic import op

# revision identifiers, used by Alembic.
revision = "20260705_01"
down_revision = "20260530_01"
branch_labels = None
depends_on = None

_REPO_ROOT = Path(__file__).resolve().parents[5]
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from agent_bom.api.hub_observations_partition import (  # noqa: E402
    ensure_observation_partitions,
    migrate_observations_to_partitioned,
)


def upgrade() -> None:
    bind = op.get_bind()
    # The shared helper is also used by the runtime psycopg pool and therefore
    # intentionally uses psycopg's ``execute(sql, tuple)`` contract.  Alembic
    # exposes a SQLAlchemy Connection, whose parameter contract is different;
    # unwrap the DBAPI connection while retaining Alembic's transaction.
    driver_connection = bind.connection.driver_connection
    migrated = migrate_observations_to_partitioned(driver_connection)
    if migrated:
        ensure_observation_partitions(driver_connection)


def downgrade() -> None:
    raise NotImplementedError(
        "Downgrading hub_findings_current_observations partitioning is not "
        "supported automatically. Restore from backup if rollback is required."
    )
