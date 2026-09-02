"""Provision the retained observation window under the migration owner.

Runtime Postgres roles are DML-only. Historical evidence inside the configured
retention horizon therefore needs migration-owned child partitions just like
current and future evidence. This revision applies the expanded bounded window
to existing deployments; the Alembic post-upgrade hook keeps it topped up.

Revision ID: 20260901_01
Revises: 20260830_03
"""

from __future__ import annotations

import sys
from pathlib import Path

from alembic import op

revision = "20260901_01"
down_revision = "20260830_03"
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
    provision_observation_partition_runway(bind.connection.driver_connection)


def downgrade() -> None:
    # Forward-only: a child may already contain retained observation evidence.
    return
