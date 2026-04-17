"""Bootstrap the enterprise control-plane schema from the Postgres baseline SQL."""

from __future__ import annotations

import sys
from pathlib import Path

from alembic import op

# revision identifiers, used by Alembic.
revision = "20260416_01"
down_revision = None
branch_labels = None
depends_on = None

_ALEMBIC_ROOT = Path(__file__).resolve().parents[1]
if str(_ALEMBIC_ROOT) not in sys.path:
    sys.path.append(str(_ALEMBIC_ROOT))

from bootstrap import load_bootstrap_sql  # noqa: E402


def upgrade() -> None:
    bind = op.get_bind()
    database_name = bind.exec_driver_sql("SELECT current_database()").scalar_one()
    bootstrap_sql = load_bootstrap_sql(database_name)
    bind.exec_driver_sql(bootstrap_sql)


def downgrade() -> None:  # pragma: no cover - baseline downgrade is intentionally manual
    raise NotImplementedError(
        "The baseline control-plane migration is not automatically reversible. "
        "Restore from backup or recreate the database for a full teardown."
    )
