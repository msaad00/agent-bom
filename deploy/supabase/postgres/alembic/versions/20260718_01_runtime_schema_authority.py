"""Move control-plane runtime store schema ownership into migrations."""

from __future__ import annotations

import sys
from pathlib import Path

from alembic import op

revision = "20260718_01"
down_revision = "20260717_03"
branch_labels = None
depends_on = None

_ALEMBIC_ROOT = Path(__file__).resolve().parents[1]
if str(_ALEMBIC_ROOT) not in sys.path:
    sys.path.append(str(_ALEMBIC_ROOT))

from bootstrap import load_runtime_schema_sql  # noqa: E402


def upgrade() -> None:
    op.get_bind().exec_driver_sql(load_runtime_schema_sql(), execution_options={"no_parameters": True})


def downgrade() -> None:
    raise NotImplementedError("Runtime schema authority migration is additive and intentionally irreversible.")
