"""What a ``min_severity`` floor means, defined once for every read path.

Only finding-like nodes carry a severity: a vulnerability, a misconfiguration
and a drift incident are rated, while the agents, servers, packages, cloud
resources and identities they hang off all rank 0. So a floor applied to
*every* node does not narrow the estate — it deletes the estate and leaves the
findings floating unattached, which is the difference between "here are your
critical findings and what they sit on" and "here are seven dots".

Every backend and every read path answers this one question, so it lives here
rather than being re-derived per store: :func:`node_passes_severity_floor` for
in-memory rows, :func:`severity_floor_sql` for a pushed-down WHERE fragment on
either driver's placeholder style. The SQL and the predicate are pinned against
each other by ``tests/test_graph_backend_semantics.py``.
"""

from __future__ import annotations

from typing import Any

from agent_bom.graph.ocsf import FINDING_ENTITY_TYPES
from agent_bom.graph.severity import SEVERITY_RANK

#: Entity types a severity floor is allowed to filter on. Everything else is
#: topology and survives any floor.
FINDING_ENTITY_VALUES: tuple[str, ...] = tuple(sorted(entity_type.value for entity_type in FINDING_ENTITY_TYPES))


def node_passes_severity_floor(
    *,
    entity_type: Any,
    severity: str = "",
    severity_id: int | None = None,
    min_severity_rank: int = 0,
) -> bool:
    """Whether a node survives ``min_severity_rank``.

    ``severity_id`` (the stored OCSF id) is preferred when a caller has it;
    both scales are 0-5 and agree, so the string is an equivalent fallback.
    """
    if not min_severity_rank:
        return True
    value = entity_type.value if hasattr(entity_type, "value") else str(entity_type)
    if value not in FINDING_ENTITY_VALUES:
        return True
    rank = int(severity_id) if severity_id is not None else SEVERITY_RANK.get((severity or "").lower(), 0)
    return rank >= min_severity_rank


def severity_floor_sql(
    min_severity_rank: int,
    *,
    column: str = "severity_id",
    entity_column: str = "entity_type",
    placeholder: str = "?",
) -> tuple[str, list[Any]]:
    """Build the same judgement as a WHERE fragment.

    ``placeholder`` is ``?`` for SQLite and ``%s`` for psycopg. Returns
    ``(sql, params)``; ``sql`` is empty when no floor is requested, so callers
    can append it unconditionally.
    """
    if not min_severity_rank:
        return "", []
    placeholders = ",".join(placeholder for _ in FINDING_ENTITY_VALUES)
    sql = f"({column} >= {placeholder} OR {entity_column} NOT IN ({placeholders}))"
    return sql, [min_severity_rank, *FINDING_ENTITY_VALUES]
