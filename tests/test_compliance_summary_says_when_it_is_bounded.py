"""A bounded compliance read must say so, in the vocabulary clients speak.

`/v1/graph/compliance` is a leadership-facing surface: it answers "how does the
estate score against NIST / CIS / SOC2". Its two backends disagreed about how —
and whether — to admit that the answer was cut short.

* Postgres bounds the read at 50,000 tagged nodes and reported
  ``{"status": "partial", "reason": "node_budget", "node_budget": 50000}``.
* SQLite read every tagged node and reported **no completeness key at all**.

`graph/completeness.py` already defines the shared vocabulary, and the UI type
`GraphCompleteness` publishes it: ``status`` is one of ``complete`` /
``truncated`` / ``sampled``, alongside ``complete`` / ``truncated`` / ``sampled``
booleans and a ``returned`` count. ``"partial"`` is in neither.

The consequence is not cosmetic, and it is worse than a missing field. The
client-side reader `graphResponseIsTruncated` treats ``completeness`` as
authoritative the moment it is present: it returns ``completeness.truncated ===
true`` and never falls back to ``pagination.has_more``. So an envelope carrying
a status word but no booleans reads as *not truncated* **and** suppresses the
fallback that would otherwise have caught it. That is pinned from the client
side in `ui/tests/completeness-envelope-contract.test.ts`.

`node_context` is the one of the two with a rendering consumer today — the
inventory asset drawer (`api/routes/inventory_assets.py`) — where a
neighbourhood cut off at the 10,000-edge budget claimed to be the whole one.
`compliance_summary` is an API/MCP surface with no UI consumer yet; the point
there is that a leadership-facing score must not answer from a silently bounded
denominator on either backend.

The identical defect was already fixed for `impact_of` — see the comment at
`postgres_graph.py`, "Was a bare 'partial'/'complete' string here and absent
entirely on SQLite: one field, two shapes". Its two sibling call sites were
missed. This pins the contract so a third shape cannot appear.
"""

from __future__ import annotations

import pytest

from agent_bom.graph.completeness import graph_completeness

VALID_STATUSES = {"complete", "truncated", "sampled"}


def assert_speaks_the_shared_vocabulary(completeness: object, *, who: str) -> None:
    assert isinstance(completeness, dict), f"{who} returned no completeness envelope"
    status = completeness.get("status")
    assert status in VALID_STATUSES, f"{who} reported status {status!r}, which no client branches on"
    # The booleans exist so clients never have to parse the string, which is
    # exactly the mistake that let "partial" pass silently.
    for key in ("complete", "truncated", "sampled"):
        assert isinstance(completeness.get(key), bool), f"{who} omitted the {key!r} boolean"
    assert completeness["complete"] is (status == "complete"), f"{who} disagrees with its own status"
    assert isinstance(completeness.get("returned"), int), f"{who} did not say how much it returned"


def test_the_shared_helper_never_emits_partial() -> None:
    """The vocabulary itself, so the assertions above are pinned to something."""
    for truncated in (False, True):
        assert graph_completeness(returned=5, truncated=truncated)["status"] in VALID_STATUSES


def test_sqlite_compliance_summary_reports_its_completeness() -> None:
    from agent_bom.api.graph_store import SQLiteGraphStore

    store = SQLiteGraphStore()
    summary = store.compliance_summary(tenant_id="")
    assert_speaks_the_shared_vocabulary(summary.get("completeness"), who="SQLite compliance_summary")


def test_sqlite_compliance_summary_reports_completeness_when_empty() -> None:
    """The no-snapshot path returned early, skipping the envelope entirely."""
    from agent_bom.api.graph_store import SQLiteGraphStore

    store = SQLiteGraphStore()
    summary = store.compliance_summary(tenant_id="", scan_id="no-such-scan")
    assert_speaks_the_shared_vocabulary(summary.get("completeness"), who="SQLite compliance_summary (empty)")


@pytest.mark.parametrize("method", ["compliance_summary", "node_context"])
def test_postgres_read_paths_do_not_invent_a_status(method: str) -> None:
    """Both Postgres sites hand-rolled `"partial"`; neither may any longer.

    Read as source rather than executed against a live Postgres, so the contract
    is pinned on every runner rather than only where a database is available.
    """
    import inspect

    from agent_bom.api.postgres_graph import PostgresGraphStore

    source = inspect.getsource(getattr(PostgresGraphStore, method))
    assert '"partial"' not in source, (
        f"PostgresGraphStore.{method} still emits the literal 'partial', which is not "
        "one of complete/truncated/sampled and which the completeness banner ignores"
    )
    assert "graph_completeness(" in source, (
        f"PostgresGraphStore.{method} should build its envelope with the shared helper rather than a fourth hand-rolled dict"
    )
