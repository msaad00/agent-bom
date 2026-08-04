"""Guards for pushing the ``severity`` facet predicate down into the store.

Every facet dimension except ``severity`` itself is already gated on
``severity_matches``, so a ``?severity=critical`` request only needs
severity-matching rows resident — except for the self-excluding severity
histogram, which the store can answer with an indexed ``GROUP BY``.

These guards assert *shape*, never wall-clock: which predicate reaches the
store, how many rows the walk visits relative to the matching subset, and that
the walked cost does not grow with the non-matching remainder of the table.
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, set_compliance_hub_store
from agent_bom.api.server import set_job_store
from agent_bom.api.store import InMemoryJobStore

SEVERITY_CYCLE = ("critical", "high", "medium", "low", "info")


@pytest.fixture(autouse=True)
def _stores() -> Any:
    set_job_store(InMemoryJobStore())
    set_compliance_hub_store(InMemoryComplianceHubStore())
    yield
    set_job_store(InMemoryJobStore())
    set_compliance_hub_store(InMemoryComplianceHubStore())


def _row(index: int) -> dict[str, Any]:
    return {
        "id": f"finding-{index}",
        "canonical_id": f"finding-{index}",
        "finding_type": "CVE",
        "source": "SBOM",
        "cve_id": f"CVE-2026-{1000 + index}",
        "security_domain": "vuln",
        "severity": SEVERITY_CYCLE[index % len(SEVERITY_CYCLE)],
        "origin": "bulk_ingest",
        "status": "open",
    }


def _install_counting_stream(
    monkeypatch: pytest.MonkeyPatch,
    total_rows: int,
) -> dict[str, Any]:
    """Model a store that honours the ``severity`` kwarg as a SQL predicate.

    ``visited`` counts the rows the store actually had to hand to the walk, which
    is the cost the pushdown is supposed to reduce.
    """
    state: dict[str, Any] = {"visited": 0, "kwargs": [], "breakdown_calls": 0}

    def _iter(_tenant_id: str, **kwargs: Any) -> Any:
        state["kwargs"].append(kwargs)
        wanted = kwargs.get("severity")

        def _gen() -> Any:
            for index in range(total_rows):
                row = _row(index)
                if wanted is not None and row["severity"] != wanted:
                    # A pushed-down predicate is resolved by the store; the row
                    # never reaches the Python walk and costs it nothing.
                    continue
                state["visited"] += 1
                yield row

        return _gen()

    monkeypatch.setattr("agent_bom.export.runner.iter_current_findings", _iter)

    class _Hub:
        def current_severity_breakdown(self, _tenant_id: str, **_kwargs: Any) -> dict[str, int]:
            state["breakdown_calls"] += 1
            counts = {key: 0 for key in ("critical", "high", "medium", "low", "info", "unknown")}
            for index in range(total_rows):
                counts[_row(index)["severity"]] += 1
            return counts

    monkeypatch.setattr(
        "agent_bom.api.compliance_hub_store.get_compliance_hub_store",
        lambda: _Hub(),
    )
    return state


def test_severity_filter_reaches_the_store_instead_of_a_python_walk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The selective predicate must be handed to the store, not filtered after."""
    from agent_bom.api.routes.scan import _finding_facets_bounded

    state = _install_counting_stream(monkeypatch, total_rows=500)

    _finding_facets_bounded(
        "tenant-pushdown",
        severity="critical",
        scan_id=None,
        since=None,
        scope={},
        status="all",
        scan_budget=10_000,
        deadline_seconds=60,
    )

    assert state["kwargs"], "the facet pass never queried the store"
    assert state["kwargs"][0]["severity"] == "critical", (
        "severity was not pushed into the store query; the walk still filters in Python"
    )


def test_facet_walk_visits_only_rows_matching_the_severity_filter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cost tracks the matching subset, not the tenant's whole current stream."""
    from agent_bom.api.routes.scan import _finding_facets_bounded

    total_rows = 500
    state = _install_counting_stream(monkeypatch, total_rows=total_rows)

    _facets, total, metadata = _finding_facets_bounded(
        "tenant-pushdown",
        severity="critical",
        scan_id=None,
        since=None,
        scope={},
        status="all",
        scan_budget=10_000,
        deadline_seconds=60,
    )

    expected_matches = total_rows // len(SEVERITY_CYCLE)
    assert total == expected_matches
    assert state["visited"] == expected_matches, (
        f"walk visited {state['visited']} rows to count {expected_matches} critical findings"
    )
    assert metadata["scanned_rows"] == expected_matches


def test_facet_cost_stays_flat_as_the_non_matching_remainder_grows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """N vs 4N in one process: only the matching subset may drive the walk.

    Without pushdown the walk visits every row, so quadrupling the table
    quadruples the visited count for a fixed-selectivity filter. The guard pins
    the ratio to the matching subset's growth, which is the same 4x — so it is
    expressed as "visited == matches" at both sizes, which is only true when the
    predicate is resolved by the store.
    """
    from agent_bom.api.routes.scan import _finding_facets_bounded

    observed: list[tuple[int, int]] = []
    for total_rows in (500, 2000):
        state = _install_counting_stream(monkeypatch, total_rows=total_rows)
        _finding_facets_bounded(
            "tenant-pushdown",
            severity="critical",
            scan_id=None,
            since=None,
            scope={},
            status="all",
            scan_budget=100_000,
            deadline_seconds=60,
        )
        observed.append((total_rows, state["visited"]))

    for total_rows, visited in observed:
        assert visited == total_rows // len(SEVERITY_CYCLE), (
            f"at {total_rows} rows the walk visited {visited}; the non-matching "
            "remainder is still being paid for in Python"
        )


def test_severity_facet_stays_self_excluding_under_pushdown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pushdown must not collapse the severity histogram to the active filter.

    The severity dimension excludes its own filter by contract, so it still has
    to report every band — sourced from the store's indexed aggregate rather
    than from the (now severity-filtered) walk.
    """
    from agent_bom.api.routes.scan import _finding_facets_bounded

    total_rows = 500
    state = _install_counting_stream(monkeypatch, total_rows=total_rows)

    facets, _total, _metadata = _finding_facets_bounded(
        "tenant-pushdown",
        severity="critical",
        scan_id=None,
        since=None,
        scope={},
        status="all",
        scan_budget=10_000,
        deadline_seconds=60,
    )

    per_band = total_rows // len(SEVERITY_CYCLE)
    assert facets["severity"] == {
        "critical": per_band,
        "high": per_band,
        "medium": per_band,
        "low": per_band,
        "info": per_band,
        "unknown": 0,
    }
    assert state["breakdown_calls"] == 1, "the self-excluding histogram was not served by the store aggregate"


@pytest.mark.parametrize("band", ["info", "informational", "unknown"])
def test_aliased_severity_bands_are_never_pushed_down(band: str) -> None:
    """Regression: the store predicate is narrower than the walk for these bands.

    ``LOWER(severity) = 'info'`` does not select rows persisted as
    ``informational``, and the ``severity <> ''`` guard excludes the blank
    severities the walk folds into ``unknown``. Pushing either band down drops
    rows, so both must stay on the exact walk.
    """
    from agent_bom.api.routes.scan import _facet_severity_histogram

    assert (
        _facet_severity_histogram(
            "tenant-alias", severity=band, scan_id=None, since=None, scope={}, status="all"
        )
        is None
    )


def test_severity_alias_rows_survive_a_filtered_facet_request() -> None:
    """End-to-end form of the same regression, over the real store."""
    from agent_bom.api.routes.scan import _finding_facets_bounded

    store = InMemoryComplianceHubStore()
    rows = [
        {"id": "a", "finding_type": "CVE", "source": "SBOM", "severity": "informational", "origin": "bulk_ingest"},
        {"id": "b", "finding_type": "CVE", "source": "SBOM", "severity": "info", "origin": "bulk_ingest"},
        {"id": "c", "finding_type": "CVE", "source": "SBOM", "severity": "critical", "origin": "bulk_ingest"},
    ]
    store.add("tenant-alias", rows)
    store.upsert_current_batch(
        "tenant-alias", rows, observed_at="2026-07-30T00:00:00Z", batch_id="b", source="fixture"
    )
    set_compliance_hub_store(store)

    _facets, total, _metadata = _finding_facets_bounded(
        "tenant-alias",
        severity="info",
        scan_id=None,
        since=None,
        scope={},
        status="all",
    )
    assert total == 2, "the 'informational' alias row was dropped by a pushed-down predicate"


def test_truncated_walk_cannot_contradict_the_severity_facet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``total`` and the severity facet must never disagree, budget or not.

    Under pushdown the histogram comes from the store's unbounded ``GROUP BY``
    while ``total`` came from the row-budgeted walk, so a tenant with more
    matching rows than the budget got an exact facet next to a truncated total
    — two contradicting numbers, both merely labelled approximate. Reproduced
    here by lowering the budget rather than materialising 50k rows.
    """
    from agent_bom.api.routes.scan import _finding_facets_bounded

    total_rows = 500
    budget = 10
    matching = total_rows // len(SEVERITY_CYCLE)
    assert matching > budget, "the case only exists when matches exceed the budget"
    _install_counting_stream(monkeypatch, total_rows=total_rows)

    facets, total, metadata = _finding_facets_bounded(
        "tenant-pushdown",
        severity="critical",
        scan_id=None,
        since=None,
        scope={},
        status="all",
        scan_budget=budget,
        deadline_seconds=60,
    )

    assert metadata["status"] == "partial", "the budget did not truncate the walk"
    assert facets["severity"]["critical"] == total, (
        f"severity facet says {facets['severity']['critical']} but total says {total}"
    )


def test_truncated_walk_labels_which_dimensions_are_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A partial walk must say *which* counts are lower bounds, not just "approximate"."""
    from agent_bom.api.routes.scan import _finding_facets_bounded

    _install_counting_stream(monkeypatch, total_rows=500)

    facets, total, metadata = _finding_facets_bounded(
        "tenant-pushdown",
        severity="critical",
        scan_id=None,
        since=None,
        scope={},
        status="all",
        scan_budget=10,
        deadline_seconds=60,
    )

    assert metadata["total_exact"] is True, "the store aggregate answers the total exactly"
    dimensions = metadata["dimensions"]
    assert dimensions["severity"] == "exact"
    assert dimensions["finding_class"] == "bounded"
    assert dimensions["freshness"] == "bounded"
    # A bounded dimension is a lower bound on the exact total, never above it.
    assert sum(facets["finding_class"].values()) <= total
    assert sum(facets["freshness"].values()) <= total


def test_complete_walk_reports_every_dimension_exact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-vacuous: the labelling is driven by real truncation, not always-on."""
    from agent_bom.api.routes.scan import _finding_facets_bounded

    _install_counting_stream(monkeypatch, total_rows=500)

    facets, total, metadata = _finding_facets_bounded(
        "tenant-pushdown",
        severity="critical",
        scan_id=None,
        since=None,
        scope={},
        status="all",
        scan_budget=10_000,
        deadline_seconds=60,
    )

    assert metadata["status"] == "complete"
    assert metadata["total_exact"] is True
    assert set(metadata["dimensions"].values()) == {"exact"}
    assert facets["severity"]["critical"] == total
    assert sum(facets["freshness"].values()) == total


def test_truncated_walk_without_pushdown_still_agrees(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The unfiltered walk truncates too; there both numbers stay lower bounds."""
    from agent_bom.api.routes.scan import _finding_facets_bounded

    _install_counting_stream(monkeypatch, total_rows=500)

    facets, total, metadata = _finding_facets_bounded(
        "tenant-pushdown",
        severity=None,
        scan_id=None,
        since=None,
        scope={},
        status="all",
        scan_budget=25,
        deadline_seconds=60,
    )

    assert metadata["status"] == "partial"
    assert metadata["total_exact"] is False
    assert set(metadata["dimensions"].values()) == {"bounded"}
    assert sum(facets["severity"].values()) == total
    assert sum(facets["freshness"].values()) == total


def test_unfiltered_facets_do_not_call_the_aggregate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No severity filter means the walk is already minimal — do not add a query."""
    from agent_bom.api.routes.scan import _finding_facets_bounded

    state = _install_counting_stream(monkeypatch, total_rows=200)

    _finding_facets_bounded(
        "tenant-pushdown",
        severity=None,
        scan_id=None,
        since=None,
        scope={},
        status="all",
        scan_budget=10_000,
        deadline_seconds=60,
    )

    assert state["kwargs"][0]["severity"] is None
    assert state["breakdown_calls"] == 0
    assert state["visited"] == 200
