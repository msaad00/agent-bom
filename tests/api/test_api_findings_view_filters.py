"""Canonical findings-view filters must run before pagination and exports."""

from __future__ import annotations

from types import SimpleNamespace

from agent_bom.api.routes import enterprise
from agent_bom.api.routes import scan as scan_routes


def _request() -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(tenant_id="tenant-alpha"))


def _page(findings: list[dict], *, next_cursor: str = "") -> dict:
    return {
        "findings": findings,
        "total": len(findings),
        "total_approximate": False,
        "warnings": [],
        "count_metadata": {},
        "filters": {},
        "next_cursor": next_cursor,
        "window": {"days": 90, "label": "Last 90 days"},
    }


def test_reachability_filter_walks_source_pages_before_returning(monkeypatch) -> None:
    calls: list[str | None] = []

    def _raw_page(_request_obj, **kwargs):
        cursor = kwargs["cursor"]
        calls.append(cursor)
        if cursor is None:
            return _page(
                [{"finding_id": "unreachable", "cve_id": "CVE-1", "graph_reachable": False}],
                next_cursor="page-2",
            )
        return _page([{"finding_id": "reachable", "cve_id": "CVE-2", "graph_reachable": True}])

    monkeypatch.setattr(scan_routes, "_list_findings_impl", _raw_page)

    result = scan_routes._list_findings_view_impl(
        _request(),
        q=None,
        severity=None,
        scan_id=None,
        sort="effective_reach",
        limit=1,
        offset=0,
        cursor=None,
        approximate_total=False,
        reachability="reachable",
    )

    assert calls == [None, "page-2"]
    assert [row["finding_id"] for row in result["findings"]] == ["reachable"]
    assert result["total"] == 1
    assert result.get("total_approximate", False) is False
    assert result["filters"]["reachability"] == "reachable"


def test_triage_filter_preserves_occurrence_identity_and_projects_decision(monkeypatch) -> None:
    monkeypatch.setattr(
        scan_routes,
        "_list_findings_impl",
        lambda _request_obj, **_kwargs: _page(
            [
                {"finding_id": "occurrence-a", "cve_id": "CVE-1", "package": "pkg-a"},
                {"finding_id": "occurrence-b", "cve_id": "CVE-2", "package": "pkg-b"},
            ]
        ),
    )
    monkeypatch.setattr(enterprise, "build_tenant_triage_state_index", lambda _tenant_id: {"index": True})
    monkeypatch.setattr(
        enterprise,
        "triage_state_for",
        lambda _index, *, vuln_id, package, server_name="": (
            {"id": "triage-a", "decision": "not_affected", "queue_state": "decided"} if vuln_id == "CVE-1" and package == "pkg-a" else None
        ),
    )

    result = scan_routes._list_findings_view_impl(
        _request(),
        q=None,
        severity=None,
        scan_id=None,
        sort="effective_reach",
        limit=25,
        offset=0,
        cursor=None,
        approximate_total=False,
        triage="not_affected",
    )

    assert [row["finding_id"] for row in result["findings"]] == ["occurrence-a"]
    assert result["findings"][0]["triage_id"] == "triage-a"
    assert result["findings"][0]["triage_decision"] == "not_affected"
    assert result["findings"][0]["triage_queue_state"] == "decided"
    assert result["filters"]["triage"] == "not_affected"


def test_untriaged_filter_excludes_rows_with_any_active_decision(monkeypatch) -> None:
    monkeypatch.setattr(
        scan_routes,
        "_list_findings_impl",
        lambda _request_obj, **_kwargs: _page(
            [
                {"finding_id": "decided", "cve_id": "CVE-1", "package": "pkg-a"},
                {"finding_id": "untriaged", "cve_id": "CVE-2", "package": "pkg-b"},
            ]
        ),
    )
    monkeypatch.setattr(enterprise, "build_tenant_triage_state_index", lambda _tenant_id: {"index": True})
    monkeypatch.setattr(
        enterprise,
        "triage_state_for",
        lambda _index, *, vuln_id, package, server_name="": (
            {"id": "triage-a", "decision": "affected", "queue_state": "decided"} if vuln_id == "CVE-1" else None
        ),
    )

    result = scan_routes._list_findings_view_impl(
        _request(),
        q=None,
        severity=None,
        scan_id=None,
        sort="effective_reach",
        limit=25,
        offset=0,
        cursor=None,
        approximate_total=False,
        triage="untriaged",
    )

    assert [row["finding_id"] for row in result["findings"]] == ["untriaged"]
    assert result["findings"][0]["triage_decision"] is None
