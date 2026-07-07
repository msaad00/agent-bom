"""Regression tests for post-#3624 audit follow-up fixes."""

from __future__ import annotations

from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, _current_page_sort_key
from agent_bom.api.finding_cursor import cursor_from_current_row, row_is_after_cursor
from agent_bom.ast_php import _php_call_sites
from agent_bom.ast_swift import _swift_call_sites
from agent_bom.finding import _remediation_guidance_for_vulnerability
from agent_bom.models import AIBOMReport, BlastRadius, Package, Severity, Vulnerability
from agent_bom.output.csv_fmt import to_csv


def test_swift_ignores_calls_in_comments() -> None:
    body = """
    // GuzzleClient.request() mentioned here only
    func handle() {
        print("ok")
    }
    """
    sites = _swift_call_sites(body, line_offset=1)
    names = {site.name for site in sites}
    assert "GuzzleClient.request" not in names
    assert "print" in names


def test_php_ignores_calls_in_comments() -> None:
    body = """
    // $client->request() is only a comment
    public function handle() {
        echo('ok');
    }
    """
    sites = _php_call_sites(body, line_offset=1)
    names = {site.name for site in sites}
    assert "$client->request" not in names


def test_remediation_guidance_suppresses_downgrade_advice() -> None:
    pkg = Package(name="minimist", version="1.2.0", ecosystem="npm")
    vuln = Vulnerability(id="CVE-2024-1", summary="x", severity=Severity.MEDIUM, fixed_version="0.2.4")
    guidance = _remediation_guidance_for_vulnerability(vuln, pkg)
    assert "0.2.4" not in guidance
    assert "vendor-recommended" in guidance.lower() or "advisory" in guidance.lower()


def test_csv_includes_malicious_columns() -> None:
    br = BlastRadius(
        vulnerability=Vulnerability(id="MAL-1", summary="malware", severity=Severity.HIGH),
        package=Package(name="evil-pkg", version="1.0.0", ecosystem="npm", is_malicious=True, malicious_reason="typosquat"),
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
        risk_score=9.0,
    )
    report = AIBOMReport(agents=[], blast_radii=[br])
    csv_text = to_csv(report, [br])
    assert "is_malicious" in csv_text.splitlines()[0]
    assert "yes" in csv_text
    assert "typosquat" in csv_text


def test_in_memory_cursor_walk_no_duplicates_on_tied_scores() -> None:
    store = InMemoryComplianceHubStore()
    tenant = "t1"
    rows = []
    for idx in range(6):
        rows.append(
            {
                "tenant_id": tenant,
                "canonical_id": f"c{idx}",
                "last_seen": f"2026-01-0{idx + 1}T00:00:00Z",
                "effective_reach_score": 5.0,
                "severity_rank": 3,
                "cvss_score": 7.0,
                "payload": {"origin": "bulk_ingest", "severity": "high"},
            }
        )
    with store._lock:
        store._current[tenant] = {row["canonical_id"]: dict(row) for row in rows}

    seen: set[str] = set()
    cursor = None
    for _ in range(10):
        page, total, next_cursor = store.list_current_page(tenant, limit=2, origin="bulk_ingest", cursor=cursor)
        assert total == 6
        for row in page:
            cid = row["canonical_id"]
            assert cid not in seen
            seen.add(cid)
        if not next_cursor:
            break
        cursor = next_cursor
    assert seen == {f"c{i}" for i in range(6)}


def test_in_memory_sort_matches_row_is_after_cursor() -> None:
    rows = [
        {"effective_reach_score": 5.0, "last_seen": "2026-01-02T00:00:00Z", "canonical_id": "a"},
        {"effective_reach_score": 5.0, "last_seen": "2026-01-01T00:00:00Z", "canonical_id": "b"},
        {"effective_reach_score": 4.0, "last_seen": "2026-01-03T00:00:00Z", "canonical_id": "c"},
    ]
    key = _current_page_sort_key("effective_reach")
    ordered = sorted(rows, key=key)
    cursor = cursor_from_current_row(ordered[0], sort="effective_reach")
    from agent_bom.api.finding_cursor import decode_finding_cursor

    primary, last_seen, canonical_id = decode_finding_cursor(cursor, expected_sort="effective_reach")
    after = [
        row
        for row in ordered
        if row_is_after_cursor(
            row,
            sort="effective_reach",
            primary=primary,
            last_seen=last_seen,
            canonical_id=canonical_id,
        )
    ]
    assert [row["canonical_id"] for row in after] == [row["canonical_id"] for row in ordered[1:]]
