"""Legacy ledger rows retain the same scan filter as new writes."""

import json
import sqlite3

import pytest

from agent_bom.api.compliance_hub_store import SQLiteComplianceHubStore


@pytest.mark.parametrize(
    "payload, expected",
    [
        ({"batch_id": "batch-a"}, "batch-a"),
        ({"batch_id": "batch-a", "scan_id": "scan-b"}, "batch-a"),
        ({"batch_id": "", "scan_id": "scan-b"}, "scan-b"),
        ({"scan_id": "scan-b"}, "scan-b"),
    ],
)
def test_legacy_ledger_scan_filter_matches_new_ingest(tmp_path, payload, expected):
    path = str(tmp_path / "legacy.db")
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE compliance_hub_findings (tenant_id TEXT NOT NULL, finding_id TEXT NOT NULL, "
            "ingested_at TEXT NOT NULL, source TEXT NOT NULL, applicable_frameworks_csv TEXT NOT NULL DEFAULT '', "
            "payload TEXT NOT NULL, ordinal INTEGER NOT NULL, PRIMARY KEY(tenant_id,finding_id))"
        )
        conn.execute(
            "INSERT INTO compliance_hub_findings VALUES(?,?,?,?,?,?,?)", ("a", "legacy", "t", "external", "", json.dumps(payload), 1)
        )
    store = SQLiteComplianceHubStore(path)
    store.add("a", [{"id": "new", **payload}])
    rows, total = store.list_page("a", limit=10, scan_id=expected)
    assert total == 2
    assert len(rows) == 2
    reopened = SQLiteComplianceHubStore(path)
    assert reopened.list_page("a", limit=10, scan_id=expected)[1] == 2
    assert reopened.list_page("b", limit=10, scan_id=expected) == ([], 0)
