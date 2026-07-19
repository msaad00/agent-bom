"""Canonical DSPM finding emission from redacted content classifications (#4157).

Covers the database + Azure Blob legs: only content-confirmed sensitive/review
locations emit findings, evidence stays redacted, findings route to the DSPM
lane, ids are deterministic (idempotent re-scan) and de-duplicated. The database
leg is proven end-to-end against the real local Docker Postgres.
"""

from __future__ import annotations

import os
import uuid

import pytest

from agent_bom.cloud.dspm_findings import build_inventory_dspm_findings
from agent_bom.finding import FindingSource, FindingType

# ── Fixture classifications (redacted, as persisted on inventory records) ──────


def _db_inventory() -> dict:
    return {
        "provider": "database",
        "dspm_databases": [
            {
                "name": "appdb",
                "engine": "postgres",
                "account_id": "acct-1",
                "content_classification": {
                    "schema_version": "agent-bom.dspm.database_scan.v1",
                    "source": "database://appdb",
                    "status": "partial",
                    "data_sensitivity": "sensitive",
                    "findings_by_type": {"email": 2, "ssn": 2},
                    "tables": [
                        {
                            "schema": "app",
                            "table": "customers",
                            "state": "executed",
                            "rows_sampled": 2,
                            "columns_sampled": 3,
                            "total_findings": 4,
                            "findings_by_type": {"email": 2, "ssn": 2},
                            "data_sensitivity": "sensitive",
                        },
                        {
                            "schema": "app",
                            "table": "metrics",
                            "state": "executed",
                            "total_findings": 0,
                            "findings_by_type": {},
                            "data_sensitivity": "none",
                        },
                        {
                            "schema": "app",
                            "table": "locked",
                            "state": "unevaluable",
                            "total_findings": 0,
                            "findings_by_type": {},
                            "data_sensitivity": "unevaluable",
                        },
                    ],
                },
            }
        ],
    }


def _blob_inventory() -> dict:
    return {
        "provider": "azure",
        "storage_accounts": [
            {
                "name": "acct1",
                "subscription_id": "sub-1",
                "content_classification": {
                    "schema_version": "agent-bom.dspm.azure_blob_account.v1",
                    "account": "acct1",
                    "status": "ok",
                    "data_sensitivity": "sensitive",
                    "findings_by_type": {"credit_card": 2},
                    "containers": [
                        {
                            "container": "customer-exports",
                            "status": "ok",
                            "objects_sampled": 1,
                            "total_findings": 2,
                            "findings_by_type": {"credit_card": 2},
                            "data_sensitivity": "sensitive",
                        },
                        {
                            "container": "telemetry",
                            "status": "ok",
                            "objects_sampled": 1,
                            "total_findings": 0,
                            "findings_by_type": {},
                            "data_sensitivity": "none",
                        },
                    ],
                },
            }
        ],
    }


# ── Database leg ──────────────────────────────────────────────────────────────


def test_database_emits_one_finding_per_sensitive_table_only():
    findings = build_inventory_dspm_findings(_db_inventory(), provider="database")
    # customers is sensitive → 1 finding; metrics (clean) + locked (unevaluable) → none.
    assert len(findings) == 1
    f = findings[0]
    assert f.finding_type == FindingType.SENSITIVE_DATA
    assert f.source == FindingSource.DSPM
    assert f.security_domain == "dspm"
    assert f.severity == "high"  # ssn present
    assert "app.customers" in f.title
    assert f.evidence["findings_by_type"] == {"email": 2, "ssn": 2}
    assert f.evidence["coverage_state"] == "executed"
    assert f.asset.location == "app.customers"


def test_unevaluable_and_clean_never_emit_a_finding():
    inv = _db_inventory()
    # Force every table to non-sensitive/unevaluable → zero findings, never a false clean.
    for t in inv["dspm_databases"][0]["content_classification"]["tables"]:
        t["data_sensitivity"] = "unevaluable"
        t["total_findings"] = 0
        t["findings_by_type"] = {}
    assert build_inventory_dspm_findings(inv, provider="database") == []


def test_findings_are_deterministic_and_idempotent():
    a = build_inventory_dspm_findings(_db_inventory(), provider="database")
    b = build_inventory_dspm_findings(_db_inventory(), provider="database")
    assert [f.id for f in a] == [f.id for f in b]


def test_findings_are_deduped_per_location():
    inv = _db_inventory()
    # Duplicate the sensitive table row → one finding, not two.
    tables = inv["dspm_databases"][0]["content_classification"]["tables"]
    tables.append(dict(tables[0]))
    findings = build_inventory_dspm_findings(inv, provider="database")
    assert len(findings) == 1


# ── Azure Blob leg ────────────────────────────────────────────────────────────


def test_blob_emits_one_finding_per_sensitive_container_only():
    findings = build_inventory_dspm_findings(_blob_inventory(), provider="azure", account_ref="azure:sub-1")
    assert len(findings) == 1
    f = findings[0]
    assert f.finding_type == FindingType.SENSITIVE_DATA
    assert f.security_domain == "dspm"
    assert f.severity == "high"  # credit_card present
    assert f.asset.location == "acct1/customer-exports"
    assert f.account_ref == "azure:sub-1"
    assert f.evidence["storage_account"] == "acct1"


# ── Live Postgres proof: scan real DB → emit findings ─────────────────────────

_PG_URL = os.environ.get("AGENT_BOM_DSPM_TEST_POSTGRES_URL") or os.environ.get("AGENT_BOM_POSTGRES_URL", "")


@pytest.mark.skipif(not _PG_URL, reason="AGENT_BOM_POSTGRES_URL not set")
def test_live_postgres_scan_emits_redacted_dspm_findings():
    import psycopg

    from agent_bom.cloud.db_content_scan import scan_database_content

    schema = f"dspm_find_{uuid.uuid4().hex[:8]}"
    with psycopg.connect(_PG_URL, autocommit=True) as admin, admin.cursor() as cur:
        cur.execute(f'CREATE SCHEMA "{schema}"')
        cur.execute(f'CREATE TABLE "{schema}"."customers" (email text, ssn text, pan text)')
        cur.execute(
            f'INSERT INTO "{schema}"."customers" VALUES '
            "('alice@example.com','123-45-6789','4111111111111111'),"
            "('bob@example.com','234-56-7890','5500005555555559')"
        )
        cur.execute(f'CREATE TABLE "{schema}"."metrics" (metric text, value double precision)')
        cur.execute(f'INSERT INTO "{schema}"."metrics" VALUES (\'cpu\',0.5)')

    try:
        with psycopg.connect(_PG_URL, autocommit=True, options="-c default_transaction_read_only=on") as reader:
            scan = scan_database_content(reader, source=f"database://{schema}", schemas=[schema], max_rows=50)

        inventory = {
            "provider": "database",
            "dspm_databases": [{"name": schema, "engine": "postgres", "content_classification": scan.to_dict()}],
        }
        findings = build_inventory_dspm_findings(inventory, provider="database", account_ref=f"database:{schema}")

        locations = {f.asset.location: f for f in findings}
        # customers is content-confirmed sensitive → a finding; metrics (clean) → none.
        assert f"{schema}.customers" in locations
        assert f"{schema}.metrics" not in locations
        customers = locations[f"{schema}.customers"]
        assert customers.security_domain == "dspm"
        assert customers.severity == "high"
        assert customers.evidence["findings_by_type"].get("ssn") == 2
        assert customers.evidence["findings_by_type"].get("credit_card") == 2

        # Redaction: no raw value in the serialized finding.
        text = repr(customers.to_dict())
        for raw in ("alice@example.com", "123-45-6789", "4111111111111111", "234-56-7890"):
            assert raw not in text

        # Idempotent: a second emit yields the same finding id.
        again = build_inventory_dspm_findings(inventory, provider="database", account_ref=f"database:{schema}")
        assert {f.id for f in findings} == {f.id for f in again}
    finally:
        with psycopg.connect(_PG_URL, autocommit=True) as admin, admin.cursor() as cur:
            cur.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
