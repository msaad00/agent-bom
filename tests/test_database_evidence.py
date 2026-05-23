from __future__ import annotations

from agent_bom.database_evidence import (
    CORE_DATABASE_EVIDENCE,
    DatabaseConnectorLane,
    DatabaseEvidenceKind,
    fallback_database_evidence_connectors,
    list_database_evidence_connectors,
)


def test_database_evidence_contract_keeps_odbc_jdbc_out_of_default_wheel() -> None:
    connectors = {entry["name"]: entry for entry in list_database_evidence_connectors()}

    assert connectors["postgres-native"]["preferred"] is True
    assert connectors["postgres-native"]["default_wheel"] is True

    for name in ("odbc-fallback", "jdbc-fallback"):
        fallback = connectors[name]
        assert fallback["preferred"] is False
        assert fallback["default_wheel"] is False
        assert fallback["credential_boundary"] == "customer_managed"
        assert fallback["writes"] is False
        assert "optional extra" in str(fallback["packaging_notes"]).lower()


def test_database_evidence_contract_covers_governance_inventory() -> None:
    evidence = {kind.value for kind in CORE_DATABASE_EVIDENCE}

    assert {
        DatabaseEvidenceKind.SCHEMA.value,
        DatabaseEvidenceKind.TABLE.value,
        DatabaseEvidenceKind.VIEW.value,
        DatabaseEvidenceKind.GRANT.value,
        DatabaseEvidenceKind.ROLE.value,
        DatabaseEvidenceKind.USER.value,
        DatabaseEvidenceKind.CLASSIFICATION_TAG.value,
        DatabaseEvidenceKind.GOVERNANCE_METADATA.value,
        DatabaseEvidenceKind.EXTERNAL_SHARE.value,
        DatabaseEvidenceKind.EXTERNAL_STAGE.value,
        DatabaseEvidenceKind.LINEAGE.value,
    } <= evidence


def test_fallback_database_evidence_connectors_only_returns_generic_lanes() -> None:
    fallbacks = fallback_database_evidence_connectors()

    assert {connector.lane for connector in fallbacks} == {DatabaseConnectorLane.ODBC, DatabaseConnectorLane.JDBC}
    assert {connector.name for connector in fallbacks} == {"odbc-fallback", "jdbc-fallback"}
