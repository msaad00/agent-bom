from __future__ import annotations

from unittest.mock import patch

from agent_bom.models import AIBOMReport
from agent_bom.output.json_fmt import to_json


def test_json_output_includes_framework_catalog_metadata():
    report = AIBOMReport(scan_id="scan-1")
    metadata = {
        "schema_version": 1,
        "catalog_id": "mitre_attack_enterprise_capec",
        "catalog_type": "mitre_attack",
        "source": "bundled",
        "attack_version": "ATT&CK vTEST",
        "updated_at": "2026-04-10T00:00:00+00:00",
        "fetched_at": 0,
        "normalized_sha256": "abc123",
        "sources": {},
        "technique_count": 557,
        "cwe_mapping_count": 146,
        "path": "/tmp/catalog.json",
    }

    with patch("agent_bom.mitre_fetch.get_catalog_metadata", return_value=metadata):
        payload = to_json(report)

    assert payload["framework_catalogs"]["mitre_attack"]["attack_version"] == "ATT&CK vTEST"
    assert payload["framework_catalogs"]["mitre_attack"]["technique_count"] == 557
