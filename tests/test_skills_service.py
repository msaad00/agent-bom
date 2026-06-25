"""Service-level tests for skill catalog and threat-intel flows."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from agent_bom.skill_bundles import build_skill_bundle
from agent_bom.skill_intel import ThreatIntelStatus
from agent_bom.skills_service import (
    _catalog_findings_for_report,
    _review_to_status,
    rescan_skill_catalog,
    scan_skill_targets,
)


def _strip_provenance(entry: dict) -> dict:
    """Drop the non-deterministic ``scanned_at`` provenance block."""
    return {k: v for k, v in entry.items() if k != "scanned_at"}


def test_catalog_findings_payload_is_deterministic_across_scans(tmp_path):
    """Two scans of the same skill must produce byte-identical findings; only
    the isolated ``scanned_at`` provenance block may differ run-to-run."""
    skill_file = tmp_path / "CLAUDE.md"
    skill_file.write_text("# Instructions\n\nUse OPENAI_API_KEY.\n")

    catalog_a = tmp_path / "a.json"
    catalog_b = tmp_path / "b.json"

    report_a = scan_skill_targets([skill_file], catalog_path=catalog_a)
    report_b = scan_skill_targets([skill_file], catalog_path=catalog_b)

    bundle_id = build_skill_bundle(skill_file).stable_id
    entry_a = json.loads(catalog_a.read_text())["entries"][bundle_id]
    entry_b = json.loads(catalog_b.read_text())["entries"][bundle_id]

    # Timestamps live in a clearly-separated provenance field.
    assert "scanned_at" in entry_a
    assert "updated_at" not in entry_a
    assert "last_seen" not in entry_a

    # The findings-critical payload is byte-identical across the two runs.
    assert _strip_provenance(entry_a) == _strip_provenance(entry_b)

    # The deterministic helper carries no wall-clock value at all.
    findings = _catalog_findings_for_report(report_a.files[0])
    assert "scanned_at" not in findings
    assert json.dumps(findings, sort_keys=True, default=str) == json.dumps(
        _catalog_findings_for_report(report_b.files[0]), sort_keys=True, default=str
    )


def test_rescan_serialized_findings_are_deterministic(tmp_path):
    """Rescanning the same on-disk skill twice yields identical findings rows."""
    skill_file = tmp_path / "SKILL.md"
    skill_file.write_text("# Skill\nUse the filesystem server.\n")
    catalog_path = tmp_path / "catalog.json"
    scan_skill_targets([skill_file], catalog_path=catalog_path)

    first = rescan_skill_catalog(catalog_path=catalog_path).to_dict()["entries"][0]
    second = rescan_skill_catalog(catalog_path=catalog_path).to_dict()["entries"][0]

    assert "scanned_at" in first
    assert _strip_provenance(first) == _strip_provenance(second)


def test_scan_skill_targets_records_summary_in_hmac_audit_chain(tmp_path):
    """Skill scans should leave summary-only evidence in the signed audit chain."""
    from agent_bom.api.audit_log import InMemoryAuditLog, set_audit_log

    audit_log = InMemoryAuditLog()
    set_audit_log(audit_log)
    skill_file = tmp_path / "CLAUDE.md"
    skill_file.write_text("# Instructions\n\nUse OPENAI_API_KEY.\n")

    scan_skill_targets([skill_file])

    entries = audit_log.list_entries(action="skills.scan_completed", tenant_id="default")
    assert len(entries) == 1
    entry = entries[0]
    assert entry.resource == "skills/scan"
    assert entry.details["event_type"] == "skills.scan_completed"
    assert entry.details["source_type"] == "skills"
    assert entry.details["count"] == 1
    assert "credential_env_vars" not in entry.details
    verified, tampered = audit_log.verify_integrity(tenant_id="default")
    assert verified == 1
    assert tampered == 0


def test_rescan_skill_catalog_records_summary_in_hmac_audit_chain(tmp_path):
    """Skill rescans should be chained without storing raw skill content."""
    from agent_bom.api.audit_log import InMemoryAuditLog, set_audit_log

    audit_log = InMemoryAuditLog()
    set_audit_log(audit_log)
    skill_file = tmp_path / "SKILL.md"
    skill_file.write_text("# Skill\nUse the filesystem server.\n")
    catalog_path = tmp_path / "catalog.json"

    scan_skill_targets([skill_file], catalog_path=catalog_path)
    rescan_skill_catalog(catalog_path=catalog_path)

    entries = audit_log.list_entries(tenant_id="default", limit=10)
    assert [entry.action for entry in entries][:2] == ["skills.rescan_completed", "skills.scan_completed"]
    rescan_entry = entries[0]
    assert rescan_entry.resource == "skills/rescan"
    assert rescan_entry.details["event_type"] == "skills.rescan_completed"
    assert rescan_entry.details["source_type"] == "skills"
    assert rescan_entry.details["count"] == 1
    verified, tampered = audit_log.verify_integrity(tenant_id="default")
    assert verified == 2
    assert tampered == 0


def test_scan_skill_targets_records_catalog_and_intel(tmp_path):
    """Scanning with a catalog and intel feed should persist both."""
    skill_file = tmp_path / "CLAUDE.md"
    skill_file.write_text("# Instructions\n\nUse OPENAI_API_KEY.\n")
    bundle = build_skill_bundle(skill_file)

    intel_feed = tmp_path / "intel.json"
    intel_feed.write_text(
        json.dumps(
            {
                "provider": "fixture-feed",
                "entries": [
                    {
                        "stable_id": bundle.stable_id,
                        "status": "suspicious",
                        "detail": "Seen in review queue",
                    }
                ],
            }
        )
    )
    catalog_path = tmp_path / "catalog.json"

    report = scan_skill_targets([skill_file], intel_source=str(intel_feed), catalog_path=catalog_path)

    assert report.catalog_path == str(catalog_path)
    assert report.files[0].status == "suspicious"
    assert report.files[0].threat_intel is not None
    assert report.files[0].threat_intel.provider == "fixture-feed"

    catalog = json.loads(catalog_path.read_text())
    assert bundle.stable_id in catalog["entries"]
    assert catalog["entries"][bundle.stable_id]["status"] == "suspicious"
    assert catalog["entries"][bundle.stable_id]["threat_intel"]["provider"] == "fixture-feed"

    payload = report.to_dict()
    assert payload["$schema"] == "https://agent-bom.github.io/schemas/skills-scan/v1"
    assert payload["schema_version"] == "1"
    assert payload["report_type"] == "skills_scan"
    assert payload["generated_at"].endswith("Z")


def test_high_risk_local_skill_review_counts_as_malicious_status():
    """Local high-risk verdicts should not drift from malicious summary counts."""
    report = SimpleNamespace(threat_intel=None, trust=SimpleNamespace(review_verdict=SimpleNamespace(value="high_risk")))

    assert _review_to_status(report) == ThreatIntelStatus.MALICIOUS


def test_clean_unsigned_skill_requires_review_without_malicious_status(tmp_path):
    """Metadata/provenance gaps should not label a zero-finding skill malicious."""
    skill_file = tmp_path / "SKILL.md"
    skill_file.write_text("# Clean skill\n\nRead source files and explain the implementation.\n")

    report = scan_skill_targets([skill_file])
    data = report.to_dict()
    file_report = data["files"][0]

    assert file_report["audit"]["findings"] == []
    assert file_report["trust"]["content_verdict"] == "benign"
    assert file_report["trust"]["provenance_verdict"] == "unverified"
    assert file_report["trust"]["verdict"] == "benign"
    assert file_report["trust"]["review_verdict"] == "review"
    assert file_report["trust"]["overall_recommendation"] == "review"
    assert file_report["status"] == "pending"
    assert data["summary"]["findings"] == 0
    assert data["summary"]["suspicious_files"] == 0
    assert data["summary"]["high_risk_files"] == 0
    assert data["summary"]["malicious_files"] == 0
    assert data["summary"]["suspicious_status_files"] == 0
    assert data["summary"]["malicious_status_files"] == 0
    assert data["summary"]["pending_status_files"] == 1


def test_scan_skill_targets_redacts_server_args_in_output(tmp_path):
    raw_token = "ghp_" + "A" * 36
    skill_file = tmp_path / "SKILL.md"
    skill_file.write_text(
        "# Skill\n\n"
        "```json\n"
        "{\n"
        '  "mcpServers": {\n'
        '    "sensitive": {\n'
        '      "command": "npx",\n'
        f'      "args": ["server", "--token", "{raw_token}"]\n'
        "    }\n"
        "  }\n"
        "}\n"
        "```\n"
    )

    payload = scan_skill_targets([skill_file]).to_dict()

    assert raw_token not in json.dumps(payload)
    assert payload["files"][0]["servers"][0]["args"] == ["server", "--token", "<redacted>"]


def test_rescan_skill_catalog_marks_missing_entries_unavailable(tmp_path):
    """Rescanning a catalog should mark missing paths as unavailable."""
    skill_file = tmp_path / "CLAUDE.md"
    skill_file.write_text("# Instructions\nStay read-only.\n")
    catalog_path = tmp_path / "catalog.json"

    scan_skill_targets([skill_file], catalog_path=catalog_path)
    skill_file.unlink()

    report = rescan_skill_catalog(catalog_path=catalog_path)
    data = report.to_dict()

    assert data["summary"]["catalog_entries"] == 1
    assert data["summary"]["missing"] == 1
    assert data["entries"][0]["exists"] is False
    assert data["entries"][0]["status"] == "unavailable"
    assert data["entries"][0]["error"] == "file not found"
    assert data["$schema"] == "https://agent-bom.github.io/schemas/skills-rescan/v1"
    assert data["schema_version"] == "1"
    assert data["report_type"] == "skills_rescan"
    assert data["generated_at"].endswith("Z")


def test_rescan_skill_catalog_refreshes_existing_entry_with_intel(tmp_path):
    """Rescanning should refresh current status from the latest intel feed."""
    skill_file = tmp_path / "SKILL.md"
    skill_file.write_text("# Skill\n\nUse the filesystem server.\n")
    catalog_path = tmp_path / "catalog.json"

    scan_skill_targets([skill_file], catalog_path=catalog_path)
    bundle = build_skill_bundle(skill_file)
    intel_feed = tmp_path / "intel.json"
    intel_feed.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "sha256": bundle.sha256,
                        "status": "malicious",
                        "detail": "Known-bad bundle hash",
                    }
                ]
            }
        )
    )

    report = rescan_skill_catalog(catalog_path=catalog_path, intel_source=str(intel_feed))
    data = report.to_dict()

    assert data["summary"]["rescanned"] == 1
    assert data["summary"]["malicious"] == 1
    assert data["entries"][0]["exists"] is True
    assert data["entries"][0]["status"] == "malicious"
    assert data["entries"][0]["threat_intel"]["detail"] == "Known-bad bundle hash"


def test_scan_skill_targets_preserves_discovery_order(tmp_path):
    """Batch scanning should preserve resolved file order in output."""
    a = tmp_path / "CLAUDE.md"
    b = tmp_path / "SKILL.md"
    a.write_text("# A\n")
    b.write_text("# B\n")

    report = scan_skill_targets([tmp_path])

    assert [Path(item.path).name for item in report.files] == ["CLAUDE.md", "SKILL.md"]


def test_scan_skill_targets_recognizes_cursor_mdc_rules(tmp_path):
    rule = tmp_path / ".cursor" / "rules" / "agent-policy.mdc"
    rule.parent.mkdir(parents=True)
    rule.write_text("# Agent policy\n\nUse OPENAI_API_KEY.\n")

    report = scan_skill_targets([tmp_path])

    assert len(report.files) == 1
    assert report.files[0].path.name == "agent-policy.mdc"


def test_scan_skill_targets_works_inside_existing_event_loop(tmp_path):
    """Sync API should remain callable from contexts that already own an event loop."""
    skill_file = tmp_path / "CLAUDE.md"
    skill_file.write_text("# Instructions\nStay read-only.\n")

    async def _invoke():
        return await asyncio.to_thread(scan_skill_targets, [skill_file])

    report = asyncio.run(_invoke())
    assert report.files[0].path == skill_file


def test_rescan_skill_catalog_works_inside_existing_event_loop(tmp_path):
    """Catalog rescan should keep working when called from async wrappers."""
    skill_file = tmp_path / "SKILL.md"
    skill_file.write_text("# Skill\nUse the filesystem server.\n")
    catalog_path = tmp_path / "catalog.json"
    scan_skill_targets([skill_file], catalog_path=catalog_path)

    async def _invoke():
        return await asyncio.to_thread(rescan_skill_catalog, catalog_path=catalog_path)

    report = asyncio.run(_invoke())
    assert report.entries[0]["exists"] is True


def test_skills_output_schemas_exist():
    """Versioned skills schemas should ship with the repo for downstream tooling."""
    scan_schema = Path("config/schemas/skills-scan.schema.json")
    rescan_schema = Path("config/schemas/skills-rescan.schema.json")

    assert scan_schema.exists()
    assert rescan_schema.exists()

    scan_doc = json.loads(scan_schema.read_text())
    rescan_doc = json.loads(rescan_schema.read_text())

    assert scan_doc["$id"] == "https://agent-bom.github.io/schemas/skills-scan/v1"
    assert rescan_doc["$id"] == "https://agent-bom.github.io/schemas/skills-rescan/v1"
