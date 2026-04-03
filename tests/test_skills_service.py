"""Service-level tests for skill catalog and threat-intel flows."""

from __future__ import annotations

import json

from agent_bom.skill_bundles import build_skill_bundle
from agent_bom.skills_service import rescan_skill_catalog, scan_skill_targets


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
