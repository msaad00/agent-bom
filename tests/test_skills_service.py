"""Service-level tests for skill catalog and threat-intel flows."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

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

    payload = report.to_dict()
    assert payload["$schema"] == "https://agent-bom.github.io/schemas/skills-scan/v1"
    assert payload["schema_version"] == "1"
    assert payload["report_type"] == "skills_scan"
    assert payload["generated_at"].endswith("Z")


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
