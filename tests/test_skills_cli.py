"""CLI tests for the first-class skills command surface."""

from __future__ import annotations

import json

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.skill_bundles import build_skill_bundle


def test_skills_scan_json(tmp_path):
    """`agent-bom skills scan` returns structured aggregate results."""
    skill_file = tmp_path / "CLAUDE.md"
    skill_file.write_text(
        """# Project instructions

Use the filesystem server:

```bash
npx @modelcontextprotocol/server-filesystem
```

Environment:
- ANTHROPIC_API_KEY
"""
    )

    runner = CliRunner()
    result = runner.invoke(main, ["skills", "scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0, result.output

    data = json.loads(result.output)
    assert data["$schema"] == "https://agent-bom.github.io/schemas/skills-scan/v1"
    assert data["schema_version"] == "1"
    assert data["report_type"] == "skills_scan"
    assert data["generated_at"].endswith("Z")
    assert data["summary"]["files_scanned"] == 1
    assert data["summary"]["bundles"] == 1
    assert data["summary"]["packages_found"] >= 1
    assert data["summary"]["credential_env_vars"] >= 1
    assert data["files"][0]["path"].endswith("CLAUDE.md")
    assert data["files"][0]["bundle"]["file_count"] == 1
    assert data["files"][0]["bundle"]["sha256"]
    assert data["files"][0]["trust"]["review_verdict"] in {"trusted", "review", "high_risk", "blocked"}
    assert "behavioral_summary" in data["files"][0]["audit"]


def test_skills_scan_json_with_catalog_and_intel(tmp_path):
    """`agent-bom skills scan` can enrich and persist to a catalog when requested."""
    skill_file = tmp_path / "CLAUDE.md"
    skill_file.write_text("# Instructions\n\nUse OPENAI_API_KEY.\n")
    bundle = build_skill_bundle(skill_file)
    intel_feed = tmp_path / "intel.json"
    intel_feed.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "stable_id": bundle.stable_id,
                        "status": "suspicious",
                        "detail": "Flagged for review",
                    }
                ]
            }
        )
    )
    catalog_path = tmp_path / "catalog.json"

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "skills",
            "scan",
            str(tmp_path),
            "--format",
            "json",
            "--intel-source",
            str(intel_feed),
            "--catalog",
            str(catalog_path),
        ],
    )
    assert result.exit_code == 0, result.output

    data = json.loads(result.output)
    assert data["catalog_path"] == str(catalog_path)
    assert data["files"][0]["status"] == "suspicious"
    assert data["files"][0]["threat_intel"]["detail"] == "Flagged for review"


def test_skills_rescan_json(tmp_path):
    """`agent-bom skills rescan` should revisit cataloged entries."""
    skill_file = tmp_path / "CLAUDE.md"
    skill_file.write_text("# Instructions\nStay read-only.\n")
    catalog_path = tmp_path / "catalog.json"

    runner = CliRunner()
    scan_result = runner.invoke(
        main,
        ["skills", "scan", str(tmp_path), "--format", "json", "--catalog", str(catalog_path)],
    )
    assert scan_result.exit_code == 0, scan_result.output

    rescan_result = runner.invoke(
        main,
        ["skills", "rescan", "--format", "json", "--catalog", str(catalog_path)],
    )
    assert rescan_result.exit_code == 0, rescan_result.output

    data = json.loads(rescan_result.output)
    assert data["$schema"] == "https://agent-bom.github.io/schemas/skills-rescan/v1"
    assert data["schema_version"] == "1"
    assert data["report_type"] == "skills_rescan"
    assert data["generated_at"].endswith("Z")
    assert data["summary"]["catalog_entries"] == 1
    assert data["summary"]["rescanned"] == 1
    assert data["entries"][0]["exists"] is True


def test_skills_scan_explicit_directory_globs_markdown(tmp_path):
    """Explicit directory targets should scan markdown files inside that directory."""
    docs_skills = tmp_path / "docs" / "skills"
    docs_skills.mkdir(parents=True)
    skill_file = docs_skills / "mcp-server-review.md"
    skill_file.write_text("# Review\n\n```bash\nnpx @modelcontextprotocol/server-filesystem\n```\n")

    runner = CliRunner()
    result = runner.invoke(main, ["skills", "scan", str(docs_skills), "--format", "json"])
    assert result.exit_code == 0, result.output

    data = json.loads(result.output)
    assert data["summary"]["files_scanned"] == 1
    assert data["files"][0]["path"].endswith("mcp-server-review.md")


def test_skills_verify_json_unsigned(tmp_path):
    """`agent-bom skills verify` reports unsigned files and exits non-zero."""
    skill_file = tmp_path / "CLAUDE.md"
    skill_file.write_text("# Instructions\nStay read-only.\n")

    runner = CliRunner()
    result = runner.invoke(main, ["skills", "verify", str(tmp_path), "--format", "json"])
    assert result.exit_code == 1, result.output

    data = json.loads(result.output)
    assert len(data["files"]) == 1
    assert data["files"][0]["status"] == "unsigned"


def test_main_help_lists_skills_command():
    """Top-level help should surface the new skills command group."""
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "skills" in result.output


def test_skills_scan_handles_referenced_files_outside_primary_directory(tmp_path):
    docs_skill = tmp_path / "docs" / "skills" / "guide.md"
    shared = tmp_path / "security" / "image-exceptions.yaml"
    docs_skill.parent.mkdir(parents=True)
    shared.parent.mkdir(parents=True)
    shared.write_text("allow: []\n")
    docs_skill.write_text("# Guide\n\n[rules](../../security/image-exceptions.yaml)\n")

    runner = CliRunner()
    result = runner.invoke(main, ["skills", "scan", str(docs_skill.parent), "--format", "json"])

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["summary"]["bundled_files"] == 2


def test_skills_scan_verbose_flag_is_supported(tmp_path):
    skill_file = tmp_path / "CLAUDE.md"
    skill_file.write_text("# Instructions\n\n```bash\nnpx @modelcontextprotocol/server-filesystem\n```\nUse API key OPENAI_API_KEY.\n")

    runner = CliRunner()
    result = runner.invoke(main, ["skills", "scan", str(tmp_path), "--verbose"])

    assert result.exit_code == 0, result.output
    assert "agent-bom skills scan" in result.output


def test_skills_scan_quiet_suppresses_heading(tmp_path):
    skill_file = tmp_path / "CLAUDE.md"
    skill_file.write_text("# Instructions\n\nUse API key OPENAI_API_KEY.\n")

    runner = CliRunner()
    result = runner.invoke(main, ["skills", "scan", str(tmp_path), "--quiet"])

    assert result.exit_code == 0, result.output
    assert "agent-bom skills scan" not in result.output
    assert "Instruction Surface" in result.output
