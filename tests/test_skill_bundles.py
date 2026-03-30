"""Tests for deterministic skill bundle identity."""

from __future__ import annotations

from agent_bom.skill_bundles import build_skill_bundle


def test_build_skill_bundle_includes_referenced_local_files(tmp_path):
    skill = tmp_path / "SKILL.md"
    script = tmp_path / "scripts" / "run.sh"
    script.parent.mkdir()
    script.write_text("#!/usr/bin/env bash\necho hi\n")
    skill.write_text("[runner](scripts/run.sh)\n")

    bundle = build_skill_bundle(skill, skill.read_text())
    assert bundle.file_count == 2
    assert bundle.referenced_file_count == 1
    assert [entry.path for entry in bundle.files] == ["SKILL.md", "scripts/run.sh"]


def test_build_skill_bundle_is_deterministic(tmp_path):
    skill = tmp_path / "SKILL.md"
    helper = tmp_path / "helper.py"
    helper.write_text("print('ok')\n")
    skill.write_text("Use `helper.py`\n")

    first = build_skill_bundle(skill, skill.read_text())
    second = build_skill_bundle(skill, skill.read_text())
    assert first.sha256 == second.sha256
    assert first.stable_id == second.stable_id
