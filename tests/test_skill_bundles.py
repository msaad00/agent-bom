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


def test_build_skill_bundle_supports_references_outside_primary_directory(tmp_path):
    docs_skill = tmp_path / "docs" / "skills" / "guide.md"
    shared = tmp_path / "security" / "image-exceptions.yaml"
    docs_skill.parent.mkdir(parents=True)
    shared.parent.mkdir(parents=True)
    shared.write_text("allow: []\n")
    docs_skill.write_text("[rules](../../security/image-exceptions.yaml)\n")

    bundle = build_skill_bundle(docs_skill, docs_skill.read_text())

    assert bundle.root == str(tmp_path)
    assert [entry.path for entry in bundle.files] == ["docs/skills/guide.md", "security/image-exceptions.yaml"]


def test_build_skill_bundle_refuses_symlinked_local_references(tmp_path):
    skill = tmp_path / "SKILL.md"
    outside = tmp_path / "outside.txt"
    symlink = tmp_path / "linked.txt"
    outside.write_text("secret material\n")
    symlink.symlink_to(outside)
    skill.write_text("[linked](linked.txt)\n")

    bundle = build_skill_bundle(skill, skill.read_text())

    assert bundle.file_count == 1
    assert [entry.path for entry in bundle.files] == ["SKILL.md"]
