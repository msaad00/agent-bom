"""First-run sample project guardrails."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.inventory import load_inventory
from agent_bom.parsers import scan_project_directory, summarize_project_inventory
from agent_bom.samples import write_first_run_sample
from agent_bom.skills_service import scan_skill_targets

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "first-run-ai-stack"


def test_first_run_inventory_matches_schema() -> None:
    inventory = load_inventory(str(SAMPLE / "inventory.json"))

    assert inventory["schema_version"] == "1"
    assert len(inventory["agents"]) == 2
    assert {agent["agent_type"] for agent in inventory["agents"]} == {"cursor", "claude-code"}

    server_names = {server["name"] for agent in inventory["agents"] for server in agent["mcp_servers"]}
    assert server_names == {"research-filesystem", "browser-helper"}


def test_generated_first_run_project_manifests_are_scannable(tmp_path: Path) -> None:
    target = tmp_path / "agent-bom-first-run"
    write_first_run_sample(target)

    result = scan_project_directory(target)
    summary = summarize_project_inventory(target, result)

    assert summary["manifest_directories"] == 2
    assert summary["package_count"] >= 5
    assert summary["lockfile_directories"] == 1
    assert summary["declaration_only_directories"] == 1
    assert summary["ecosystems"]["npm"] >= 2
    assert summary["ecosystems"]["pypi"] >= 3


def test_first_run_sample_uses_known_vulnerable_versions() -> None:
    inventory = load_inventory(str(SAMPLE / "inventory.json"))

    package_versions = {
        (package["ecosystem"], package["name"], package["version"])
        for agent in inventory["agents"]
        for server in agent["mcp_servers"]
        for package in server["packages"]
    }
    assert ("pypi", "flask", "2.2.0") in package_versions
    assert ("npm", "axios", "0.21.1") in package_versions


def test_generated_first_run_manifests_use_known_vulnerable_versions(tmp_path: Path) -> None:
    target = tmp_path / "agent-bom-first-run"
    write_first_run_sample(target)

    requirements = (target / "services" / "research-mcp" / "requirements.txt").read_text(encoding="utf-8")
    package_json = json.loads((target / "services" / "browser-helper" / "package.json").read_text(encoding="utf-8"))

    assert "flask==2.2.0" in requirements
    assert "werkzeug==2.2.2" in requirements
    assert "requests==2.28.0" in requirements
    assert package_json["dependencies"]["axios"] == "0.21.1"
    assert package_json["dependencies"]["lodash"] == "4.17.20"


def test_first_run_prompt_is_recognized_by_skills_scan() -> None:
    report = scan_skill_targets([SAMPLE])
    payload = report.to_dict()

    assert payload["summary"]["files_scanned"] >= 1
    assert any(Path(file_report.path).name == "agent-system-prompt.md" for file_report in report.files)


def test_first_run_docs_reference_real_paths() -> None:
    readme = (SAMPLE / "README.md").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "FIRST_RUN.md").read_text(encoding="utf-8")

    for relative in [
        "examples/first-run-ai-stack/inventory.json",
        "examples/first-run-ai-stack",
    ]:
        assert relative in readme
        assert relative in guide
        assert (ROOT / relative).exists()


def test_packaged_first_run_sample_can_be_written_and_scanned(tmp_path: Path) -> None:
    target = tmp_path / "agent-bom-first-run"
    written = write_first_run_sample(target)

    assert (target / "inventory.json") in written
    inventory = load_inventory(str(target / "inventory.json"))
    result = scan_project_directory(target)

    assert len(inventory["agents"]) == 2
    assert "flask==2.2.0" in (target / "services" / "research-mcp" / "requirements.txt").read_text(encoding="utf-8")
    assert '"axios": "0.21.1"' in (target / "services" / "browser-helper" / "package.json").read_text(encoding="utf-8")
    assert any(path.name == "research-mcp" for path in result)
    assert any(path.name == "browser-helper" for path in result)


def test_samples_first_run_cli_writes_next_command(tmp_path: Path) -> None:
    target = tmp_path / "sample"
    result = CliRunner().invoke(main, ["samples", "first-run", "--output", str(target)])

    assert result.exit_code == 0
    assert "agent-bom agents --inventory" in result.output
    assert (target / "inventory.json").exists()


def test_samples_first_run_cli_accepts_target_alias(tmp_path: Path) -> None:
    target = tmp_path / "sample"
    result = CliRunner().invoke(main, ["samples", "first-run", "--target", str(target)])

    assert result.exit_code == 0
    assert "agent-bom agents --inventory" in result.output
    assert (target / "inventory.json").exists()
