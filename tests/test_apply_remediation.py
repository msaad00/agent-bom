"""Tests for guided remediation apply_fixes and registry enrichment."""

from __future__ import annotations

import json
from pathlib import Path

from agent_bom.remediate import (
    PackageFix,
    RemediationPlan,
    apply_fixes,
    apply_fixes_from_json,
)

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _npm_fix(package="express", current="4.17.1", fixed="4.21.0"):
    return PackageFix(
        package=package,
        ecosystem="npm",
        current_version=current,
        fixed_version=fixed,
        command=f"npm install {package}@{fixed}",
        vulns=["CVE-2024-0001"],
        agents=["claude-desktop"],
    )


def _pip_fix(package="flask", current="2.0.0", fixed="3.0.0"):
    return PackageFix(
        package=package,
        ecosystem="pypi",
        current_version=current,
        fixed_version=fixed,
        command=f"pip install '{package}>={fixed}'",
        vulns=["CVE-2024-0002"],
        agents=["cursor"],
    )


# ─── npm apply tests ─────────────────────────────────────────────────────────


def test_apply_npm_fixes(tmp_path):
    """Modifies package.json with fixed versions."""
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({
        "name": "test-app",
        "dependencies": {"express": "^4.17.1", "lodash": "^4.17.21"},
    }, indent=2))

    plan = RemediationPlan(package_fixes=[_npm_fix()])
    result = apply_fixes(plan, [tmp_path])

    assert len(result.applied) == 1
    assert result.applied[0].package == "express"
    assert result.dry_run is False

    # Verify file was modified
    data = json.loads(pkg_json.read_text())
    assert data["dependencies"]["express"] == "^4.21.0"
    # Lodash should be untouched
    assert data["dependencies"]["lodash"] == "^4.17.21"


def test_apply_npm_dry_run(tmp_path):
    """Preview without modifying files."""
    pkg_json = tmp_path / "package.json"
    original = json.dumps({
        "dependencies": {"express": "^4.17.1"},
    }, indent=2)
    pkg_json.write_text(original)

    plan = RemediationPlan(package_fixes=[_npm_fix()])
    result = apply_fixes(plan, [tmp_path], dry_run=True)

    assert result.dry_run is True
    assert len(result.applied) == 1
    # File should NOT be modified
    assert pkg_json.read_text() == original


def test_apply_npm_backup(tmp_path):
    """Creates .agent-bom-backup file before modifying."""
    pkg_json = tmp_path / "package.json"
    original = json.dumps({
        "dependencies": {"express": "^4.17.1"},
    }, indent=2)
    pkg_json.write_text(original)

    plan = RemediationPlan(package_fixes=[_npm_fix()])
    result = apply_fixes(plan, [tmp_path], backup=True)

    assert len(result.backed_up) == 1
    backup_path = Path(result.backed_up[0])
    assert backup_path.exists()
    assert backup_path.name == "package.json.agent-bom-backup"
    # Backup should contain original content
    assert json.loads(backup_path.read_text())["dependencies"]["express"] == "^4.17.1"


def test_apply_npm_no_backup(tmp_path):
    """Skips backup when backup=False."""
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({
        "dependencies": {"express": "^4.17.1"},
    }, indent=2))

    plan = RemediationPlan(package_fixes=[_npm_fix()])
    result = apply_fixes(plan, [tmp_path], backup=False)

    assert len(result.backed_up) == 0
    assert not (tmp_path / "package.json.agent-bom-backup").exists()


def test_apply_npm_dev_dependencies(tmp_path):
    """Updates packages in devDependencies too."""
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({
        "dependencies": {},
        "devDependencies": {"express": "^4.17.1"},
    }, indent=2))

    plan = RemediationPlan(package_fixes=[_npm_fix()])
    result = apply_fixes(plan, [tmp_path])

    assert len(result.applied) == 1
    data = json.loads(pkg_json.read_text())
    assert data["devDependencies"]["express"] == "^4.21.0"


# ─── pip apply tests ─────────────────────────────────────────────────────────


def test_apply_pip_fixes(tmp_path):
    """Modifies requirements.txt with fixed versions."""
    req_txt = tmp_path / "requirements.txt"
    req_txt.write_text("flask==2.0.0\nrequests==2.28.0\n")

    plan = RemediationPlan(package_fixes=[_pip_fix()])
    result = apply_fixes(plan, [tmp_path])

    assert len(result.applied) == 1
    assert result.applied[0].package == "flask"

    lines = req_txt.read_text().splitlines()
    assert lines[0] == "flask>=3.0.0"
    assert lines[1] == "requests==2.28.0"


def test_apply_pip_preserves_comments(tmp_path):
    """Comments and blank lines in requirements.txt are preserved."""
    req_txt = tmp_path / "requirements.txt"
    req_txt.write_text("# Production deps\nflask==2.0.0\n\n# Dev deps\npytest==7.0.0\n")

    plan = RemediationPlan(package_fixes=[_pip_fix()])
    result = apply_fixes(plan, [tmp_path])

    lines = req_txt.read_text().splitlines()
    assert lines[0] == "# Production deps"
    assert lines[1] == "flask>=3.0.0"
    assert lines[2] == ""
    assert lines[3] == "# Dev deps"
    assert lines[4] == "pytest==7.0.0"


# ─── Edge cases ──────────────────────────────────────────────────────────────


def test_apply_skips_unknown_ecosystem(tmp_path):
    """Cargo/go fixes are skipped gracefully."""
    cargo_fix = PackageFix(
        package="serde",
        ecosystem="cargo",
        current_version="1.0.0",
        fixed_version="1.1.0",
        command="cargo update -p serde",
    )
    plan = RemediationPlan(package_fixes=[cargo_fix])
    result = apply_fixes(plan, [tmp_path])

    assert len(result.skipped) == 1
    assert result.skipped[0].package == "serde"
    assert len(result.applied) == 0


def test_apply_no_matching_file(tmp_path):
    """Returns skipped when no dependency file exists."""
    plan = RemediationPlan(package_fixes=[_npm_fix()])
    result = apply_fixes(plan, [tmp_path])

    assert len(result.skipped) == 1
    assert len(result.applied) == 0


def test_apply_empty_plan(tmp_path):
    """Empty plan returns empty result."""
    plan = RemediationPlan()
    result = apply_fixes(plan, [tmp_path])

    assert len(result.applied) == 0
    assert len(result.skipped) == 0


# ─── apply from JSON ─────────────────────────────────────────────────────────


def test_apply_from_json(tmp_path):
    """Standalone apply command reads scan JSON and modifies files."""
    # Create scan output JSON
    scan_json = tmp_path / "scan.json"
    scan_json.write_text(json.dumps({
        "remediation_plan": [
            {
                "package": "express",
                "ecosystem": "npm",
                "current_version": "4.17.1",
                "fixed_version": "4.21.0",
                "vulnerabilities": ["CVE-2024-0001"],
                "affected_agents": ["claude-desktop"],
            }
        ],
    }))

    # Create package.json
    project = tmp_path / "project"
    project.mkdir()
    (project / "package.json").write_text(json.dumps({
        "dependencies": {"express": "^4.17.1"},
    }, indent=2))

    result = apply_fixes_from_json(str(scan_json), str(project))

    assert len(result.applied) == 1
    data = json.loads((project / "package.json").read_text())
    assert data["dependencies"]["express"] == "^4.21.0"


def test_apply_from_json_no_remediation(tmp_path):
    """Scan JSON with no remediation_plan returns empty result."""
    scan_json = tmp_path / "scan.json"
    scan_json.write_text(json.dumps({"agents": []}))

    result = apply_fixes_from_json(str(scan_json), str(tmp_path))

    assert len(result.applied) == 0
    assert len(result.skipped) == 0


# ─── Registry enrichment tests ───────────────────────────────────────────────


def test_registry_enrich_fills_missing(tmp_path, monkeypatch):
    """Enrichment adds risk_level/credentials to entries with empty fields."""
    from agent_bom import registry as reg_mod

    # Create a minimal registry with incomplete entries
    test_registry = tmp_path / "test_registry.json"
    test_registry.write_text(json.dumps({
        "servers": {
            "mcp-github-server": {
                "package": "mcp-github-server",
                "ecosystem": "npm",
                "latest_version": "1.0.0",
                "description": "",
                "name": "GitHub Server",
                "risk_justification": "",
                "category": "developer-tools",
                "verified": False,
                "tools": ["create_issue"],
            },
        },
    }))

    # Monkeypatch the registry path
    monkeypatch.setattr(reg_mod, "_REGISTRY_PATH", test_registry)

    result = reg_mod.enrich_registry_entries(dry_run=False)

    assert result.total == 1
    assert result.enriched == 1

    # Verify file was updated
    data = json.loads(test_registry.read_text())
    entry = data["servers"]["mcp-github-server"]
    assert entry["description"] != ""
    assert entry["risk_justification"] != ""


def test_registry_enrich_infers_risk_level(tmp_path, monkeypatch):
    """Enrichment infers risk_level from category patterns."""
    from agent_bom import registry as reg_mod

    test_registry = tmp_path / "test_registry.json"
    test_registry.write_text(json.dumps({
        "servers": {
            "mcp-fs-server": {
                "package": "mcp-fs-server",
                "ecosystem": "npm",
                "latest_version": "1.0.0",
                "description": "Filesystem access",
                "name": "FS Server",
                "risk_justification": "Full filesystem access",
                "category": "filesystem",
                "verified": False,
                "tools": ["read_file"],
                "credential_env_vars": [],
                # risk_level intentionally missing — should be inferred as "high"
            },
        },
    }))

    monkeypatch.setattr(reg_mod, "_REGISTRY_PATH", test_registry)

    result = reg_mod.enrich_registry_entries(dry_run=False)

    assert result.enriched == 1
    data = json.loads(test_registry.read_text())
    assert data["servers"]["mcp-fs-server"]["risk_level"] == "high"


def test_registry_enrich_infers_credentials(tmp_path, monkeypatch):
    """Enrichment infers credential_env_vars from package name patterns."""
    from agent_bom import registry as reg_mod

    test_registry = tmp_path / "test_registry.json"
    test_registry.write_text(json.dumps({
        "servers": {
            "mcp-slack-bot": {
                "package": "mcp-slack-bot",
                "ecosystem": "npm",
                "latest_version": "1.0.0",
                "description": "Slack bot",
                "name": "Slack Bot",
                "risk_justification": "",
                "category": "communication",
            },
        },
    }))

    monkeypatch.setattr(reg_mod, "_REGISTRY_PATH", test_registry)

    result = reg_mod.enrich_registry_entries(dry_run=False)

    assert result.enriched == 1
    data = json.loads(test_registry.read_text())
    entry = data["servers"]["mcp-slack-bot"]
    assert "SLACK_BOT_TOKEN" in entry["credential_env_vars"]


def test_registry_enrich_dry_run(tmp_path, monkeypatch):
    """Dry run previews enrichment without modifying registry."""
    from agent_bom import registry as reg_mod

    test_registry = tmp_path / "test_registry.json"
    original = json.dumps({
        "servers": {
            "mcp-test-server": {
                "package": "mcp-test-server",
                "ecosystem": "npm",
                "latest_version": "1.0.0",
                "description": "",
                "name": "Test",
                "risk_justification": "",
                "category": "",
            },
        },
    })
    test_registry.write_text(original)

    monkeypatch.setattr(reg_mod, "_REGISTRY_PATH", test_registry)

    result = reg_mod.enrich_registry_entries(dry_run=True)

    assert result.enriched == 1
    # File should NOT be modified
    assert test_registry.read_text() == original


def test_registry_enrich_all_complete(tmp_path, monkeypatch):
    """When all entries are complete, nothing is enriched."""
    from agent_bom import registry as reg_mod

    test_registry = tmp_path / "test_registry.json"
    test_registry.write_text(json.dumps({
        "servers": {
            "mcp-complete-server": {
                "package": "mcp-complete-server",
                "ecosystem": "npm",
                "latest_version": "1.0.0",
                "description": "A complete server",
                "name": "Complete",
                "risk_justification": "Fully documented risk",
                "category": "utilities",
                "risk_level": "low",
                "verified": True,
                "tools": ["do_thing"],
                "credential_env_vars": [],
            },
        },
    }))

    monkeypatch.setattr(reg_mod, "_REGISTRY_PATH", test_registry)

    result = reg_mod.enrich_registry_entries(dry_run=False)

    assert result.enriched == 0
    assert result.skipped == 1
