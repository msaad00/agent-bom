"""Tests for agent_bom.remediate — remediation plan generation and export."""

from __future__ import annotations

from agent_bom.remediate import (
    CredentialFix,
    PackageFix,
    RemediationPlan,
    export_remediation_md,
    export_remediation_sh,
    generate_credential_fixes,
    generate_package_fixes,
)

# ── Credential fix tests ────────────────────────────────────────────────────


def test_credential_fix_github_pat():
    """GitHub PAT template mentions repo scope and links to github.com."""
    fixes = generate_credential_fixes(
        {"GITHUB_PERSONAL_ACCESS_TOKEN": ["agent/server"]}
    )
    assert len(fixes) == 1
    fix = fixes[0]
    assert isinstance(fix, CredentialFix)
    assert fix.credential_name == "GITHUB_PERSONAL_ACCESS_TOKEN"
    assert fix.locations == ["agent/server"]
    assert "repo scope" in fix.risk_description
    assert "github.com" in fix.reference_url


def test_credential_fix_postgres():
    """Postgres template recommends a read-only role."""
    fixes = generate_credential_fixes(
        {"POSTGRES_CONNECTION_STRING": ["db/server"]}
    )
    assert len(fixes) == 1
    fix = fixes[0]
    assert fix.credential_name == "POSTGRES_CONNECTION_STRING"
    assert any("read-only" in step for step in fix.fix_steps)


def test_credential_fix_slack():
    """Slack template links to slack.com."""
    fixes = generate_credential_fixes(
        {"SLACK_BOT_TOKEN": ["slack/server"]}
    )
    assert len(fixes) == 1
    fix = fixes[0]
    assert fix.credential_name == "SLACK_BOT_TOKEN"
    assert "slack.com" in fix.reference_url


def test_credential_fix_generic_api_key():
    """An unknown *_API_KEY credential matches the pattern-based fallback."""
    fixes = generate_credential_fixes(
        {"MY_API_KEY": ["svc/server"]}
    )
    assert len(fixes) == 1
    fix = fixes[0]
    assert isinstance(fix, CredentialFix)
    assert fix.credential_name == "MY_API_KEY"
    assert fix.locations == ["svc/server"]
    # Pattern fallback for API_KEY mentions "unknown"
    assert "unknown" in fix.risk_description.lower()


# ── Package fix tests ────────────────────────────────────────────────────────


def test_package_fix_npm():
    """npm ecosystem produces an 'npm install' command."""
    plan_items = [
        {
            "package": "express",
            "ecosystem": "npm",
            "current": "4.17.1",
            "fix": "4.21.0",
            "vulns": ["GHSA-1234"],
            "agents": ["my-agent"],
        }
    ]
    fixable, unfixable = generate_package_fixes(plan_items)
    assert len(fixable) == 1
    assert len(unfixable) == 0
    fix = fixable[0]
    assert isinstance(fix, PackageFix)
    assert "npm install" in fix.command
    assert "express@4.21.0" in fix.command
    assert fix.fixed_version == "4.21.0"


def test_package_fix_pypi():
    """PyPI ecosystem produces a 'pip install' command."""
    plan_items = [
        {
            "package": "requests",
            "ecosystem": "pypi",
            "current": "2.28.0",
            "fix": "2.32.0",
            "vulns": ["CVE-2024-0001"],
            "agents": ["scanner"],
        }
    ]
    fixable, unfixable = generate_package_fixes(plan_items)
    assert len(fixable) == 1
    assert len(unfixable) == 0
    fix = fixable[0]
    assert "pip install" in fix.command
    assert "requests" in fix.command
    assert "2.32.0" in fix.command


# ── Export tests ──────────────────────────────────────────────────────────────


def test_export_md(tmp_path):
    """export_remediation_md writes a markdown file with correct heading and package info."""
    plan = RemediationPlan(
        package_fixes=[
            PackageFix(
                package="lodash",
                ecosystem="npm",
                current_version="4.17.20",
                fixed_version="4.17.21",
                command="npm install lodash@4.17.21",
                vulns=["CVE-2021-23337"],
                agents=["web-agent"],
            ),
        ],
        credential_fixes=[
            CredentialFix(
                credential_name="GITHUB_PERSONAL_ACCESS_TOKEN",
                locations=["agent/server"],
                risk_description="Token may have full repo scope.",
                fix_steps=["Create a fine-grained PAT"],
            ),
        ],
    )
    out = tmp_path / "remediation.md"
    export_remediation_md(plan, str(out))

    content = out.read_text()
    assert "# agent-bom Remediation Plan" in content
    assert "lodash" in content
    assert "GITHUB_PERSONAL_ACCESS_TOKEN" in content


def test_export_sh(tmp_path):
    """export_remediation_sh writes a bash script starting with a shebang."""
    plan = RemediationPlan(
        package_fixes=[
            PackageFix(
                package="axios",
                ecosystem="npm",
                current_version="0.21.0",
                fixed_version="0.21.1",
                command="npm install axios@0.21.1",
                vulns=["CVE-2021-3749"],
                agents=["api-agent"],
            ),
        ],
    )
    out = tmp_path / "remediation.sh"
    export_remediation_sh(plan, str(out))

    content = out.read_text()
    assert content.startswith("#!/usr/bin/env bash")
    assert "npm install axios@0.21.1" in content
    # Verify file is executable
    import stat
    mode = out.stat().st_mode
    assert mode & stat.S_IXUSR
