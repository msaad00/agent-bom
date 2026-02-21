"""Tests for skill file security audit."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from agent_bom.models import AIBOMReport, MCPServer, Package, TransportType
from agent_bom.output import to_json
from agent_bom.parsers.skill_audit import SkillAuditResult, audit_skill_result
from agent_bom.parsers.skills import SkillScanResult

# ── 1. Typosquat detection ───────────────────────────────────────────────────


def test_typosquat_detection():
    """A near-match package name is flagged as HIGH typosquat."""
    result = SkillScanResult(
        packages=[
            Package(
                name="@modelcontextprotocol/server-filesytem",  # typo: missing 's'
                version="latest",
                ecosystem="npm",
            ),
        ],
        source_files=["CLAUDE.md"],
    )
    with patch("agent_bom.parsers.skill_audit._batch_verify_packages_sync",
               return_value={}):
        audit = audit_skill_result(result)

    typosquat_findings = [f for f in audit.findings if f.category == "typosquat"]
    assert len(typosquat_findings) >= 1
    assert typosquat_findings[0].severity == "high"
    assert "server-filesytem" in typosquat_findings[0].detail


# ── 2. Exact match not flagged ───────────────────────────────────────────────


def test_exact_match_not_flagged():
    """A package that exactly matches a registry entry has no typosquat finding."""
    result = SkillScanResult(
        packages=[
            Package(
                name="@modelcontextprotocol/server-filesystem",
                version="latest",
                ecosystem="npm",
            ),
        ],
        source_files=["CLAUDE.md"],
    )
    audit = audit_skill_result(result)

    typosquat_findings = [f for f in audit.findings if f.category == "typosquat"]
    assert len(typosquat_findings) == 0


# ── 3. Unverified server ────────────────────────────────────────────────────


def test_unverified_server():
    """An MCP server not in the registry is flagged as MEDIUM unverified_server."""
    result = SkillScanResult(
        servers=[
            MCPServer(
                name="my-custom-server",
                command="node",
                args=["server.js"],
            ),
        ],
        source_files=["CLAUDE.md"],
    )
    audit = audit_skill_result(result)

    unverified = [f for f in audit.findings if f.category == "unverified_server"]
    assert len(unverified) >= 1
    assert unverified[0].severity == "medium"


# ── 4. Verified server OK ───────────────────────────────────────────────────


def test_verified_server_ok():
    """A server whose args match a known registry pattern completes without error."""
    result = SkillScanResult(
        servers=[
            MCPServer(
                name="filesystem",
                command="npx",
                args=["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
            ),
        ],
        source_files=["CLAUDE.md"],
    )
    audit = audit_skill_result(result)

    # Should complete without raising and return a valid result
    assert isinstance(audit, SkillAuditResult)
    # Should NOT have an unverified_server finding for this known server
    unverified = [f for f in audit.findings if f.category == "unverified_server"]
    assert len(unverified) == 0


# ── 5. Unknown package ──────────────────────────────────────────────────────


def test_unknown_package():
    """A completely unknown package is flagged as LOW unknown_package."""
    result = SkillScanResult(
        packages=[
            Package(
                name="totally-fake-package-xyz",
                version="1.0.0",
                ecosystem="npm",
            ),
        ],
        source_files=["skill.md"],
    )
    # Mock verification to avoid network calls — package doesn't exist
    with patch("agent_bom.parsers.skill_audit._batch_verify_packages_sync",
               return_value={"totally-fake-package-xyz": False}):
        audit = audit_skill_result(result)

    unknown = [f for f in audit.findings if f.category == "unknown_package"]
    assert len(unknown) >= 1
    assert unknown[0].severity == "low"
    assert "totally-fake-package-xyz" in unknown[0].detail


# ── 6. Shell access via command ──────────────────────────────────────────────


def test_shell_access_command():
    """A server using /bin/bash is flagged as HIGH shell_access."""
    result = SkillScanResult(
        servers=[
            MCPServer(
                name="my-shell",
                command="/bin/bash",
                args=["-c", "echo hello"],
            ),
        ],
        source_files=["CLAUDE.md"],
    )
    audit = audit_skill_result(result)

    shell_findings = [f for f in audit.findings if f.category == "shell_access"]
    assert len(shell_findings) >= 1
    assert any(f.severity == "high" for f in shell_findings)


# ── 7. Shell access via args ────────────────────────────────────────────────


def test_shell_access_args():
    """Dangerous arguments like --allow-exec are flagged as HIGH shell_access."""
    result = SkillScanResult(
        servers=[
            MCPServer(
                name="code-runner",
                command="node",
                args=["--allow-exec", "server.js"],
            ),
        ],
        source_files=["CLAUDE.md"],
    )
    audit = audit_skill_result(result)

    shell_findings = [
        f for f in audit.findings
        if f.category == "shell_access" and "argument" in f.title.lower()
    ]
    assert len(shell_findings) >= 1
    assert shell_findings[0].severity == "high"


# ── 8. Excessive credentials ────────────────────────────────────────────────


def test_excessive_credentials():
    """10 credential env vars triggers MEDIUM excessive_permissions."""
    result = SkillScanResult(
        credential_env_vars=[
            "API_KEY_1", "API_KEY_2", "API_KEY_3", "API_KEY_4",
            "SECRET_1", "SECRET_2", "SECRET_3", "SECRET_4",
            "TOKEN_1", "TOKEN_2",
        ],
        source_files=["CLAUDE.md"],
    )
    audit = audit_skill_result(result)

    excessive = [f for f in audit.findings if f.category == "excessive_permissions"]
    assert len(excessive) >= 1
    assert excessive[0].severity == "medium"


# ── 9. External URL ─────────────────────────────────────────────────────────


def test_external_url():
    """An SSE server pointing to a remote URL is flagged as MEDIUM external_url."""
    result = SkillScanResult(
        servers=[
            MCPServer(
                name="remote-server",
                command="",
                transport=TransportType.SSE,
                url="https://evil.example.com/mcp",
            ),
        ],
        source_files=["CLAUDE.md"],
    )
    audit = audit_skill_result(result)

    external = [f for f in audit.findings if f.category == "external_url"]
    assert len(external) >= 1
    assert external[0].severity == "medium"
    assert "remote-server" in external[0].detail
    assert "external URL" in external[0].detail
    assert external[0].context == "config_block"


# ── 10. Localhost URL OK ─────────────────────────────────────────────────────


def test_localhost_url_ok():
    """An SSE server on localhost should NOT get an external_url finding."""
    result = SkillScanResult(
        servers=[
            MCPServer(
                name="local-server",
                command="",
                transport=TransportType.SSE,
                url="http://localhost:3000/mcp",
            ),
        ],
        source_files=["CLAUDE.md"],
    )
    audit = audit_skill_result(result)

    external = [f for f in audit.findings if f.category == "external_url"]
    assert len(external) == 0


# ── 11. Empty result passes ──────────────────────────────────────────────────


def test_empty_result_passes():
    """An empty SkillScanResult produces a passing audit with no findings."""
    result = SkillScanResult()
    audit = audit_skill_result(result)

    assert audit.passed is True
    assert audit.findings == []
    assert audit.packages_checked == 0
    assert audit.servers_checked == 0


# ── 12. Passed flag reflects high findings ───────────────────────────────────


def test_audit_result_passed_flag():
    """audit.passed is False when a HIGH finding is present (shell access)."""
    result = SkillScanResult(
        servers=[
            MCPServer(
                name="danger-shell",
                command="bash",
                args=["-c", "rm -rf /"],
            ),
        ],
        source_files=["CLAUDE.md"],
    )
    audit = audit_skill_result(result)

    assert audit.passed is False
    high_findings = [f for f in audit.findings if f.severity == "high"]
    assert len(high_findings) >= 1


# ── 13. JSON output includes skill_audit ──────────────────────────────────


def test_skill_audit_in_json_output():
    """to_json() includes skill_audit when skill_audit_data is set on the report."""
    report = AIBOMReport(agents=[], blast_radii=[])
    report.skill_audit_data = {
        "findings": [
            {
                "severity": "high",
                "category": "shell_access",
                "title": "Shell access via server 'evil'",
                "detail": "Server uses bash",
                "source_file": "CLAUDE.md",
                "package": None,
                "server": "evil",
                "recommendation": "Use a sandboxed MCP server.",
                "context": "config_block",
            }
        ],
        "packages_checked": 3,
        "servers_checked": 1,
        "credentials_checked": 0,
        "passed": False,
    }
    result = to_json(report)

    assert "skill_audit" in result
    assert result["skill_audit"]["passed"] is False
    assert len(result["skill_audit"]["findings"]) == 1
    assert result["skill_audit"]["findings"][0]["category"] == "shell_access"
    assert result["skill_audit"]["packages_checked"] == 3


def test_skill_audit_absent_when_no_scan():
    """to_json() does NOT include skill_audit when no skill files were scanned."""
    report = AIBOMReport(agents=[], blast_radii=[])
    result = to_json(report)
    assert "skill_audit" not in result


# ── 15. AI fields on SkillFinding ──────────────────────────────────────────


def test_skill_finding_has_ai_fields():
    """SkillFinding should have ai_analysis and ai_adjusted_severity defaults."""
    from agent_bom.parsers.skill_audit import SkillFinding
    f = SkillFinding(
        severity="high", category="test", title="test",
        detail="test", source_file="test.md",
    )
    assert f.ai_analysis is None
    assert f.ai_adjusted_severity is None


# ── 16. AI fields on SkillAuditResult ──────────────────────────────────────


def test_skill_audit_result_has_ai_fields():
    """SkillAuditResult should have ai_skill_summary and ai_overall_risk_level."""
    from agent_bom.parsers.skill_audit import SkillAuditResult
    r = SkillAuditResult()
    assert r.ai_skill_summary is None
    assert r.ai_overall_risk_level is None


# ── 17. JSON output includes AI skill audit fields ────────────────────────


def test_skill_audit_ai_fields_in_json():
    """to_json includes AI skill analysis fields when set."""
    report = AIBOMReport(agents=[], blast_radii=[])
    report.skill_audit_data = {
        "findings": [],
        "packages_checked": 0,
        "servers_checked": 0,
        "credentials_checked": 0,
        "passed": True,
        "ai_skill_summary": "No significant risks detected.",
        "ai_overall_risk_level": "low",
    }
    result = to_json(report)
    assert result["skill_audit"]["ai_skill_summary"] == "No significant risks detected."
    assert result["skill_audit"]["ai_overall_risk_level"] == "low"


# ── Dynamic package verification tests ───────────────────────────────────


def test_verify_package_exists_pypi():
    """Should return True when PyPI responds 200."""
    from agent_bom.parsers.skill_audit import _verify_package_exists

    mock_resp = MagicMock()
    mock_resp.status_code = 200

    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=AsyncMock())
    mock_cm.__aexit__ = AsyncMock(return_value=False)

    import agent_bom.http_client as _hc
    with patch.object(_hc, "create_client", return_value=mock_cm), \
         patch.object(_hc, "request_with_retry", new_callable=AsyncMock, return_value=mock_resp):
        result = asyncio.run(_verify_package_exists("requests", "pypi"))
        assert result is True


def test_verify_package_not_found():
    """Should return False when registry responds 404."""
    from agent_bom.parsers.skill_audit import _verify_package_exists

    mock_resp = MagicMock()
    mock_resp.status_code = 404

    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=AsyncMock())
    mock_cm.__aexit__ = AsyncMock(return_value=False)

    import agent_bom.http_client as _hc
    with patch.object(_hc, "create_client", return_value=mock_cm), \
         patch.object(_hc, "request_with_retry", new_callable=AsyncMock, return_value=mock_resp):
        result = asyncio.run(_verify_package_exists("zzz-not-real-abc", "pypi"))
        assert result is False


def test_verify_package_network_error():
    """Should return None on network error."""
    from agent_bom.parsers.skill_audit import _verify_package_exists

    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=AsyncMock())
    mock_cm.__aexit__ = AsyncMock(return_value=False)

    import agent_bom.http_client as _hc
    with patch.object(_hc, "create_client", return_value=mock_cm), \
         patch.object(_hc, "request_with_retry", new_callable=AsyncMock, return_value=None):
        result = asyncio.run(_verify_package_exists("requests", "pypi"))
        assert result is None


def test_batch_verify_packages():
    """Should verify multiple packages concurrently."""
    from agent_bom.parsers.skill_audit import _batch_verify_packages

    async def mock_verify(name, eco):
        if name == "requests":
            return True
        return False

    with patch("agent_bom.parsers.skill_audit._verify_package_exists",
               side_effect=mock_verify):
        results = asyncio.run(_batch_verify_packages([
            ("requests", "pypi"),
            ("zzz-fake", "pypi"),
        ]))
        assert results["requests"] is True
        # fail-open: False from _verify → still False (only None coerced to True)
        assert results["zzz-fake"] is False


def test_unknown_package_skipped_if_verified():
    """A package verified on PyPI should NOT be flagged as unknown."""
    result = SkillScanResult(
        packages=[
            Package(name="flask", version="latest", ecosystem="pypi"),
        ],
        source_files=["skill.md"],
    )
    # flask exists on PyPI → verified as True
    with patch("agent_bom.parsers.skill_audit._batch_verify_packages_sync",
               return_value={"flask": True}):
        audit = audit_skill_result(result)

    unknown = [f for f in audit.findings if f.category == "unknown_package"]
    assert len(unknown) == 0


def test_unknown_package_flagged_if_not_verified():
    """A package not on PyPI and not in registry should be flagged."""
    result = SkillScanResult(
        packages=[
            Package(name="zzz-not-real-pkg", version="latest", ecosystem="pypi"),
        ],
        source_files=["skill.md"],
    )
    with patch("agent_bom.parsers.skill_audit._batch_verify_packages_sync",
               return_value={"zzz-not-real-pkg": False}):
        audit = audit_skill_result(result)

    unknown = [f for f in audit.findings if f.category == "unknown_package"]
    assert len(unknown) == 1
    assert "PyPI" in unknown[0].detail


def test_verification_failure_falls_back():
    """When verification errors, audit still runs (fail-open)."""
    result = SkillScanResult(
        packages=[
            Package(name="some-package", version="latest", ecosystem="pypi"),
        ],
        source_files=["skill.md"],
    )
    # Simulate network failure
    with patch("agent_bom.parsers.skill_audit._batch_verify_packages_sync",
               side_effect=Exception("Network error")):
        audit = audit_skill_result(result)

    # Should still produce findings (falls back to registry-only behavior)
    unknown = [f for f in audit.findings if f.category == "unknown_package"]
    assert len(unknown) == 1
