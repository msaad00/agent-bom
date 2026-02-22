"""Tests for Snyk vulnerability enrichment."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from agent_bom.models import Package, Severity, Vulnerability
from agent_bom.snyk import _purl_for_package, _severity_from_snyk, enrich_with_snyk_sync

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(data, status=200):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status
    resp.json.return_value = data
    return resp


def _mock_snyk_issue(issue_id="SNYK-JS-EXPRESS-123", title="Test vuln", severity="high", cvss=7.5, cve_ids=None):
    return {
        "id": issue_id,
        "type": "issue",
        "attributes": {
            "title": title,
            "effective_severity_level": severity,
            "cvss_score": cvss,
            "slots": {
                "references": [
                    {"type": "cve", "value": cve_id}
                    for cve_id in (cve_ids or [])
                ],
            },
        },
    }


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------


def test_purl_for_npm_package():
    """purl generation for npm package."""
    pkg = Package(name="express", version="4.17.1", ecosystem="npm")
    assert _purl_for_package(pkg) == "pkg:npm/express@4.17.1"


def test_purl_for_pypi_package():
    """purl generation for PyPI package."""
    pkg = Package(name="requests", version="2.31.0", ecosystem="pypi")
    assert _purl_for_package(pkg) == "pkg:pypi/requests@2.31.0"


def test_purl_for_unknown_ecosystem():
    """Unknown ecosystem returns None."""
    pkg = Package(name="test", version="1.0", ecosystem="unknown")
    assert _purl_for_package(pkg) is None


def test_purl_uses_existing():
    """If package already has a purl, use it."""
    pkg = Package(name="test", version="1.0", ecosystem="npm", purl="pkg:npm/test@1.0")
    assert _purl_for_package(pkg) == "pkg:npm/test@1.0"


def test_severity_mapping():
    """Snyk severity strings map to our Severity enum."""
    assert _severity_from_snyk("critical") == Severity.CRITICAL
    assert _severity_from_snyk("high") == Severity.HIGH
    assert _severity_from_snyk("medium") == Severity.MEDIUM
    assert _severity_from_snyk("low") == Severity.LOW
    assert _severity_from_snyk("unknown") == Severity.MEDIUM  # default


# ---------------------------------------------------------------------------
# enrich_with_snyk
# ---------------------------------------------------------------------------


def test_enrich_no_token():
    """Enrichment without token returns 0."""
    pkg = Package(name="express", version="4.17.1", ecosystem="npm")
    count = enrich_with_snyk_sync([pkg], token=None, org_id="org-123")
    assert count == 0


def test_enrich_no_org():
    """Enrichment without org_id returns 0."""
    pkg = Package(name="express", version="4.17.1", ecosystem="npm")
    count = enrich_with_snyk_sync([pkg], token="test-key", org_id=None)
    assert count == 0


@patch("agent_bom.snyk.request_with_retry")
@patch("agent_bom.snyk.create_client")
def test_enrich_adds_new_vuln(mock_client_factory, mock_request):
    """Snyk enrichment adds a new vulnerability."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client_factory.return_value = mock_client

    mock_request.return_value = _make_response({
        "data": [_mock_snyk_issue(cve_ids=["CVE-2025-9999"])],
    })

    pkg = Package(name="express", version="4.17.1", ecosystem="npm")
    count = enrich_with_snyk_sync([pkg], token="test-key", org_id="org-123")
    assert count == 1
    assert len(pkg.vulnerabilities) == 1
    assert pkg.vulnerabilities[0].id == "CVE-2025-9999"
    assert "[Snyk]" in pkg.vulnerabilities[0].summary


@patch("agent_bom.snyk.request_with_retry")
@patch("agent_bom.snyk.create_client")
def test_enrich_dedup_with_osv(mock_client_factory, mock_request):
    """Snyk enrichment does not add duplicate CVEs already found by OSV."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client_factory.return_value = mock_client

    mock_request.return_value = _make_response({
        "data": [_mock_snyk_issue(cve_ids=["CVE-2025-0001"])],
    })

    pkg = Package(name="express", version="4.17.1", ecosystem="npm")
    pkg.vulnerabilities = [
        Vulnerability(id="CVE-2025-0001", summary="Already known", severity=Severity.HIGH),
    ]
    count = enrich_with_snyk_sync([pkg], token="test-key", org_id="org-123")
    assert count == 0
    assert len(pkg.vulnerabilities) == 1  # no duplicates added


@patch("agent_bom.snyk.request_with_retry")
@patch("agent_bom.snyk.create_client")
def test_enrich_404_not_in_snyk(mock_client_factory, mock_request):
    """404 from Snyk means package not in their DB — no error."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client_factory.return_value = mock_client

    mock_request.return_value = _make_response({}, status=404)

    pkg = Package(name="my-internal-pkg", version="1.0.0", ecosystem="npm")
    count = enrich_with_snyk_sync([pkg], token="test-key", org_id="org-123")
    assert count == 0
    assert len(pkg.vulnerabilities) == 0


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


def test_cli_snyk_flags():
    """CLI scan command should accept --snyk, --snyk-token, --snyk-org flags."""
    from click.testing import CliRunner

    from agent_bom.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--snyk" in result.output
    assert "--snyk-token" in result.output
    assert "--snyk-org" in result.output
