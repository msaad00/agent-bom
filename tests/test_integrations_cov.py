"""Tests for integrations — drata.py, vanta.py, jira.py coverage expansion."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


class TestDrataIntegration:
    @pytest.mark.asyncio
    async def test_upload_evidence_success(self):
        from agent_bom.integrations.drata import upload_evidence

        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": "ev_123"}

        with (
            patch("agent_bom.integrations.drata.create_client"),
            patch("agent_bom.integrations.drata.request_with_retry", return_value=mock_response),
        ):
            scan_result = {
                "summary": {"total_vulnerabilities": 5, "total_agents": 3},
                "tool_version": "0.68.1",
            }
            result = await upload_evidence("token123", scan_result)
            assert result == "ev_123"

    @pytest.mark.asyncio
    async def test_upload_evidence_failure(self):
        from agent_bom.integrations.drata import upload_evidence

        mock_response = MagicMock()
        mock_response.status_code = 400

        with (
            patch("agent_bom.integrations.drata.create_client"),
            patch("agent_bom.integrations.drata.request_with_retry", return_value=mock_response),
        ):
            result = await upload_evidence("token123", {"summary": {}})
            assert result is None

    @pytest.mark.asyncio
    async def test_upload_evidence_no_response(self):
        from agent_bom.integrations.drata import upload_evidence

        with (
            patch("agent_bom.integrations.drata.create_client"),
            patch("agent_bom.integrations.drata.request_with_retry", return_value=None),
        ):
            result = await upload_evidence("token123", {"summary": {}})
            assert result is None

    @pytest.mark.asyncio
    async def test_upload_with_control_id(self):
        from agent_bom.integrations.drata import upload_evidence

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": "ev_456"}

        with (
            patch("agent_bom.integrations.drata.create_client"),
            patch("agent_bom.integrations.drata.request_with_retry", return_value=mock_response),
        ):
            result = await upload_evidence("token123", {"summary": {}}, control_id=42)
            assert result == "ev_456"


class TestVantaIntegration:
    @pytest.mark.asyncio
    async def test_upload_evidence_success(self):
        from agent_bom.integrations.vanta import upload_evidence

        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": "vev_123"}

        with (
            patch("agent_bom.integrations.vanta.create_client"),
            patch("agent_bom.integrations.vanta.request_with_retry", return_value=mock_response),
        ):
            scan_result = {
                "summary": {"total_vulnerabilities": 2, "total_agents": 1},
                "blast_radius": [{"severity": "critical"}, {"severity": "high"}],
                "tool_version": "0.68.1",
            }
            result = await upload_evidence("vtoken", scan_result)
            assert result == "vev_123"

    @pytest.mark.asyncio
    async def test_upload_evidence_failure(self):
        from agent_bom.integrations.vanta import upload_evidence

        mock_response = MagicMock()
        mock_response.status_code = 403

        with (
            patch("agent_bom.integrations.vanta.create_client"),
            patch("agent_bom.integrations.vanta.request_with_retry", return_value=mock_response),
        ):
            result = await upload_evidence("vtoken", {"summary": {}, "blast_radius": []})
            assert result is None

    @pytest.mark.asyncio
    async def test_upload_evidence_no_response(self):
        from agent_bom.integrations.vanta import upload_evidence

        with (
            patch("agent_bom.integrations.vanta.create_client"),
            patch("agent_bom.integrations.vanta.request_with_retry", return_value=None),
        ):
            result = await upload_evidence("vtoken", {"summary": {}, "blast_radius": []})
            assert result is None


class TestJiraIntegration:
    @pytest.mark.asyncio
    async def test_create_ticket_success(self):
        from agent_bom.integrations.jira import create_jira_ticket

        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"key": "SEC-123"}

        with (
            patch("agent_bom.integrations.jira.create_client"),
            patch("agent_bom.integrations.jira.request_with_retry", return_value=mock_response),
        ):
            finding = {
                "vulnerability_id": "CVE-2024-1234",
                "severity": "high",
                "package": "express@4.17.0",
                "risk_score": 8.5,
                "fixed_version": "4.18.2",
                "affected_agents": ["agent1"],
                "affected_servers": ["server1"],
                "exposed_credentials": [],
                "owasp_tags": ["LLM02"],
                "owasp_mcp_tags": ["MCP01"],
            }
            result = await create_jira_ticket(
                "https://test.atlassian.net",
                "user@test.com",
                "api-token",
                "SEC",
                finding,
            )
            assert result == "SEC-123"

    @pytest.mark.asyncio
    async def test_create_ticket_failure(self):
        from agent_bom.integrations.jira import create_jira_ticket

        mock_response = MagicMock()
        mock_response.status_code = 400

        with (
            patch("agent_bom.integrations.jira.create_client"),
            patch("agent_bom.integrations.jira.request_with_retry", return_value=mock_response),
        ):
            finding = {
                "vulnerability_id": "CVE-2024-1234",
                "severity": "medium",
                "package": "test",
                "risk_score": 5.0,
                "affected_agents": [],
                "affected_servers": [],
                "exposed_credentials": [],
            }
            result = await create_jira_ticket(
                "https://test.atlassian.net",
                "user@test.com",
                "api-token",
                "SEC",
                finding,
            )
            assert result is None

    @pytest.mark.asyncio
    async def test_create_ticket_no_response(self):
        from agent_bom.integrations.jira import create_jira_ticket

        with (
            patch("agent_bom.integrations.jira.create_client"),
            patch("agent_bom.integrations.jira.request_with_retry", return_value=None),
        ):
            finding = {
                "vulnerability_id": "CVE-2024-5678",
                "severity": "low",
                "package": "test",
                "risk_score": 2.0,
                "affected_agents": [],
                "affected_servers": [],
                "exposed_credentials": [],
            }
            result = await create_jira_ticket(
                "https://test.atlassian.net",
                "user@test.com",
                "api-token",
                "SEC",
                finding,
            )
            assert result is None
